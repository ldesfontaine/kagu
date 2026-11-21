package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/ldesfontaine/opencloud/internal/domain/restic"
	"github.com/ldesfontaine/opencloud/internal/edge/server/httpx"
	"github.com/ldesfontaine/opencloud/internal/kit/ratelimit"
)

// Ce qu'un client peut tenir ouvert (R-A2-18) : des connexions, comptées à
// l'acceptation, et le temps qu'une réponse hors flux met à partir. Le
// serveur HTTP ne pose pas de WriteTimeout : il couperait aussi les flux.
const (
	// Une source dont la connexion est refusée est dite au journal une fois
	// par minute, pas une ligne par tentative.
	refusalLogEvery = time.Minute
	refusalLogIdle  = 2 * refusalLogEvery
)

// refusalLog dit un refus une fois par minute et par source : un client qui
// insiste ne remplit pas le journal.
type refusalLog struct {
	logger *slog.Logger
	seen   *ratelimit.BySource
}

func newRefusalLog(logger *slog.Logger) *refusalLog {
	return &refusalLog{logger: logger, seen: ratelimit.NewBySource(1/refusalLogEvery.Seconds(), 1, refusalLogIdle)}
}

// note journalise le refus de cette source, sauf si elle l'a déjà été depuis
// moins d'une minute ; limit dit la borne atteinte.
func (l *refusalLog) note(address, limit string) {
	if l.logger == nil || !l.seen.Allow(address) {
		return
	}
	l.logger.Warn("connection refused: too many open connections", "source", address, "limit", limit)
}

// ConnectionLimits borne les connexions ouvertes en même temps.
type ConnectionLimits struct {
	// Total : toutes sources confondues. PerSource : une source, jugée comme
	// ratelimit.SourceSlots (une IPv4, un /64 en IPv6).
	Total     int
	PerSource int
	// Trusted : les mandataires de confiance (trusted_proxies). Leur pair
	// TCP est le mandataire, pas le client : l'adresse que le client y met
	// n'est lisible qu'une fois la requête lue. Ils ne comptent donc que dans
	// le total ; la borne par source se prend alors sur la requête
	// (Server.limitClientsBehindProxy), à l'adresse que la requête donne.
	Trusted []netip.Prefix
	Logger  *slog.Logger
}

// LimitConnections enveloppe l'écouteur : une connexion au-delà des bornes
// est fermée à l'acceptation, avant d'avoir lu un octet.
func LimitConnections(inner net.Listener, limits ConnectionLimits) net.Listener {
	return &limitedListener{
		Listener: inner,
		limits:   limits,
		total:    ratelimit.NewSlots(int32(limits.Total)), // #nosec G115 -- borné à 1 000 000 par config.MaxConnections.
		sources:  ratelimit.NewSourceSlots(limits.PerSource),
		refusals: newRefusalLog(limits.Logger),
	}
}

type limitedListener struct {
	net.Listener
	limits   ConnectionLimits
	total    *ratelimit.Slots
	sources  *ratelimit.SourceSlots
	refusals *refusalLog
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		address := peerAddress(conn)
		held, reason := l.take(address)
		if held == nil {
			_ = conn.Close()
			l.refusals.note(address, reason)
			continue
		}
		return &countedConn{Conn: conn, release: held}, nil
	}
}

// take réserve la place de la connexion ; la fonction rendue la libère. Nil,
// avec la raison, quand une borne est atteinte.
func (l *limitedListener) take(address string) (release func(), reason string) {
	if !l.total.Take() {
		return nil, "total"
	}
	if isTrustedPeer(l.limits.Trusted, address) {
		return l.total.Release, ""
	}
	if !l.sources.Take(address) {
		l.total.Release()
		return nil, "per_source"
	}
	return func() {
		l.sources.Release(address)
		l.total.Release()
	}, ""
}

// countedConn rend sa place une seule fois, quel que soit le nombre de Close.
type countedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func isTrustedPeer(trusted []netip.Prefix, address string) bool {
	parsed, err := netip.ParseAddr(address)
	return err == nil && prefixesContain(trusted, parsed)
}

func peerAddress(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// boundResponseWrite pose, avant toute route, la durée qu'une réponse a pour
// partir. Une route de flux la lève (liftWriteDeadline) : le défaut borne,
// une route ajoutée plus tard l'est sans y penser.
func boundResponseWrite(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setWriteDeadline(w, time.Now().Add(timeout))
		next.ServeHTTP(w, r)
	})
}

// liftWriteDeadline laisse un flux ouvert aussi longtemps que son client :
// net/http ne remet pas l'échéance à zéro d'une requête à l'autre sur une
// connexion gardée, et celle d'une réponse précédente couperait le flux.
func liftWriteDeadline(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setWriteDeadline(w, time.Time{})
		next(w, r)
	}
}

// setWriteDeadline ignore l'erreur : un écrivain sans échéance (le
// httptest.ResponseRecorder) n'a pas de connexion à borner.
func setWriteDeadline(w http.ResponseWriter, deadline time.Time) {
	_ = http.NewResponseController(w).SetWriteDeadline(deadline)
}

// limitClientsBehindProxy borne, pour un pair de trusted_proxies, ce que
// l'écouteur ne peut pas : les requêtes ouvertes en même temps par client.
// L'adresse est celle de clientAddress, la règle de lecture de
// X-Forwarded-For que tout le serveur partage. Un pair qui n'est pas un
// mandataire est déjà compté par connexion, à l'acceptation : pas deux fois.
// Une requête de flux garde sa place tant qu'elle dure, comme une connexion.
func (s *Server) limitClientsBehindProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.trustsPeer(r) {
			next.ServeHTTP(w, r)
			return
		}
		address := s.clientAddress(r)
		if !s.clientSlots.Take(address) {
			s.refusals.note(address, "per_source")
			httpx.WriteTooMany(w)
			return
		}
		defer s.clientSlots.Release(address)
		next.ServeHTTP(w, r)
	})
}

// browseWriteBound : browse attend la cible jusqu'à restic.BrowseWait, puis
// répond (un 504 au besoin). La marge laisse partir cette réponse ; la durée
// générale de 30 s la couperait avant.
const (
	browseWriteMargin = 15 * time.Second
	browseWriteBound  = restic.BrowseWait + browseWriteMargin
)

// boundWriteTo remplace, pour une route, la durée d'écriture générale par la
// sienne.
func boundWriteTo(bound time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setWriteDeadline(w, time.Now().Add(bound))
		next(w, r)
	}
}

// transferIdleTimeout : un colis ou un relais restic n'a pas de durée, mais
// il est coupé quand plus aucun octet ne passe pendant ce temps. Trois
// minutes : plus que les deux du relais qui attend la tête de la réponse de
// la cible (restic.defaultHeadTimeout), où rien ne passe encore, et très
// au-dessus d'un transfert lent mais vivant, dont chaque morceau relance le
// compte.
const transferIdleTimeout = 3 * time.Minute

// cutIfIdle coupe le transfert dont plus aucun octet ne passe, dans un sens
// ou dans l'autre, pendant idle. Il ne pose pas d'échéance à chaque écriture :
// une minuterie, relancée à chaque morceau, ramène les deux échéances de la
// connexion à maintenant quand elle sonne, ce qui fait échouer la lecture ou
// l'écriture en cours. Celles que la route pose elle-même (l'envoi d'un colis
// a la sienne) ne sont pas touchées.
func cutIfIdle(idle time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		timer := time.AfterFunc(idle, func() {
			now := time.Now()
			_ = controller.SetReadDeadline(now)
			_ = controller.SetWriteDeadline(now)
		})
		defer timer.Stop()
		moved := func() { timer.Reset(idle) }
		r.Body = &movingBody{ReadCloser: r.Body, moved: moved}
		next(&movingWriter{ResponseWriter: w, moved: moved}, r)
	}
}

// movingWriter et movingBody disent à cutIfIdle que des octets ont passé.
type movingWriter struct {
	http.ResponseWriter
	moved func()
}

func (w *movingWriter) Write(chunk []byte) (int, error) {
	written, err := w.ResponseWriter.Write(chunk)
	if written > 0 {
		w.moved()
	}
	return written, err
}

// Unwrap laisse http.ResponseController joindre la connexion et Flush.
func (w *movingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type movingBody struct {
	io.ReadCloser
	moved func()
}

func (b *movingBody) Read(chunk []byte) (int, error) {
	read, err := b.ReadCloser.Read(chunk)
	if read > 0 {
		b.moved()
	}
	return read, err
}
