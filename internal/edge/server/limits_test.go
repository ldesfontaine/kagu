package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/opencloud/internal/domain/restic"
	"github.com/ldesfontaine/opencloud/internal/kit/ratelimit"
	"github.com/ldesfontaine/opencloud/internal/kit/wait/waittest"
)

// listenLimitedForTest sert un http.Server sur une vraie boucle locale, via
// LimitConnections : c'est ce que serve monte.
func listenLimitedForTest(t *testing.T, limits ConnectionLimits, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: handler}
	go func() { _ = httpServer.Serve(LimitConnections(listener, limits)) }()
	t.Cleanup(func() { _ = httpServer.Close() })
	return listener.Addr().String()
}

// dialFrom ouvre une connexion depuis une adresse source donnée de la boucle
// locale (127.0.0.0/8 en entier est locale sous Linux).
func dialFrom(t *testing.T, source, address string) net.Conn {
	t.Helper()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// isRefused : le serveur a fermé la connexion sans rien dire. Une connexion
// gardée ne lit rien avant l'échéance.
func isRefused(t *testing.T, conn net.Conn) bool {
	t.Helper()
	return isRefusedWithin(t, conn, 300*time.Millisecond)
}

func isRefusedWithin(t *testing.T, conn net.Conn, wait time.Duration) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := conn.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "reset")
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

// TestR_A2_18 : critère W-F7. La 65e connexion d'une source est refusée ; une
// réponse hors flux qui dépasse la durée est coupée, un flux plus long ne
// l'est pas. Les durées sont celles du test (150 ms, 700 ms) : la règle ne
// dépend pas de la valeur, et 30 s puis 10 min ne tiendraient pas dans un test.
// La part « cinquième ?wait= » attend D8 (T11-08).
func TestR_A2_18(t *testing.T) {
	t.Run("the 65th connection of a source is refused, the 64 first held", func(t *testing.T) {
		address := listenLimitedForTest(t, ConnectionLimits{Total: 1024, PerSource: 64}, okHandler)
		held := make([]net.Conn, 0, 64)
		for range 64 {
			held = append(held, dialFrom(t, "127.0.0.1", address))
		}
		if !isRefused(t, dialFrom(t, "127.0.0.1", address)) {
			t.Fatal("65th connection of one source was served")
		}
		for i, conn := range held {
			if isRefusedWithin(t, conn, 5*time.Millisecond) {
				t.Fatalf("held connection %d was closed", i)
			}
		}
	})

	t.Run("a closed connection gives its place back", func(t *testing.T) {
		address := listenLimitedForTest(t, ConnectionLimits{Total: 1024, PerSource: 2}, okHandler)
		first := dialFrom(t, "127.0.0.1", address)
		dialFrom(t, "127.0.0.1", address)
		if !isRefused(t, dialFrom(t, "127.0.0.1", address)) {
			t.Fatal("third connection was served")
		}
		_ = first.Close()
		waittest.Until(t, "a place freed by Close is taken again", func() bool {
			return !isRefused(t, dialFrom(t, "127.0.0.1", address))
		})
	})

	t.Run("another source is not refused for the first one", func(t *testing.T) {
		address := listenLimitedForTest(t, ConnectionLimits{Total: 1024, PerSource: 1}, okHandler)
		dialFrom(t, "127.0.0.1", address)
		if !isRefused(t, dialFrom(t, "127.0.0.1", address)) {
			t.Fatal("second connection of the same source was served")
		}
		if isRefused(t, dialFrom(t, "127.0.0.2", address)) {
			t.Fatal("a second source was refused for the first one")
		}
	})

	t.Run("the total is bounded across sources", func(t *testing.T) {
		address := listenLimitedForTest(t, ConnectionLimits{Total: 2, PerSource: 64}, okHandler)
		dialFrom(t, "127.0.0.1", address)
		dialFrom(t, "127.0.0.2", address)
		if !isRefused(t, dialFrom(t, "127.0.0.3", address)) {
			t.Fatal("connection over the total was served")
		}
	})

	t.Run("a trusted proxy counts in the total only", func(t *testing.T) {
		trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		address := listenLimitedForTest(t, ConnectionLimits{Total: 3, PerSource: 1, Trusted: trusted}, okHandler)
		dialFrom(t, "127.0.0.1", address)
		dialFrom(t, "127.0.0.1", address)
		dialFrom(t, "127.0.0.1", address)
		if !isRefused(t, dialFrom(t, "127.0.0.1", address)) {
			t.Fatal("trusted proxy went past the total")
		}
	})

	t.Run("a refusal is logged once a minute per source", func(t *testing.T) {
		logs := &logBuffer{}
		limits := ConnectionLimits{Total: 1024, PerSource: 1, Logger: slog.New(slog.NewTextHandler(logs, nil))}
		address := listenLimitedForTest(t, limits, okHandler)
		dialFrom(t, "127.0.0.1", address)
		for range 5 {
			if !isRefused(t, dialFrom(t, "127.0.0.1", address)) {
				t.Fatal("extra connection was served")
			}
		}
		if lines := strings.Count(logs.String(), "connection refused"); lines != 1 {
			t.Fatalf("%d log lines for 5 refusals of one source, want 1:\n%s", lines, logs.String())
		}
	})

	t.Run("a response outside a stream is cut, a longer stream is not", func(t *testing.T) {
		const bound, hold = 150 * time.Millisecond, 700 * time.Millisecond
		outcomes := make(chan error, 2)
		slow := func(w http.ResponseWriter, _ *http.Request) {
			outcomes <- writeAfter(w, hold)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /slow", slow)
		mux.HandleFunc("GET /stream", liftDeadlines(slow))
		address := listenLimitedForTest(t, ConnectionLimits{Total: 1024, PerSource: 64}, boundResponseWrite(bound, mux))

		_, _ = http.Get("http://" + address + "/slow")
		if err := <-outcomes; err == nil {
			t.Fatal("a response outside a stream outlived its write duration")
		}
		response, err := http.Get("http://" + address + "/stream")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if err := <-outcomes; err != nil {
			t.Fatalf("a stream was cut: %v", err)
		}
	})

	t.Run("a stream is not cut by the deadline of the previous response on its connection", func(t *testing.T) {
		const bound, hold = 150 * time.Millisecond, 400 * time.Millisecond
		outcomes := make(chan error, 1)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /short", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		mux.HandleFunc("GET /stream", liftDeadlines(func(w http.ResponseWriter, _ *http.Request) {
			outcomes <- writeAfter(w, hold)
		}))
		address := listenLimitedForTest(t, ConnectionLimits{Total: 1024, PerSource: 64}, boundResponseWrite(bound, mux))

		client := &http.Client{}
		get := func(path string) (reused bool) {
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
			request, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "http://"+address+path, nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			return reused
		}
		get("/short")
		time.Sleep(2 * bound)
		if !get("/stream") {
			t.Skip("the connection was not reused: nothing to check")
		}
		if err := <-outcomes; err != nil {
			t.Fatalf("stream cut by the stale deadline of /short: %v", err)
		}
	})
}

// writeAfter attend hold, puis écrit et pousse ce qu'un client lit : l'erreur
// est celle de la connexion, coupée ou non par l'échéance.
func writeAfter(w http.ResponseWriter, hold time.Duration) error {
	time.Sleep(hold)
	if _, err := w.Write([]byte("late")); err != nil {
		return err
	}
	return http.NewResponseController(w).Flush()
}

// deadlineRecorder garde les échéances d'écriture et de lecture posées en
// dernier.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline     time.Time
	set          bool
	readDeadline time.Time
	readSet      bool
}

func (r *deadlineRecorder) SetReadDeadline(deadline time.Time) error {
	r.readDeadline, r.readSet = deadline, true
	return nil
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline, r.set = deadline, true
	return nil
}

// Les routes de flux perdent la durée d'écriture, toutes les autres la
// gardent : lu sur l'arbre réel, sans attendre un flux de 30 s.
func TestR_A2_18_StreamRoutesLiftTheDeadlineOthersKeepIt(t *testing.T) {
	bench := newTestServer(t)
	handler := boundRequestRead(30*time.Second, boundResponseWrite(30*time.Second, bench.mux()))
	deadlineOf := func(method, path string) *deadlineRecorder {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequestWithContext(ctx, method, path, nil)
		recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	for _, path := range []string{"/api/events", "/api/containers/c1/logs/stream", "/statut/page/api/events", "/agent/stream", "/agent/parcels/p1/f.age", "/agent/relay/body/r1", "/agent/relay/rest/m1/config"} {
		if recorded := deadlineOf(http.MethodGet, path); !recorded.set || !recorded.deadline.IsZero() {
			t.Errorf("GET %s: write deadline %v, want none", path, recorded.deadline)
		}
		if recorded := deadlineOf(http.MethodGet, path); !recorded.readSet || !recorded.readDeadline.IsZero() {
			t.Errorf("GET %s: read deadline %v, want none", path, recorded.readDeadline)
		}
	}
	browse := deadlineOf(http.MethodPost, "/api/machines/m1/restic-backups/b1/actions/browse")
	if left := time.Until(browse.deadline); !browse.set || left < browseWriteBound-5*time.Second || left > browseWriteBound {
		t.Errorf("browse: write deadline in %v, want about %v", left, browseWriteBound)
	}
	if left := time.Until(browse.readDeadline); !browse.readSet || left < browseWriteBound-5*time.Second || left > browseWriteBound {
		t.Errorf("browse: read deadline in %v, want about %v", left, browseWriteBound)
	}
	if browseWriteBound <= restic.BrowseWait {
		t.Errorf("browse bound %v leaves no margin over the wait %v", browseWriteBound, restic.BrowseWait)
	}
	for _, path := range []string{"/api/session", "/api/machines", "/api/jobs", "/statut/page/api/status", "/", "/ping/token"} {
		recorded := deadlineOf(http.MethodGet, path)
		if left := time.Until(recorded.deadline); !recorded.set || left < 25*time.Second || left > 30*time.Second {
			t.Errorf("GET %s: write deadline in %v, want about 30s", path, left)
		}
		if left := time.Until(recorded.readDeadline); !recorded.readSet || left < 25*time.Second || left > 30*time.Second {
			t.Errorf("GET %s: read deadline in %v, want about 30s", path, left)
		}
	}
}

// Une entrée de streamRoutes qui ne désigne aucune route ne lèverait rien :
// la liste ne doit pas survivre à un renommage.
func TestR_A2_18_EveryStreamRouteExists(t *testing.T) {
	existing := map[string]bool{}
	for _, route := range newTestServer(t).routes() {
		existing[route.method+" "+route.pattern] = true
	}
	listed := append(slices.Clone(streamRoutes), transferRoutes...)
	for entry := range ownBoundRoutes {
		listed = append(listed, entry)
	}
	for _, entry := range listed {
		if !existing[entry] {
			t.Errorf("stream route %q is not a route of the tree", entry)
		}
	}
}

// Derrière un mandataire de confiance, la borne par source se prend sur
// l'adresse que la requête donne, lue comme partout (clientAddress) ; un pair
// qui n'est pas un mandataire reste compté par connexion, pas ici.
func TestR_A2_18_BehindATrustedProxyTheBoundIsPerClient(t *testing.T) {
	bench := newTestServer(t)
	bench.trustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	bench.clientSlots = ratelimit.NewSourceSlots(2)
	logs := &logBuffer{}
	bench.refusals = newRefusalLog(slog.New(slog.NewTextHandler(logs, nil)))

	entered, release := make(chan struct{}, 16), make(chan struct{})
	handler := bench.limitClientsBehindProxy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-time.After(time.Second): // une borne qui ne refuse pas rend la main, le test échoue
		}
	}))
	serve := func(peer, forwardedFor string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		request.RemoteAddr = peer + ":4000"
		if forwardedFor != "" {
			request.Header.Set("X-Forwarded-For", forwardedFor)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	hold := func(peer, forwardedFor string) {
		go serve(peer, forwardedFor)
		<-entered
	}

	hold("127.0.0.1", "203.0.113.9")
	hold("127.0.0.1", "203.0.113.9")
	if got := serve("127.0.0.1", "203.0.113.9").Code; got != http.StatusTooManyRequests {
		t.Fatalf("third request of one client behind the proxy: %d, want 429", got)
	}
	// Ce que le client écrit à gauche ne lui ouvre pas de compte neuf.
	if got := serve("127.0.0.1", "198.51.100.77, 203.0.113.9").Code; got != http.StatusTooManyRequests {
		t.Fatalf("forged left entry: %d, want 429", got)
	}
	if lines := strings.Count(logs.String(), "connection refused"); lines != 1 {
		t.Fatalf("%d log lines for 2 refusals of one client, want 1", lines)
	}
	hold("127.0.0.1", "203.0.113.10") // un autre client passe
	// Un pair qui n'est pas un mandataire n'est pas compté ici, et son
	// X-Forwarded-For ne vaut rien.
	for range 3 {
		hold("192.0.2.50", "203.0.113.9")
	}
	close(release)
	eventually := func() bool { return bench.clientSlots.Sources() == 0 }
	waittest.Until(t, "the places to be given back", eventually)
	hold2 := make(chan struct{})
	go func() { <-entered; close(hold2) }()
	if got := serve("127.0.0.1", "203.0.113.9").Code; got == http.StatusTooManyRequests {
		t.Fatal("the places were not given back")
	}
	<-hold2
}

// Un transfert qui ne bouge plus est coupé, un transfert lent mais vivant ne
// l'est pas. 150 ms de silence font la coupure du test (3 min en production).
func TestR_A2_18_AStalledTransferIsCutASlowOneIsNot(t *testing.T) {
	const idle = 150 * time.Millisecond
	outcomes := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /send/{gaps}", cutIfIdle(idle, func(w http.ResponseWriter, r *http.Request) {
		gap, _ := time.ParseDuration(r.PathValue("gaps"))
		var err error
		// Le premier morceau part tout de suite : sans en-tête reçu, le client
		// rejouerait un GET dont la connexion a été coupée.
		for range 8 {
			if _, err = w.Write([]byte("chunk")); err != nil {
				break
			}
			if err = http.NewResponseController(w).Flush(); err != nil {
				break
			}
			time.Sleep(gap)
		}
		outcomes <- err
	}))
	mux.HandleFunc("POST /receive", cutIfIdle(idle, func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		outcomes <- err
	}))
	address := listenLimitedForTest(t, ConnectionLimits{Total: 1024, PerSource: 64}, mux)

	get := func(gap string) {
		response, err := http.Get("http://" + address + "/send/" + gap)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}
	get("50ms") // 8 morceaux sur 400 ms, plus que idle : vivant
	if err := <-outcomes; err != nil {
		t.Fatalf("a slow but live download was cut: %v", err)
	}
	get("400ms") // un silence de 400 ms entre deux morceaux : stagnant
	if err := <-outcomes; err == nil {
		t.Fatal("a stalled download was not cut")
	}

	upload := func(gap time.Duration, chunks int) {
		reader, writer := io.Pipe()
		go func() {
			for range chunks {
				time.Sleep(gap)
				if _, err := writer.Write([]byte("chunk")); err != nil {
					return
				}
			}
			writer.Close()
		}()
		response, err := http.Post("http://"+address+"/receive", "application/octet-stream", reader)
		if err == nil {
			response.Body.Close()
		}
		reader.Close()
	}
	upload(50*time.Millisecond, 8)
	if err := <-outcomes; err != nil {
		t.Fatalf("a slow but live upload was cut: %v", err)
	}
	upload(400*time.Millisecond, 2)
	if err := <-outcomes; err == nil {
		t.Fatal("a stalled upload was not cut")
	}
}
