package server

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/opencloud/internal/kit/ratelimit"
)

// TU-21 : derrière un mandataire déclaré, la place du client se rend quand le
// handler finit, mais net/http lit encore le corps non lu avant de répondre.
// Sans échéance de lecture, un corps envoyé au compte-gouttes tient la
// connexion hors de la borne par client.
func TestTU21_ATrickledBodyDoesNotHoldTheConnectionPastTheReadDeadline(t *testing.T) {
	const perClient = 2
	const held = 10
	const readBound = 500 * time.Millisecond
	bench := newFirstSetupServer(t)
	bench.enableBasic(t)
	bench.trustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	bench.clientSlots = ratelimit.NewSourceSlots(perClient)
	bench.refusals = newRefusalLog(nil)
	// L'ordre de serve : l'écouteur compté (le mandataire ne compte qu'au
	// total), l'échéance de lecture, la borne par client, puis le serveur.
	address := listenLimitedForTest(t, ConnectionLimits{
		Total: 1024, PerSource: 64,
		Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}, boundRequestRead(readBound, bench.limitClientsBehindProxy(bench.Server)))

	// Le même client (203.0.113.9 vu par le mandataire) ouvre `held` requêtes
	// anonymes au corps annoncé de 1000 octets, et n'en envoie qu'un.
	conns := make([]net.Conn, 0, held)
	for range held {
		conn := dialFrom(t, "127.0.0.1", address)
		fmt.Fprintf(conn, "POST /api/counts HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
		conns = append(conns, conn)
	}
	time.Sleep(4 * readBound)
	stillHeld := 0
	for _, conn := range conns {
		if !isClosedByServer(t, conn) {
			stillHeld++
		}
	}
	if stillHeld > perClient {
		t.Errorf("un seul client derrière le mandataire tient %d connexions ouvertes, borne %d", stillHeld, perClient)
	}
}

// isClosedByServer lit jusqu'à la fin de la connexion : la réponse déjà
// partie se lit, puis la fermeture ; une connexion tenue ne rend rien avant
// l'échéance du test.
func isClosedByServer(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	reader := bufio.NewReader(conn)
	for {
		if _, err := reader.ReadString('\n'); err != nil {
			ne, timeout := err.(net.Error)
			return !(timeout && ne.Timeout())
		}
	}
}

// Un X-Forwarded-For venu d'un pair non déclaré est ignoré : une ligne de
// journal le dit, une fois par pair, sans bruit pour un pair déclaré.
func TestTU21_ForwardedForFromAnUndeclaredPeerIsLoggedOnce(t *testing.T) {
	bench := newFirstSetupServer(t)
	bench.clientSlots = ratelimit.NewSourceSlots(2)
	logs := &logBuffer{}
	bench.refusals = newRefusalLog(slog.New(slog.NewTextHandler(logs, nil)))
	handler := bench.limitClientsBehindProxy(okHandler)
	send := func(peer string) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = peer + ":4000"
		request.Header.Set("X-Forwarded-For", "203.0.113.9")
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	for range 3 {
		send("10.0.0.7")
	}
	if lines := strings.Count(logs.String(), "X-Forwarded-For ignored"); lines != 1 {
		t.Fatalf("%d lignes pour 3 requêtes d'un pair non déclaré, voulu 1 :\n%s", lines, logs.String())
	}

	bench.trustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.8/32")}
	send("10.0.0.8")
	if lines := strings.Count(logs.String(), "X-Forwarded-For ignored"); lines != 1 {
		t.Fatalf("un pair déclaré a été journalisé :\n%s", logs.String())
	}
}
