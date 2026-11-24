package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pingapi "github.com/ldesfontaine/kagu/internal/edge/server/ping"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/ratelimit"
)

// callLogin joue POST /api/auth/login sur HTTPS depuis ce pair, comme le
// navigateur de la page de connexion.
func callLogin(server *Server, peer, username, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(authLoginRequest{Username: username, Password: password})
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	request.RemoteAddr = peer
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(anonymousHeader, "1")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

func TestLogin_AttemptBudget_IsSharedByAnIPv6SixtyFour(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	for i := range authAttemptBurst {
		if got := callLogin(server.Server, "[2001:db8:1:2::1]:4000", testUsername, "guess"); got.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i+1, got.Code)
		}
	}
	if got := callLogin(server.Server, "[2001:db8:1:2::2]:4000", testUsername, testPassword); got.Code != http.StatusTooManyRequests {
		t.Fatalf("same /64: status %d, want 429", got.Code)
	}
	if got := callLogin(server.Server, "[2001:db8:1:3::1]:4000", testUsername, testPassword); got.Code != http.StatusOK {
		t.Fatalf("another /64: status %d, want 200", got.Code)
	}
}

// Le verdict « file pleine » est un 429 avec Retry-After, comme le limiteur ;
// une requête abandonnée n'est pas un mauvais mot de passe.
type refusingAuth struct {
	AuthService
	err error
}

func (a refusingAuth) Login(context.Context, auth.State, string, string, string, auth.SessionClient) (auth.OpenedSession, error) {
	return auth.OpenedSession{}, a.err
}

func TestLogin_FullVerificationQueue_Is429WithRetryAfter(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	server.auth = refusingAuth{AuthService: server.operator, err: auth.ErrVerificationQueueFull}
	recorder := callLogin(server.Server, "192.0.2.1:1234", testUsername, "guess")
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
	if recorder.Header().Get("Set-Cookie") != "" {
		t.Fatal("a full queue opened a session")
	}
}

func TestLogin_CanceledWait_IsNotAFailedLogin(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	server.auth = refusingAuth{AuthService: server.operator, err: context.Canceled}
	recorder := callLogin(server.Server, "192.0.2.1:1234", testUsername, "guess")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", recorder.Code)
	}
}

// L'opérateur connecté passe même quand la file des connexions est pleine :
// sa session ne repasse pas par bcrypt.
func TestLogin_SignedInOperator_PassesWhileTheQueueIsRefusing(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	token := signIn(server.Server, testUsername, testPassword)
	server.auth = refusingAuth{AuthService: server.operator, err: auth.ErrVerificationQueueFull}
	request := httptest.NewRequest(http.MethodGet, "/api/counts", nil)
	presentOverHTTPS(request, token)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("signed-in operator: status %d", recorder.Code)
	}
}

// inventedSource donne une adresse de pair différente par i.
func inventedSource(i int) string {
	return fmt.Sprintf("10.%d.%d.%d:4000", i>>16, (i>>8)&255, i&255)
}

// E02-19 : une table de connexion pleine d'adresses inventées n'empêche pas
// le bon mot de passe d'une source neuve ; la mémoire reste bornée.
func TestE02_19_ARightPasswordFromANewSourceIsServedAfterAFullTable(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	server.authLimit = ratelimit.NewBySourceWithGlobal(authAttemptRate, authAttemptBurst, authIdle,
		ratelimit.GlobalLimit{PerMinute: ratelimit.MaxSources + 10, Exempt: isLoopbackAddress})
	server.authLimit.SetClock(func() time.Time { return testNow })
	for i := range ratelimit.MaxSources {
		server.authLimit.Allow(host(inventedSource(i)))
	}
	if size := server.authLimit.Size(); size != ratelimit.MaxSources {
		t.Fatalf("the table holds %d sources, want it full at %d", size, ratelimit.MaxSources)
	}
	if got := callLogin(server.Server, "203.0.113.200:4000", testUsername, testPassword); got.Code != http.StatusOK {
		t.Fatalf("a new source with the right password: status %d, want 200", got.Code)
	}
	if size := server.authLimit.Size(); size > ratelimit.MaxSources {
		t.Fatalf("the table holds %d sources, cap %d", size, ratelimit.MaxSources)
	}
}

func host(peer string) string {
	address, _, _ := net.SplitHostPort(peer)
	return address
}

// Une rafale de sources inventées au-delà de la limite globale : 429 pour
// tous, sauf la boucle locale, que la limite globale ne compte jamais.
func TestE02_19_APastTheGlobalLimitEveryoneIsRefusedButLoopback(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	const global = 15
	server.authLimit = ratelimit.NewBySourceWithGlobal(authAttemptRate, authAttemptBurst, authIdle,
		ratelimit.GlobalLimit{PerMinute: global, Exempt: isLoopbackAddress})
	server.authLimit.SetClock(func() time.Time { return testNow })
	for i := range global {
		if got := callLogin(server.Server, inventedSource(i), testUsername, "guess"); got.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d under the global limit: status %d", i+1, got.Code)
		}
	}
	got := callLogin(server.Server, "203.0.113.200:4000", testUsername, testPassword)
	if got.Code != http.StatusTooManyRequests || got.Header().Get("Retry-After") == "" {
		t.Fatalf("a legitimate new source past the global limit: status %d", got.Code)
	}
	if got := callLogin(server.Server, inventedSource(9999), testUsername, "guess"); got.Code != http.StatusTooManyRequests {
		t.Fatalf("an invented source past the global limit: status %d", got.Code)
	}
	if got := callLogin(server.Server, "127.0.0.1:4000", testUsername, testPassword); got.Code != http.StatusOK {
		t.Fatalf("loopback past the global limit: status %d, want 200", got.Code)
	}
}

// Deux compteurs, deux tables : chacun garde son compte exact, que l'autre
// soit saturé ou non.
func TestE02_19_PingsAndLoginsHaveSeparateCounters(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	const loginGlobal, pingGlobal, pingsFirst = 15, pingapi.DefaultGlobalPerMinute, 5000
	server.authLimit = ratelimit.NewBySourceWithGlobal(authAttemptRate, authAttemptBurst, authIdle,
		ratelimit.GlobalLimit{PerMinute: loginGlobal, Exempt: isLoopbackAddress})
	server.authLimit.SetClock(func() time.Time { return testNow })
	ping := func(i int) int {
		request := httptest.NewRequest(http.MethodGet, "/ping/hb_unknown", nil)
		request.RemoteAddr = inventedSource(i)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		return recorder.Code
	}
	for i := range pingsFirst {
		if got := ping(i); got != http.StatusNotFound {
			t.Fatalf("ping %d: status %d", i+1, got)
		}
	}
	// Les pings déjà reçus ne prennent rien à la connexion : elle a tout son compte.
	for i := range loginGlobal {
		if got := callLogin(server.Server, inventedSource(1000+i), testUsername, "guess"); got.Code != http.StatusUnauthorized {
			t.Fatalf("login %d after pings: status %d, want 401", i+1, got.Code)
		}
	}
	if got := callLogin(server.Server, inventedSource(2000), testUsername, "guess"); got.Code != http.StatusTooManyRequests {
		t.Fatalf("the login counter is not saturated: status %d", got.Code)
	}
	// La connexion saturée ne prend rien aux pings : il leur reste leur compte.
	for i := range pingGlobal - pingsFirst {
		if got := ping(3000 + i); got != http.StatusNotFound {
			t.Fatalf("ping %d after logins: status %d, want 404", i+1, got)
		}
	}
	if got := ping(4000); got != http.StatusTooManyRequests {
		t.Fatalf("the ping counter is not saturated: status %d", got)
	}
}
