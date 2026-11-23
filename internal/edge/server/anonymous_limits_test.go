package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
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
	request.AddCookie(&http.Cookie{Name: brand.SessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("signed-in operator: status %d", recorder.Code)
	}
}
