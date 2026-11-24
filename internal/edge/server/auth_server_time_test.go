package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth/authtest"
)

// E02-21 : l'écran du code porte l'heure du serveur, celle qui juge le code,
// lue sans session : la page de connexion la montre avant tout code juste.
func TestE02_21_TheCodeScreenCarriesTheServerTime(t *testing.T) {
	server, _, _, now := withTOTPServer(t)
	*now = now.Add(-5 * time.Minute)
	request := httptest.NewRequest(http.MethodGet, "/api/auth", nil)
	request.Header.Set(anonymousHeader, "1")
	read := httptest.NewRecorder()
	server.ServeHTTP(read, request)
	var state authResponse
	decodeAPI(t, read, &state)
	if state.SignedIn || !state.ServerTime.Equal(*now) || state.ServerTime.Location() != time.UTC {
		t.Fatalf("anonymous auth state %+v, want the server time %s", state, now)
	}
}

// E02-21 : aucun oracle. Un code faux qui aurait été juste cinq minutes plus
// tard reçoit la même réponse, octet pour octet, qu'un code faux quelconque :
// la réponse ne dit rien de l'écart des horloges.
func TestE02_21_AWrongCodeSaysNothingOfTheClock(t *testing.T) {
	server, _, secret, now := withTOTPServer(t)
	nearlyRight := authtest.TOTPCode(t, secret, now.Add(5*time.Minute))
	anyWrong := aWrongCode(t, secret, *now)
	if nearlyRight == anyWrong {
		t.Fatal("the two codes must differ")
	}
	near := callLoginFrom(server.Server, "192.0.2.10:1234", testPassword, nearlyRight)
	other := callLoginFrom(server.Server, "192.0.2.10:1234", testPassword, anyWrong)
	if near.Code != http.StatusUnauthorized || errorCode(t, near) != "auth.totp_wrong" {
		t.Fatalf("a code five minutes ahead: %d %s", near.Code, near.Body.String())
	}
	if near.Code != other.Code || near.Body.String() != other.Body.String() {
		t.Fatalf("near %d %q, other %d %q", near.Code, near.Body.String(), other.Code, other.Body.String())
	}
	for name := range near.Header() {
		// L'identifiant de la requête est tiré à chaque requête, code ou non.
		if name != "X-Request-Id" && near.Header().Get(name) != other.Header().Get(name) {
			t.Errorf("header %s: %q, %q", name, near.Header().Get(name), other.Header().Get(name))
		}
	}
	if len(near.Header()) != len(other.Header()) {
		t.Fatalf("headers %v, %v", near.Header(), other.Header())
	}
}
