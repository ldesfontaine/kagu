package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const changedPassword = "another long passphrase"

// storedPasswordHash lit l'empreinte en base, là où un changement l'écrirait.
func (ts *testServer) storedPasswordHash(t *testing.T) string {
	t.Helper()
	state, err := ts.operator.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return state.PasswordHash
}

func changePasswordBody(current, password string) string {
	return `{"current":"` + current + `","password":"` + password + `"}`
}

func TestR_A2_9_ChangingThePasswordNeedsTheCurrentOne(t *testing.T) {
	server := newTestServer(t)
	server.issueAPIToken(t, "lecteur")
	before := server.storedPasswordHash(t)

	for name, body := range map[string]string{
		"absent":                  `{"password":"` + changedPassword + `"}`,
		"empty":                   changePasswordBody("", changedPassword),
		"wrong":                   changePasswordBody("not the password", changedPassword),
		"wrong and a bad new one": changePasswordBody("not the password", "short"),
	} {
		got := callSignedInJSON(server.Server, http.MethodPut, "/api/auth/password", body, testPassword)
		if got.Code != http.StatusForbidden || errorCode(t, got) != "auth.current_password_wrong" {
			t.Fatalf("%s current: %d %s, want 403 auth.current_password_wrong", name, got.Code, got.Body.String())
		}
		if server.storedPasswordHash(t) != before {
			t.Fatalf("%s current: the stored hash changed", name)
		}
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, changedPassword); got.Code != http.StatusUnauthorized {
		t.Fatalf("the refused password opens: %d", got.Code)
	}

	changed := callSignedInJSON(server.Server, http.MethodPut, "/api/auth/password", changePasswordBody(testPassword, changedPassword), testPassword)
	if changed.Code != http.StatusOK {
		t.Fatalf("right current: %d %s", changed.Code, changed.Body.String())
	}
	var response authPasswordResponse
	decodeAPI(t, changed, &response)
	if response.APITokens != 1 {
		t.Fatalf("api_tokens %d, want the 1 token that lives", response.APITokens)
	}
	if body := changed.Body.String(); strings.Contains(body, "$2") || strings.Contains(body, testPassword) || strings.Contains(body, changedPassword) {
		t.Fatal("neither a hash nor a password leaves the process")
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, changedPassword); got.Code != http.StatusOK {
		t.Fatalf("new password: %d", got.Code)
	}
	if got := callAs(server.Server, http.MethodGet, "/api/counts", testUsername, testPassword); got.Code != http.StatusUnauthorized {
		t.Fatalf("old password after change: %d", got.Code)
	}
}

// Un mot de passe actuel faux compte comme un échec de connexion : la route
// n'est pas un oracle sans frein, même pour le bon mot de passe ensuite.
func TestR_A2_9_AWrongCurrentPasswordCountsAgainstTheSourceLimit(t *testing.T) {
	server := newTestServer(t)
	before := server.storedPasswordHash(t)
	attempt := func(current string) int {
		request := httptest.NewRequest(http.MethodPut, "/api/auth/password", strings.NewReader(changePasswordBody(current, changedPassword)))
		request.RemoteAddr = "203.0.113.9:4000"
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Content-Type", "application/json")
		signInRequest(server.Server, request, testUsername, testPassword)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		return recorder.Code
	}
	limited := false
	for range authAttemptBurst + 1 {
		got := attempt("guess")
		if got == http.StatusTooManyRequests {
			limited = true
			break
		}
		if got != http.StatusForbidden {
			t.Fatalf("wrong current: status %d, want 403", got)
		}
	}
	if !limited {
		t.Fatal("the guesses were never limited")
	}
	if got := attempt(testPassword); got != http.StatusTooManyRequests {
		t.Fatalf("right current after the burst: status %d, want 429", got)
	}
	if server.storedPasswordHash(t) != before {
		t.Fatal("a limited request changed the hash")
	}
}
