package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/auth/authtest"
	"github.com/ldesfontaine/kagu/internal/gesture/verb"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// writeWith joue une écriture JSON du front en HTTPS, sous le cookie donné.
func writeWith(server *Server, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(anonymousHeader, "1")
	overHTTPS(request)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// signedInCookie ouvre une session du compte de test par le composant.
func signedInCookie(t *testing.T, server *Server) *http.Cookie {
	t.Helper()
	token := signIn(server, testUsername, testPassword)
	if token == "" {
		t.Fatal("sign-in refused")
	}
	return &http.Cookie{Name: brand.SessionCookie, Value: token}
}

// loginWithCode joue la connexion en HTTPS, avec le code à six chiffres.
func loginWithCode(server *Server, code string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(authLoginRequest{Username: testUsername, Password: testPassword, Code: code})
	return loginBody(server, string(body))
}

func loginBody(server *Server, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(anonymousHeader, "1")
	overHTTPS(request)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// levelFourWitness inscrit au registre, le temps du test, un geste témoin de
// niveau 4 : aucune route réelle ne l'est encore (E4, D7, E5 viendront). La
// route est celle de « mettre à jour en dernier », qui répond 200 et ne coûte
// rien.
func levelFourWitness(t *testing.T) {
	t.Helper()
	witness := verb.Verb{
		ID: "machine.update_last", Route: "PUT /api/machines/{id}/update-last", Params: []string{"id"}, Body: []string{"update_last"},
		Target: verb.TargetMachine, Label: "api_token.verb_machine_delete", Summary: "api_token.verb_machine_delete_text",
		Level: 4, Reason: "api_token.verb_machine_delete_text", Audit: audit.MachineUpdateLast,
	}
	useRegistry(t, registryWith(t, verb.Default, witness))
}

const witnessPath = "/api/machines/" + remoteID + "/update-last"
const witnessBody = `{"update_last":true}`

// reauthBody : la redemande, mot de passe et code.
func reauthBody(password, code string) string {
	body, _ := json.Marshal(reauthRequest{Password: password, Code: code})
	return string(body)
}

// renewedCookie rend le cookie qu'une redemande réussie a posé.
func renewedCookie(t *testing.T, recorder *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("reauth: %d %s", recorder.Code, recorder.Body.String())
	}
	cookie := cookieNamed(recorder, brand.SessionCookie)
	if cookie == nil {
		t.Fatal("reauth set no cookie")
	}
	return cookie
}

// R-A2-7 : en native, un geste de niveau 4 sans redemande fraîche répond 403
// auth.reauth_required et ne s'exécute pas ; un mot de passe faux ne pose
// rien ; le juste pose reauth_at et un jeton neuf, et le geste passe.
func TestR_A2_7_LevelFourNeedsAFreshReauthInNative(t *testing.T) {
	levelFourWitness(t)
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	session := signedInCookie(t, server.Server)
	before := server.latestAuditID(t)

	got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, session)
	if got.Code != http.StatusForbidden || errorCode(t, got) != "auth.reauth_required" {
		t.Fatalf("without reauth: %d %s, want 403 auth.reauth_required", got.Code, got.Body.String())
	}
	if events := server.auditSince(t, before); len(events) != 0 {
		t.Fatalf("the gesture ran: %+v", events)
	}

	wrong := writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody("a wrong passphrase", ""), session)
	if wrong.Code != http.StatusForbidden || errorCode(t, wrong) != "auth.current_password_wrong" {
		t.Fatalf("wrong password: %d %s", wrong.Code, wrong.Body.String())
	}
	if got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, session); got.Code != http.StatusForbidden {
		t.Fatalf("a wrong password opened the gesture: %d", got.Code)
	}

	renewed := renewedCookie(t, writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody(testPassword, ""), session))
	if renewed.Value == session.Value {
		t.Fatal("the session token was not renewed")
	}
	if got := readWith(server.Server, "/api/counts", session, "192.0.2.1:1234"); got.Code != http.StatusUnauthorized {
		t.Fatalf("the token presented before the reauth still opens: %d", got.Code)
	}
	if got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, renewed); got.Code != http.StatusOK {
		t.Fatalf("after reauth: %d %s", got.Code, got.Body.String())
	}
}

// R-A2-8 : en forward, rien n'est redemandé ; le geste de niveau 4 passe.
func TestR_A2_8_LevelFourAsksNothingInForward(t *testing.T) {
	levelFourWitness(t)
	server := newFirstSetupServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	server.enableForward(t)
	got := callForwardedJSON(server.Server, http.MethodPut, witnessPath, witnessBody, trustedPeer, auth.DefaultForwardHeader, "lucas")
	if got.Code != http.StatusOK {
		t.Fatalf("forward: %d %s, want 200", got.Code, got.Body.String())
	}
}

// R-CNX-6 : la redemande vaut cinq minutes, pour cette session seulement. Une
// autre session du même compte reste refusée ; passé le délai, la session qui
// a redonné son mot de passe l'est aussi.
func TestR_CNX_6_ReauthLastsFiveMinutesForThisSessionOnly(t *testing.T) {
	levelFourWitness(t)
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	now := testNow
	server.operator.SetClock(func() time.Time { return now })
	mine := signedInCookie(t, server.Server)
	other := signedInCookie(t, server.Server)

	mine = renewedCookie(t, writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody(testPassword, ""), mine))
	if got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, other); got.Code != http.StatusForbidden || errorCode(t, got) != "auth.reauth_required" {
		t.Fatalf("another session rides on my reauth: %d %s", got.Code, got.Body.String())
	}
	now = testNow.Add(auth.ReauthLifetime - time.Second)
	if got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, mine); got.Code != http.StatusOK {
		t.Fatalf("within five minutes: %d %s", got.Code, got.Body.String())
	}
	now = testNow.Add(auth.ReauthLifetime)
	if got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, mine); got.Code != http.StatusForbidden || errorCode(t, got) != "auth.reauth_required" {
		t.Fatalf("after five minutes: %d %s", got.Code, got.Body.String())
	}
}

type totpProposal struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QRCode string `json:"qr_code"`
}

func (ts *testServer) totpActive(t *testing.T, cookie *http.Cookie) bool {
	t.Helper()
	var state authResponse
	decodeAPI(t, readWith(ts.Server, "/api/auth", cookie, "192.0.2.1:1234"), &state)
	return state.TOTP
}

// R-CNX-2 : en native, le code est proposé, jamais imposé. Sans lui, la
// connexion ne demande que le mot de passe ; posé (sur un premier code
// juste), elle le demande en second écran ; retiré (sur le mot de passe), elle
// ne le demande plus.
func TestR_CNX_2_TOTPIsOfferedNeverRequired(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	now := testNow
	server.operator.SetClock(func() time.Time { return now })
	if got := loginWithCode(server.Server, ""); got.Code != http.StatusOK {
		t.Fatalf("no code enrolled: %d %s", got.Code, got.Body.String())
	}
	session := signedInCookie(t, server.Server)
	if server.totpActive(t, session) {
		t.Fatal("a fresh account has a code")
	}

	var proposal totpProposal
	decodeAPI(t, readWith(server.Server, "/api/auth/totp/proposal", session, "192.0.2.1:1234"), &proposal)
	if proposal.Secret == "" || !strings.HasPrefix(proposal.URI, "otpauth://totp/") || !strings.HasPrefix(proposal.QRCode, "data:image/png;base64,") {
		t.Fatalf("proposal %+v", proposal)
	}
	if server.totpActive(t, session) {
		t.Fatal("a proposal enabled the code")
	}
	enrolment := authtest.TOTPCode(t, proposal.Secret, now)
	enable := writeWith(server.Server, http.MethodPost, "/api/auth/totp", `{"secret":"`+proposal.Secret+`","code":"`+enrolment+`"}`, session)
	if enable.Code != http.StatusNoContent || !server.totpActive(t, session) {
		t.Fatalf("enable: %d %s", enable.Code, enable.Body.String())
	}

	if got := loginWithCode(server.Server, ""); got.Code != http.StatusUnauthorized || errorCode(t, got) != "auth.totp_required" || cookieNamed(got, brand.SessionCookie) != nil {
		t.Fatalf("password alone with a code enrolled: %d %s", got.Code, got.Body.String())
	}
	if got := loginWithCode(server.Server, enrolment); got.Code != http.StatusUnauthorized || errorCode(t, got) != "auth.totp_wrong" {
		t.Fatalf("the enrolment code replayed: %d %s", got.Code, got.Body.String())
	}
	now = now.Add(auth.TOTPPeriod)
	if got := loginWithCode(server.Server, authtest.TOTPCode(t, proposal.Secret, now)); got.Code != http.StatusOK || cookieNamed(got, brand.SessionCookie) == nil {
		t.Fatalf("password and code: %d %s", got.Code, got.Body.String())
	}

	if got := writeWith(server.Server, http.MethodDelete, "/api/auth/totp", `{"password":"a wrong passphrase"}`, session); got.Code != http.StatusForbidden || !server.totpActive(t, session) {
		t.Fatalf("remove with a wrong password: %d %s", got.Code, got.Body.String())
	}
	if got := writeWith(server.Server, http.MethodDelete, "/api/auth/totp", `{"password":"`+testPassword+`"}`, session); got.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", got.Code, got.Body.String())
	}
	if got := loginWithCode(server.Server, ""); got.Code != http.StatusOK {
		t.Fatalf("after removal: %d %s", got.Code, got.Body.String())
	}
}

// Avec le code actif, la redemande le demande aussi ; le secret ne sort ni
// dans l'état, ni dans le journal d'audit, ni dans les journaux du serveur.
func TestReauth_AsksTheCodeAndTheSecretNeverLeaks(t *testing.T) {
	levelFourWitness(t)
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	now := testNow
	server.operator.SetClock(func() time.Time { return now })
	session := signedInCookie(t, server.Server)
	var proposal totpProposal
	decodeAPI(t, readWith(server.Server, "/api/auth/totp/proposal", session, "192.0.2.1:1234"), &proposal)
	before := server.latestAuditID(t)
	enable := writeWith(server.Server, http.MethodPost, "/api/auth/totp", `{"secret":"`+proposal.Secret+`","code":"`+authtest.TOTPCode(t, proposal.Secret, now)+`"}`, session)
	if enable.Code != http.StatusNoContent {
		t.Fatalf("enable: %d %s", enable.Code, enable.Body.String())
	}
	now = now.Add(auth.TOTPPeriod)

	if got := writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody(testPassword, ""), session); got.Code != http.StatusForbidden || errorCode(t, got) != "auth.totp_required" {
		t.Fatalf("reauth without the code: %d %s", got.Code, got.Body.String())
	}
	session = renewedCookie(t, writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody(testPassword, authtest.TOTPCode(t, proposal.Secret, now)), session))
	if got := writeWith(server.Server, http.MethodPut, witnessPath, witnessBody, session); got.Code != http.StatusOK {
		t.Fatalf("after password and code: %d %s", got.Code, got.Body.String())
	}

	state := readWith(server.Server, "/api/auth", session, "192.0.2.1:1234").Body.String()
	events, _ := json.Marshal(server.auditSince(t, before))
	for name, seen := range map[string]string{"state": state, "audit": string(events), "logs": server.logs.String()} {
		if strings.Contains(seen, proposal.Secret) {
			t.Errorf("the code secret shows in the %s", name)
		}
	}
}

// Négatifs : la proposition et les gestes du code sont fermés aux jetons
// d'API ; un code déjà actif ne se propose ni ne se pose deux fois ; un secret
// trop court est refusé.
func TestTOTPRoutes_Refusals(t *testing.T) {
	server := newTestServer(t)
	bearer := server.issueAPIToken(t, "lecteur")
	for _, call := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/auth/totp/proposal", ""},
		{http.MethodPost, "/api/auth/totp", `{}`},
		{http.MethodDelete, "/api/auth/totp", `{}`},
		{http.MethodPost, "/api/auth/reauth", `{}`},
	} {
		if got := callBearerBody(server.Server, call.method, call.path, bearer, call.body); got.Code != http.StatusForbidden {
			t.Errorf("%s %s with a token: %d, want 403", call.method, call.path, got.Code)
		}
	}

	session := signedInCookie(t, server.Server)
	weak := writeWith(server.Server, http.MethodPost, "/api/auth/totp", `{"secret":"MFRGGZDF","code":"123456"}`, session)
	if weak.Code != http.StatusUnprocessableEntity || errorCode(t, weak) != "auth.totp_secret_invalid" {
		t.Fatalf("weak secret: %d %s", weak.Code, weak.Body.String())
	}
	var proposal totpProposal
	decodeAPI(t, readWith(server.Server, "/api/auth/totp/proposal", session, "192.0.2.1:1234"), &proposal)
	code := authtest.TOTPCode(t, proposal.Secret, testNow)
	if got := writeWith(server.Server, http.MethodPost, "/api/auth/totp", `{"secret":"`+proposal.Secret+`","code":"`+code+`"}`, session); got.Code != http.StatusNoContent {
		t.Fatalf("enable: %d %s", got.Code, got.Body.String())
	}
	if got := readWith(server.Server, "/api/auth/totp/proposal", session, "192.0.2.1:1234"); got.Code != http.StatusConflict {
		t.Fatalf("proposal while active: %d", got.Code)
	}

	// Root le retire par le canal local, sans rien demander.
	if got := callControl(server, http.MethodPost, "/control/admin/reset-totp", `{}`, rootUID); got.Code != http.StatusNoContent {
		t.Fatalf("reset-totp: %d %s", got.Code, got.Body.String())
	}
	if active, err := server.operator.TOTPActive(context.Background()); err != nil || active {
		t.Fatalf("after reset-totp: %v %v", active, err)
	}
	if got := callControl(server, http.MethodPost, "/control/admin/reset-totp", `{}`, rootUID); got.Code != http.StatusConflict || errorCode(t, got) != "auth.totp_inactive" {
		t.Fatalf("reset-totp twice: %d %s", got.Code, got.Body.String())
	}
}
