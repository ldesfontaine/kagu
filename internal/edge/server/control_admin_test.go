package server

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
)

// asPeer pose sur la requête l'uid que le noyau aurait donné pour son pair,
// comme peercred.ConnContext le fait sur la socket.
func asPeer(request *http.Request, uid uint32) *http.Request {
	readUID := func(net.Conn) (uint32, error) { return uid, nil }
	return request.WithContext(peercred.ConnContext(readUID)(request.Context(), nil))
}

// asRoot : la requête de `sudo kagu admin …`.
func asRoot(request *http.Request) *http.Request {
	return asPeer(request, rootUID)
}

// callControl joue une requête sur la socket, sous l'uid donné.
func callControl(ts *testServer, method, path, body string, uid uint32) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, "http://control"+path, strings.NewReader(body))
	ts.ControlHandler().ServeHTTP(recorder, asPeer(request, uid))
	return recorder
}

// serviceUID : un compte qui n'est pas root, celui du service par exemple.
const serviceUID = 998

// adminBodies : un corps valable pour chaque route d'administration, pour
// qu'un refus ne puisse venir que de la garde.
var adminBodies = map[string]string{
	"POST /control/admin/setup-code":         `{}`,
	"POST /control/admin/reset-password":     `{"password":"a passphrase from root"}`,
	"POST /control/admin/reset-totp":         `{}`,
	"POST /control/admin/unlock":             `{}`,
	"POST /control/admin/auth-mode":          `{"mode":"forward","header":"X-Forwarded-User"}`,
	"POST /control/admin/sessions/close-all": `{}`,
	"POST /control/admin/tokens/revoke-all":  `{}`,
	"GET /control/admin/health":              ``,
	"POST /control/admin/backup/pre-upgrade": `{}`,
	"POST /control/admin/releases/import":    `{"folder":"/var/lib/kagu-import/v0.0.2"}`,
}

// R-A2-11 : un pair d'uid non nul reçoit 403 sur chaque route
// /control/admin/, setup-code compris (N-3), et rien n'est écrit ; un pair
// dont l'uid n'a pas été lu aussi. Le fichier de l'annuaire reste servi au
// compte du service. Hors root, le pair réel de la socket n'est pas root : la
// vraie lecture de l'uid le refuse aussi.
func TestR_A2_11_AdminRoutesRefuseANonRootPeer(t *testing.T) {
	ts := newTestServer(t)
	token := ts.issueAPIToken(t, "lecteur")
	session := signIn(ts.Server, testUsername, testPassword)
	before, err := ts.operator.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	routes := ts.adminRoutes()
	if len(routes) != len(adminBodies) {
		t.Fatalf("%d admin routes, %d bodies: give each route its body", len(routes), len(adminBodies))
	}
	for _, route := range routes {
		method, path, _ := strings.Cut(route.pattern, " ")
		body, known := adminBodies[route.pattern]
		if !known {
			t.Fatalf("%s has no body in adminBodies", route.pattern)
		}
		if got := callControl(ts, method, path, body, serviceUID); got.Code != http.StatusForbidden {
			t.Errorf("%s as uid %d: %d, want 403", route.pattern, serviceUID, got.Code)
		}
		unread := httptest.NewRecorder()
		ts.ControlHandler().ServeHTTP(unread, httptest.NewRequest(method, "http://control"+path, strings.NewReader(body)))
		if unread.Code != http.StatusForbidden {
			t.Errorf("%s without a peer uid: %d, want 403", route.pattern, unread.Code)
		}
	}
	if got := callControl(ts, http.MethodPost, "/control/admin/unknown", `{}`, serviceUID); got.Code != http.StatusForbidden {
		t.Errorf("an unknown admin route as uid %d: %d, want 403", serviceUID, got.Code)
	}

	after, err := ts.operator.State(context.Background())
	if err != nil || !after.Same(before) {
		t.Fatalf("a refused peer changed the access: %+v %v", after, err)
	}
	for _, written := range []string{brand.UpgradeDir, brand.ReleasesDir} {
		if _, err := ts.state.Stat(written); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a refused peer wrote %s in the state: %v", written, err)
		}
	}
	if got := callWithSession(ts.Server, "/api/counts", session); got.Code != http.StatusOK {
		t.Fatalf("a refused peer closed a session: %d", got.Code)
	}
	if got := callBearer(ts.Server, "/api/counts", token); got.Code != http.StatusOK {
		t.Fatalf("a refused peer revoked a token: %d", got.Code)
	}
	if got := callControl(ts, http.MethodGet, "/api/manifest/export", "", serviceUID); got.Code != http.StatusOK {
		t.Fatalf("the service account lost the directory file: %d %s", got.Code, got.Body.String())
	}

	if os.Geteuid() == 0 {
		return
	}
	t.Run("through a real socket", func(t *testing.T) {
		client := serveControlOnSocket(t, ts)
		response, err := client.Post("http://control/control/admin/setup-code", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("uid %d on setup-code: %d, want 403", os.Geteuid(), response.StatusCode)
		}
		export, err := client.Get("http://control/api/manifest/export")
		if err != nil {
			t.Fatal(err)
		}
		_ = export.Body.Close()
		if export.StatusCode != http.StatusOK {
			t.Fatalf("the service account on the directory file: %d", export.StatusCode)
		}
	})
}

// serveControlOnSocket sert ControlHandler sur une vraie socket, l'uid lu par
// peercred.Peer, et rend un client qui s'y connecte.
func serveControlOnSocket(t *testing.T, ts *testServer) *http.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	listener, err := peercred.Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	control := &http.Server{Handler: ts.ControlHandler(), ConnContext: peercred.ConnContext(peercred.Peer)}
	go func() { _ = control.Serve(listener) }()
	t.Cleanup(func() { _ = control.Close() })
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

// R-A2-10 : rien de ce que le port sert ne rouvre la première configuration
// ni ne refait l'accès. La route « désactiver » n'existe plus, et les routes
// d'administration ne sont servies que par la socket, même à l'opérateur
// connecté.
func TestR_A2_10_NothingReopensTheFirstSetupFromThePort(t *testing.T) {
	ts := newTestServer(t)
	before, err := ts.operator.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := callSignedInJSON(ts.Server, http.MethodPost, "/api/auth/actions/disable", `{}`, testPassword); got.Code != http.StatusNotFound {
		t.Fatalf("POST /api/auth/actions/disable: %d %s, want 404", got.Code, got.Body.String())
	}
	// Un GET qu'aucune route ne prend reçoit le repli du port (la page de
	// l'application si le front est compilé) : seule cette réponse-là, à
	// l'octet près, dit qu'une route d'administration n'y est pas servie.
	unrouted := callSignedInJSON(ts.Server, http.MethodGet, "/__aucune-route-r-a2-10", "", testPassword)
	for _, route := range ts.adminRoutes() {
		method, path, _ := strings.Cut(route.pattern, " ")
		for _, onPort := range []string{path, "/api" + path} {
			got := callSignedInJSON(ts.Server, method, onPort, adminBodies[route.pattern], testPassword)
			if method == http.MethodGet && sameResponse(got, unrouted) {
				continue
			}
			if got.Code < 300 || got.Code == http.StatusNotModified {
				t.Errorf("%s %s served on the port: %d", method, onPort, got.Code)
			}
		}
	}
	for _, route := range ts.routes() {
		if strings.HasPrefix(route.pattern, adminPrefix) {
			t.Errorf("%s %s is a route of the port", route.method, route.pattern)
		}
	}
	after, err := ts.operator.State(context.Background())
	if err != nil || !after.Same(before) || after.Mode != auth.ModeNative {
		t.Fatalf("the port changed the access: %+v %v", after, err)
	}
}

// reset-password par root : toutes les sessions meurent, le nouveau mot de
// passe ouvre, et ni lui ni son empreinte ne sortent dans le journal de
// serve, la réponse ou l'audit, qui nomme root par son uid.
func TestAdminResetPassword_ClosesEverySessionAndLeavesNoTrace(t *testing.T) {
	ts := newTestServer(t)
	first := signIn(ts.Server, testUsername, testPassword)
	second := signIn(ts.Server, testUsername, testPassword)
	const fresh = "a passphrase from root"
	got := callControl(ts, http.MethodPost, "/control/admin/reset-password", `{"password":"`+fresh+`"}`, rootUID)
	if got.Code != http.StatusOK || strings.TrimSpace(got.Body.String()) != `{"closed":2}` {
		t.Fatalf("reset: %d %s", got.Code, got.Body.String())
	}
	for _, session := range []string{first, second} {
		if code := callWithSession(ts.Server, "/api/counts", session).Code; code != http.StatusUnauthorized {
			t.Fatalf("a session survived the reset: %d", code)
		}
	}
	if code := callAs(ts.Server, http.MethodGet, "/api/counts", testUsername, fresh).Code; code != http.StatusOK {
		t.Fatalf("the new password: %d", code)
	}
	state, err := ts.operator.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	events, err := ts.db.ListAuditEvents(context.Background(), audit.Query{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var reset *audit.Event
	for index := range events {
		if events[index].Action == audit.AuthResetPassword {
			reset = &events[index]
		}
	}
	if reset == nil || reset.Actor.Kind != audit.ActorCLI || reset.Actor.Name != "uid:0" {
		t.Fatalf("audit of the reset: %+v", reset)
	}
	audited := callSignedInJSON(ts.Server, http.MethodGet, "/api/audit?limit=200", "", fresh).Body.String()
	for where, text := range map[string]string{"logs": ts.logs.String(), "answer": got.Body.String(), "audit": audited} {
		if strings.Contains(text, fresh) || strings.Contains(text, state.PasswordHash) {
			t.Errorf("%s carries the new password or its hash", where)
		}
	}
}

// Ce que root se voit refuser, avec la clé que la commande traduit : un mot
// de passe trop court, un reset en SSO, un mode inconnu ou none.
func TestAdminRoutes_RefusalsCarryTheirKey(t *testing.T) {
	ts := newTestServer(t)
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/reset-password", `{"password":"short"}`, rootUID), http.StatusUnprocessableEntity, "auth.password_too_short")
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/reset-password", `{"password":"x","extra":1}`, rootUID), http.StatusBadRequest, codeBadJSON)
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/auth-mode", `{"mode":"none"}`, rootUID), http.StatusUnprocessableEntity, "auth.mode_invalid")
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/auth-mode", `{"mode":"native","username":"lucas","password":"a passphrase from root"}`, rootUID), http.StatusConflict, "auth.same_mode")
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/setup-code", `{}`, rootUID), http.StatusConflict, "auth.already_enabled")

	if got := callControl(ts, http.MethodPost, "/control/admin/auth-mode", `{"mode":"forward","header":"X-Forwarded-User"}`, rootUID); got.Code != http.StatusOK {
		t.Fatalf("to forward: %d %s", got.Code, got.Body.String())
	}
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/reset-password", `{"password":"a passphrase from root"}`, rootUID), http.StatusConflict, "auth.no_password")
}

// sessions/close-all et tokens/revoke-all : chacun ne touche qu'à ce qu'il
// nomme.
func TestAdminRoutes_CloseSessionsAndRevokeTokens(t *testing.T) {
	ts := newTestServer(t)
	token := ts.issueAPIToken(t, "lecteur")
	session := signIn(ts.Server, testUsername, testPassword)

	closed := callControl(ts, http.MethodPost, "/control/admin/sessions/close-all", "", rootUID)
	if closed.Code != http.StatusOK || strings.TrimSpace(closed.Body.String()) != `{"closed":1}` {
		t.Fatalf("close-all: %d %s", closed.Code, closed.Body.String())
	}
	if code := callWithSession(ts.Server, "/api/counts", session).Code; code != http.StatusUnauthorized {
		t.Fatalf("a session survived close-all: %d", code)
	}
	if code := callBearer(ts.Server, "/api/counts", token).Code; code != http.StatusOK {
		t.Fatalf("close-all revoked a token: %d", code)
	}

	revoked := callControl(ts, http.MethodPost, "/control/admin/tokens/revoke-all", `{}`, rootUID)
	if revoked.Code != http.StatusOK || strings.TrimSpace(revoked.Body.String()) != `{"revoked":1}` {
		t.Fatalf("revoke-all: %d %s", revoked.Code, revoked.Body.String())
	}
	if code := callBearer(ts.Server, "/api/counts", token).Code; code != http.StatusUnauthorized {
		t.Fatalf("a token survived revoke-all: %d", code)
	}
	if code := callAs(ts.Server, http.MethodGet, "/api/counts", testUsername, testPassword).Code; code != http.StatusOK {
		t.Fatalf("revoke-all touched the account: %d", code)
	}
}

// sameResponse : même code, même Content-Type, même corps à l'octet près.
func sameResponse(got, want *httptest.ResponseRecorder) bool {
	return got.Code == want.Code &&
		got.Header().Get("Content-Type") == want.Header().Get("Content-Type") &&
		bytes.Equal(got.Body.Bytes(), want.Body.Bytes())
}
