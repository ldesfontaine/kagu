package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unreadBody est un corps géant qui compte ce qu'on en lit.
type unreadBody struct{ read int }

func (b *unreadBody) Read(p []byte) (int, error) {
	b.read += len(p)
	return len(p), nil
}

// guardedServer remet la garde du pair que le banc lève, derrière le
// mandataire 10.10.80.10 : la configuration du banc d'E02-07.
func guardedServer(t *testing.T) *testServer {
	t.Helper()
	server := newTestServer(t)
	server.operatorFromAnyPeer = false
	server.trustedProxies = parsePrefixes(t, "10.10.80.10/32")
	return server
}

func fromPeer(server *Server, method, path string, body io.Reader, peer string, shape func(*http.Request)) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, body)
	request.Header.Set(anonymousHeader, "1")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.RemoteAddr = peer
	if shape != nil {
		shape(request)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// R-CNX-5 : d'un pair qui n'est ni la boucle locale ni un mandataire de
// confiance, l'interface de l'opérateur n'est pas servie : la page, l'API, et
// la connexion, dont le corps (le mot de passe) n'est pas lu.
func TestR_CNX_5_TheInterfaceIsRefusedToAPeerThatBypassesTheProxy(t *testing.T) {
	server := guardedServer(t)
	const neighbour = "10.10.80.11:41000"
	for _, path := range []string{"/", "/machines", "/api/auth", "/api/machines", "/api/unknown"} {
		got := fromPeer(server.Server, http.MethodGet, path, nil, neighbour, nil)
		if got.Code != http.StatusForbidden {
			t.Errorf("GET %s from a neighbour: %d, want 403", path, got.Code)
		}
		if strings.HasPrefix(path, "/api/") && errorCode(t, got) != codeHTTPSRequired {
			t.Errorf("GET %s from a neighbour: %s", path, got.Body.String())
		}
	}
	login := &unreadBody{}
	got := fromPeer(server.Server, http.MethodPost, "/api/auth/login", io.LimitReader(login, 1<<30), neighbour, overHTTPS)
	if got.Code != http.StatusForbidden || errorCode(t, got) != codeHTTPSRequired {
		t.Fatalf("login from a neighbour: %d %s", got.Code, got.Body.String())
	}
	if login.read != 0 {
		t.Fatalf("the refused login read %d bytes of its body", login.read)
	}
}

// R-CNX-5 : le mandataire de confiance et la boucle locale sont servis ; les
// routes des agents et des tâches ne changent pas, d'où qu'elles viennent.
func TestR_CNX_5_TheProxyAndLoopbackAreServedAgentRoutesUnchanged(t *testing.T) {
	server := guardedServer(t)
	job := server.createJob(t, "job")
	viaProxy := func(request *http.Request) {
		request.Header.Set("X-Forwarded-For", "198.51.100.7")
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	for _, path := range []string{"/", "/api/auth"} {
		if got := fromPeer(server.Server, http.MethodGet, path, nil, "10.10.80.10:41000", viaProxy); got.Code == http.StatusForbidden {
			t.Errorf("GET %s through the proxy: 403 %s", path, got.Body.String())
		}
		if got := fromPeer(server.Server, http.MethodGet, path, nil, "127.0.0.1:41000", nil); got.Code == http.StatusForbidden {
			t.Errorf("GET %s from loopback: 403 %s", path, got.Body.String())
		}
	}
	if got := fromPeer(server.Server, http.MethodGet, "/api/auth", nil, "10.10.80.10:41000", viaProxy); got.Code != http.StatusOK {
		t.Fatalf("/api/auth through the proxy: %d", got.Code)
	}
	const neighbour = "10.10.80.11:41000"
	if got := fromPeer(server.Server, http.MethodGet, "/ping/"+job.Token, nil, neighbour, nil); got.Code != http.StatusOK {
		t.Fatalf("a ping from a neighbour: %d", got.Code)
	}
	enroll := fromPeer(server.Server, http.MethodPost, "/agent/enroll", strings.NewReader(`{}`), neighbour, nil)
	if enroll.Code == http.StatusForbidden && strings.Contains(enroll.Body.String(), codeHTTPSRequired) {
		t.Fatalf("an agent route met the peer guard: %d %s", enroll.Code, enroll.Body.String())
	}
}
