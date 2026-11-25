package main

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
)

// serveAgentSocket ouvre la socket des agents dans un dossier court, pour
// account, l'uid du pair lu par readPeer, et rend son chemin.
func serveAgentSocket(t *testing.T, account agentAccount, handler http.Handler, readPeer func(net.Conn) (uint32, error)) string {
	t.Helper()
	path := filepath.Join(shortDir(t), filepath.Base(brand.AgentSocketPath))
	agents := startAgentSocket(slog.New(slog.DiscardHandler), path, account, handler, readPeer)
	if agents == nil {
		t.Fatal("the agent socket did not open")
	}
	t.Cleanup(func() { _ = agents.Close() })
	return path
}

// requestOver envoie method path sur la socket et rend le statut.
func requestOver(t *testing.T, socket, method, path string) int {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	request, err := http.NewRequest(method, "http://localhost"+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

// countingHandler compte les requêtes qui l'atteignent.
func countingHandler(reached *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
}

func peerOf(uid uint32) func(net.Conn) (uint32, error) {
	return func(net.Conn) (uint32, error) { return uid, nil }
}

// R-B1-7 : la socket des agents n'admet que l'uid du compte de l'agent. Un
// pair d'un autre uid, root compris, reçoit 403 et n'atteint aucun handler ;
// le compte de l'agent passe.
func TestR_B1_7_AgentSocketAdmitsOnlyTheAgentUID(t *testing.T) {
	const agentUID = 990
	account := agentAccount{uid: agentUID, gid: os.Getgid()}
	for _, other := range []uint32{0, agentUID + 1} {
		var reached atomic.Int32
		socket := serveAgentSocket(t, account, countingHandler(&reached), peerOf(other))
		if status := requestOver(t, socket, http.MethodPost, "/agent/enroll"); status != http.StatusForbidden {
			t.Fatalf("uid %d: status %d, want 403", other, status)
		}
		if reached.Load() != 0 {
			t.Fatalf("uid %d reached the handler", other)
		}
	}

	var reached atomic.Int32
	socket := serveAgentSocket(t, account, countingHandler(&reached), peerOf(agentUID))
	if status := requestOver(t, socket, http.MethodPost, "/agent/enroll"); status != http.StatusNoContent || reached.Load() != 1 {
		t.Fatalf("agent uid: status %d, reached %d", status, reached.Load())
	}
}

// R-A5-5 : un membre du groupe de l'agent qui n'est pas ce compte (serve, qui
// en reçoit le groupe) ouvre la socket, mais il est refusé. Le pair est lu
// par le vrai peercred.Peer : ce test a le groupe de la socket, pas l'uid
// admis.
func TestR_A5_5_AGroupMemberOtherThanTheAgentIsRefused(t *testing.T) {
	account := agentAccount{uid: uint32(os.Getuid()) + 1, gid: os.Getgid()} // #nosec G115 -- un uid tient dans un uint32.
	var reached atomic.Int32
	socket := serveAgentSocket(t, account, countingHandler(&reached), peercred.Peer)

	info, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode()&fs.ModeSocket == 0 || info.Mode().Perm() != agentSocketMode || int(stat.Gid) != account.gid {
		t.Fatalf("socket %v gid %d, want %04o gid %d", info.Mode(), stat.Gid, agentSocketMode, account.gid)
	}
	if status := requestOver(t, socket, http.MethodGet, "/agent/stream"); status != http.StatusForbidden {
		t.Fatalf("group member: status %d, want 403", status)
	}
	if reached.Load() != 0 {
		t.Fatal("a group member other than the agent reached the handler")
	}
}

// La socket des agents ne sert que les routes de l'agent : ni l'API, ni le
// fichier de l'annuaire, ni l'administration, ni l'interface. Une route de
// l'agent y répond, refus compris, sans 404.
func TestAgentSocket_ServesOnlyAgentRoutes(t *testing.T) {
	const agentUID = 990
	_, _, srv := realServer(t, filepath.Join(shortDir(t), "state"))
	account := agentAccount{uid: agentUID, gid: os.Getgid()}
	socket := serveAgentSocket(t, account, srv.AgentSocketHandler(), peerOf(agentUID))

	closed := []struct{ method, path string }{
		{http.MethodGet, "/api/session"},
		{http.MethodGet, "/api/manifest/export"},
		{http.MethodPost, "/control/admin/setup-code"},
		{http.MethodGet, "/control/admin/health"},
		{http.MethodGet, "/"},
		{http.MethodGet, "/ping/hb_x"},
	}
	for _, route := range closed {
		if status := requestOver(t, socket, route.method, route.path); status != http.StatusNotFound {
			t.Fatalf("%s %s: status %d, want 404", route.method, route.path, status)
		}
	}
	if status := requestOver(t, socket, http.MethodPost, "/agent/enroll"); status == http.StatusNotFound || status < 400 {
		t.Fatalf("POST /agent/enroll without a token: status %d, want a refusal from the route", status)
	}
}

// La socket porte le groupe de l'agent, pas celui de serve : c'est par lui
// que l'agent l'ouvre. Le groupe de l'agent est joué par un groupe secondaire
// du compte du test.
func TestAgentSocket_CarriesTheAgentGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	other := -1
	for _, group := range groups {
		if group != os.Getegid() {
			other = group
		}
	}
	if other < 0 {
		t.Skip("the test account has no group other than its own")
	}
	socket := serveAgentSocket(t, agentAccount{uid: 990, gid: other}, http.NotFoundHandler(), peerOf(990))
	info, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if gid := info.Sys().(*syscall.Stat_t).Gid; int(gid) != other {
		t.Fatalf("socket gid %d, want %d", gid, other)
	}
}
