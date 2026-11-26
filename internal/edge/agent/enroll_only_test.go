package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// serveOnSocket sert handler sur une vraie socket Unix, sous un chemin court
// (la limite d'une socket est d'une centaine d'octets, plus court que
// t.TempDir()), et rend ce chemin.
func serveOnSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "as")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return path
}

// -enroll-only : l'agent s'enrôle par la socket, écrit son identité avec
// l'adresse unix: telle quelle, et rend la main sans ouvrir le flux ; relancé,
// il voit son identité et sort sans rien demander au serveur.
func TestR_B1_7_EnrollOnlyEnrollsThroughTheUnixSocketAndExits(t *testing.T) {
	b := newBench(t)
	serverKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var requests, enrollments atomic.Int32
	socket := serveOnSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/agent/enroll" {
			http.NotFound(w, r)
			return
		}
		enrollments.Add(1)
		_ = json.NewEncoder(w).Encode(agentwire.EnrollResponse{
			MachineID: "m-local", AgentID: "a-local", Name: "local", ServerKey: base64.StdEncoding.EncodeToString(serverKey),
		})
	}))
	options := b.options("kg_local")
	options.Server = "unix:" + socket
	options.EnrollOnly = true

	// Borné : un agent qui ouvrirait le flux ne rendrait jamais la main.
	if err := runBounded(options); err != nil {
		t.Fatalf("enroll only: %v", err)
	}
	if requests.Load() != 1 || enrollments.Load() != 1 {
		t.Fatalf("%d requests, %d enrollments: the stream was opened or nothing was enrolled", requests.Load(), enrollments.Load())
	}
	identity, err := LoadIdentity(b.stateDir)
	if err != nil || identity.Server != "unix:"+socket || identity.MachineID != "m-local" || identity.AgentID != "a-local" {
		t.Fatalf("identity %+v %v", identity, err)
	}

	// La reprise de setup : même ligne, l'identité est là, rien ne part.
	if err := runBounded(options); err != nil {
		t.Fatalf("enroll only again: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("the enrolled agent sent %d more requests", requests.Load()-1)
	}
	again, err := LoadIdentity(b.stateDir)
	if err != nil || again.MachineID != identity.MachineID || !bytes.Equal(again.PublicKey, identity.PublicKey) {
		t.Fatalf("identity changed on the second run: %+v %v", again, err)
	}
}

// runBounded lance l'agent sous benchTimeout : l'échéance passée, il rend
// l'erreur du contexte plutôt que nil.
func runBounded(options Options) error {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()
	err := Run(ctx, options)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Sans identité ni jeton, -enroll-only refuse comme le lancement ordinaire,
// sans rien écrire.
func TestRun_EnrollOnlyWithoutTokenRefuses(t *testing.T) {
	b := newBench(t)
	err := Run(context.Background(), Options{StateDir: b.stateDir, Server: "unix:/run/none.sock", EnrollOnly: true, Logger: b.logger})
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("got %v", err)
	}
	if _, err := LoadIdentity(b.stateDir); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("identity written without enrolling")
	}
}

// Par la socket, tout passe comme par HTTPS : un vrai serveur reçoit
// l'enrôlement, le flux et le signal, et l'agent revient avec son identité.
func TestRun_EnrollsAndStreamsThroughTheUnixSocket(t *testing.T) {
	b := newBench(t)
	socket := serveOnSocket(t, b.handler)
	token, _, err := b.machines.CreateToken(context.Background(), "kagu-local", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := b.options(token)
	options.Server = "unix:" + socket
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	online := b.waitFor(t, "kagu-local", func(s machine.Status) bool { return s.Online })
	b.waitFor(t, "kagu-local", func(s machine.Status) bool { return s.LastSeenAt.After(online.LastSeenAt) })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	identity, err := LoadIdentity(b.stateDir)
	if err != nil || identity.Server != "unix:"+socket || identity.MachineID != online.ID || identity.Language != lang.English {
		t.Fatalf("identity %+v %v", identity, err)
	}
}

// Le serveur se joint par http://, https:// ou unix:<chemin absolu>, rien
// d'autre : un chemin relatif dépendrait du dossier de lancement.
func TestNewClient_RefusesAnUnknownScheme(t *testing.T) {
	for _, server := range []string{"example.com", "ftp://example.com", "file:///run/kagu/agent.sock", "unix", "UNIX:/run/kagu/agent.sock", "tcp://127.0.0.1:8080", ""} {
		if _, err := NewClient(server, "v"); err == nil {
			t.Errorf("%q accepted", server)
		}
	}
	for _, server := range []string{"unix:", "unix:agent.sock", "unix:./agent.sock", "unix:run/kagu/agent.sock", "unix:../agent.sock"} {
		if _, err := NewClient(server, "v"); !errors.Is(err, ErrSocketNotAbsolute) {
			t.Errorf("%q: %v", server, err)
		}
	}
	if _, err := NewClient("unix:/run/kagu/agent.sock", "v"); err != nil {
		t.Errorf("absolute socket refused: %v", err)
	}
}
