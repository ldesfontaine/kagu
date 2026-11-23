package peercred

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// listenShort ouvre une socket dans un dossier au chemin court : le chemin
// d'une socket Unix ne dépasse pas 107 octets, et t.TempDir() porte le nom du
// test.
func listenShort(t *testing.T) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "test.sock")
	listener, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, path
}

// serveOnly sert OnlyUID(…, allowed) sur une vraie socket, l'uid lu par
// readUID, et rend le statut d'un GET.
func serveOnly(t *testing.T, allowed uint32, readUID func(net.Conn) (uint32, error)) int {
	t.Helper()
	listener, path := listenShort(t)
	admitted := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server := &http.Server{Handler: OnlyUID(admitted, allowed), ConnContext: ConnContext(readUID)}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	response, err := client.Get("http://socket/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

// R-A2-11 : un pair d'un autre uid que celui admis reçoit 403, l'uid admis
// passe. L'uid est celui que le noyau donne (Peer), pas un en-tête. Hors
// root, le pair de ce test n'a pas l'uid 0 : la vraie lecture le refuse.
// Sous root, le refus d'un autre uid se joue avec l'uid 0 lu et un autre
// admis.
func TestR_A2_11_AdminRoutesRefuseANonRootPeer(t *testing.T) {
	self := uint32(os.Getuid()) // #nosec G115 -- un uid tient dans 32 bits.
	if self != 0 {
		if got := serveOnly(t, 0, Peer); got != http.StatusForbidden {
			t.Fatalf("a peer of uid %d got %d on a root-only route, want 403", self, got)
		}
	}
	if got := serveOnly(t, self+1, Peer); got != http.StatusForbidden {
		t.Fatalf("a peer of uid %d got %d on a route for uid %d, want 403", self, got, self+1)
	}
	if got := serveOnly(t, self, Peer); got != http.StatusNoContent {
		t.Fatalf("the admitted uid got %d", got)
	}
}

// Un pair dont l'uid ne se lit pas n'a pas d'uid : il ne passe pas, même
// quand l'uid admis est 0, la valeur nulle d'un uint32.
func TestOnlyUID_RefusesAPeerWhoseUIDWasNotRead(t *testing.T) {
	unreadable := func(net.Conn) (uint32, error) { return 0, errors.New("no credentials") }
	if got := serveOnly(t, 0, unreadable); got != http.StatusForbidden {
		t.Fatalf("an unread peer got %d, want 403", got)
	}
}

// Peer ne lit que l'uid d'une socket Unix.
func TestPeer_RefusesAConnectionThatIsNotUnix(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := Peer(server); err == nil {
		t.Fatal("a pipe has no peer credentials")
	}
}

// Listen pose le mode, remplace une socket orpheline, et laisse en place un
// autre fichier comme une socket vivante.
func TestListen_SetsTheModeAndNeverTakesAnotherFile(t *testing.T) {
	listener, path := listenShort(t)
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&fs.ModeSocket == 0 {
		t.Fatalf("mode %v, %v: want a socket in 0600", info.Mode(), err)
	}
	if _, err := Listen(path, 0o600); err == nil {
		t.Fatal("a live socket was taken")
	}

	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = listener.Close()
	again, err := Listen(path, 0o600)
	if err != nil {
		t.Fatalf("a stale socket must be replaced: %v", err)
	}
	_ = again.Close()

	if err := os.WriteFile(path, []byte("à moi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o600); err == nil {
		t.Fatal("a file that is not a socket was replaced")
	}
	if kept, err := os.ReadFile(path); err != nil || string(kept) != "à moi" { // #nosec G304 -- le fichier du test.
		t.Fatalf("the file was touched: %q, %v", kept, err)
	}
}
