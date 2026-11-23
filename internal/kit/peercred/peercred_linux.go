package peercred

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// Listen ouvre la socket Unix de path et lui pose mode. Ce qui protège
// l'instant entre sa création et son chmod est le dossier qui la contient :
// c'est à l'appelant de l'avoir fermé.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// removeStaleSocket retire la socket qu'un arrêt brutal a laissée, et elle
// seule. Une socket qui répond est celle d'un autre serveur vivant : la
// retirer le laisserait sans commande, donc on n'y touche pas et on n'en
// ouvre pas. Tout autre fichier du même nom reste où il est : ce n'est pas à
// l'écoute de le jeter.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return errors.New("a file that is not a socket sits at its place")
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return errors.New("another server already listens on it")
	}
	// Seule une socket sans écouteur est une orpheline ; toute autre erreur
	// (droits, délai) ne prouve pas qu'elle l'est.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot tell whether it is stale: %w", err)
	}
	return os.Remove(path)
}

// Peer rend l'uid du processus à l'autre bout d'une connexion Unix, tel que
// le noyau l'a noté à la connexion. Jamais le groupe : un compte de service
// peut appartenir au groupe d'un autre, pas prendre son uid.
func Peer(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *syscall.Ucred
	var readErr error
	err = raw.Control(func(fd uintptr) {
		credentials, readErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) // #nosec G115 -- un descripteur de fichier tient dans un int.
	})
	if err != nil {
		return 0, err
	}
	if readErr != nil {
		return 0, fmt.Errorf("read the peer credentials: %w", readErr)
	}
	return credentials.Uid, nil
}

type uidKey struct{}

// ConnContext rend le crochet de http.Server.ConnContext : l'uid du pair se
// lit une fois par connexion, par readUID (Peer ; un test donne le sien), et
// va dans le contexte de chaque requête. r.RemoteAddr ne le dit pas : il est
// vide sur une socket Unix. Un pair illisible n'a pas d'uid : OnlyUID le
// refuse.
func ConnContext(readUID func(net.Conn) (uint32, error)) func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, conn net.Conn) context.Context {
		uid, err := readUID(conn)
		if err != nil {
			return ctx
		}
		return context.WithValue(ctx, uidKey{}, uid)
	}
}

// UID rend l'uid du pair de la requête, s'il a été lu.
func UID(ctx context.Context) (uint32, bool) {
	uid, known := ctx.Value(uidKey{}).(uint32)
	return uid, known
}

// OnlyUID ne laisse passer que le pair d'uid allowed : tout autre, ou un
// pair dont l'uid n'a pas été lu, reçoit 403.
func OnlyUID(next http.Handler, allowed uint32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, known := UID(r.Context())
		if !known || uid != allowed {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
