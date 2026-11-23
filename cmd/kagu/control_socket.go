package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
)

// controlSocketMode : seul le compte du service, ou root, s'y connecte.
const controlSocketMode = 0o600

// startControlSocket sert state_dir/control.sock : c'est par là que la
// commande locale parle à serve, sans jeton ni port, et que root refait un
// accès perdu. Si la socket ne peut pas s'ouvrir (chemin de plus de 107
// octets, dossier en lecture seule, un autre serve déjà là), serve continue
// sans elle : observer passe avant, l'export seul en pâtit.
//
// Ce qui protège la socket : le dossier d'état, que serve a vérifié fermé
// avant de démarrer (requirePrivateStateDir), puis son propre mode 0600. Les
// routes d'administration exigent en plus un pair d'uid 0, que readPeer lit
// une fois par connexion (peercred.Peer ; un test donne le sien).
func startControlSocket(logger *slog.Logger, statePath string, handler http.Handler, readPeer func(net.Conn) (uint32, error)) *http.Server {
	path := filepath.Join(statePath, brand.ControlSocketFile)
	listener, err := peercred.Listen(path, controlSocketMode)
	if err != nil {
		logger.Warn("control socket unavailable, export, apply and admin disabled", "path", path, "error", err)
		return nil
	}
	control := newHTTPServer("", handler)
	control.ConnContext = peercred.ConnContext(readPeer)
	go func() {
		if err := control.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("control socket stopped", "path", path, "error", err)
		}
	}()
	logger.Info("control socket", "path", path)
	return control
}

// requirePrivateStateDir refuse un dossier d'état que d'autres comptes
// peuvent traverser ou lire : la socket y serait atteignable pendant
// l'instant qui sépare sa création de son chmod, et la base avec. serve ne
// démarre pas : sans canal local sûr, root n'a plus de secours (R-A2-11).
func requirePrivateStateDir(stateDir *os.Root, statePath string) error {
	info, err := stateDir.Stat(".")
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode&0o077 == 0 {
		return nil
	}
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	return &refusal{message: catalogs.For(lang.Default).Format("admin.state_dir_open", statePath, fmt.Sprintf("%04o", mode), statePath)}
}
