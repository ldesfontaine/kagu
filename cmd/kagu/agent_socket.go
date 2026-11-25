package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
)

// agentSocketMode : l'agent local l'ouvre par le groupe, serve par son uid.
// Tout autre compte n'y entre pas ; un membre du groupe qui n'est pas l'agent
// l'ouvre, mais OnlyUID le refuse.
const agentSocketMode = 0o660

// agentAccount est le compte de l'agent local : son uid, seul admis sur la
// socket, et le gid du groupe du même nom, que la socket porte.
type agentAccount struct {
	uid uint32
	gid int
}

// openAgentSocket sert brand.AgentSocketPath à l'agent de la machine Kagu.
// Sans compte de l'agent, ou sans le dossier que l'unité crée
// (RuntimeDirectory), serve continue sans elle : l'agent local n'a alors que
// l'adresse publique, comme aujourd'hui.
func openAgentSocket(logger *slog.Logger, handler http.Handler) *http.Server {
	account, err := lookupAgentAccount()
	if err != nil {
		logger.Warn("agent socket unavailable, no local agent account", "account", brand.AgentAccount, "error", err)
		return nil
	}
	return startAgentSocket(logger, brand.AgentSocketPath, account, handler, peercred.Peer)
}

// startAgentSocket sert les routes de l'agent sur path, au seul pair d'uid
// account.uid, que readPeer lit une fois par connexion (peercred.Peer ; un
// test donne le sien). Jamais le groupe : serve le porte aussi (R-A5-5).
func startAgentSocket(logger *slog.Logger, path string, account agentAccount, handler http.Handler, readPeer func(net.Conn) (uint32, error)) *http.Server {
	listener, err := peercred.Listen(path, agentSocketMode)
	if err != nil {
		logger.Warn("agent socket unavailable", "path", path, "error", err)
		return nil
	}
	// Jusqu'ici la socket porte le groupe de serve, qui n'a que lui.
	if err := os.Chown(path, -1, account.gid); err != nil {
		_ = listener.Close()
		logger.Warn("agent socket unavailable, cannot give it the agent group", "path", path, "error", err)
		return nil
	}
	agents := newHTTPServer("", peercred.OnlyUID(handler, account.uid))
	agents.ConnContext = peercred.ConnContext(readPeer)
	go func() {
		if err := agents.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("agent socket stopped", "path", path, "error", err)
		}
	}()
	logger.Info("agent socket", "path", path, "uid", account.uid)
	return agents
}

// lookupAgentAccount lit le compte brand.AgentAccount et son groupe.
func lookupAgentAccount() (agentAccount, error) {
	found, err := user.Lookup(brand.AgentAccount)
	if err != nil {
		return agentAccount{}, err
	}
	group, err := user.LookupGroup(brand.AgentAccount)
	if err != nil {
		return agentAccount{}, err
	}
	uid, err := strconv.ParseUint(found.Uid, 10, 32)
	if err != nil {
		return agentAccount{}, fmt.Errorf("uid %q: %w", found.Uid, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return agentAccount{}, fmt.Errorf("gid %q: %w", group.Gid, err)
	}
	return agentAccount{uid: uint32(uid), gid: gid}, nil // #nosec G115 -- ParseUint l'a borné à 32 bits.
}
