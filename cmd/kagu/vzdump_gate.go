package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
)

// kagu vzdump-gate : une connexion de la porte vzdump, servie en root par
// kagu-vzdump@.service, la socket sur l'entrée et la sortie standard
// (Accept=yes). systemd seul la lance ; elle ne prend aucune option.
func runVzdumpGate(args []string) error {
	if len(args) > 0 {
		return errors.New("vzdump-gate takes no argument")
	}
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	return agent.ServeVzdumpGate(ctx, conn)
}

// kagu agent vzdump-stream <invité> : ce que restic lance sous le compte de
// l'agent pour sauvegarder un invité ; le flux de vzdump sur la sortie
// standard, par la porte.
func runVzdumpStream(args []string) error {
	if len(args) != 1 {
		return errors.New("vzdump-stream takes one guest number")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.StreamVzdump(ctx, args[0], os.Stdout, os.Stderr)
}
