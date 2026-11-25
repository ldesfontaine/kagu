package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

const authUsage = `Usage : {command} auth status [-config chemin]

  status    dit si l'interface est protégée, par quel identifiant ou
            derrière quel en-tête d'identité du SSO, et quelles
            identités forward_users admet. Refaire un accès perdu ou
            changer de mode : sudo {command} admin
`

// kagu auth status : l'état de l'accès, lu dans la base sous le compte
// du service. La commande ne change rien : refaire l'accès passe par
// « admin », sur le canal local, à root seul.
func runAuth(args []string) error {
	return authCommand(args, os.Stdout)
}

func authCommand(args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "status" {
		fmt.Fprint(os.Stderr, strings.ReplaceAll(authUsage, "{command}", brand.Command))
		if len(args) < 1 {
			return &refusal{message: "sous-commande manquante"}
		}
		return &refusal{message: "sous-commande inconnue : " + args[0]}
	}
	flags := flag.NewFlagSet("auth status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", config.DefaultPath, "chemin du fichier de configuration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	stateDir, err := openStateDir(cfg.StateDir)
	if err != nil {
		return err
	}
	defer stateDir.Close()
	ctx := audit.WithActor(context.Background(), audit.CLI(currentAccount()))
	db, err := store.Open(ctx, stateDir)
	if err != nil {
		return err
	}
	defer db.Close()
	return printAuthStatus(ctx, auth.New(db, logger), cfg.ForwardUsers, out)
}

// printAuthStatus dit l'état de l'accès. forwardUsers est la liste de
// config.toml, qui ne se lit qu'en mode forward : dans les autres, elle ne
// sert à rien et l'afficher laisserait croire le contraire.
func printAuthStatus(ctx context.Context, access *auth.Service, forwardUsers []string, out io.Writer) error {
	state, err := access.State(ctx)
	if err != nil {
		return err
	}
	enabledAt := state.EnabledAt.UTC().Format(time.RFC3339)
	switch state.Mode {
	case auth.ModeNone:
		_, err = fmt.Fprintln(out, "mode : none — aucun compte, l'interface attend sa première configuration")
		return err
	case auth.ModeForward:
		_, err = fmt.Fprintf(out, "mode : forward — derrière un SSO en amont\nen-tête d'identité : %s\nidentités admises : %s\nactivée le : %s\n",
			state.Header, describeForwardUsers(forwardUsers), enabledAt)
		return err
	}
	_, err = fmt.Fprintf(out, "mode : %s — un compte, la connexion ouvre une session\nidentifiant : %s\nactivée le : %s\n",
		state.Mode, state.Username, enabledAt)
	return err
}

// describeForwardUsers : la liste entre guillemets, pour qu'un espace ou une
// faute de casse se voie, ou la phrase qui dit qu'il n'y a pas de liste.
func describeForwardUsers(users []string) string {
	if len(users) == 0 {
		return "toute identité transmise par le SSO"
	}
	quoted := make([]string, len(users))
	for index, user := range users {
		quoted[index] = strconv.Quote(user)
	}
	return strings.Join(quoted, ", ")
}
