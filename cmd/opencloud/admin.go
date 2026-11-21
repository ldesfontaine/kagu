package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ldesfontaine/opencloud/internal/edge/config"
	"github.com/ldesfontaine/opencloud/internal/fact/auth"
	"github.com/ldesfontaine/opencloud/internal/kit/brand"
)

const adminUsage = `Usage : {command} admin setup-code [-config chemin]

  setup-code  tire le code de première configuration : 8 chiffres, valables
              30 minutes, un seul usage, 5 essais faux au plus. Sans lui,
              la page de première configuration ne crée aucun compte. Un
              nouveau code remplace l'ancien (échu, brûlé ou non). Le
              serveur doit tourner : la commande lui parle par la socket de
              state_dir.
`

// setupCodePath est la route que la socket est seule à servir (internal/edge/server).
const setupCodePath = "/control/admin/setup-code"

// opencloud admin : les gestes d'administration qui passent par la socket
// locale du serveur. Qui l'ouvre peut déjà lire la base.
func runAdmin(args []string) error {
	return adminCommand(args, os.Stdout)
}

func adminCommand(args []string, out io.Writer) error {
	if len(args) < 1 || args[0] != "setup-code" {
		fmt.Fprint(os.Stderr, strings.ReplaceAll(adminUsage, "{command}", brand.Command))
		if len(args) < 1 {
			return &refusal{message: "sous-commande manquante"}
		}
		return &refusal{message: "sous-commande inconnue : " + args[0]}
	}
	flags := flag.NewFlagSet("admin setup-code", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", config.DefaultPath, "chemin du fichier de configuration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	return issueSetupCode(context.Background(), newControlClient(cfg.StateDir), out)
}

func issueSetupCode(ctx context.Context, client *controlClient, out io.Writer) error {
	status, body, err := client.post(ctx, setupCodePath, struct{}{}, controlTimeout)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		return &refusal{message: "la première configuration est déjà faite : il n'y a pas de code à tirer (la rouvrir : " + brand.Command + " auth disable)"}
	}
	if status != http.StatusCreated {
		return serverRefusal(status, body)
	}
	var issued struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		return fmt.Errorf("read the server's answer: %w", err)
	}
	_, err = fmt.Fprintf(out, "Code de première configuration : %s\nValable jusqu'à %s (%d minutes), un seul usage, %d essais faux au plus. Saisissez-le sur la page de première configuration.\n",
		issued.Code, issued.ExpiresAt.Local().Format("15:04"), int(auth.SetupCodeLifetime.Minutes()), auth.MaxSetupCodeFailures)
	return err
}
