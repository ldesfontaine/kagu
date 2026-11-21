// Commande oforge : banc d'essai, jamais livré. Elle joue un serveur
// compromis qui a server.key : elle signe un ordre aux paramètres écrits
// octet pour octet, l'écrit en base comme Service.Send, puis le fait livrer
// à l'agent par la socket de contrôle d'un serve qui tourne (route
// POST /control/forge, internal/server/control.go). Voir LISEZ-MOI.md.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ldesfontaine/opencloud/internal/action"
	"github.com/ldesfontaine/opencloud/internal/agentwire"
	"github.com/ldesfontaine/opencloud/internal/brand"
	"github.com/ldesfontaine/opencloud/internal/config"
	"github.com/ldesfontaine/opencloud/internal/ident"
	"github.com/ldesfontaine/opencloud/internal/store"
)

const (
	// Le temps que l'agent a pour rapporter, avant que l'outil rende la main.
	reportWait   = 20 * time.Second
	reportPeriod = 500 * time.Millisecond
	requestedBy  = "operator:oforge"
)

type options struct {
	configPath string
	machineID  string
	kind       agentwire.Kind
	// Les paramètres tels que tapés : jamais décodés, jamais ré-encodés.
	params json.RawMessage
	pinned string
	dryRun bool
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "oforge:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	cfg, _, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	stateDir, err := os.OpenRoot(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("open state dir: %w", err)
	}
	defer stateDir.Close()
	key, err := action.LoadKey(stateDir)
	if err != nil {
		return err
	}
	if opts.dryRun {
		return printDryRun(stdout, key, opts)
	}
	db, err := store.Open(ctx, stateDir)
	if err != nil {
		return err
	}
	defer db.Close()
	return forge(ctx, stdout, db, key, filepath.Join(cfg.StateDir, brand.ControlSocketFile), opts)
}

func parseOptions(args []string) (options, error) {
	flags := flag.NewFlagSet("oforge", flag.ContinueOnError)
	var opts options
	var kind, params string
	flags.StringVar(&opts.configPath, "config", config.DefaultPath, "config.toml de serve (donne state_dir)")
	flags.StringVar(&opts.machineID, "machine", "", "identifiant de la machine visée")
	flags.StringVar(&kind, "kind", "", "genre de l'ordre, par exemple backup.produce")
	flags.StringVar(&params, "params", "{}", "paramètres, JSON brut, signés tels quels")
	flags.StringVar(&opts.pinned, "pinned", "", "empreinte de la clé précédente, si l'agent l'a épinglée (sinon la courante)")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "imprime le corps signé, ne dépose rien")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if kind == "" || (opts.machineID == "" && !opts.dryRun) {
		return options{}, errors.New("-kind et -machine sont requis")
	}
	if !json.Valid([]byte(params)) {
		return options{}, errors.New("-params n'est pas du JSON")
	}
	opts.kind = agentwire.Kind(kind)
	opts.params = json.RawMessage(params)
	return opts, nil
}

// printDryRun signe un ordre aux valeurs fictives et imprime son corps : ce
// qui prouve que les paramètres partent tels quels, clés répétées et casses
// différentes comprises.
func printDryRun(stdout io.Writer, key *action.Key, opts options) error {
	order := action.Order{
		RunID: "dry-run", MachineID: opts.machineID, AgentID: "dry-run-agent",
		Kind: opts.kind, Params: opts.params, NotAfter: time.Now().Add(action.OrderLifetime), Seq: 0,
	}
	signed, err := key.Sign(order, opts.pinned)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", signed.Body)
	return err
}

// forge écrit le run, signe, fait livrer par la socket de contrôle, puis
// attend le rapport de l'agent.
func forge(ctx context.Context, stdout io.Writer, db *store.DB, key *action.Key, socketPath string, opts options) error {
	target, err := db.GetMachine(ctx, opts.machineID)
	if err != nil {
		return fmt.Errorf("machine %q: %w", opts.machineID, err)
	}
	if target.Agent.ID == "" {
		return fmt.Errorf("machine %q: pas d'agent", opts.machineID)
	}
	pinned := opts.pinned
	if pinned == "" {
		pinned = target.Agent.ServerKeyFingerprint
	}
	runID, err := ident.New()
	if err != nil {
		return fmt.Errorf("generate run id: %w", err)
	}
	now := time.Now()
	// Écrit avant de signer, comme Service.Send : le rang vient de la base.
	run, err := db.InsertRun(ctx, action.Run{
		ID: runID, Kind: opts.kind, Params: opts.params,
		MachineID: target.ID, MachineName: target.Name, AgentID: target.Agent.ID,
		State: action.StateQueued, NotAfter: now.Add(action.OrderLifetime),
		RequestedBy: requestedBy, RequestedAt: now,
	})
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	fmt.Fprintln(stdout, "run_id:", run.ID)
	signed, err := key.Sign(action.Order{
		RunID: run.ID, MachineID: run.MachineID, AgentID: run.AgentID, Kind: run.Kind,
		Params: run.Params, NotAfter: run.NotAfter, Seq: run.Seq,
	}, pinned)
	if err != nil {
		return err
	}
	// Marqué envoyé avant de partir : la réponse de l'agent trouve un run envoyé.
	if err := db.SetRunState(ctx, run.ID, action.StateSent, "", time.Time{}); err != nil {
		return fmt.Errorf("mark run sent: %w", err)
	}
	if err := postForge(ctx, socketPath, run, signed); err != nil {
		_ = db.SetRunState(ctx, run.ID, action.StateFailed, action.ReasonUndelivered, time.Now())
		return err
	}
	fmt.Fprintln(stdout, "livré à serve, en attente de l'agent")
	return waitReport(ctx, stdout, db, run.ID)
}

func postForge(ctx context.Context, socketPath string, run action.Run, signed agentwire.SignedOrder) error {
	body, err := json.Marshal(map[string]any{"machine_id": run.MachineID, "kind": run.Kind, "order": signed})
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://control/control/forge", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("socket de contrôle %s (serve tourne-t-il ? route forge présente ?) : %w", socketPath, err)
	}
	defer response.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("serve refuse la livraison : %d %s", response.StatusCode, bytes.TrimSpace(reply))
	}
	return nil
}

// waitReport relit le run en base jusqu'à ce que l'agent l'ait fini, ou que
// reportWait passe ; il imprime l'état et la raison.
func waitReport(ctx context.Context, stdout io.Writer, db *store.DB, runID string) error {
	deadline := time.Now().Add(reportWait)
	for {
		run, err := db.GetActionRun(ctx, runID)
		if err != nil {
			return err
		}
		if run.State.IsFinished() || time.Now().After(deadline) {
			fmt.Fprintf(stdout, "état: %s\nraison: %s\n", run.State, run.Reason)
			for _, line := range run.Output {
				fmt.Fprintf(stdout, "  [%s] %s\n", line.Stream, line.Line)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reportPeriod):
		}
	}
}
