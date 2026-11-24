package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/seal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// La rotation rescelle chaque secret avec une clé neuve : le serveur
// redémarre avec elle seule, l'ancienne est mise de côté et n'ouvre plus la
// base.
func TestSecretsRotate_ResealsWithANewKeyAndSetsTheOldOneAside(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, db := openState(t, stateDir)
	logger, _ := capturedLogger()
	ctx := context.Background()
	if err := openSecrets(ctx, root, db, logger); err != nil {
		t.Fatal(err)
	}
	addHeartbeat(t, db, "hb_rotated")
	old := mustLoad(t, root)
	db.Close()

	var out bytes.Buffer
	if err := secretsCommand([]string{"rotate", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Secrets rescellés : 1") {
		t.Fatalf("output: %q", out.String())
	}
	current := mustLoad(t, root)
	if current.ID() == old.ID() || current.Len() != 1 {
		t.Fatalf("key %s (%d keys), old %s", current.ID(), current.Len(), old.ID())
	}
	kept := keptKeyFile(t, root.FS(), ".rotated-")
	if content, err := root.ReadFile(kept); err != nil || !strings.Contains(string(content), old.ID()) || strings.Contains(string(content), current.ID()) {
		t.Fatalf("the kept file is not the old key alone: %q %v", content, err)
	}

	again, err := store.Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := openSecrets(ctx, root, again, logger); err != nil {
		t.Fatalf("the next start must work: %v", err)
	}
	if _, err := again.GetHeartbeatByToken(ctx, "hb_rotated"); err != nil {
		t.Fatalf("the ping token was lost: %v", err)
	}
	again.SetSealer(old)
	if err := again.VerifySealedSecrets(ctx); !errors.Is(err, store.ErrSecretUnreadable) {
		t.Fatalf("the old key still opens the base: %v", err)
	}
}

// Interrompue après avoir posé la clé neuve, la commande reprend sans en
// tirer une troisième.
func TestSecretsRotate_ResumesAnInterruptedRotation(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, db := openState(t, stateDir)
	logger, _ := capturedLogger()
	ctx := context.Background()
	if err := openSecrets(ctx, root, db, logger); err != nil {
		t.Fatal(err)
	}
	addHeartbeat(t, db, "hb_interrupted")
	db.Close()
	interrupted := mustLoad(t, root).WithNewKey()
	if err := seal.Save(root, interrupted); err != nil {
		t.Fatal(err)
	}
	if err := secretsCommand([]string{"rotate", "-config", configPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if current := mustLoad(t, root); current.ID() != interrupted.ID() || current.Len() != 1 {
		t.Fatalf("got key %s, want %s alone", current.ID(), interrupted.ID())
	}
}

// Sans clé, rien à faire tourner : refus, rien d'écrit.
func TestSecretsRotate_RefusesWithoutAKey(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, _ := openState(t, stateDir)
	err := secretsCommand([]string{"rotate", "-config", configPath}, &bytes.Buffer{})
	var refused *refusal
	if !errors.As(err, &refused) {
		t.Fatalf("got %v, want a refusal", err)
	}
	if _, err := root.Stat(brand.SecretKeyFile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused rotation wrote a key: %v", err)
	}
}

// La clé du serveur : une neuve devant, la précédente gardée ; une seule
// rotation à la fois ; la finir refuse tant qu'un agent actif est resté sur
// la précédente, sauf -force, qui le nomme à ré-enrôler.
func TestSecretsServerKey_RotatesThenFinishesOnceTheAgentsFollowed(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, db := openState(t, stateDir)
	ctx := context.Background()
	var refused *refusal
	if err := secretsCommand([]string{"rotate-server-key", "-config", configPath}, &bytes.Buffer{}); !errors.As(err, &refused) {
		t.Fatalf("without a key: %v", err)
	}
	old, _, err := action.LoadOrCreateKey(root)
	if err != nil {
		t.Fatal(err)
	}
	machines := machine.New(db, machine.NewSessions(), slog.New(slog.DiscardHandler))
	host := storetest.EnrollMachine(t, machines, "11111111-2222-4333-8444-555555555555", "vps-paris-1")
	if err := db.RecordServerKey(ctx, host.Agent.ID, old.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordProtocol(ctx, host.Agent.ID, agentwire.ProtocolVersion); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := secretsCommand([]string{"rotate-server-key", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	rotated, err := action.LoadKey(root)
	if err != nil || rotated.PreviousFingerprint() != old.Fingerprint() || rotated.Fingerprint() == old.Fingerprint() {
		t.Fatalf("rotated %q/%q %v", rotated.Fingerprint(), rotated.PreviousFingerprint(), err)
	}
	// La sortie donne la ligne « trust set » de la neuve, que root colle sur
	// chaque machine : aucun ordre ne la livre (R-A3-9).
	if !strings.Contains(out.String(), rotated.Fingerprint()) || !strings.Contains(out.String(), agentpolicy.ServerKeyLine(rotated.PublicKey())) {
		t.Fatalf("output: %q", out.String())
	}
	if err := secretsCommand([]string{"rotate-server-key", "-config", configPath}, &bytes.Buffer{}); !errors.As(err, &refused) || !strings.Contains(refused.message, "déjà en cours") {
		t.Fatalf("a second rotation: %v", err)
	}

	err = secretsCommand([]string{"finish-server-key", "-config", configPath}, &bytes.Buffer{})
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "vps-paris-1") || !strings.Contains(refused.message, agentpolicy.ServerKeyLine(rotated.PublicKey())) {
		t.Fatalf("an agent still on the previous key: %v", err)
	}
	if still, _ := action.LoadKey(root); still.PreviousFingerprint() != old.Fingerprint() {
		t.Fatal("a refused finish changed the key")
	}
	out.Reset()
	if err := secretsCommand([]string{"finish-server-key", "-force", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	finished, err := action.LoadKey(root)
	if err != nil || finished.PreviousFingerprint() != "" || finished.Fingerprint() != rotated.Fingerprint() {
		t.Fatalf("finished %v", err)
	}
	if !strings.Contains(out.String(), "À ré-enrôler : vps-paris-1") {
		t.Fatalf("output: %q", out.String())
	}
	if err := secretsCommand([]string{"finish-server-key", "-config", configPath}, &bytes.Buffer{}); !errors.As(err, &refused) || !strings.Contains(refused.message, "rien à finir") {
		t.Fatalf("finishing twice: %v", err)
	}
}

// Décision de Lucas (#588) : la rotation de la clé du serveur est refusée tant
// qu'une machine enrôlée a un agent plus ancien que le serveur, ou dont le
// protocole n'est pas connu (pas revenu depuis qu'on le garde) ; le refus nomme
// ces machines et server.key ne change pas. Une machine révoquée ne compte
// pas ; toutes au protocole courant, la rotation passe.
func TestDecision588_RotationIsRefusedWhileAnAgentIsBehind(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, db := openState(t, stateDir)
	ctx := context.Background()
	if _, _, err := action.LoadOrCreateKey(root); err != nil {
		t.Fatal(err)
	}
	before, err := root.ReadFile(brand.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	machines := machine.New(db, machine.NewSessions(), slog.New(slog.DiscardHandler))
	old := storetest.EnrollMachine(t, machines, "11111111-2222-4333-8444-555555555555", "vps-paris-1")
	current := storetest.EnrollMachine(t, machines, "22222222-3333-4444-8555-666666666666", "vps-lyon-2")
	silent := storetest.EnrollMachine(t, machines, "33333333-4444-4555-8666-777777777777", "vps-nice-3")
	if err := machines.NoteProtocol(ctx, old.Agent.ID, agentwire.LegacyProtocolVersion); err != nil {
		t.Fatal(err)
	}
	if err := machines.NoteProtocol(ctx, current.Agent.ID, agentwire.ProtocolVersion); err != nil {
		t.Fatal(err)
	}

	var refused *refusal
	err = secretsCommand([]string{"rotate-server-key", "-config", configPath}, &bytes.Buffer{})
	if !errors.As(err, &refused) || !strings.Contains(refused.message, "vps-paris-1 (protocole 2)") ||
		!strings.Contains(refused.message, "vps-nice-3 (protocole inconnu") || strings.Contains(refused.message, "vps-lyon-2") ||
		!strings.Contains(refused.message, "Mettez-les à jour d'abord") {
		t.Fatalf("an agent behind: %v", err)
	}
	if after, _ := root.ReadFile(brand.ServerKeyFile); string(after) != string(before) {
		t.Fatal("a refused rotation changed server.key")
	}

	if err := machines.NoteProtocol(ctx, old.Agent.ID, agentwire.ProtocolVersion); err != nil {
		t.Fatal(err)
	}
	if err := machines.NoteProtocol(ctx, silent.Agent.ID, "garbage"); err != nil {
		t.Fatal(err)
	}
	if err := secretsCommand([]string{"rotate-server-key", "-config", configPath}, &bytes.Buffer{}); !errors.As(err, &refused) || !strings.Contains(refused.message, "vps-nice-3") || strings.Contains(refused.message, "vps-paris-1") {
		t.Fatalf("an unreadable protocol counts as behind: %v", err)
	}
	if _, err := db.RevokeAgent(ctx, silent.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := secretsCommand([]string{"rotate-server-key", "-config", configPath}, &bytes.Buffer{}); err != nil {
		t.Fatalf("every agent current: %v", err)
	}
	if rotated, err := action.LoadKey(root); err != nil || rotated.PreviousFingerprint() == "" {
		t.Fatalf("the rotation did not happen: %v", err)
	}
}

// QA-13 : « secrets server-key » imprime l'empreinte de la clé qui signe les
// ordres, celle que « agent trust set server-key » imprime sur une machine ;
// rien d'autre, ni la clé privée ni la précédente. Sans clé, un refus.
func TestSecretsServerKey_PrintsTheFingerprintOnly(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, db := openState(t, stateDir)
	db.Close()
	var refused *refusal
	if err := secretsCommand([]string{"server-key", "-config", configPath}, &bytes.Buffer{}); !errors.As(err, &refused) {
		t.Fatalf("without a key: %v", err)
	}
	key, _, err := action.LoadOrCreateKey(root)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := root.ReadFile(brand.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := secretsCommand([]string{"server-key", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != key.Fingerprint()+"\n" || key.Fingerprint() != agentwire.KeyFingerprint(key.PublicKey()) {
		t.Fatalf("output %q, want %s", out.String(), key.Fingerprint())
	}
	for _, line := range strings.Split(strings.TrimSpace(string(keyFile)), "\n") {
		for _, field := range strings.Fields(line) {
			if len(field) > 20 && strings.Contains(out.String(), field) {
				t.Fatalf("server.key leaks into the output: %q", out.String())
			}
		}
	}
}

func keptKeyFile(t *testing.T, dir fs.FS, marker string) string {
	t.Helper()
	entries, err := fs.ReadDir(dir, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), brand.SecretKeyFile+marker) {
			return entry.Name()
		}
	}
	t.Fatalf("no %s file among %v", marker, entries)
	return ""
}
