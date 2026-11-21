package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ldesfontaine/opencloud/internal/edge/store"
	"github.com/ldesfontaine/opencloud/internal/fact/auth"
	"github.com/ldesfontaine/opencloud/internal/fact/auth/authtest"
	"github.com/ldesfontaine/opencloud/internal/kit/brand"
)

// writeConfig écrit une configuration minimale vers un state_dir neuf.
func writeConfig(t *testing.T) (configPath, stateDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	configPath = filepath.Join(dir, "config.toml")
	content := "listen = \"127.0.0.1:18081\"\nstate_dir = \"" + stateDir + "\"\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, stateDir
}

// enableIn active le mode basic comme le ferait serve, dans la même base.
func enableIn(t *testing.T, stateDir string) {
	t.Helper()
	root, err := openStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	db, err := store.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err := auth.New(db, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	service.SetHashCost(bcrypt.MinCost)
	if _, err := service.EnableBasic(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, service), "lucas", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthCommand_StatusThenDisableReopensTheInterface(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	enableIn(t, stateDir)

	var out bytes.Buffer
	if err := authCommand([]string{"status", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mode : basic") || !strings.Contains(out.String(), "identifiant : lucas") {
		t.Fatalf("status: %q", out.String())
	}
	if strings.Contains(out.String(), "$2") {
		t.Fatal("status must not print the hash")
	}

	out.Reset()
	if err := authCommand([]string{"disable", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "désactivée") {
		t.Fatalf("disable: %q", out.String())
	}

	out.Reset()
	if err := authCommand([]string{"status", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mode : none") {
		t.Fatalf("status after disable: %q", out.String())
	}

	out.Reset()
	if err := authCommand([]string{"disable", "-config", configPath}, &out); err != nil {
		t.Fatalf("disabling twice is not an error: %v", err)
	}
	if !strings.Contains(out.String(), "déjà") {
		t.Fatalf("disable twice: %q", out.String())
	}
}

func TestAuthCommand_StatusShowsTheForwardHeaderAndDisableReopens(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	root, err := openStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.New(db, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnableForward(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, service), "X-Forwarded-User"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	root.Close()

	var out bytes.Buffer
	if err := authCommand([]string{"status", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mode : forward") || !strings.Contains(out.String(), "en-tête d'identité : X-Forwarded-User") {
		t.Fatalf("status: %q", out.String())
	}
	if strings.Contains(out.String(), "identifiant :") {
		t.Fatalf("forward mode has no stored username: %q", out.String())
	}

	out.Reset()
	if err := authCommand([]string{"disable", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := authCommand([]string{"status", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mode : none") {
		t.Fatalf("status after disable: %q", out.String())
	}
}

func TestAuthCommand_RefusesAnUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	if err := authCommand([]string{"enable"}, &out); err == nil {
		t.Fatal("enable is not offered from the command line")
	}
	if err := authCommand(nil, &out); err == nil {
		t.Fatal("a subcommand is required")
	}
}

func TestLogInterfaceAccess_WarnsAndNamesTheSetupCodeCommandWhileAwaitingSetup(t *testing.T) {
	_, stateDir := writeConfig(t)
	root, err := openStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	db, err := store.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	service, err := auth.New(db, logger)
	if err != nil {
		t.Fatal(err)
	}

	for _, listen := range []string{"127.0.0.1:8080", ":8080"} {
		logs.Reset()
		logInterfaceAccess(context.Background(), logger, service, listen)
		if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "sudo "+brand.Command+" admin setup-code") {
			t.Fatalf("%s: %q", listen, logs.String())
		}
	}

	service.SetHashCost(bcrypt.MinCost)
	if _, err := service.EnableBasic(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, service), "lucas", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	logInterfaceAccess(context.Background(), logger, service, ":8080")
	if strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("protected: %q", logs.String())
	}
}

func TestWarnIfForwardUnproven_SpeaksOnlyForForwardWithLoopbackAndNoSecret(t *testing.T) {
	_, stateDir := writeConfig(t)
	root, err := openStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	db, err := store.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	service, err := auth.New(db, logger)
	if err != nil {
		t.Fatal(err)
	}
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	container := []netip.Prefix{netip.MustParsePrefix("172.18.0.2/32")}
	speaks := func(trusted []netip.Prefix, hasSecret bool) bool {
		logs.Reset()
		warnIfForwardUnproven(context.Background(), logger, service, trusted, hasSecret)
		return strings.Contains(logs.String(), "level=WARN")
	}

	if speaks(loopback, false) {
		t.Fatal("no forward mode yet: nothing to warn about")
	}
	if _, err := service.EnableForward(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, service), auth.DefaultForwardHeader); err != nil {
		t.Fatal(err)
	}
	if !speaks(loopback, false) {
		t.Fatal("forward mode, loopback trusted, no secret: must warn")
	}
	if !strings.Contains(logs.String(), "forward_secret_file") {
		t.Fatalf("the warning must name the key to set: %q", logs.String())
	}
	if speaks(loopback, true) {
		t.Fatal("with a secret there is nothing to warn about")
	}
	if speaks(container, false) {
		t.Fatal("a non-loopback proxy keeps its previous behavior")
	}
}

// enableForwardIn active le mode forward dans la base de l'état, comme serve.
func enableForwardIn(t *testing.T, stateDir string) {
	t.Helper()
	root, err := openStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	db, err := store.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err := auth.New(db, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnableForward(context.Background(), auth.State{Mode: auth.ModeNone}, authtest.SetupCode(t, service), auth.DefaultForwardHeader); err != nil {
		t.Fatal(err)
	}
}

func authStatusWith(t *testing.T, configPath string) string {
	t.Helper()
	var out bytes.Buffer
	if err := authCommand([]string{"status", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestAuthCommand_StatusSaysWhoForwardUsersAdmits(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	enableForwardIn(t, stateDir)

	if got := authStatusWith(t, configPath); !strings.Contains(got, "identités admises : toute identité transmise par le SSO") {
		t.Fatalf("no list: %q", got)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	withList := string(content) + "forward_users = [\"lucas\", \"Léa\"]\n"
	if err := os.WriteFile(configPath, []byte(withList), 0o600); err != nil {
		t.Fatal(err)
	}
	// Entre guillemets : une faute de casse se voit.
	if got := authStatusWith(t, configPath); !strings.Contains(got, `identités admises : "lucas", "Léa"`) {
		t.Fatalf("with a list: %q", got)
	}
}

// En basic, la liste ne sert à rien : l'afficher laisserait croire qu'elle garde.
func TestAuthCommand_StatusDoesNotShowForwardUsersOutsideForwardMode(t *testing.T) {
	configPath, stateDir := writeConfig(t)
	enableIn(t, stateDir)
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(content, []byte("forward_users = [\"lucas\"]\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := authStatusWith(t, configPath); strings.Contains(got, "identités admises") {
		t.Fatalf("basic mode: %q", got)
	}
}

// Une liste fausse arrête aussi la commande, comme serve.
func TestAuthCommand_AFalseForwardUsersListIsRefused(t *testing.T) {
	configPath, _ := writeConfig(t)
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(content, []byte("forward_users = [\"lucas\", \"lucas\"]\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := authCommand([]string{"status", "-config", configPath}, &out); err == nil {
		t.Fatal("a list with a duplicate must be refused")
	}
}
