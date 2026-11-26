package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/edge/server"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/live"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
)

const newPassword = "a passphrase from root"

// typedTwice : le terminal où l'opérateur a tapé deux fois le nouveau mot de
// passe.
var typedTwice = fakeTerminal(newPassword + "\n" + newPassword + "\n")

// fakeAdmin est un serveur qui retient ce qu'il a reçu et rend la réponse
// donnée, pour une seule route d'administration.
type fakeAdmin struct {
	received []map[string]string
}

func (f *fakeAdmin) handler(path string, status int, answer string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.received = append(f.received, body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	})
	return mux
}

// runAdminAgainst lance « admin args… » sous root contre un faux serveur, et
// rend la sortie, l'erreur et ce que le serveur a reçu.
func runAdminAgainst(t *testing.T, path string, status int, answer string, terminal terminalOpener, args ...string) (string, *fakeAdmin, error) {
	t.Helper()
	configPath, stateDir := writeShortConfig(t)
	fake := &fakeAdmin{}
	serveOnControlSocket(t, stateDir, fake.handler(path, status, answer))
	var out bytes.Buffer
	err := adminCommand(append(args, "-config", configPath), &out, terminal, 0)
	return out.String(), fake, err
}

func TestAdminSetupCode_PrintsTheCodeTheServerIssued(t *testing.T) {
	out, _, err := runAdminAgainst(t, "/control/admin/setup-code", http.StatusCreated, `{"code":"12345678","expires_at":"2026-11-19T10:30:00Z"}`, noTerminal, "setup-code")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"12345678", "30 minutes", "un seul usage", "5 essais"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q: %q", want, out)
		}
	}
}

func TestAdminSetupCode_SaysWhenTheFirstSetupIsAlreadyDone(t *testing.T) {
	out, _, err := runAdminAgainst(t, "/control/admin/setup-code", http.StatusConflict, `{"error":"auth.already_enabled"}`, noTerminal, "setup-code")
	if err == nil || !strings.Contains(err.Error(), "déjà faite") || !strings.Contains(err.Error(), "reset-password") {
		t.Fatalf("got %v", err)
	}
	if out != "" {
		t.Fatalf("printed %q", out)
	}
}

func TestAdminCommand_NeedsTheServer(t *testing.T) {
	configPath, _ := writeShortConfig(t)
	for _, gesture := range [][]string{{"setup-code"}, {"reset-password"}, {"sessions", "close-all"}} {
		err := adminCommand(append(gesture, "-config", configPath), &bytes.Buffer{}, typedTwice, 0)
		if err == nil || !strings.Contains(err.Error(), "ne tourne pas") {
			t.Fatalf("%v: got %v", gesture, err)
		}
	}
}

func TestAdminCommand_RefusesAMissingOrUnknownGesture(t *testing.T) {
	for _, args := range [][]string{nil, {"disable"}, {"auth-mode"}, {"auth-mode", "none"}, {"sessions"}, {"tokens", "list"}} {
		if err := adminCommand(args, &bytes.Buffer{}, noTerminal, 0); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}

// Le nouveau mot de passe se tape deux fois sur le terminal ; il part au
// serveur et ne s'écrit pas sur la sortie.
func TestAdminResetPassword_AsksTwiceAndNeverPrintsIt(t *testing.T) {
	out, fake, err := runAdminAgainst(t, "/control/admin/reset-password", http.StatusOK, `{"closed":2}`, typedTwice, "reset-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.received) != 1 || fake.received[0]["password"] != newPassword {
		t.Fatalf("the server received %v", fake.received)
	}
	if strings.Contains(out, newPassword) || !strings.Contains(out, "Sessions fermées : 2") {
		t.Fatalf("output %q", out)
	}
}

// Deux saisies différentes ou pas de terminal : rien ne part au serveur. Le
// compte qui n'est pas root : TestE02_12_EveryAdminGestureRefusesANonRootAccountBeforeTheSocket.
func TestAdminResetPassword_RefusesBeforeSendingAnything(t *testing.T) {
	cases := []struct {
		name     string
		terminal terminalOpener
		euid     int
		want     string
	}{
		{"two different entries", fakeTerminal(newPassword + "\n" + "another passphrase\n"), 0, "pas identiques"},
		{"no terminal", noTerminal, 0, "terminal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			configPath, stateDir := writeShortConfig(t)
			fake := &fakeAdmin{}
			serveOnControlSocket(t, stateDir, fake.handler("/control/admin/reset-password", http.StatusOK, `{"closed":0}`))
			err := adminCommand([]string{"reset-password", "-config", configPath}, &bytes.Buffer{}, c.terminal, c.euid)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if len(fake.received) != 0 {
				t.Fatalf("the server received %v", fake.received)
			}
		})
	}
}

// E02-12, R-A2-11 : sous un compte qui n'est pas root, chaque geste d'admin
// rend le refus commun (code de sortie 2) sans ouvrir la socket ; la socket
// d'essai, qui refuserait comme la vraie, ne voit passer aucune requête.
func TestE02_12_EveryAdminGestureRefusesANonRootAccountBeforeTheSocket(t *testing.T) {
	catalogs, err := lang.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := catalogs.For(lang.Default).Get("admin.root_only")
	for gesture := range adminPaths {
		t.Run(gesture, func(t *testing.T) {
			configPath, stateDir := writeShortConfig(t)
			var reached atomic.Int32
			serveOnControlSocket(t, stateDir, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			args := append(strings.Fields(gesture), "-config", configPath)
			err := adminCommand(args, &bytes.Buffer{}, typedTwice, 1000)
			var refused *refusal
			if !errors.As(err, &refused) || refused.Error() != want {
				t.Fatalf("got %v, want the refusal %q (exit status 2)", err, want)
			}
			if reached.Load() != 0 {
				t.Fatalf("the socket was opened: %d requests", reached.Load())
			}
		})
	}
}

// Les refus du serveur se disent avec la suite à donner : 403 de la socket
// (pas root), pas de mot de passe en SSO, pas encore de compte.
func TestAdminCommand_SaysTheServerRefusalsWithWhatToDo(t *testing.T) {
	for answer, want := range map[string]string{
		"":                             "Réservé à root",
		`{"error":"auth.no_password"}`: "auth-mode native",
		`{"error":"auth.disabled"}`:    "admin setup-code",
	} {
		status := http.StatusConflict
		if answer == "" {
			status = http.StatusForbidden
		}
		_, _, err := runAdminAgainst(t, "/control/admin/reset-password", status, answer, typedTwice, "reset-password")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%d %s: got %v, want %q", status, answer, err, want)
		}
	}
}

func TestAdminAuthMode_SendsWhatEachModeNeeds(t *testing.T) {
	out, fake, err := runAdminAgainst(t, "/control/admin/auth-mode", http.StatusOK, `{"mode":"forward","header":"Remote-User","closed":1}`, noTerminal, "auth-mode", "forward")
	if err != nil {
		t.Fatal(err)
	}
	if fake.received[0]["mode"] != "forward" || fake.received[0]["header"] != auth.DefaultForwardHeader || !strings.Contains(out, "Remote-User") {
		t.Fatalf("forward: received %v, printed %q", fake.received, out)
	}

	out, fake, err = runAdminAgainst(t, "/control/admin/auth-mode", http.StatusOK, `{"mode":"native","username":"lucas","closed":0}`, typedTwice, "auth-mode", "native", "-username", "lucas")
	if err != nil {
		t.Fatal(err)
	}
	if fake.received[0]["mode"] != "native" || fake.received[0]["username"] != "lucas" || fake.received[0]["password"] != newPassword || strings.Contains(out, newPassword) {
		t.Fatalf("native: received %v, printed %q", fake.received, out)
	}

	_, fake, err = runAdminAgainst(t, "/control/admin/auth-mode", http.StatusOK, `{}`, typedTwice, "auth-mode", "native")
	if err == nil || !strings.Contains(err.Error(), "-username") || len(fake.received) != 0 {
		t.Fatalf("native without a name: %v, received %v", err, fake.received)
	}
}

func TestAdminSessionsAndTokens_SayHowMany(t *testing.T) {
	out, _, err := runAdminAgainst(t, "/control/admin/sessions/close-all", http.StatusOK, `{"closed":3}`, noTerminal, "sessions", "close-all")
	if err != nil || !strings.Contains(out, "Sessions fermées : 3") {
		t.Fatalf("sessions: %q %v", out, err)
	}
	out, _, err = runAdminAgainst(t, "/control/admin/tokens/revoke-all", http.StatusOK, `{"revoked":4}`, noTerminal, "tokens", "revoke-all")
	if err != nil || !strings.Contains(out, "révoqués : 4") {
		t.Fatalf("tokens: %q %v", out, err)
	}
}

// localServer fait tourner le vrai serveur sur la socket de state_dir, l'uid
// du pair lu par readPeer, avec un compte native et deux sessions ouvertes.
func localServer(t *testing.T, readPeer func(net.Conn) (uint32, error)) (configPath string, db *store.DB, operator *auth.Service) {
	t.Helper()
	configPath, stateDir := writeShortConfig(t)
	db, parts, srv := realServer(t, stateDir)
	control := startControlSocket(slog.New(slog.DiscardHandler), stateDir, srv.ControlHandler(), readPeer)
	if control == nil {
		t.Fatal("the control socket did not open")
	}
	t.Cleanup(func() { _ = control.Close() })

	ctx := context.Background()
	operator = parts.operator
	issued, err := operator.IssueSetupCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := operator.SetupNative(ctx, auth.State{Mode: auth.ModeNone}, issued.Code, "lucas", "correct horse battery", auth.SessionClient{}); err != nil {
		t.Fatal(err)
	}
	// L'état tel que la base le rend : l'heure d'activation y est arrondie.
	state, err := operator.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Login(ctx, state, "lucas", "correct horse battery", "", auth.SessionClient{}); err != nil {
		t.Fatal(err)
	}
	return configPath, db, operator
}

// realServer monte le vrai serveur sur la base de state_dir, sans l'écouter.
func realServer(t *testing.T, stateDir string) (*store.DB, *components, *server.Server) {
	t.Helper()
	return realServerLogging(t, stateDir, slog.New(slog.DiscardHandler))
}

// realServerLogging est realServer, son journal écrit par logger.
// adjust change les composants avant que le serveur les reçoive : un banc y
// pose ce que la machine de test n'a pas (des clés de version de test).
func realServerLogging(t *testing.T, stateDir string, logger *slog.Logger, adjust ...func(*components)) (*store.DB, *components, *server.Server) {
	t.Helper()
	root, err := openStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	db, err := store.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfg := config.Default()
	cfg.StateDir = stateDir
	parts, err := buildComponents(cfg, root, db, logger)
	if err != nil {
		t.Fatal(err)
	}
	parts.operator.SetHashCost(bcrypt.MinCost)
	for _, change := range adjust {
		change(parts)
	}
	options := parts.serverOptions(cfg)
	options.Live = live.New()
	options.PublicLive = live.New()
	srv, err := server.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return db, parts, srv
}

func asRootPeer(net.Conn) (uint32, error) {
	return 0, nil
}

// R-A2-10 : reset-password, par le canal local, ferme toutes les lignes
// d'operator_sessions.
func TestR_A2_10_ResetPasswordClosesEverySession(t *testing.T) {
	configPath, db, _ := localServer(t, asRootPeer)
	if sessions, err := db.ListSessions(context.Background()); err != nil || len(sessions) != 2 {
		t.Fatalf("before: %d sessions, %v", len(sessions), err)
	}
	var out bytes.Buffer
	if err := adminCommand([]string{"reset-password", "-config", configPath}, &out, typedTwice, 0); err != nil {
		t.Fatal(err)
	}
	sessions, err := db.ListSessions(context.Background())
	if err != nil || len(sessions) != 0 {
		t.Fatalf("after: %d sessions left, %v", len(sessions), err)
	}
	if !strings.Contains(out.String(), "Sessions fermées : 2") {
		t.Fatalf("output %q", out.String())
	}
}

// R-CNX-4 : le mot de passe perdu se refait sur la machine, par root, sans
// interface ni e-mail ; un autre compte de la machine, lu par le vrai
// peercred.Peer, est refusé et rien ne change.
func TestR_CNX_4_ResetPasswordByRootOnTheLocalChannel(t *testing.T) {
	configPath, _, operator := localServer(t, asRootPeer)
	if err := adminCommand([]string{"reset-password", "-config", configPath}, &bytes.Buffer{}, typedTwice, 0); err != nil {
		t.Fatal(err)
	}
	state, err := operator.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if matches, err := operator.Verify(context.Background(), state, "lucas", newPassword); err != nil || !matches {
		t.Fatalf("the new password does not open: %v %v", matches, err)
	}

	if os.Geteuid() == 0 {
		t.Skip("run as root: the refusal of another account is proven by internal/kit/peercred")
	}
	configPath, db, operator := localServer(t, peercred.Peer)
	before, _ := operator.State(context.Background())
	err = adminCommand([]string{"reset-password", "-config", configPath}, &bytes.Buffer{}, typedTwice, 0)
	if err == nil || !strings.Contains(err.Error(), "Réservé à root") {
		t.Fatalf("a non-root peer: %v", err)
	}
	after, _ := operator.State(context.Background())
	sessions, _ := db.ListSessions(context.Background())
	if !after.Same(before) || len(sessions) != 2 {
		t.Fatalf("a non-root peer changed something: %+v, %d sessions", after, len(sessions))
	}
}

// reset-totp : root retire le code à six chiffres par la socket ; rien à
// retirer se dit avec la suite.
func TestAdminResetTOTP_RemovesTheCodeOrSaysThereIsNone(t *testing.T) {
	out, fake, err := runAdminAgainst(t, "/control/admin/reset-totp", http.StatusNoContent, "", noTerminal, "reset-totp")
	if err != nil || len(fake.received) != 1 || !strings.Contains(out, "retiré") {
		t.Fatalf("out %q, received %v, err %v", out, fake.received, err)
	}
	_, _, err = runAdminAgainst(t, "/control/admin/reset-totp", http.StatusConflict, `{"error":"auth.totp_inactive"}`, noTerminal, "reset-totp")
	if err == nil || !strings.Contains(err.Error(), "rien à retirer") {
		t.Fatalf("got %v", err)
	}
}

// unlock : root remet à zéro les échecs du compte par la socket ; en SSO il n'y
// a pas de compte à débloquer, et la commande le dit.
func TestAdminUnlock_ResetsTheAccountFailuresOrSaysThereIsNoAccount(t *testing.T) {
	for _, answered := range []struct {
		name, answer, wantOut, wantRefusal string
		status                             int
	}{
		{"account", "", "remis à zéro", "", http.StatusNoContent},
		{"sso", `{"error":"auth.no_password"}`, "", "SSO", http.StatusConflict},
	} {
		t.Run(answered.name, func(t *testing.T) {
			out, fake, err := runAdminAgainst(t, "/control/admin/unlock", answered.status, answered.answer, noTerminal, "unlock")
			if len(fake.received) != 1 || !strings.Contains(out, answered.wantOut) {
				t.Fatalf("out %q, received %v", out, fake.received)
			}
			if (err == nil) != (answered.wantRefusal == "") || (err != nil && !strings.Contains(err.Error(), answered.wantRefusal)) {
				t.Fatalf("got %v, want a refusal saying %q", err, answered.wantRefusal)
			}
		})
	}
}
