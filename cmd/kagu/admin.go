package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	refusals "github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Les gestes de « admin », tels qu'on les tape. Chacun a sa route sous
// /control/admin/, que la socket ne sert qu'à root (internal/edge/server).
const (
	adminSetupCode     = "setup-code"
	adminResetPassword = "reset-password"
	adminResetTOTP     = "reset-totp"
	adminUnlock        = "unlock"
	adminModeNative    = "auth-mode native"
	adminModeForward   = "auth-mode forward"
	adminCloseSessions = "sessions close-all"
	adminRevokeTokens  = "tokens revoke-all" // #nosec G101 -- un nom de geste, pas un secret.
)

// adminPaths : la route de chaque geste.
var adminPaths = map[string]string{
	adminSetupCode:     "/control/admin/setup-code",
	adminResetPassword: "/control/admin/reset-password",
	adminResetTOTP:     "/control/admin/reset-totp",
	adminUnlock:        "/control/admin/unlock",
	adminModeNative:    "/control/admin/auth-mode",
	adminModeForward:   "/control/admin/auth-mode",
	adminCloseSessions: "/control/admin/sessions/close-all",
	adminRevokeTokens:  "/control/admin/tokens/revoke-all",
}

// opencloud admin : les gestes de root sur la machine Kagu, par la socket
// locale du serveur qui tourne (R-A2-10, R-A2-11). Le serveur juge l'uid du
// pair : seul root passe.
func runAdmin(args []string) error {
	return adminCommand(args, os.Stdout, openSilentTerminal, os.Geteuid())
}

// adminRun porte ce dont un geste a besoin : la socket, les textes, la
// sortie, et le terminal où se saisit un mot de passe.
type adminRun struct {
	client       *controlClient
	text         lang.Catalog
	out          io.Writer
	openTerminal terminalOpener
	euid         int
}

func adminCommand(args []string, out io.Writer, openTerminal terminalOpener, euid int) error {
	catalogs, err := lang.Load()
	if err != nil {
		return err
	}
	text := catalogs.For(lang.Default)
	gesture, rest, known := splitAdminArguments(args)
	if !known {
		fmt.Fprintln(os.Stderr, text.Get("admin.usage"))
		if len(args) == 0 {
			return &refusal{message: text.Get("admin.missing")}
		}
		return &refusal{message: text.Format("admin.unknown", strings.Join(args, " "))}
	}
	flags := flag.NewFlagSet("admin "+gesture, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", config.DefaultPath, "chemin du fichier de configuration")
	var header, username *string
	switch gesture {
	case adminModeForward:
		header = flags.String("header", auth.DefaultForwardHeader, "en-tête d'identité que pose le SSO")
	case adminModeNative:
		username = flags.String("username", "", "identifiant du compte")
	}
	if err := flags.Parse(rest); err != nil {
		return err
	}
	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	run := adminRun{client: newControlClient(cfg.StateDir), text: text, out: out, openTerminal: openTerminal, euid: euid}
	ctx := context.Background()
	switch gesture {
	case adminSetupCode:
		return run.issueSetupCode(ctx)
	case adminResetPassword:
		return run.resetPassword(ctx)
	case adminResetTOTP:
		return run.resetTOTP(ctx)
	case adminUnlock:
		return run.unlock(ctx)
	case adminModeNative:
		return run.setNative(ctx, *username)
	case adminModeForward:
		return run.setForward(ctx, *header)
	case adminCloseSessions:
		return run.closeAllSessions(ctx)
	}
	return run.revokeAllTokens(ctx)
}

// splitAdminArguments lit le geste, d'un mot ou de deux, et rend ce qui suit
// (les options).
func splitAdminArguments(args []string) (gesture string, rest []string, known bool) {
	if len(args) >= 1 {
		if _, found := adminPaths[args[0]]; found {
			return args[0], args[1:], true
		}
	}
	if len(args) >= 2 {
		if _, found := adminPaths[args[0]+" "+args[1]]; found {
			return args[0] + " " + args[1], args[2:], true
		}
	}
	return "", nil, false
}

func (a adminRun) issueSetupCode(ctx context.Context) error {
	var issued struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.call(ctx, adminSetupCode, struct{}{}, http.StatusCreated, &issued); err != nil {
		return err
	}
	_, err := fmt.Fprintln(a.out, a.text.Format("admin.setup_code_done",
		issued.Code, issued.ExpiresAt.Local().Format("15:04"), int(auth.SetupCodeLifetime.Minutes()), auth.MaxSetupCodeFailures))
	return err
}

func (a adminRun) resetPassword(ctx context.Context) error {
	password, err := a.readNewPassword()
	if err != nil {
		return err
	}
	var reset struct {
		Closed int `json:"closed"`
	}
	if err := a.call(ctx, adminResetPassword, map[string]string{"password": password}, http.StatusOK, &reset); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.out, a.text.Format("admin.reset_done", reset.Closed))
	return err
}

// resetTOTP retire le code à six chiffres : le téléphone perdu, il n'y a pas
// de codes de secours, root est le secours (R-CNX-4).
func (a adminRun) resetTOTP(ctx context.Context) error {
	if err := a.callWithoutAnswer(ctx, adminResetTOTP, struct{}{}, http.StatusNoContent); err != nil {
		return err
	}
	_, err := fmt.Fprintln(a.out, a.text.Get("admin.reset_totp_done"))
	return err
}

// unlock remet à zéro les échecs du compte : le code suspendu après trop de
// codes faux, le compte ralenti après trop de mots de passe faux (R-A2-16).
func (a adminRun) unlock(ctx context.Context) error {
	if err := a.callWithoutAnswer(ctx, adminUnlock, struct{}{}, http.StatusNoContent); err != nil {
		return err
	}
	_, err := fmt.Fprintln(a.out, a.text.Get("admin.unlock_done"))
	return err
}

func (a adminRun) setNative(ctx context.Context, username string) error {
	if username == "" {
		return &refusal{message: a.text.Get("admin.username_missing")}
	}
	password, err := a.readNewPassword()
	if err != nil {
		return err
	}
	request := map[string]string{"mode": string(auth.ModeNative), "username": username, "password": password}
	return a.changeMode(ctx, adminModeNative, request, "admin.mode_native_done")
}

func (a adminRun) setForward(ctx context.Context, header string) error {
	request := map[string]string{"mode": string(auth.ModeForward), "header": header}
	return a.changeMode(ctx, adminModeForward, request, "admin.mode_forward_done")
}

// changeMode envoie le changement et dit ce qui est en vigueur ; doneKey
// prend le compte ou l'en-tête, puis les sessions fermées.
func (a adminRun) changeMode(ctx context.Context, gesture string, request map[string]string, doneKey string) error {
	var changed struct {
		Username string `json:"username"`
		Header   string `json:"header"`
		Closed   int    `json:"closed"`
	}
	if err := a.call(ctx, gesture, request, http.StatusOK, &changed); err != nil {
		return err
	}
	// Un seul des deux est rempli : le compte en native, l'en-tête en forward.
	who := changed.Username
	if who == "" {
		who = changed.Header
	}
	_, err := fmt.Fprintln(a.out, a.text.Format(doneKey, printable(who), changed.Closed))
	return err
}

func (a adminRun) closeAllSessions(ctx context.Context) error {
	var closed struct {
		Closed int `json:"closed"`
	}
	if err := a.call(ctx, adminCloseSessions, struct{}{}, http.StatusOK, &closed); err != nil {
		return err
	}
	_, err := fmt.Fprintln(a.out, a.text.Format("admin.sessions_closed", closed.Closed))
	return err
}

func (a adminRun) revokeAllTokens(ctx context.Context) error {
	var revoked struct {
		Revoked int `json:"revoked"`
	}
	if err := a.call(ctx, adminRevokeTokens, struct{}{}, http.StatusOK, &revoked); err != nil {
		return err
	}
	_, err := fmt.Fprintln(a.out, a.text.Format("admin.tokens_revoked", revoked.Revoked))
	return err
}

// call envoie le geste à la socket et lit la réponse attendue dans answer.
func (a adminRun) call(ctx context.Context, gesture string, payload any, want int, answer any) error {
	body, err := a.send(ctx, gesture, payload, want)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, answer); err != nil {
		return fmt.Errorf("read the server's answer: %w", err)
	}
	return nil
}

// callWithoutAnswer envoie un geste dont la réponse attendue n'a pas de corps.
func (a adminRun) callWithoutAnswer(ctx context.Context, gesture string, payload any, want int) error {
	_, err := a.send(ctx, gesture, payload, want)
	return err
}

// send envoie le geste à la socket et rend le corps de la réponse attendue,
// ou le refus dit dans la langue de la commande.
func (a adminRun) send(ctx context.Context, gesture string, payload any, want int) ([]byte, error) {
	status, body, err := a.client.post(ctx, adminPaths[gesture], payload, controlTimeout)
	if err != nil {
		return nil, err
	}
	if status != want {
		return nil, a.refusalOf(status, body)
	}
	return body, nil
}

// adminHints : les refus du serveur que la commande dit avec la suite à
// donner, plutôt qu'avec le texte de l'interface.
var adminHints = map[error]string{
	auth.ErrDisabled:       "admin.no_account_yet",
	auth.ErrNoPassword:     "admin.forward_no_password",
	auth.ErrAlreadyEnabled: "admin.setup_already_done",
	auth.ErrTOTPInactive:   "admin.totp_none",
}

// refusalOf dit un refus du serveur dans la langue de la commande. Un 403
// est celui de la socket : le pair n'est pas root.
func (a adminRun) refusalOf(status int, body []byte) error {
	if status == http.StatusForbidden {
		return &refusal{message: a.text.Get("admin.root_only")}
	}
	var refused struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &refused) != nil || refused.Error == "" {
		return serverRefusal(status, body)
	}
	for sentinel, hint := range adminHints {
		if key, _ := refusals.KeyOf(sentinel); key == refused.Error {
			return &refusal{message: a.text.Get(hint)}
		}
	}
	return &refusal{message: a.text.Get(catalogKey(refused.Error))}
}

// readNewPassword demande le nouveau mot de passe deux fois, sur le terminal
// et sans écho : jamais sur l'entrée standard, jamais affiché. Un compte qui
// n'est pas root est refusé avant : le serveur le refuserait après la saisie.
func (a adminRun) readNewPassword() (string, error) {
	if a.euid != 0 {
		return "", &refusal{message: a.text.Get("admin.root_only")}
	}
	terminal, err := a.openTerminal()
	if err != nil {
		return "", &refusal{message: a.text.Get("admin.password_needs_tty")}
	}
	defer terminal.Close()
	answers := bufio.NewReader(terminal)
	first := a.ask(answers, "admin.password_prompt")
	second := a.ask(answers, "admin.password_again")
	if first != second {
		return "", &refusal{message: a.text.Get("auth.password_mismatch")}
	}
	return first, nil
}

// ask pose la question et lit une ligne. L'Entrée de l'opérateur ne s'est
// pas affichée : le retour à la ligne s'écrit ici.
func (a adminRun) ask(answers *bufio.Reader, key string) string {
	fmt.Fprint(a.out, a.text.Get(key))
	line, _ := answers.ReadString('\n')
	fmt.Fprintln(a.out)
	return strings.TrimRight(line, "\r\n")
}
