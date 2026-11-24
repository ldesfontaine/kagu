package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 : SHA-1 est l'algorithme des applications d'authentification ; HMAC-SHA-1 reste sûr.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Le code à six chiffres (R-A2-6, RFC 6238), proposé en native, jamais
// imposé. L'algorithme est écrit ici sur crypto/hmac (décision QA-09) et tenu
// par les vecteurs de la RFC (totp_test.go). Un pas de 30 s, un pas de marge
// de part et d'autre ; un code ne sert qu'une fois. Pas de codes de secours :
// le secours est root (admin reset-totp).
const (
	TOTPPeriod = 30 * time.Second
	TOTPDigits = 6
	// Le pas d'avant et celui d'après valent aussi : une horloge de téléphone
	// décalée de quelques secondes ne refuse pas le code.
	totpSkewSteps = 1
	// 160 bits, la taille de la sortie de SHA-1 (RFC 4226 §4).
	totpSecretBytes = 20
)

var (
	// Le mot de passe est juste, le code manque : la connexion le demande en
	// second écran.
	ErrTOTPRequired = refusal.Invalid("auth.totp_required", "auth: code required")
	// Faux, hors de sa fenêtre, ou déjà servi : jamais lequel.
	ErrTOTPWrong         = refusal.Invalid("auth.totp_wrong", "auth: code wrong, expired or already used")
	ErrTOTPActive        = refusal.Conflict("auth.totp_active", "auth: code already active")
	ErrTOTPInactive      = refusal.Conflict("auth.totp_inactive", "auth: no code active")
	ErrTOTPSecretInvalid = refusal.Invalid("auth.totp_secret_invalid", "auth: code secret invalid")
)

// totpEncoding : la base 32 sans remplissage des URI otpauth.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// TOTP est ce que la base garde du code : le secret, en clair ici (le store
// le scelle), et le dernier pas servi. Un secret vide : aucun code actif.
type TOTP struct {
	Secret   string
	LastStep int64
}

func (t TOTP) Active() bool {
	return t.Secret != ""
}

// TOTPProposal est un secret tiré pour l'activation, que rien ne garde : le
// premier code juste l'enregistre (EnableTOTP). URI est ce que le QR code
// porte.
type TOTPProposal struct {
	Secret string
	URI    string
}

// Ce que le code attend du store.
type TOTPStore interface {
	GetTOTP(ctx context.Context) (TOTP, error)
	// EnableTOTPIfNone pose le secret et le pas déjà servi, en native et sans
	// code actif seulement ; dit s'il a écrit.
	EnableTOTPIfNone(ctx context.Context, secret string, servedStep int64) (bool, error)
	// ClearTOTP retire le code ; dit s'il y en avait un.
	ClearTOTP(ctx context.Context) (bool, error)
	// ConsumeTOTPStep pose step comme dernier pas servi s'il vient après le
	// précédent et si le code n'est pas suspendu à at, d'un seul tenant ; il
	// remet alors à zéro les codes faux. Dit s'il a écrit.
	ConsumeTOTPStep(ctx context.Context, step int64, at time.Time) (bool, error)
}

// hotp est la valeur HOTP (RFC 4226 §5.3) du secret au compteur donné, en
// digits chiffres. TOTP (RFC 6238) prend pour compteur le pas de 30 s.
func hotp(secret []byte, counter uint64, digits int) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulo := uint32(1)
	for range digits {
		modulo *= 10
	}
	return fmt.Sprintf("%0*d", digits, truncated%modulo)
}

// TOTPCode est le code à six chiffres du secret au pas donné.
func TOTPCode(secret []byte, step int64) string {
	return hotp(secret, uint64(step), TOTPDigits) // #nosec G115 -- un pas d'horloge, positif après 1970.
}

// TOTPStep est le pas de 30 s de l'instant.
func TOTPStep(at time.Time) int64 {
	return at.Unix() / int64(TOTPPeriod/time.Second)
}

// Now est l'heure du serveur, celle à laquelle un code se juge : l'écran du
// code la montre, l'opérateur la compare à son téléphone. Un écart ne se dit
// jamais à partir d'un code : ce serait un oracle (E02-21).
func (s *Service) Now() time.Time {
	return s.now()
}

// matchTOTPStep rend le pas dont le code est celui saisi, parmi le pas de now
// et ses voisins, s'il vient après lastStep. Les trois codes sont comparés en
// temps constant, chacun jusqu'au bout : la durée ne dit pas lequel a failli.
func matchTOTPStep(secret []byte, given string, now time.Time, lastStep int64) (int64, bool) {
	if !isTOTPCodeShape(given) {
		return 0, false
	}
	current := TOTPStep(now)
	matched, found := int64(0), false
	for step := current - totpSkewSteps; step <= current+totpSkewSteps; step++ {
		expected := TOTPCode(secret, step)
		equal := subtle.ConstantTimeCompare([]byte(expected), []byte(given)) == 1
		if equal && step > lastStep && !found {
			matched, found = step, true
		}
	}
	return matched, found
}

// isTOTPCodeShape : six chiffres ASCII, rien d'autre. La longueur n'est pas
// un secret.
func isTOTPCodeShape(code string) bool {
	if len(code) != TOTPDigits {
		return false
	}
	return strings.Trim(code, "0123456789") == ""
}

// DecodeTOTPSecret lit un secret en base 32 et refuse tout autre que 160 bits :
// un secret court choisi par le client affaiblirait le code.
func DecodeTOTPSecret(secret string) ([]byte, error) {
	decoded, err := totpEncoding.DecodeString(secret)
	if err != nil || len(decoded) != totpSecretBytes {
		return nil, ErrTOTPSecretInvalid
	}
	return decoded, nil
}

// ProposeTOTP tire un secret pour l'activation et rend l'URI à scanner. Rien
// n'est écrit : le secret ne vaut qu'une fois confirmé par un premier code.
func (s *Service) ProposeTOTP(ctx context.Context, state State) (TOTPProposal, error) {
	if err := requireNative(state); err != nil {
		return TOTPProposal{}, err
	}
	current, err := s.store.GetTOTP(ctx)
	if err != nil {
		return TOTPProposal{}, err
	}
	if current.Active() {
		return TOTPProposal{}, ErrTOTPActive
	}
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return TOTPProposal{}, fmt.Errorf("draw code secret: %w", err)
	}
	secret := totpEncoding.EncodeToString(raw)
	return TOTPProposal{Secret: secret, URI: totpURI(secret, state.Username)}, nil
}

// totpURI est l'adresse otpauth que les applications lisent (le format de
// Google Authenticator, que toutes suivent).
func totpURI(secret, username string) string {
	issuer := brand.ProductName
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprint(TOTPDigits))
	query.Set("period", fmt.Sprint(int(TOTPPeriod/time.Second)))
	label := url.PathEscape(issuer + ":" + username)
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// EnableTOTP enregistre le secret proposé si code en est un code juste, sous
// l'état qui a admis la requête. Le pas de ce premier code est servi : il ne
// rouvre pas la connexion qui suit.
func (s *Service) EnableTOTP(ctx context.Context, expected State, secret, code string) error {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return err
	}
	if !current.Same(expected) {
		return ErrStateChanged
	}
	if err := requireNative(current); err != nil {
		return err
	}
	raw, err := DecodeTOTPSecret(secret)
	if err != nil {
		return err
	}
	step, matches := matchTOTPStep(raw, code, s.now(), 0)
	if !matches {
		return ErrTOTPWrong
	}
	enabled, err := s.store.EnableTOTPIfNone(ctx, secret, step)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrTOTPActive
	}
	s.logger.Info("interface code enabled", "username", current.Username)
	s.auditor.Record(ctx, authEvent(audit.AuthTOTPEnable, current))
	return nil
}

// DisableTOTP retire le code, si password est le mot de passe en vigueur : il
// est jugé par Verify, comme au changement de mot de passe.
func (s *Service) DisableTOTP(ctx context.Context, expected State, password string) error {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return err
	}
	if !current.Same(expected) {
		return ErrStateChanged
	}
	if err := requireNative(current); err != nil {
		return err
	}
	if err := s.requirePassword(ctx, current, password); err != nil {
		return err
	}
	return s.clearTOTP(ctx, current, audit.AuthTOTPDisable)
}

// ResetTOTP retire le code sans rien demander : c'est le secours de root, par
// le canal local seulement (R-CNX-4). Il n'y a pas de codes de secours.
func (s *Service) ResetTOTP(ctx context.Context) error {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return err
	}
	if err := requireNative(current); err != nil {
		return err
	}
	return s.clearTOTP(ctx, current, audit.AuthTOTPReset)
}

func (s *Service) clearTOTP(ctx context.Context, state State, action audit.Action) error {
	cleared, err := s.store.ClearTOTP(ctx)
	if err != nil {
		return err
	}
	if !cleared {
		return ErrTOTPInactive
	}
	s.logger.Warn("interface code removed", "username", state.Username, "action", string(action))
	s.auditor.Record(ctx, authEvent(action, state))
	s.notifyUnlocked(ctx, state.Username)
	return nil
}

// TOTPActive dit si la connexion demande un code.
func (s *Service) TOTPActive(ctx context.Context) (bool, error) {
	current, err := s.store.GetTOTP(ctx)
	if err != nil {
		return false, err
	}
	return current.Active(), nil
}

// requireTOTP juge le code quand il est actif, et sert son pas : le même code
// présenté encore dans sa fenêtre est refusé (R-A2-6). Sans code actif, rien
// n'est demandé (R-CNX-2). Un code qui n'est pas servi (faux, déjà servi ou
// suspendu) se compte contre le compte (R-A2-16) ; source est l'adresse de la
// requête. Suspendu, le code juste est refusé comme les autres.
func (s *Service) requireTOTP(ctx context.Context, state State, code, source string) error {
	current, err := s.store.GetTOTP(ctx)
	if err != nil {
		return err
	}
	if !current.Active() {
		return nil
	}
	if code == "" {
		return ErrTOTPRequired
	}
	raw, err := DecodeTOTPSecret(current.Secret)
	if err != nil {
		return fmt.Errorf("stored code secret: %w", err)
	}
	now := s.now()
	if step, matches := matchTOTPStep(raw, code, now, current.LastStep); matches {
		// Deux requêtes du même code en même temps : une seule sert le pas.
		served, err := s.store.ConsumeTOTPStep(ctx, step, now)
		if err != nil {
			return err
		}
		if served {
			s.notifyUnlocked(ctx, state.Username)
			return nil
		}
	}
	return s.refuseWrongTOTP(ctx, state, source)
}

// requireNative : le code et la redemande n'existent qu'en native ; en
// forward, c'est le SSO qui authentifie.
func requireNative(state State) error {
	switch state.Mode {
	case ModeNative:
		return nil
	case ModeForward:
		return ErrNoPassword
	}
	return ErrDisabled
}
