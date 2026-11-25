package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ldesfontaine/kagu/internal/kit/audit"
)

// Coût bcrypt : environ 100 ms par vérification sur une machine modeste. Il
// ne se paie qu'à la connexion et au changement de mot de passe : ensuite, la
// session porte l'opérateur.
const (
	DefaultHashCost = 12
	// Les vérifications qui attendent derrière celle qui tourne. La file tient
	// la rafale entière qu'une adresse a le droit de présenter (dix essais,
	// voir authAttemptBurst dans internal/edge/server) : plusieurs onglets qui
	// se connectent ensemble attendent le premier au lieu d'être refusés.
	// Au-delà, refus immédiat : l'attente d'un opérateur admis reste bornée à
	// dix bcrypt.
	maxQueuedVerifications = 9
)

// ErrVerificationQueueFull : trop de vérifications attendent déjà. L'appelant
// répond 429 sans rien comparer ; ce n'est pas un mauvais mot de passe.
var ErrVerificationQueueFull = errors.New("auth: verification queue full")

// Ce que le service attend du store.
type Store interface {
	GetAuthState(ctx context.Context) (State, error)
	// SaveAuthStateIf n'écrit que si l'état stocké vaut encore expected, et
	// dit s'il a écrit. Un retour au mode none efface aussi les sessions.
	SaveAuthStateIf(ctx context.Context, expected, next State, at time.Time) (bool, error)
	GetSetupCode(ctx context.Context) (SetupCode, error)
	// SaveSetupCodeIfNone remplace le code, seulement en mode none, et dit
	// s'il a écrit.
	SaveSetupCodeIfNone(ctx context.Context, code SetupCode, at time.Time) (bool, error)
	RecordSetupCodeFailure(ctx context.Context) error
	SessionStore
	TOTPStore
	AccountStore
}

type Service struct {
	store    Store
	auditor  *audit.Recorder
	logger   *slog.Logger
	now      func() time.Time
	hashCost int
	// Les seuils des échecs par compte, et les alertes qu'ils ouvrent.
	limits  AccountLimits
	alerter AccountAlerter

	// Tire et vérifie le code de première configuration, un à la fois.
	setupMu sync.Mutex
	// Une vérification lente à la fois : borne le processeur. Un canal d'une
	// place plutôt qu'un mutex, pour qu'une attente puisse être abandonnée
	// avec la requête qui la porte.
	verifying chan struct{}
	// Le nombre d'attentes en cours, pour refuser au-delà de la borne.
	queued atomic.Int32
	// Les fins de session que des flux attendent (session_watch.go).
	watches sessionWatches
}

func New(store Store, logger *slog.Logger) *Service {
	return &Service{
		store: store, logger: logger, now: time.Now, hashCost: DefaultHashCost, limits: DefaultAccountLimits(),
		verifying: make(chan struct{}, 1),
	}
}

func (s *Service) SetClock(now func() time.Time) {
	s.now = now
}

// SetHashCost sert aux tests, où bcrypt au coût réel coûterait des secondes.
func (s *Service) SetHashCost(cost int) {
	s.hashCost = cost
}

// State relit l'état dans la base à chaque appel : un changement de mode ou
// de mot de passe prend effet à la requête suivante, sans redémarrer serve.
func (s *Service) State(ctx context.Context) (State, error) {
	return s.store.GetAuthState(ctx)
}

// Les changements d'état prennent l'état sous lequel la requête a été
// autorisée (expected) : une requête dont le corps a traîné ne s'applique pas
// à un état qu'elle n'a pas vu. La comparaison et l'écriture se font d'un seul
// tenant dans la base ; la lecture qui précède évite seulement un hachage
// inutile.

// EnableNative choisit identifiant et mot de passe, et passe en mode native.
// Sans le code de première configuration, rien ne se crée (setupCode).
func (s *Service) EnableNative(ctx context.Context, expected State, setupCode, username, password string) (State, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return State{}, err
	}
	if current.Mode != ModeNone {
		return State{}, ErrAlreadyEnabled
	}
	if err := s.requireFirstSetup(ctx, setupCode); err != nil {
		return State{}, err
	}
	if err := ValidateUsername(username); err != nil {
		return State{}, err
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return State{}, err
	}
	next := State{Mode: ModeNative, Username: username, PasswordHash: hash, EnabledAt: s.now()}
	if err := s.replaceState(ctx, expected, next); err != nil {
		return State{}, err
	}
	s.logger.Info("interface authentication enabled", "mode", string(ModeNative), "username", username)
	s.auditor.Record(ctx, authEvent(audit.AuthEnable, next))
	return next, nil
}

// requireFirstSetup juge le code, puis, s'il est inutilisable, relit l'état :
// un code effacé parce qu'une autre activation vient de réussir se dit « déjà
// activé », pas « code brûlé ». L'exclusion reste celle de replaceState.
func (s *Service) requireFirstSetup(ctx context.Context, setupCode string) error {
	err := s.requireSetupCode(ctx, setupCode)
	if !errors.Is(err, ErrSetupCodeUnusable) {
		return err
	}
	current, stateErr := s.store.GetAuthState(ctx)
	if stateErr != nil {
		return stateErr
	}
	if current.Mode != ModeNone {
		return ErrAlreadyEnabled
	}
	return err
}

// EnableForward passe en mode forward : l'identité vient de l'en-tête
// que pose le mandataire. Le serveur vérifie d'abord que la requête qui
// active le porte déjà, sans quoi l'opérateur s'enfermerait dehors.
func (s *Service) EnableForward(ctx context.Context, expected State, setupCode, header string) (State, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return State{}, err
	}
	if current.Mode != ModeNone {
		return State{}, ErrAlreadyEnabled
	}
	if err := s.requireFirstSetup(ctx, setupCode); err != nil {
		return State{}, err
	}
	if err := ValidateHeader(header); err != nil {
		return State{}, err
	}
	next := State{Mode: ModeForward, Header: header, EnabledAt: s.now()}
	if err := s.replaceState(ctx, expected, next); err != nil {
		return State{}, err
	}
	s.logger.Info("interface authentication enabled", "mode", string(ModeForward), "header", header)
	s.auditor.Record(ctx, authEvent(audit.AuthEnable, next))
	return next, nil
}

// ChangePassword garde l'identifiant et remplace l'empreinte, si currentPassword
// est celui en vigueur. Il est jugé par Verify (même file bcrypt bornée que la
// connexion), avant tout hachage du nouveau. Les sessions autres que
// keepSession sont fermées (R-A2-9) : celle qui a changé le mot de passe reste.
func (s *Service) ChangePassword(ctx context.Context, expected State, keepSession, currentPassword, password string) (State, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return State{}, err
	}
	if !current.Same(expected) {
		return State{}, ErrStateChanged
	}
	if current.Mode == ModeForward {
		return State{}, ErrNoPassword
	}
	if current.Mode != ModeNative {
		return State{}, ErrDisabled
	}
	if err := s.requirePassword(ctx, current, currentPassword); err != nil {
		return State{}, err
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return State{}, err
	}
	next := current
	next.PasswordHash = hash
	if err := s.replaceState(ctx, expected, next); err != nil {
		return State{}, err
	}
	closed, err := s.closeOtherSessions(ctx, keepSession)
	if err != nil {
		return State{}, err
	}
	s.logger.Info("interface password changed", "username", next.Username, "sessions_closed", closed)
	s.auditor.Record(ctx, authEvent(audit.AuthChangePassword, next))
	return next, nil
}

// ResetPassword refait le mot de passe du compte, sans demander l'ancien :
// c'est le secours de root, par le canal local seulement (R-A2-10). Toutes
// les sessions sont fermées (R-A2-2), et le nombre en est rendu.
func (s *Service) ResetPassword(ctx context.Context, password string) (int, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return 0, err
	}
	if current.Mode == ModeForward {
		return 0, ErrNoPassword
	}
	if current.Mode != ModeNative {
		return 0, ErrDisabled
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return 0, err
	}
	next := current
	next.PasswordHash = hash
	if err := s.replaceState(ctx, current, next); err != nil {
		return 0, err
	}
	closed, err := s.closeAllSessions(ctx)
	if err != nil {
		return 0, err
	}
	s.logger.Warn("interface password reset on the local channel", "username", next.Username, "sessions_closed", closed)
	s.auditor.Record(ctx, authEvent(audit.AuthResetPassword, next))
	return closed, nil
}

// ModeChange est ce que root demande par le canal local : le mode visé, et
// ce qu'il lui faut. Username et Password ne valent que pour native, Header
// que pour forward.
type ModeChange struct {
	Mode     Mode
	Header   string
	Username string
	Password string
}

// SetMode passe une installation déjà configurée d'un mode à l'autre, ou
// change l'en-tête du SSO. Il ne ramène jamais à none : rien ne rouvre la
// première configuration (R-A2-10). Toutes les sessions sont fermées :
// elles ont été ouvertes sous l'ancien accès.
func (s *Service) SetMode(ctx context.Context, change ModeChange) (State, int, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return State{}, 0, err
	}
	if current.Mode == ModeNone {
		return State{}, 0, ErrDisabled
	}
	if changesNothing(current, change) {
		return State{}, 0, ErrSameMode
	}
	next, err := s.stateFor(change)
	if err != nil {
		return State{}, 0, err
	}
	if err := s.replaceState(ctx, current, next); err != nil {
		return State{}, 0, err
	}
	closed, err := s.closeAllSessions(ctx)
	if err != nil {
		return State{}, 0, err
	}
	s.logger.Warn("interface access mode changed on the local channel", "previous_mode", string(current.Mode), "mode", string(next.Mode), "sessions_closed", closed)
	s.auditor.Record(ctx, authEvent(audit.AuthChangeMode, next))
	return next, closed, nil
}

// changesNothing : de native à native, le mot de passe se refait par
// ResetPassword ; de forward à forward, seul l'en-tête peut changer.
func changesNothing(current State, change ModeChange) bool {
	if current.Mode != change.Mode {
		return false
	}
	return current.Mode == ModeNative || current.Header == change.Header
}

// stateFor juge la demande et rend l'état qu'elle écrirait.
func (s *Service) stateFor(change ModeChange) (State, error) {
	switch change.Mode {
	case ModeNative:
		if err := ValidateUsername(change.Username); err != nil {
			return State{}, err
		}
		hash, err := s.hashPassword(change.Password)
		if err != nil {
			return State{}, err
		}
		return State{Mode: ModeNative, Username: change.Username, PasswordHash: hash, EnabledAt: s.now()}, nil
	case ModeForward:
		if err := ValidateHeader(change.Header); err != nil {
			return State{}, err
		}
		return State{Mode: ModeForward, Header: change.Header, EnabledAt: s.now()}, nil
	}
	return State{}, ErrModeInvalid
}

// closeAllSessions ferme toutes les sessions et leurs flux (R-A2-12) :
// aucune n'a l'identifiant vide.
func (s *Service) closeAllSessions(ctx context.Context) (int, error) {
	return s.closeOtherSessions(ctx, "")
}

// replaceState écrit next si l'état stocké vaut encore expected.
func (s *Service) replaceState(ctx context.Context, expected, next State) error {
	swapped, err := s.store.SaveAuthStateIf(ctx, expected, next, s.now())
	if err != nil {
		return err
	}
	if !swapped {
		return ErrStateChanged
	}
	return nil
}

// Verify compare au prix de bcrypt. L'identifiant est comparé en temps
// constant, le mot de passe par bcrypt même quand l'identifiant est faux : la
// durée ne dit pas lequel l'est.
//
// L'erreur dit qu'on n'a rien comparé : la file est pleine
// (ErrVerificationQueueFull), ou la requête a pris fin pendant l'attente.
// Un bcrypt déjà commencé ne s'interrompt pas, mais aucun ne commence pour
// une requête abandonnée.
func (s *Service) Verify(ctx context.Context, state State, username, password string) (bool, error) {
	if state.Mode != ModeNative || state.PasswordHash == "" {
		return false, nil
	}
	if err := s.acquireVerification(ctx); err != nil {
		return false, err
	}
	defer func() { <-s.verifying }()
	usernameMatches := sameText(username, state.Username)
	passwordMatches := bcrypt.CompareHashAndPassword([]byte(state.PasswordHash), []byte(password)) == nil
	return usernameMatches && passwordMatches, nil
}

// requirePassword juge par judgePassword le mot de passe en vigueur, que redonne la
// personne connectée : faux, ErrCurrentPasswordWrong.
func (s *Service) requirePassword(ctx context.Context, state State, password string) error {
	matches, err := s.judgePassword(ctx, state, state.Username, password)
	if err != nil {
		return err
	}
	if !matches {
		return ErrCurrentPasswordWrong
	}
	return nil
}

// sameText compare deux textes en temps constant : les empreintes ont la même
// longueur quoi qu'on ait saisi.
func sameText(given, expected string) bool {
	givenSum := sha256.Sum256([]byte(given))
	expectedSum := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(givenSum[:], expectedSum[:]) == 1
}

// acquireVerification prend la place de la vérification lente. Si elle est
// prise, on entre dans la file, bornée : au-delà, refus immédiat.
func (s *Service) acquireVerification(ctx context.Context) error {
	select {
	case s.verifying <- struct{}{}:
		return s.stopIfCanceled(ctx)
	default:
	}
	if s.queued.Add(1) > maxQueuedVerifications {
		s.queued.Add(-1)
		return ErrVerificationQueueFull
	}
	defer s.queued.Add(-1)
	select {
	case s.verifying <- struct{}{}:
		return s.stopIfCanceled(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopIfCanceled rend la place si la requête a pris fin au moment où elle
// l'obtenait : select choisit au hasard quand les deux sont prêts.
func (s *Service) stopIfCanceled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		<-s.verifying
		return err
	}
	return nil
}

func (s *Service) hashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.hashCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}
