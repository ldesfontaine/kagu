package auth

import (
	"context"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Les échecs comptés par compte (R-A2-16, W-M4), en plus du limiteur par
// adresse du serveur : une force brute répartie sur beaucoup de sources ne
// passe pas sous le plafond de chacune. Il n'y a qu'un compte ; ses compteurs
// sont ceux de la ligne unique de auth_settings, écrits dans la transaction
// de la tentative (ChangeAccountFailures).
const (
	// Les valeurs par défaut des quatre seuils : le fichier de configuration
	// les règle (internal/edge/config).
	DefaultTOTPFailures            = 5
	DefaultTOTPLock                = 15 * time.Minute
	DefaultPasswordFailuresPerHour = 20
	DefaultPasswordPace            = 30 * time.Second
	// MaxTOTPFailures est ce que la colonne totp_failures tient : le plus haut
	// seuil de codes faux que la configuration admet.
	MaxTOTPFailures = 5
	// L'heure sur laquelle se comptent les mots de passe faux.
	passwordFailureWindow = time.Hour
)

var (
	// Le code est suspendu : tout code, le juste aussi, est refusé jusqu'à la
	// fin de la suspension. Le refus porte cette heure (TOTPLockedError).
	ErrTOTPLocked = refusal.Invalid("auth.totp_locked", "auth: code suspended after too many wrong codes")
	// Trop de mots de passe faux dans l'heure : le compte n'accepte plus qu'un
	// essai à la fois par intervalle, toutes sources confondues. Le serveur le
	// rend en 429.
	ErrAccountSlowed = refusal.Invalid("auth.account_slowed", "auth: account slowed after too many wrong passwords")
)

// TOTPLockedError est ErrTOTPLocked avec l'heure où la suspension prend fin :
// la page de connexion la dit.
type TOTPLockedError struct {
	Until time.Time
}

func (e *TOTPLockedError) Error() string {
	return ErrTOTPLocked.Error()
}

func (e *TOTPLockedError) Unwrap() error {
	return ErrTOTPLocked
}

// AccountLimits sont les quatre seuils des échecs par compte.
type AccountLimits struct {
	// Les codes faux d'affilée qui suspendent le code, et la durée de la
	// suspension.
	TOTPFailures int
	TOTPLock     time.Duration
	// Les mots de passe faux de l'heure au-delà desquels le compte ralentit,
	// et l'intervalle entre deux essais une fois ralenti.
	PasswordFailuresPerHour int
	PasswordPace            time.Duration
}

func DefaultAccountLimits() AccountLimits {
	return AccountLimits{
		TOTPFailures: DefaultTOTPFailures, TOTPLock: DefaultTOTPLock,
		PasswordFailuresPerHour: DefaultPasswordFailuresPerHour, PasswordPace: DefaultPasswordPace,
	}
}

// TOTPFailures : les codes faux d'affilée, et la fin de la suspension du code
// (zéro : il n'est pas suspendu).
type TOTPFailures struct {
	Count       int
	LockedUntil time.Time
}

// Locked dit si le code est suspendu à cet instant. La requête de
// ConsumeTOTPStep (internal/edge/store) l'écrit en SQL.
func (f TOTPFailures) Locked(at time.Time) bool {
	return at.Before(f.LockedUntil)
}

// fail compte un code faux ; au seuil, la suspension commence et le compte
// repart de zéro. Une suspension en cours ne bouge pas.
func (f TOTPFailures) fail(at time.Time, limits AccountLimits) TOTPFailures {
	if f.Locked(at) {
		return f
	}
	count := f.Count + 1
	if count >= limits.TOTPFailures {
		return TOTPFailures{LockedUntil: at.Add(limits.TOTPLock)}
	}
	return TOTPFailures{Count: count}
}

// PasswordFailures : les mots de passe faux de l'heure comptée, qui commence
// à WindowStart.
type PasswordFailures struct {
	Count       int
	WindowStart time.Time
}

// CountAt est le nombre de mots de passe faux de l'heure en cours ; une heure
// passée ne compte plus.
func (f PasswordFailures) CountAt(at time.Time) int {
	if f.WindowStart.IsZero() || !at.Before(f.WindowStart.Add(passwordFailureWindow)) {
		return 0
	}
	return f.Count
}

// fail compte un mot de passe faux ; le premier d'une heure neuve ouvre la
// fenêtre.
func (f PasswordFailures) fail(at time.Time) PasswordFailures {
	if f.CountAt(at) == 0 {
		return PasswordFailures{Count: 1, WindowStart: at}
	}
	return PasswordFailures{Count: f.Count + 1, WindowStart: f.WindowStart}
}

// AccountFailures sont les compteurs du compte, tels que la base les garde.
type AccountFailures struct {
	TOTP     TOTPFailures
	Password PasswordFailures
}

// Same dit si deux relevés sont les mêmes, instants compris.
func (f AccountFailures) Same(other AccountFailures) bool {
	return f.TOTP.Count == other.TOTP.Count && f.TOTP.LockedUntil.Equal(other.TOTP.LockedUntil) &&
		f.Password.Count == other.Password.Count && f.Password.WindowStart.Equal(other.Password.WindowStart)
}

// Ce que les échecs par compte attendent du store.
type AccountStore interface {
	GetAccountFailures(ctx context.Context) (AccountFailures, error)
	// ChangeAccountFailures lit les compteurs, applique change et écrit le
	// résultat dans une seule transaction : deux tentatives en même temps se
	// suivent, aucune ne compte sur un compte déjà périmé. Rend l'avant et
	// l'après ; n'écrit rien si change ne les modifie pas.
	ChangeAccountFailures(ctx context.Context, change func(AccountFailures) AccountFailures) (before, after AccountFailures, err error)
}

// TOTPLock est le fait que l'alerte dit : le code vient d'être suspendu.
type TOTPLock struct {
	Username string
	Until    time.Time
	// La source de la dernière tentative fausse.
	Source string
}

// AccountAlerter reçoit les faits du code suspendu ; serve y branche les
// alertes (le composant ne remonte pas vers elles).
type AccountAlerter interface {
	TOTPLocked(ctx context.Context, lock TOTPLock)
	// TOTPUnlocked : la suspension est levée, par root ou par un code juste.
	TOTPUnlocked(ctx context.Context, username string)
}

// SetAccountLimits remplace les seuils par défaut (le fichier de configuration).
func (s *Service) SetAccountLimits(limits AccountLimits) {
	s.limits = limits
}

// SetAlerter branche les alertes ; sans elles, rien ne s'ouvre.
func (s *Service) SetAlerter(alerter AccountAlerter) {
	s.alerter = alerter
}

// judgePassword compare le mot de passe, sous les échecs du compte : ralenti,
// il n'est pas même comparé ; faux, il est compté ; juste, il remet le compte
// à zéro. Le compteur s'écrit dans sa propre transaction (la vérification
// bcrypt, lente, ne tient pas le verrou d'écriture), et deux faux en même
// temps comptent deux fois.
func (s *Service) judgePassword(ctx context.Context, state State, username, password string) (bool, error) {
	if state.Mode != ModeNative || state.PasswordHash == "" {
		return false, nil
	}
	if err := s.admitPasswordAttempt(ctx); err != nil {
		return false, err
	}
	matches, err := s.Verify(ctx, state, username, password)
	if err != nil {
		return false, err
	}
	if matches {
		return true, s.clearPasswordFailures(ctx)
	}
	return false, s.recordPasswordFailure(ctx)
}

// admitPasswordAttempt refuse l'essai quand le compte est ralenti et que le
// dernier est trop proche, quelle que soit sa source. Chaque essai admis
// compte comme « le dernier », ralenti ou non : celui qui franchit le seuil
// est déjà suivi du délai. L'instant du dernier essai ne vit qu'en mémoire ;
// un redémarrage de serve rend un essai de plus.
func (s *Service) admitPasswordAttempt(ctx context.Context) error {
	failures, err := s.store.GetAccountFailures(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	s.paceMu.Lock()
	defer s.paceMu.Unlock()
	slowed := failures.Password.CountAt(now) > s.limits.PasswordFailuresPerHour
	if slowed && now.Sub(s.lastPasswordAttempt) < s.limits.PasswordPace {
		return ErrAccountSlowed
	}
	s.lastPasswordAttempt = now
	return nil
}

func (s *Service) recordPasswordFailure(ctx context.Context) error {
	now := s.now()
	_, _, err := s.store.ChangeAccountFailures(ctx, func(failures AccountFailures) AccountFailures {
		failures.Password = failures.Password.fail(now)
		return failures
	})
	return err
}

func (s *Service) clearPasswordFailures(ctx context.Context) error {
	_, _, err := s.store.ChangeAccountFailures(ctx, func(failures AccountFailures) AccountFailures {
		failures.Password = PasswordFailures{}
		return failures
	})
	return err
}

// refuseWrongTOTP compte un code faux et rend le refus qu'il mérite : suspendu
// (déjà, ou à l'instant, et l'alerte part), sinon faux.
func (s *Service) refuseWrongTOTP(ctx context.Context, state State, source string) error {
	now := s.now()
	before, after, err := s.store.ChangeAccountFailures(ctx, func(failures AccountFailures) AccountFailures {
		failures.TOTP = failures.TOTP.fail(now, s.limits)
		return failures
	})
	if err != nil {
		return err
	}
	if !after.TOTP.Locked(now) {
		return ErrTOTPWrong
	}
	if !before.TOTP.Locked(now) {
		s.logger.Warn("interface code suspended after wrong codes", "username", state.Username, "until", after.TOTP.LockedUntil, "source", source)
		if s.alerter != nil {
			s.alerter.TOTPLocked(ctx, TOTPLock{Username: state.Username, Until: after.TOTP.LockedUntil, Source: source})
		}
	}
	return &TOTPLockedError{Until: after.TOTP.LockedUntil}
}

// Unlock remet à zéro les deux compteurs du compte : le secours de root, par
// le canal local seulement. Il lève la suspension du code et le ralentissement
// du compte.
func (s *Service) Unlock(ctx context.Context) error {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return err
	}
	if err := requireNative(current); err != nil {
		return err
	}
	if _, _, err := s.store.ChangeAccountFailures(ctx, func(AccountFailures) AccountFailures {
		return AccountFailures{}
	}); err != nil {
		return err
	}
	s.paceMu.Lock()
	s.lastPasswordAttempt = time.Time{}
	s.paceMu.Unlock()
	s.logger.Warn("interface account failures reset on the local channel", "username", current.Username)
	s.auditor.Record(ctx, authEvent(audit.AuthUnlock, current))
	s.notifyUnlocked(ctx, current.Username)
	return nil
}

func (s *Service) notifyUnlocked(ctx context.Context, username string) {
	if s.alerter != nil {
		s.alerter.TOTPUnlocked(ctx, username)
	}
}
