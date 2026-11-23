package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/ratelimit"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

// Une session de l'opérateur (R-A2-2) : un jeton de 256 bits tiré au hasard,
// que la base ne garde que par son empreinte. Elle meurt après deux heures
// sans requête, douze heures au plus, à la déconnexion et au changement de
// mot de passe (pour les autres sessions).
const (
	SessionIdleTimeout = 2 * time.Hour
	SessionLifetime    = 12 * time.Hour
	// seen_at ne s'écrit qu'une fois par minute : une écriture par requête
	// ferait de chaque lecture de l'écran une écriture en base.
	sessionSeenStep = time.Minute
	// Le navigateur, tel qu'il se présente : texte venu d'ailleurs, borné.
	MaxUserAgentLength = 200
)

var (
	// Nom ou mot de passe faux : jamais lequel.
	ErrLoginFailed     = refusal.Invalid("auth.login_failed", "auth: wrong name or password")
	ErrSessionNotFound = errors.New("auth: session not found")
	// En forward, le cookie présenté a été ouvert pour une autre identité que
	// celle de l'en-tête : la session est effacée (R-A2-17).
	ErrSessionIdentityChanged = errors.New("auth: session opened for another identity")
)

// Session est ce que la base garde d'une session ; jamais son jeton.
type Session struct {
	ID        string
	Identity  string
	CreatedAt time.Time
	SeenAt    time.Time
	ExpiresAt time.Time
	// Source : l'adresse cliente à l'ouverture, au /64 en IPv6.
	Source    string
	UserAgent string
}

// aliveAt dit si la session vit encore à cet instant.
func (s Session) aliveAt(now time.Time) bool {
	return now.Before(s.endsAt())
}

// endsAt est l'instant où la session meurt si aucune requête ne vient :
// deux heures après la dernière, douze après l'ouverture au plus.
func (s Session) endsAt() time.Time {
	idleEnd := s.SeenAt.Add(SessionIdleTimeout)
	if idleEnd.Before(s.ExpiresAt) {
		return idleEnd
	}
	return s.ExpiresAt
}

// OpenedSession porte le jeton en clair, rendu une seule fois, pour le
// cookie.
type OpenedSession struct {
	Session
	Token string
}

// SessionClient dit d'où vient la requête qui ouvre la session.
type SessionClient struct {
	Address   string
	UserAgent string
}

// Ce que les sessions attendent du store.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session, tokenHash string) error
	SessionByTokenHash(ctx context.Context, tokenHash string) (Session, bool, error)
	SessionByID(ctx context.Context, id string) (Session, bool, error)
	TouchSession(ctx context.Context, id string, seenAt time.Time) error
	// DeleteSession dit si la session existait.
	DeleteSession(ctx context.Context, id string) (bool, error)
	// DeleteOtherSessions efface toutes les sessions sauf keepID, et dit
	// combien.
	DeleteOtherSessions(ctx context.Context, keepID string) (int, error)
	// DeleteDeadSessions efface celles dont la dernière requête est avant
	// idleSince ou dont la fin est passée à now.
	DeleteDeadSessions(ctx context.Context, idleSince, now time.Time) error
	ListSessions(ctx context.Context) ([]Session, error)
}

// Login juge nom et mot de passe sous l'état qui a admis la requête, et ouvre
// une session neuve : rien n'est repris d'un cookie présenté (W-F1).
func (s *Service) Login(ctx context.Context, expected State, username, password string, client SessionClient) (OpenedSession, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return OpenedSession{}, err
	}
	if !current.Same(expected) {
		return OpenedSession{}, ErrStateChanged
	}
	if current.Mode != ModeNative {
		return OpenedSession{}, ErrDisabled
	}
	matches, err := s.Verify(ctx, current, username, password)
	if err != nil {
		return OpenedSession{}, err
	}
	if !matches {
		return OpenedSession{}, ErrLoginFailed
	}
	return s.openSession(ctx, current.Username, client)
}

// SetupNative crée le compte de la première configuration (EnableNative) et
// ouvre sa première session.
func (s *Service) SetupNative(ctx context.Context, expected State, setupCode, username, password string, client SessionClient) (State, OpenedSession, error) {
	state, err := s.EnableNative(ctx, expected, setupCode, username, password)
	if err != nil {
		return State{}, OpenedSession{}, err
	}
	opened, err := s.openSession(ctx, state.Username, client)
	if err != nil {
		return State{}, OpenedSession{}, err
	}
	return state, opened, nil
}

// openSession tire un jeton neuf et écrit son empreinte. Les sessions mortes
// sont effacées au passage : sans cela, celles qu'on ne présente plus
// resteraient en base.
func (s *Service) openSession(ctx context.Context, identity string, client SessionClient) (OpenedSession, error) {
	now := s.now()
	if err := s.store.DeleteDeadSessions(ctx, now.Add(-SessionIdleTimeout), now); err != nil {
		return OpenedSession{}, err
	}
	token, err := ident.NewSecret()
	if err != nil {
		return OpenedSession{}, fmt.Errorf("draw session token: %w", err)
	}
	id, err := ident.New()
	if err != nil {
		return OpenedSession{}, fmt.Errorf("draw session id: %w", err)
	}
	userAgent, _ := untrusted.Strip(client.UserAgent)
	session := Session{
		ID:        id,
		Identity:  identity,
		CreatedAt: now,
		SeenAt:    now,
		ExpiresAt: now.Add(SessionLifetime),
		Source:    ratelimit.SourceKey(client.Address),
		UserAgent: untrusted.Bound(userAgent, MaxUserAgentLength),
	}
	if err := s.store.CreateSession(ctx, session, ident.HashToken(token)); err != nil {
		return OpenedSession{}, err
	}
	s.logger.Info("operator session opened", "session", id, "identity", identity, "source", session.Source)
	return OpenedSession{Session: session, Token: token}, nil
}

// ResumeSession rend la session du jeton présenté, si elle vit encore sous
// state. Une session morte, ou ouverte pour un autre compte, est effacée.
func (s *Service) ResumeSession(ctx context.Context, state State, token string) (Session, bool, error) {
	if state.Mode != ModeNative {
		return Session{}, false, nil
	}
	session, found, err := s.resumeSession(ctx, token, state.Username)
	if errors.Is(err, ErrSessionIdentityChanged) {
		return Session{}, false, nil
	}
	return session, found, err
}

// OpenForwardSession ouvre la session d'une requête que la garde du
// mandataire vient d'admettre sous expected, pour l'identité de l'en-tête.
// Elle lie flux et audit ; elle ne remplace jamais la garde (R-A2-17).
func (s *Service) OpenForwardSession(ctx context.Context, expected State, identity string, client SessionClient) (OpenedSession, error) {
	current, err := s.store.GetAuthState(ctx)
	if err != nil {
		return OpenedSession{}, err
	}
	if !current.Same(expected) {
		return OpenedSession{}, ErrStateChanged
	}
	if current.Mode != ModeForward {
		return OpenedSession{}, ErrDisabled
	}
	return s.openSession(ctx, identity, client)
}

// ResumeForwardSession rend la session du jeton présenté, si elle vit encore
// et porte l'identité que l'en-tête vient de prouver. Une autre identité tue
// la session : ErrSessionIdentityChanged (R-A2-17). Une session morte est
// effacée sans erreur : la garde a admis la requête, une neuve s'ouvre.
func (s *Service) ResumeForwardSession(ctx context.Context, state State, token, identity string) (Session, bool, error) {
	if state.Mode != ModeForward {
		return Session{}, false, nil
	}
	return s.resumeSession(ctx, token, identity)
}

// resumeSession rend la session vivante du jeton, ouverte pour identity.
func (s *Service) resumeSession(ctx context.Context, token, identity string) (Session, bool, error) {
	if token == "" {
		return Session{}, false, nil
	}
	session, found, err := s.store.SessionByTokenHash(ctx, ident.HashToken(token))
	if err != nil || !found {
		return Session{}, false, err
	}
	now := s.now()
	if !session.aliveAt(now) {
		return Session{}, false, s.endSession(ctx, session.ID)
	}
	if session.Identity != identity {
		if err := s.endSession(ctx, session.ID); err != nil {
			return Session{}, false, err
		}
		s.logger.Warn("operator session closed: another identity presented its cookie", "session", session.ID)
		return Session{}, false, ErrSessionIdentityChanged
	}
	if now.Sub(session.SeenAt) >= sessionSeenStep {
		// Un seen_at non écrit (disque plein) ne ferme rien : la session
		// mourra au pire plus tôt.
		if err := s.store.TouchSession(ctx, session.ID, now); err != nil {
			s.logger.Warn("operator session not touched", "session", session.ID, "error", err)
		} else {
			session.SeenAt = now
		}
	}
	return session, true, nil
}

// ClosePresentedSession ferme la session du jeton présenté, s'il en ouvre une :
// en forward, un cookie arrivé sans la preuve du mandataire meurt (R-A2-17).
func (s *Service) ClosePresentedSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	session, found, err := s.store.SessionByTokenHash(ctx, ident.HashToken(token))
	if err != nil || !found {
		return err
	}
	if err := s.endSession(ctx, session.ID); err != nil {
		return err
	}
	s.logger.Warn("operator session closed: its cookie came without the proxy proof", "session", session.ID)
	return nil
}

// SessionAlive dit si la session id vit encore.
func (s *Service) SessionAlive(ctx context.Context, id string) (bool, error) {
	_, alive, err := s.liveSession(ctx, id)
	return alive, err
}

// liveSession relit la session id ; morte, elle est effacée.
func (s *Service) liveSession(ctx context.Context, id string) (Session, bool, error) {
	session, found, err := s.store.SessionByID(ctx, id)
	if err != nil || !found {
		return Session{}, false, err
	}
	if !session.aliveAt(s.now()) {
		return Session{}, false, s.endSession(ctx, id)
	}
	return session, true, nil
}

// Sessions rend les sessions vivantes, les plus récentes d'abord.
func (s *Service) Sessions(ctx context.Context) ([]Session, error) {
	all, err := s.store.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	alive := make([]Session, 0, len(all))
	for _, session := range all {
		if session.aliveAt(now) {
			alive = append(alive, session)
		}
	}
	return alive, nil
}

// CloseSession ferme une session : déconnexion, ou fermeture depuis la liste.
func (s *Service) CloseSession(ctx context.Context, id string) error {
	deleted, err := s.store.DeleteSession(ctx, id)
	s.watches.end(id)
	if err != nil {
		return err
	}
	if !deleted {
		return ErrSessionNotFound
	}
	s.logger.Info("operator session closed", "session", id)
	return nil
}

// CloseOtherSessions ferme toutes les sessions sauf keepID, et dit combien.
func (s *Service) CloseOtherSessions(ctx context.Context, keepID string) (int, error) {
	closed, err := s.closeOtherSessions(ctx, keepID)
	if err != nil {
		return 0, err
	}
	s.logger.Info("operator sessions closed", "kept", keepID, "closed", closed)
	return closed, nil
}

// endSession efface une session et ferme ses flux.
func (s *Service) endSession(ctx context.Context, id string) error {
	_, err := s.store.DeleteSession(ctx, id)
	s.watches.end(id)
	return err
}

// closeOtherSessions efface toutes les sessions sauf keepID et ferme leurs
// flux. Un keepID vide n'en garde aucune.
func (s *Service) closeOtherSessions(ctx context.Context, keepID string) (int, error) {
	closed, err := s.store.DeleteOtherSessions(ctx, keepID)
	s.watches.endAllBut(keepID)
	return closed, err
}

// CloseAllSessions ferme toutes les sessions, par le canal local : root met
// tout le monde dehors sans toucher au mot de passe.
func (s *Service) CloseAllSessions(ctx context.Context) (int, error) {
	closed, err := s.closeAllSessions(ctx)
	if err != nil {
		return 0, err
	}
	s.logger.Warn("operator sessions closed on the local channel", "closed", closed)
	return closed, nil
}
