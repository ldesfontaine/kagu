package machine

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/step"
)

// L'arrivée d'une machine (R-B1-11) : tant qu'elle n'est pas enrôlée, son
// avancement vit sur son jeton, sous gesture_steps « enrollment:<id> » ;
// enrôlée, sa fiche le relit par le jeton que son agent a consommé.

// MaxArrivalSteps : un parcours d'arrivée tient les neuf étapes de join, ou
// les lignes de setup ; au-delà, ce n'est pas l'un d'eux.
const MaxArrivalSteps = 16

// Les codes d'un enrôlement refusé : rendus à l'agent, et écrits en détail de
// l'étape « Agent enrôlé » sur le jeton.
const (
	RefusedTokenConsumed = "token_consumed"
	RefusedTokenExpired  = "token_expired"
)

// ArrivalState dit où en est le jeton d'une machine qui arrive.
type ArrivalState string

const (
	ArrivalPending  ArrivalState = "pending"
	ArrivalExpired  ArrivalState = "expired"
	ArrivalEnrolled ArrivalState = "enrolled"
)

// Arrival est ce que la tuile « en cours d'arrivée » lit d'un jeton.
type Arrival struct {
	State     ArrivalState
	ExpiresAt time.Time
	Steps     []step.Step
}

// RecordJoinProgress écrit le parcours que join rapporte, à la place du
// précédent, sous le jeton dont il a le clair : comparé par empreinte, jamais
// consommé. Un jeton en attente prend tout parcours ; un jeton servi, celui
// seulement qui dit « Agent enrôlé » fait, pour que la même ligne recollée
// sur une autre machine n'écrase pas la frise de celle qui est arrivée ; un
// jeton expiré, aucun.
func (s *Service) RecordJoinProgress(ctx context.Context, cleartext string, reported []step.Step) error {
	steps, ok := step.CleanAll(reported, MaxArrivalSteps)
	if !ok || len(steps) == 0 {
		return ErrBadField
	}
	token, err := s.store.TokenByHash(ctx, ident.HashToken(cleartext))
	if err != nil {
		return err
	}
	switch {
	case !token.ConsumedAt.IsZero():
		if !saysEnrolled(steps) {
			return ErrTokenConsumed
		}
	case token.isExpired(s.now()):
		return ErrTokenExpired
	}
	if err := s.store.ReplaceEnrollmentSteps(ctx, token.ID, steps); err != nil {
		return err
	}
	s.changed(token.MachineID)
	return nil
}

// RecordLocalProgress écrit le parcours que setup rapporte pour l'agent de la
// machine Kagu, par la socket de contrôle, à root seul : sous le jeton que
// cet agent a consommé, sinon sous celui qui lui est offert.
// ErrTokenNotFound tant qu'aucun ne l'est : les premières lignes de setup
// précèdent le serveur.
func (s *Service) RecordLocalProgress(ctx context.Context, reported []step.Step) error {
	steps, ok := step.CleanAll(reported, MaxArrivalSteps)
	if !ok || len(steps) == 0 {
		return ErrBadField
	}
	tokenID, err := s.localTokenID(ctx)
	if err != nil {
		return err
	}
	if err := s.store.ReplaceEnrollmentSteps(ctx, tokenID, steps); err != nil {
		return err
	}
	s.changed(LocalID)
	return nil
}

// localTokenID rend le jeton de l'agent de la machine Kagu : celui qu'il a
// consommé, sinon celui qui lui est offert.
func (s *Service) localTokenID(ctx context.Context) (string, error) {
	local, err := s.store.GetMachine(ctx, LocalID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if err == nil && local.Agent.Exists() {
		token, err := s.store.TokenOfAgent(ctx, local.Agent.ID)
		if !errors.Is(err, ErrTokenNotFound) {
			return token.ID, err
		}
	}
	s.offerLock.Lock()
	defer s.offerLock.Unlock()
	if s.offer.token.ID == "" {
		return "", ErrTokenNotFound
	}
	return s.offer.token.ID, nil
}

// saysEnrolled dit si le parcours porte « Agent enrôlé » fait.
func saysEnrolled(steps []step.Step) bool {
	return slices.ContainsFunc(steps, func(checked step.Step) bool {
		return checked.Key == step.EnrollEnrolled && checked.State == step.StateDone
	})
}

// isExpired : passé son heure, un jeton non servi n'enrôle plus rien.
func (t Token) isExpired(now time.Time) bool {
	return !t.ExpiresAt.After(now)
}

// noteRefusedEnrollment écrit sur le jeton l'enrôlement qu'il vient de
// refuser, à la suite de ce qu'il porte : la tuile dit « jeton expiré » avec
// l'heure, la fiche de la machine servie garde la tentative. Un échec
// d'écriture ne change pas le refus rendu à l'agent.
func (s *Service) noteRefusedEnrollment(ctx context.Context, cleartext string, refused error) {
	token, err := s.store.TokenByHash(ctx, ident.HashToken(cleartext))
	if err != nil {
		s.logger.Error("read the refused token", "error", err)
		return
	}
	code := RefusedTokenExpired
	if errors.Is(refused, ErrTokenConsumed) {
		code = RefusedTokenConsumed
	}
	attempt := step.Step{Key: step.EnrollEnrolled, State: step.StateFailed, Detail: code, At: s.now()}
	if err := s.store.AppendEnrollmentStep(ctx, token.ID, attempt); err != nil {
		s.logger.Error("note the refused enrollment", "token_id", token.ID, "error", err)
		return
	}
	s.changed(token.MachineID)
}

// ArrivalOf rend l'état d'un jeton et son parcours, consommé ou non.
func (s *Service) ArrivalOf(ctx context.Context, tokenID string) (Arrival, error) {
	token, err := s.store.TokenByID(ctx, tokenID)
	if err != nil {
		return Arrival{}, err
	}
	steps, err := s.store.EnrollmentSteps(ctx, token.ID)
	if err != nil {
		return Arrival{}, err
	}
	state := ArrivalPending
	switch {
	case !token.ConsumedAt.IsZero():
		state = ArrivalEnrolled
	case token.isExpired(s.now()):
		state = ArrivalExpired
	}
	return Arrival{State: state, ExpiresAt: token.ExpiresAt, Steps: steps}, nil
}

// ArrivalSteps rend le parcours d'arrivée d'un agent, lu par le jeton qu'il a
// consommé : la frise de la fiche. Vide si ce jeton est purgé, ou pour un
// agent d'avant les jetons.
func (s *Service) ArrivalSteps(ctx context.Context, agentID string) ([]step.Step, error) {
	if agentID == "" {
		return []step.Step{}, nil
	}
	token, err := s.store.TokenOfAgent(ctx, agentID)
	if errors.Is(err, ErrTokenNotFound) {
		return []step.Step{}, nil
	}
	if err != nil {
		return nil, err
	}
	return s.store.EnrollmentSteps(ctx, token.ID)
}
