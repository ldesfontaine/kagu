package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Le code de première configuration (R-A2-5) : tant qu'aucun compte n'existe,
// seul celui qui lit ce code sur la machine peut en créer un.
const (
	setupCodeDigits = 8
	// Au bout de ce temps le code est échu ; un autre se tire par la commande.
	SetupCodeLifetime = 30 * time.Minute
	// Les essais faux, au total : au dernier, le code est brûlé, le bon
	// compris.
	MaxSetupCodeFailures = 5
)

var (
	ErrSetupCodeMissing = refusal.Invalid("auth.setup_code_required", "auth: setup code missing")
	ErrSetupCodeWrong   = refusal.Invalid("auth.setup_code_wrong", "auth: setup code wrong")
	// Aucun code tiré, échu ou brûlé : ce que l'opérateur y fait est le même.
	ErrSetupCodeUnusable = refusal.Conflict("auth.setup_code_unusable", "auth: setup code absent, expired or burnt")
)

// SetupCode est ce que la base garde : l'empreinte du code, jamais le code.
type SetupCode struct {
	Hash     string
	Expires  time.Time
	Failures int
}

// IssuedSetupCode est le code en clair, rendu une seule fois à la commande
// qui l'a demandé.
type IssuedSetupCode struct {
	Code      string
	ExpiresAt time.Time
}

// IssueSetupCode tire un code et remplace celui d'avant, brûlé ou non. Il ne
// se tire qu'en mode none : ailleurs, la première configuration est faite.
func (s *Service) IssueSetupCode(ctx context.Context) (IssuedSetupCode, error) {
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(setupCodeDigits), nil)
	number, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return IssuedSetupCode{}, fmt.Errorf("generate setup code: %w", err)
	}
	issued := IssuedSetupCode{
		Code:      fmt.Sprintf("%0*d", setupCodeDigits, number),
		ExpiresAt: s.now().Add(SetupCodeLifetime),
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	saved, err := s.store.SaveSetupCodeIfNone(ctx, SetupCode{Hash: ident.HashSecret(issued.Code), Expires: issued.ExpiresAt}, s.now())
	if err != nil {
		return IssuedSetupCode{}, err
	}
	if !saved {
		return IssuedSetupCode{}, ErrAlreadyEnabled
	}
	s.logger.Warn("first setup code issued", "expires_at", issued.ExpiresAt.UTC().Format(time.RFC3339))
	s.auditor.Record(ctx, setupCodeEvent(issued.ExpiresAt))
	return issued, nil
}

// requireSetupCode est la seule porte de la première configuration. Un essai
// faux est compté avant de répondre ; le code juste ne s'use pas ici : c'est
// le changement d'état qui l'efface (writeAuthState), pour qu'un mot de passe
// refusé ensuite ne le brûle pas.
func (s *Service) requireSetupCode(ctx context.Context, given string) error {
	given = strings.TrimSpace(given)
	if given == "" {
		return ErrSetupCodeMissing
	}
	// Compter et comparer d'un tenant : des essais en parallèle ne dépassent
	// pas la borne.
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	stored, err := s.store.GetSetupCode(ctx)
	if err != nil {
		return err
	}
	if stored.Hash == "" || !s.now().Before(stored.Expires) || stored.Failures >= MaxSetupCodeFailures {
		return ErrSetupCodeUnusable
	}
	if !hmac.Equal([]byte(ident.HashSecret(given)), []byte(stored.Hash)) {
		if err := s.store.RecordSetupCodeFailure(ctx); err != nil {
			return err
		}
		return ErrSetupCodeWrong
	}
	return nil
}
