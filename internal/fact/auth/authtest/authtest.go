// Package authtest réunit les gestes que les tests du serveur et des
// commandes recopieraient : tirer le code de première configuration, calculer
// le code à six chiffres d'une application. Seuls des _test.go l'importent.
package authtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

// SetupCode tire le code qui ouvre la première configuration. Hors du mode
// none, aucun code n'existe : il rend le vide, que le service refuse comme il
// refuserait un code absent.
func SetupCode(t testing.TB, service *auth.Service) string {
	t.Helper()
	issued, err := service.IssueSetupCode(context.Background())
	if errors.Is(err, auth.ErrAlreadyEnabled) {
		return ""
	}
	if err != nil {
		t.Fatalf("issue setup code: %v", err)
	}
	return issued.Code
}

// TOTPCode rend le code à six chiffres que donnerait une application pour ce
// secret à cet instant.
func TOTPCode(t testing.TB, secret string, at time.Time) string {
	t.Helper()
	raw, err := auth.DecodeTOTPSecret(secret)
	if err != nil {
		t.Fatalf("decode code secret: %v", err)
	}
	return auth.TOTPCode(raw, auth.TOTPStep(at))
}
