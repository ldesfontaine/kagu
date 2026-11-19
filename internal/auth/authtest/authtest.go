// Package authtest réunit le geste que les tests du serveur et des commandes
// recopiaient : tirer le code de première configuration. Seuls des _test.go
// l'importent.
package authtest

import (
	"context"
	"errors"
	"testing"

	"github.com/ldesfontaine/opencloud/internal/auth"
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
