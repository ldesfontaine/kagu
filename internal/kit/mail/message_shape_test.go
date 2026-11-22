package mail_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/ldesfontaine/opencloud/internal/kit/mail"
)

// La forme de l'identifiant du message (32 hexadécimaux) et de la frontière
// MIME (24) est celle d'avant le passage par ident.
func TestCompose_RandomPartsKeepTheirShape(t *testing.T) {
	raw, err := mail.Compose("alertes@exemple.fr", mail.Message{
		To: []string{"lucas@exemple.fr"}, Subject: "s", Text: "t", HTML: "<p>t</p>",
	}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^Message-ID: <[0-9a-f]{32}@exemple\.fr>\r$`).Match(raw) {
		t.Fatalf("message id: %s", raw)
	}
	if !regexp.MustCompile(`boundary="[0-9a-f]{24}"`).Match(raw) {
		t.Fatalf("boundary: %s", raw)
	}
}
