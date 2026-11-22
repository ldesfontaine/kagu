package alert_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

func matrixDefinition(homeserver string) alert.ChannelDefinition {
	return alert.ChannelDefinition{
		Name: "salon", URL: homeserver, Format: alert.FormatMatrix, Destination: roomID,
		MinSeverity: alert.SeverityAttention, Enabled: true,
	}
}

// R-A2-14 : le jeton gardé n'est gardé que si le serveur d'accueil (schéma,
// hôte, port) ne change pas.
func TestR_A2_14(t *testing.T) {
	ctx := context.Background()
	for name, changed := range map[string]string{
		"host": "https://autre.exemple.fr",
		"port": "https://matrix.exemple.fr:8448",
	} {
		f := newFixture(t)
		channel := f.matrixChannel(t, "https://matrix.exemple.fr")
		_, err := f.UpdateChannel(ctx, channel.ID, matrixDefinition(changed))
		if !errors.Is(err, alert.ErrChannelSecretRequired) {
			t.Errorf("%s: want secret_required, got %v", name, err)
		}
		if key, _ := refusal.KeyOf(err); key != "channel.secret_required" {
			t.Errorf("%s: key %q", name, key)
		}
		reread, err := f.db.GetChannel(ctx, channel.ID)
		if err != nil || reread.URL != "https://matrix.exemple.fr" || reread.Secret != "syt_bot_token" {
			t.Errorf("%s: the refusal must write nothing: %+v, %v", name, reread, err)
		}
	}

	f := newFixture(t)
	channel := f.matrixChannel(t, "https://matrix.exemple.fr")
	renewed := matrixDefinition("https://autre.exemple.fr")
	renewed.Secret = "syt_new_token"
	if updated, err := f.UpdateChannel(ctx, channel.ID, renewed); err != nil || updated.Secret != "syt_new_token" {
		t.Fatalf("new host with a new token: %+v, %v", updated, err)
	}

	// Même serveur : le nom, la casse de l'hôte, le port écrit ou non ne
	// redemandent rien, le salon non plus.
	f = newFixture(t)
	channel = f.matrixChannel(t, "https://matrix.exemple.fr")
	same := matrixDefinition("https://MATRIX.exemple.fr:443")
	same.Name = "autre nom"
	same.Destination = "!autre:matrix.exemple.fr"
	if updated, err := f.UpdateChannel(ctx, channel.ID, same); err != nil || updated.Secret != "syt_bot_token" {
		t.Fatalf("same homeserver keeps the token: %+v, %v", updated, err)
	}
}

// Un secret de signature de webhook réutilisé comme jeton Matrix partirait
// vers le nouveau serveur : le passage vers Matrix le redemande.
func TestR_A2_14_AWebhookSecretIsNotReusedAsAMatrixToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, err := f.db.InsertChannel(ctx, alert.Channel{
		Name: "salon", URL: "https://matrix.exemple.fr/hook", Format: alert.FormatJSON, Secret: "hmac_key",
		MinSeverity: alert.SeverityAttention, Enabled: true, CreatedAt: f.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.UpdateChannel(ctx, id, matrixDefinition("https://matrix.exemple.fr")); !errors.Is(err, alert.ErrChannelSecretRequired) {
		t.Fatalf("got %v", err)
	}
}

// R-SEC-7 : le refus et le journal ne montrent ni le jeton ni l'adresse ;
// le journal dit l'ancien et le nouvel hôte.
func TestR_SEC_7(t *testing.T) {
	f := newFixture(t)
	f.SetAuditor(audit.New(f.db, slog.New(slog.NewTextHandler(os.Stderr, nil))))
	ctx := audit.WithActor(context.Background(), audit.Operator("lucas"))
	channel := f.matrixChannel(t, "https://matrix.exemple.fr")
	_, err := f.UpdateChannel(ctx, channel.ID, matrixDefinition("https://autre.exemple.fr"))
	if err == nil || strings.Contains(err.Error(), "syt_bot_token") {
		t.Fatalf("refusal: %v", err)
	}
	renewed := matrixDefinition("https://autre.exemple.fr/path")
	renewed.Secret = "syt_new_token"
	if _, err := f.UpdateChannel(ctx, channel.ID, renewed); err != nil {
		t.Fatal(err)
	}
	events, err := f.db.ListAuditEvents(context.Background(), audit.Query{Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("only the accepted change is journaled: %+v, %v", events, err)
	}
	details := events[0].Details
	if details["previous_host"] != "matrix.exemple.fr" || details["host"] != "autre.exemple.fr" {
		t.Errorf("hosts: %+v", details)
	}
	for name, value := range details {
		if strings.Contains(value, "syt_") || strings.Contains(value, "path") || name == "url" || name == "secret" {
			t.Errorf("leaks %s=%s", name, value)
		}
	}
}
