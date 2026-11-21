package settings_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/opencloud/internal/domain/alert"
	"github.com/ldesfontaine/opencloud/internal/domain/settings"
	"github.com/ldesfontaine/opencloud/internal/edge/store"
	"github.com/ldesfontaine/opencloud/internal/edge/store/storetest"
	"github.com/ldesfontaine/opencloud/internal/kit/audit"
	"github.com/ldesfontaine/opencloud/internal/kit/lang"
	"github.com/ldesfontaine/opencloud/internal/kit/mail"
	"github.com/ldesfontaine/opencloud/internal/kit/refusal"
)

func newService(t *testing.T) (*settings.Service, *store.DB) {
	t.Helper()
	db := storetest.Open(t)
	return settings.New(db, slog.New(slog.NewTextHandler(io.Discard, nil))), db
}

func load(t *testing.T, db *store.DB) settings.Settings {
	t.Helper()
	current, err := db.LoadSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func TestSetMailRelay_NoPort_FollowsTheTLSMode(t *testing.T) {
	service, _ := newService(t)
	ctx := context.Background()
	for mode, want := range map[mail.TLSMode]int{mail.TLSImplicit: 465, mail.TLSStartTLS: 587, mail.TLSNone: 587} {
		relay, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: mail.Relay{
			Host: " 10.0.0.25 ", TLS: mode, From: " oc@example.org ",
		}})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if relay.Port != want || relay.Host != "10.0.0.25" || relay.From != "oc@example.org" {
			t.Fatalf("%s: got %+v", mode, relay)
		}
	}
}

// Le mot de passe gardé est celui de la base au moment d'écrire, pas celui
// lu plus tôt : un autre processus a pu le changer entre-temps.
func TestSetMailRelay_EmptyPassword_KeepsTheOneInTheDatabase(t *testing.T) {
	service, db := newService(t)
	ctx := context.Background()
	typed := mail.Relay{Host: "smtp.example.org", Port: 587, TLS: mail.TLSStartTLS, Username: "alerts", Password: "s3cret", From: "oc@example.org"}
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateSettings(ctx, func(current *settings.Settings) { current.MailPassword = "rotated-elsewhere" }); err != nil {
		t.Fatal(err)
	}
	typed.Password = ""
	relay, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed})
	if err != nil || relay.Password != "rotated-elsewhere" {
		t.Fatalf("kept: %+v, %v", relay, err)
	}
	if relay, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed, ClearPassword: true}); err != nil || relay.Password != "" {
		t.Fatalf("cleared: %+v, %v", relay, err)
	}
	if saved := load(t, db); saved.MailPassword != "" || saved.MailHost != "smtp.example.org" {
		t.Fatalf("saved: %+v", saved)
	}
}

func TestSetMailRelay_Invalid_IsRefusedAndWritesNothing(t *testing.T) {
	service, db := newService(t)
	_, err := service.SetMailRelay(context.Background(), settings.MailRelayChange{Relay: mail.Relay{Host: "smtp.example.org", Port: 70000, TLS: mail.TLSStartTLS}})
	if !errors.Is(err, mail.ErrPortInvalid) {
		t.Fatalf("got %v", err)
	}
	if key, ok := refusal.KeyOf(err); !ok || key != "settings.mail_port_invalid" {
		t.Fatalf("key %q %v", key, ok)
	}
	if saved := load(t, db); saved != settings.Defaults() {
		t.Fatalf("saved: %+v", saved)
	}
}

// Une saisie refusée laisse le relais en place tel quel, mot de passe
// compris.
func TestSetMailRelay_InvalidOverAnExistingRelay_LeavesTheRowAsItWas(t *testing.T) {
	service, db := newService(t)
	ctx := context.Background()
	typed := mail.Relay{Host: "smtp.example.org", TLS: mail.TLSStartTLS, Username: "alerts", Password: "s3cret", From: "oc@example.org"}
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed}); err != nil {
		t.Fatal(err)
	}
	before := load(t, db)
	_, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: mail.Relay{Host: "smtp.example.org", TLS: "ssl", From: "oc@example.org"}, ClearPassword: true})
	if !errors.Is(err, mail.ErrTLSModeInvalid) {
		t.Fatalf("got %v", err)
	}
	if after := load(t, db); after != before {
		t.Fatalf("got %+v, want %+v", after, before)
	}
}

// Un hôte vide retire le relais sans rien valider : tout s'efface, le mot
// de passe compris.
func TestSetMailRelay_NoHost_ClearsEverything(t *testing.T) {
	service, db := newService(t)
	ctx := context.Background()
	typed := mail.Relay{Host: "smtp.example.org", TLS: mail.TLSStartTLS, Password: "s3cret", From: "oc@example.org"}
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed}); err != nil {
		t.Fatal(err)
	}
	relay, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: mail.Relay{Host: "  ", Port: 70000}})
	if err != nil || relay.Configured() {
		t.Fatalf("got %+v, %v", relay, err)
	}
	if saved := load(t, db); saved.MailHost != "" || saved.MailPassword != "" || saved.MailFrom != "" || saved.MailPort != 0 {
		t.Fatalf("saved: %+v", saved)
	}
}

func TestSetLifecycleEnabled_TellsWhenItIsTurnedOn(t *testing.T) {
	service, _ := newService(t)
	ctx := context.Background()
	steps := []struct {
		enabled, isTurnedOn bool
	}{
		// Une installation neuve l'a déjà : rien n'est rallumé.
		{enabled: true, isTurnedOn: false},
		{enabled: false, isTurnedOn: false},
		{enabled: false, isTurnedOn: false},
		{enabled: true, isTurnedOn: true},
		{enabled: true, isTurnedOn: false},
	}
	for index, step := range steps {
		isTurnedOn, err := service.SetLifecycleEnabled(ctx, step.enabled)
		if err != nil || isTurnedOn != step.isTurnedOn {
			t.Fatalf("step %d: turned on %v, %v", index, isTurnedOn, err)
		}
		enabled, err := service.LifecycleEnabled(ctx)
		if err != nil || enabled != step.enabled {
			t.Fatalf("step %d: enabled %v, %v", index, enabled, err)
		}
	}
}

func TestSetLanguage_UnknownCode_IsRefused(t *testing.T) {
	service, db := newService(t)
	ctx := context.Background()
	err := service.SetLanguage(ctx, "de")
	if !errors.Is(err, settings.ErrLanguageUnknown) {
		t.Fatalf("got %v", err)
	}
	if key, ok := refusal.KeyOf(err); !ok || key != "error.unknown_language" {
		t.Fatalf("key %q %v", key, ok)
	}
	if saved := load(t, db); saved != settings.Defaults() {
		t.Fatalf("saved: %+v", saved)
	}
}

func TestLanguage_NothingChosen_IsTheDefault_ThenTheChoice(t *testing.T) {
	service, _ := newService(t)
	ctx := context.Background()
	if code, err := service.Language(ctx); err != nil || code != lang.Default {
		t.Fatalf("default: %q, %v", code, err)
	}
	if err := service.SetLanguage(ctx, lang.English); err != nil {
		t.Fatal(err)
	}
	if code, err := service.Language(ctx); err != nil || code != lang.English {
		t.Fatalf("chosen: %q, %v", code, err)
	}
	if code := service.CurrentLanguage(); code != lang.English {
		t.Fatalf("current: %q", code)
	}
}

func TestSetDangerReminderHours_OutOfBounds_IsRefused_AndTheDefaultStays(t *testing.T) {
	service, _ := newService(t)
	ctx := context.Background()
	for _, hours := range []int{-1, alert.MaxReminderHours + 1} {
		if err := service.SetDangerReminderHours(ctx, hours); !errors.Is(err, settings.ErrReminderInvalid) {
			t.Fatalf("%d h: %v", hours, err)
		}
	}
	if hours, err := service.DangerReminderHours(ctx); err != nil || hours != alert.DefaultReminderHours {
		t.Fatalf("default: %d, %v", hours, err)
	}
	if err := service.SetDangerReminderHours(ctx, 6); err != nil {
		t.Fatal(err)
	}
	if delay := service.CurrentDangerReminder(); delay != 6*time.Hour {
		t.Fatalf("set: %v", delay)
	}
	// Zéro coupe le rappel : ce n'est pas « rien de réglé ».
	if err := service.SetDangerReminderHours(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if delay := service.CurrentDangerReminder(); delay != 0 {
		t.Fatalf("turned off: %v", delay)
	}
}

// Chaque geste ne touche que ses clés : la langue, les seuils, le relais et
// la fin de support écrits l'un après l'autre survivent tous.
func TestGestures_KeepTheOtherKeys(t *testing.T) {
	service, db := newService(t)
	ctx := context.Background()
	if err := service.SetLanguage(ctx, lang.English); err != nil {
		t.Fatal(err)
	}
	if err := service.SetDangerReminderHours(ctx, 24); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: mail.Relay{Host: "smtp.example.org", TLS: mail.TLSStartTLS, From: "oc@example.org"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetLifecycleEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	want := settings.Settings{
		Language:            lang.English,
		DangerReminderHours: 24,
		MailHost:            "smtp.example.org", MailPort: 587, MailTLS: "starttls", MailFrom: "oc@example.org",
		LifecycleDisabled: true,
	}
	if saved := load(t, db); saved != want {
		t.Fatalf("got %+v, want %+v", saved, want)
	}
}

// Une base qui ne répond pas : les lectures au moment de servir rendent
// leur valeur de repli.
type failingStore struct{}

var errDatabaseDown = errors.New("database down")

func (failingStore) LoadSettings(context.Context) (settings.Settings, error) {
	return settings.Settings{}, errDatabaseDown
}

func (failingStore) UpdateSettings(context.Context, func(*settings.Settings)) (settings.Settings, error) {
	return settings.Settings{}, errDatabaseDown
}

func TestCurrentReads_DatabaseDown_FallBack(t *testing.T) {
	service := settings.New(failingStore{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if code := service.CurrentLanguage(); code != lang.Default {
		t.Errorf("language: %q", code)
	}
	if relay := service.CurrentMailRelay(); relay != (mail.Relay{}) {
		t.Errorf("relay: %+v", relay)
	}
	if delay := service.CurrentDangerReminder(); delay != alert.DefaultReminderHours*time.Hour {
		t.Errorf("reminder: %v", delay)
	}
	if service.CurrentLifecycleEnabled() {
		t.Error("lifecycle must be off when the setting cannot be read")
	}
}

// R-A2-14 : le mot de passe gardé n'est gardé que si l'hôte, le port et le
// mode TLS ne changent pas ; l'expéditeur et l'identifiant n'y changent rien.
func TestR_A2_14(t *testing.T) {
	ctx := context.Background()
	original := mail.Relay{Host: "smtp.example.org", Port: 587, TLS: mail.TLSStartTLS, Username: "alerts", Password: "s3cret", From: "oc@example.org"}
	for name, change := range map[string]func(*mail.Relay){
		"host": func(r *mail.Relay) { r.Host = "smtp.other.org" },
		"port": func(r *mail.Relay) { r.Port = 2525 },
		"tls":  func(r *mail.Relay) { r.TLS = mail.TLSImplicit; r.Port = 587 },
	} {
		service, db := newService(t)
		if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: original}); err != nil {
			t.Fatal(err)
		}
		typed := original
		typed.Password = ""
		change(&typed)
		_, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed})
		if !errors.Is(err, settings.ErrMailPasswordRequired) {
			t.Errorf("%s: want password_required, got %v", name, err)
		}
		if saved := load(t, db); saved.MailHost != original.Host || saved.MailPort != original.Port || saved.MailPassword != "s3cret" {
			t.Errorf("%s: the refusal must write nothing: %+v", name, saved)
		}
	}

	service, db := newService(t)
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: original}); err != nil {
		t.Fatal(err)
	}
	typed := original
	typed.Password = ""
	typed.From = "other@example.org"
	typed.Username = "someone"
	typed.Host = "SMTP.example.org"
	if relay, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: typed}); err != nil || relay.Password != "s3cret" || relay.From != "other@example.org" {
		t.Fatalf("sender change keeps the password: %+v, %v", relay, err)
	}
	moved := original
	moved.Host = "smtp.other.org"
	moved.Password = "new-secret"
	if relay, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: moved}); err != nil || relay.Password != "new-secret" {
		t.Fatalf("new host with a new password: %+v, %v", relay, err)
	}
	moved.Password = ""
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: mail.Relay{}}); err != nil {
		t.Fatalf("removing the relay needs no password: %v", err)
	}
	if saved := load(t, db); saved.MailHost != "" || saved.MailPassword != "" {
		t.Fatalf("saved: %+v", saved)
	}
	// Premier réglage : rien n'est gardé, rien n'est redemandé.
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: moved}); err != nil {
		t.Fatalf("first setup without password: %v", err)
	}
}

// R-SEC-7 : le refus ne montre pas le mot de passe, le journal dit l'ancien
// et le nouvel hôte sans lui.
func TestR_SEC_7(t *testing.T) {
	service, db := newService(t)
	service.SetAuditor(audit.New(db, slog.New(slog.NewTextHandler(io.Discard, nil))))
	ctx := context.Background()
	original := mail.Relay{Host: "smtp.example.org", Port: 587, TLS: mail.TLSStartTLS, Password: "s3cret", From: "oc@example.org"}
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: original}); err != nil {
		t.Fatal(err)
	}
	moved := original
	moved.Host, moved.Password = "smtp.other.org", ""
	_, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: moved})
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("refusal: %v", err)
	}
	moved.Password = "new-secret"
	if _, err := service.SetMailRelay(ctx, settings.MailRelayChange{Relay: moved}); err != nil {
		t.Fatal(err)
	}
	events, err := db.ListAuditEvents(ctx, audit.Query{Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %+v, %v", events, err)
	}
	details := events[0].Details
	if details["previous_host"] != "smtp.example.org" || details["host"] != "smtp.other.org" {
		t.Errorf("hosts: %+v", details)
	}
	for name, value := range details {
		if strings.Contains(value, "s3cret") || strings.Contains(value, "new-secret") {
			t.Errorf("leaks %s=%s", name, value)
		}
	}
}
