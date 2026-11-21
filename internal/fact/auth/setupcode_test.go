package auth

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestIssueSetupCode_GivesEightDigitsAndKeepsOnlyTheirHash(t *testing.T) {
	service, store := newTestService(t)
	issued, err := service.IssueSetupCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9]{8}$`).MatchString(issued.Code) {
		t.Fatalf("code %q", issued.Code)
	}
	if store.code.Hash == "" || strings.Contains(store.code.Hash, issued.Code) {
		t.Fatalf("stored %q for the code %q", store.code.Hash, issued.Code)
	}
	if got := store.code.Expires.Sub(issued.ExpiresAt); got != 0 || time.Until(issued.ExpiresAt) > SetupCodeLifetime {
		t.Fatalf("expiry %v, stored %v", issued.ExpiresAt, store.code.Expires)
	}
}

func TestIssueSetupCode_RefusedOnceAnAccountExists(t *testing.T) {
	service, _ := newTestService(t)
	if _, err := service.EnableBasic(context.Background(), none, issueCode(t, service), "lucas", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueSetupCode(context.Background()); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("got %v", err)
	}
}

func TestEnable_RefusesEveryWrongOrMissingCodeAndCreatesNothing(t *testing.T) {
	ctx := context.Background()
	for name, enable := range map[string]func(*Service, string) error{
		"basic": func(service *Service, code string) error {
			_, err := service.EnableBasic(ctx, none, code, "lucas", "correct horse battery")
			return err
		},
		"forward": func(service *Service, code string) error {
			_, err := service.EnableForward(ctx, none, code, DefaultForwardHeader)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, store := newTestService(t)
			if err := enable(service, "12345678"); !errors.Is(err, ErrSetupCodeUnusable) {
				t.Fatalf("no code issued: %v", err)
			}
			issued := issueCodeIssued(t, service)
			if err := enable(service, ""); !errors.Is(err, ErrSetupCodeMissing) {
				t.Fatalf("empty: %v", err)
			}
			if err := enable(service, wrongCode(issued.Code)); !errors.Is(err, ErrSetupCodeWrong) {
				t.Fatalf("wrong: %v", err)
			}
			if store.state.Mode != "" && store.state.Mode != ModeNone {
				t.Fatalf("an account was created: %+v", store.state)
			}
			if err := enable(service, " "+issued.Code+"\n"); err != nil {
				t.Fatalf("the right code, with blanks around it: %v", err)
			}
		})
	}
}

func TestEnable_TheFifthWrongTryBurnsTheRightCodeToo(t *testing.T) {
	service, store := newTestService(t)
	issued := issueCodeIssued(t, service)
	for try := 1; try <= MaxSetupCodeFailures; try++ {
		_, err := service.EnableBasic(context.Background(), none, wrongCode(issued.Code), "lucas", "correct horse battery")
		if !errors.Is(err, ErrSetupCodeWrong) {
			t.Fatalf("try %d: %v", try, err)
		}
	}
	if _, err := service.EnableBasic(context.Background(), none, issued.Code, "lucas", "correct horse battery"); !errors.Is(err, ErrSetupCodeUnusable) {
		t.Fatalf("the right code after five failures: %v", err)
	}
	if store.state.Mode == ModeBasic {
		t.Fatal("an account was created with a burnt code")
	}
}

func TestEnable_AnExpiredCodeIsRefusedFromItsExpiryInstant(t *testing.T) {
	service, _ := newTestService(t)
	start := time.Unix(1_800_000_000, 0)
	now := start
	service.SetClock(func() time.Time { return now })
	issued := issueCodeIssued(t, service)
	now = start.Add(SetupCodeLifetime)
	if _, err := service.EnableBasic(context.Background(), none, issued.Code, "lucas", "correct horse battery"); !errors.Is(err, ErrSetupCodeUnusable) {
		t.Fatalf("got %v", err)
	}
}

func issueCodeIssued(t *testing.T, service *Service) IssuedSetupCode {
	t.Helper()
	issued, err := service.IssueSetupCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func wrongCode(code string) string {
	if code == "00000000" {
		return "00000001"
	}
	return "00000000"
}
