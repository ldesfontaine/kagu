package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func setupCodeHandler(status int, body string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+setupCodePath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	return mux
}

func TestAdminSetupCode_PrintsTheCodeTheServerIssued(t *testing.T) {
	configPath, stateDir := writeShortConfig(t)
	serveOnControlSocket(t, stateDir, setupCodeHandler(http.StatusCreated, `{"code":"12345678","expires_at":"2026-11-19T10:30:00Z"}`))

	var out bytes.Buffer
	if err := adminCommand([]string{"setup-code", "-config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"12345678", "30 minutes", "un seul usage", "5 essais"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output lacks %q: %q", want, out.String())
		}
	}
}

func TestAdminSetupCode_SaysWhenTheFirstSetupIsAlreadyDone(t *testing.T) {
	configPath, stateDir := writeShortConfig(t)
	serveOnControlSocket(t, stateDir, setupCodeHandler(http.StatusConflict, `{"error":"auth.already_enabled"}`))

	var out bytes.Buffer
	err := adminCommand([]string{"setup-code", "-config", configPath}, &out)
	if err == nil || !strings.Contains(err.Error(), "déjà faite") {
		t.Fatalf("got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("printed %q", out.String())
	}
}

func TestAdminSetupCode_NeedsTheServer(t *testing.T) {
	configPath, _ := writeShortConfig(t)
	err := adminCommand([]string{"setup-code", "-config", configPath}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "ne tourne pas") {
		t.Fatalf("got %v", err)
	}
}

func TestAdminCommand_RefusesAMissingOrUnknownSubcommand(t *testing.T) {
	for _, args := range [][]string{nil, {"disable"}} {
		if err := adminCommand(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}
