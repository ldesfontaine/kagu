package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
)

// E01-11 : la fiche lit le refus gardé en base (un nom d'hôte que la 050 a
// rejugé) avec celui d'une version dite au flux, sans en rendre les octets.
func TestE01_11_TheMachinePageShowsTheRefusalNotTheValue(t *testing.T) {
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	if err := server.db.NoteReportRefusal(context.Background(), remoteID, machine.ReportFieldHostname, true); err != nil {
		t.Fatal(err)
	}
	current, err := server.machines.Get(context.Background(), remoteID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.machines.Connect(context.Background(), current.Machine, "192.0.2.1", "v1\x1b[2J", "", "", "", ""); err != nil {
		t.Fatal(err)
	}

	recorder := callAPI(server.Server, http.MethodGet, "/api/machines/"+remoteID, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var page struct {
		ReportRejected []string `json:"report_rejected"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(page.ReportRejected, []string{machine.ReportFieldHostname, machine.ReportFieldVersion}) {
		t.Fatalf("report_rejected %v", page.ReportRejected)
	}
	if strings.Contains(recorder.Body.String(), `\u001b[2J`) {
		t.Fatalf("la fiche rend la version refusée : %s", recorder.Body.String())
	}
}
