package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// R-DROIT-4 (critère B-6) : un refus de droit porte, dans la réponse, le
// droit, la machine dont l'agent doit le tenir, et la ligne constante que root
// colle sur elle (R-DROIT-8). Un refus qui n'est pas un droit n'en porte pas.
func TestR_DROIT_4_ARightRefusalCarriesItsFix(t *testing.T) {
	server := newTestServer(t)
	id := deploySetup(t, server, "observe")
	got := callAPI(server.Server, http.MethodPost, "/api/directory/services/"+id+"/actions/deploy", map[string]any{})
	var refused apiError
	decodeAPI(t, got, &refused)
	want := fixJSON{Right: "docker.deploy", Machine: remoteID, Command: agentpolicy.PendingLine()}
	if got.Code != http.StatusConflict || refused.Error != "deploy.right_missing" || refused.Fix == nil || *refused.Fix != want {
		t.Fatalf("%d %s, want the fix %+v", got.Code, got.Body.String(), want)
	}

	other := callAPI(server.Server, http.MethodPost, "/api/directory/services/svc_inconnu/actions/deploy", map[string]any{})
	var plain apiError
	decodeAPI(t, other, &plain)
	if plain.Fix != nil {
		t.Fatalf("a refusal that is not a right carries no fix: %s", other.Body.String())
	}
}

// Un ordre que l'agent a refusé faute d'un droit porte le même fix que le
// refus du serveur ; une raison dont le droit est inconnu n'en porte pas.
func TestRunFix_ARefusedRunCarriesThePendingLine(t *testing.T) {
	refused := action.Run{MachineID: "m1", Reason: agentwire.RightMissing("restic.verify")}
	want := fixJSON{Right: "restic.verify", Machine: "m1", Command: agentpolicy.PendingLine()}
	if fix := runFixOf(refused); fix == nil || *fix != want {
		t.Fatalf("fix %+v, want %+v", fix, want)
	}
	anchored := runFixOf(action.Run{MachineID: "m1", Kind: agentwire.KindResticBackup, Reason: "anchor_missing:restic.target-cert"})
	if anchored == nil || anchored.Machine != "m1" || anchored.Right != "" || anchored.Command != "sudo "+brand.Command+" agent trust list" {
		t.Fatalf("anchor fix %+v", anchored)
	}
	for _, reason := range []string{"right_missing:docker.deploy;reboot", "right_missing:", "timeout", ""} {
		if fix := runFixOf(action.Run{MachineID: "m1", Reason: reason}); fix != nil {
			t.Errorf("reason %q: fix %+v, want none", reason, fix)
		}
	}
}

// R-A4-10 : la réponse au jeton porte la même ligne que celle de la
// personne, pour la machine qui manque du droit (ici la cible du dépôt).
func TestR_A4_10_TheTokenAnswerCarriesThePendingLine(t *testing.T) {
	bench := readyResticBench(t)
	backupID := bench.createServiceBackup(t)
	bearer, _ := bench.issueWriteToken(t, "agent-ia", "restic.backup.verify")
	got := callResticVerb(bench, "restic.backup.verify", backupID, bearer)
	var refused apiError
	decodeAPI(t, got, &refused)
	want := fixJSON{Right: "restic.verify", Machine: resticTargetID, Command: agentpolicy.PendingLine()}
	if got.Code != http.StatusConflict || refused.Error != "restic.target_verify_right_missing" || refused.Fix == nil || *refused.Fix != want {
		t.Fatalf("%d %s, want the fix %+v", got.Code, got.Body.String(), want)
	}
}

// R-DROIT-8 (E03-07) : aucune réponse ne donne plus une ligne qui pose un
// droit nommé ; le refus d'un droit, le groupe pas permis de l'onglet Droits et
// la session rendent tous la ligne constante, agentpolicy.PendingLine.
func TestR_A3_15_E03_07_NoAnswerCarriesALineForARight(t *testing.T) {
	server := newTestServer(t)
	id := deploySetup(t, server, "observe")
	answers := map[string]string{
		"refusal": callAPI(server.Server, http.MethodPost, "/api/directory/services/"+id+"/actions/deploy", map[string]any{}).Body.String(),
		"machine": callAPI(server.Server, http.MethodGet, "/api/machines/"+remoteID, nil).Body.String(),
		"session": callAPI(server.Server, http.MethodGet, "/api/session", nil).Body.String(),
	}
	for route, body := range answers {
		if !strings.Contains(body, `"`+agentpolicy.PendingLine()+`"`) {
			t.Errorf("%s: no pending line in %s", route, body)
		}
		for _, right := range agentpolicy.Names() {
			if line := brand.Command + " agent grant " + right; strings.Contains(body, line) {
				t.Errorf("%s carries %q", route, line)
			}
		}
	}
	if fix := runFixOf(action.Run{MachineID: "m1", Reason: agentwire.RightMissing("docker.deploy")}); fix == nil || fix.Command != agentpolicy.PendingLine() {
		t.Errorf("run fix %+v, want the pending line", fix)
	}
}
