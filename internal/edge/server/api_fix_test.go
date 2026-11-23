package server

import (
	"net/http"
	"testing"

	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// R-DROIT-4 (critère B-6) : un refus de droit porte, dans la réponse, le
// droit, la machine dont l'agent doit le tenir, et la ligne grant que root
// colle sur elle. Un refus qui n'est pas un droit n'en porte pas.
func TestR_DROIT_4_ARightRefusalCarriesItsFix(t *testing.T) {
	server := newTestServer(t)
	id := deploySetup(t, server, "observe")
	got := callAPI(server.Server, http.MethodPost, "/api/directory/services/"+id+"/actions/deploy", map[string]any{})
	var refused apiError
	decodeAPI(t, got, &refused)
	want := fixJSON{Right: "docker.deploy", Machine: remoteID, Command: "sudo " + brand.Command + " agent grant docker.deploy"}
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
func TestRunFix_ARefusedRunCarriesTheGrantLine(t *testing.T) {
	refused := action.Run{MachineID: "m1", Reason: agentwire.RightMissing("restic.verify")}
	want := fixJSON{Right: "restic.verify", Machine: "m1", Command: "sudo " + brand.Command + " agent grant restic.verify"}
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

// R-A4-10 : la réponse au jeton porte la même ligne grant que celle de la
// personne, pour la machine qui manque du droit (ici la cible du dépôt).
func TestR_A4_10_TheTokenAnswerCarriesTheGrantLine(t *testing.T) {
	bench := readyResticBench(t)
	backupID := bench.createServiceBackup(t)
	bearer, _ := bench.issueWriteToken(t, "agent-ia", "restic.backup.verify")
	got := callResticVerb(bench, "restic.backup.verify", backupID, bearer)
	var refused apiError
	decodeAPI(t, got, &refused)
	want := fixJSON{Right: "restic.verify", Machine: resticTargetID, Command: "sudo " + brand.Command + " agent grant restic.verify"}
	if got.Code != http.StatusConflict || refused.Error != "restic.target_verify_right_missing" || refused.Fix == nil || *refused.Fix != want {
		t.Fatalf("%d %s, want the fix %+v", got.Code, got.Body.String(), want)
	}
}
