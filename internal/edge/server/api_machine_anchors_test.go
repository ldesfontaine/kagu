package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/domain/restic"
	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Les ancres que l'agent dit à l'ouverture de son flux sont gardées et rendues
// par la fiche de la machine, avec trois états distincts par type : posées,
// aucune posée, illisibles ; et un quatrième pour l'agent qui n'en dit rien.
func TestMachine_SaysTheAnchorsItsAgentReports(t *testing.T) {
	server := newTestServer(t)
	enrolled, private := server.enroll(t, "pve", remoteID)

	anchorsOf := func() anchorsJSON {
		recorder := callAPI(server.Server, http.MethodGet, "/api/machines", nil)
		var response struct {
			Machines []struct {
				ID    string `json:"id"`
				Agent *struct {
					Anchors anchorsJSON `json:"anchors"`
				} `json:"agent"`
			} `json:"machines"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		for _, found := range response.Machines {
			if found.ID == enrolled.ID && found.Agent != nil {
				return found.Agent.Anchors
			}
		}
		t.Fatal("machine not listed")
		return anchorsJSON{}
	}
	stateOf := func(anchors anchorsJSON, name string) string {
		for _, kind := range anchors.Kinds {
			if kind.Name == name {
				return kind.State
			}
		}
		return ""
	}

	// Un agent qui n'a rien dit (v0.6.0) : non rapportées, le serveur ne juge rien.
	silent := anchorsOf()
	if silent.Reported || len(silent.Kinds) != len(anchor.Names()) {
		t.Fatalf("silent agent: %+v", silent)
	}

	resp, _, _, cancel := servertest.OpenStreamWithAnchors(t, server.Server, enrolled.ID, private, "backup.guest=101:102,restic.target-cert=!")
	reported := anchorsOf()
	cancel()
	resp.Body.Close()
	if !reported.Reported || stateOf(reported, "backup.guest") != "set" || stateOf(reported, "restic.target-cert") != "unreadable" || stateOf(reported, "backup.recipient") != "none" {
		t.Fatalf("reported: %+v", reported)
	}
	var guests []string
	for _, kind := range reported.Kinds {
		if kind.Name == "backup.guest" {
			guests = kind.Values
		}
	}
	if !slices.Equal(guests, []string{"101", "102"}) {
		t.Fatalf("guests %v", guests)
	}

	// Un texte qui ne se lit pas est ignoré en entier : l'état redevient « non rapporté ».
	resp, _, _, cancel = servertest.OpenStreamWithAnchors(t, server.Server, enrolled.ID, private, "backup.guest=0101")
	garbled := anchorsOf()
	cancel()
	resp.Body.Close()
	if garbled.Reported {
		t.Fatalf("garbled header: %+v", garbled)
	}

	resp, _, _, cancel = servertest.OpenStreamWithAnchors(t, server.Server, enrolled.ID, private, "none")
	none := anchorsOf()
	cancel()
	resp.Body.Close()
	if !none.Reported || stateOf(none, "backup.guest") != "none" {
		t.Fatalf("none: %+v", none)
	}
}

// Une protection dont la dernière passe est refusée par une ancre porte la
// commande à lancer : exacte pour une VM d'un plan par archives (sa VM, la clé
// du trousseau), « trust list » sinon (restic : la valeur n'est pas connue).
func TestProtectionFix_ExactForAnArchivePlanListOtherwise(t *testing.T) {
	const recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	archive := restic.Protection{Origin: restic.OriginArchive, Reason: "anchor_missing:backup.guest"}
	fix := protectionFix(archive, restic.Source{VMID: 312}, recipient)
	if fix == nil || !fix.Exact || !strings.HasSuffix(fix.Command, " agent trust add backup.guest 312") {
		t.Fatalf("%+v", fix)
	}
	archive.Reason = "anchor_outside:backup.recipient"
	if fix = protectionFix(archive, restic.Source{VMID: 312}, recipient); fix == nil || !fix.Exact || !strings.HasSuffix(fix.Command, " agent trust add backup.recipient "+recipient) {
		t.Fatalf("%+v", fix)
	}
	if fix = protectionFix(archive, restic.Source{VMID: 312}, ""); fix == nil || fix.Exact || !strings.HasSuffix(fix.Command, " agent trust list") {
		t.Fatalf("no keyring: %+v", fix)
	}
	resticOrigin := restic.Protection{Origin: restic.OriginRestic, Reason: "anchor_missing:restic.target-cert"}
	if fix = protectionFix(resticOrigin, restic.Source{VMID: 312}, recipient); fix == nil || fix.Exact || !strings.HasSuffix(fix.Command, " agent trust list") {
		t.Fatalf("restic: %+v", fix)
	}
	missing := restic.Protection{Origin: restic.OriginRestic, Reason: "restic.source_right_missing", Fix: &refusal.Fix{Right: "restic.produce", Machine: "m-src"}}
	if fix = protectionFix(missing, restic.Source{MachineID: "m-src"}, recipient); fix == nil || fix.Right != "restic.produce" || fix.Machine != "m-src" || fix.Command != agentpolicy.PendingLine() {
		t.Fatalf("right: %+v", fix)
	}
	if fix = protectionFix(restic.Protection{Reason: "timeout"}, restic.Source{}, recipient); fix != nil {
		t.Fatalf("another reason has no fix: %+v", fix)
	}
}
