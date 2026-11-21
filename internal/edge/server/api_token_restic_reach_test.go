package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ldesfontaine/opencloud/internal/gesture/apitoken"
	"github.com/ldesfontaine/opencloud/internal/kit/audit"
)

// callResticVerb appelle un verbe restic sous la machine source, avec un
// Bearer.
func callResticVerb(bench *resticBench, verbID, backupID, bearer string) *httptest.ResponseRecorder {
	gesture := strings.TrimPrefix(verbID, "restic.backup.")
	request := httptest.NewRequest(http.MethodPost, "/api/machines/"+resticSourceID+"/restic-backups/"+backupID+"/actions/"+gesture, strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	recorder := httptest.NewRecorder()
	bench.ServeHTTP(recorder, request)
	return recorder
}

// R-A4-11 : verify et browse envoient leur ordre à la cible du dépôt ; la
// portée du jeton les juge sur la source et sur la cible. La cible du banc
// n'a pas le droit : un verbe admis y répond 409 sans rien envoyer, un verbe
// refusé répond 403 avant.
func TestR_A4_11(t *testing.T) {
	bench := readyResticBench(t)
	backupID := bench.createServiceBackup(t)
	target := tapOrders(t, bench.target)

	cases := []struct {
		name     string
		reach    apitoken.Reach
		refused  bool
		deniedOn string
	}{
		{"source only", apitoken.Reach{OnlyMachines: true, Machines: []string{resticSourceID}}, true, resticTargetID},
		{"target only", apitoken.Reach{OnlyMachines: true, Machines: []string{resticTargetID}}, true, resticSourceID},
		{"nobody", apitoken.Reach{OnlyMachines: true}, true, resticSourceID},
		{"source and target", apitoken.Reach{OnlyMachines: true, Machines: []string{resticSourceID, resticTargetID}}, false, ""},
		{"no limit", apitoken.Reach{}, false, ""},
	}
	rightMissing := map[string]string{"restic.backup.verify": "restic.target_verify_right_missing", "restic.backup.browse": "restic.target_browse_right_missing"}
	for _, c := range cases {
		for verbID, missing := range rightMissing {
			t.Run(c.name+" "+verbID, func(t *testing.T) {
				bearer, token := bench.issueWriteToken(t, c.name+verbID, verbID)
				if _, err := bench.apiTokens.SetReach(context.Background(), token.ID, c.reach); err != nil {
					t.Fatal(err)
				}
				before := bench.latestAuditID(t)
				got := callResticVerb(bench, verbID, backupID, bearer)
				if c.refused {
					requireOutOfScope(t, c.name, got)
					denied := 0
					for _, event := range bench.auditSince(t, before) {
						if event.Action == audit.APITokenDeny {
							denied++
							if event.Details["reason"] != "out_of_scope" || event.Details["machine"] != c.deniedOn {
								t.Errorf("details %+v, want machine %s", event.Details, c.deniedOn)
							}
						}
					}
					if denied != 1 {
						t.Errorf("%d deny events, want 1", denied)
					}
				} else if got.Code != http.StatusConflict || errorCode(t, got) != missing {
					t.Errorf("%s: %d %s, want the verb itself to answer %s", c.name, got.Code, got.Body.String(), missing)
				}
				target.none(t, "the target must receive no order")
			})
		}
	}
}

// Une sauvegarde inconnue, ou d'une autre source, ne désigne aucune cible : la
// source seule est jugée, et la route répond 404 comme pour l'opérateur.
func TestR_A4_11_AnUnknownBackupIsJudgedOnTheSourceOnly(t *testing.T) {
	bench := readyResticBench(t)
	bench.createServiceBackup(t)
	bearer, token := bench.issueWriteToken(t, "inconnue", "restic.backup.verify")
	if _, err := bench.apiTokens.SetReach(context.Background(), token.ID, apitoken.Reach{OnlyMachines: true, Machines: []string{resticSourceID}}); err != nil {
		t.Fatal(err)
	}
	got := callResticVerb(bench, "restic.backup.verify", "inconnue", bearer)
	if got.Code != http.StatusNotFound {
		t.Errorf("%d %s, want 404", got.Code, got.Body.String())
	}
}
