package agentwire

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/anchor"
)

// Un champ qui peut porter un secret ou un contenu n'entre jamais dans une
// liste blanche, quel que soit le genre.
func TestJournalFields_NeverNameASecretOrAContent(t *testing.T) {
	forbidden := []string{"secret", "password", "passphrase", "token", "private", "env", "compose", "certificate", "files", "key"}
	for _, kind := range OrderKinds() {
		fields, _ := JournalFields(kind)
		for _, field := range fields {
			for _, word := range forbidden {
				// public_key est la clé publique de l'agent.server_key : publique.
				if strings.Contains(field, word) && field != "public_key" {
					t.Errorf("%s: field %q looks like a secret or a content", kind, field)
				}
			}
		}
	}
}

func TestJournalParams_KeepsOnlyTheListedPlainFields(t *testing.T) {
	params := json.RawMessage(`{"target":"abc","host":"10.0.0.2","port":8000,"user":"u","certificate":"-----BEGIN CERTIFICATE-----","rest_password":"hunter2","extra":{"a":1}}`)
	got := JournalParams(KindResticProvision, params)
	want := map[string]string{"target": "abc", "host": "10.0.0.2", "port": "8000", "user": "u"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("params %v, expected %v", got, want)
	}
	if got := JournalParams(KindAgentPing, params); got != nil {
		t.Fatalf("a kind with an empty list logs nothing: %v", got)
	}
	long := json.RawMessage(`{"path":"` + strings.Repeat("a", 300) + `","stamp":"line\nbreak"}`)
	if got := JournalParams(KindResticRestore, long); len(got) != 0 {
		t.Fatalf("a long or unprintable value is a content, not an identifier: %v", got)
	}
	if got := JournalParams(KindResticProvision, json.RawMessage(`not json`)); got != nil {
		t.Fatalf("unreadable parameters: %v", got)
	}
}

func TestAnchorRefusal_NamesTheKindAndIsAReportedReason(t *testing.T) {
	for _, kind := range anchor.Kinds() {
		for _, why := range []anchor.Why{anchor.WhyMissing, anchor.WhyUnreadable, anchor.WhyOutside} {
			reason := AnchorRefusal(anchor.Finding{Kind: kind, Why: why})
			if !strings.HasSuffix(reason, ":"+kind.Name) || !IsReportedReason(reason) {
				t.Errorf("%s %s: %q", kind.Name, why, reason)
			}
		}
	}
	for _, reason := range []string{"anchor_missing:nothing", "right_missing:nothing", "anchor_missing:"} {
		if IsReportedReason(reason) {
			t.Errorf("%q must not be a reported reason", reason)
		}
	}
	if !IsReportedReason(RightMissing("backup.produce")) || !IsReportedReason(ReasonBusy) {
		t.Error("plain and right reasons stay reported")
	}
}
