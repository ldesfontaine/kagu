package agentwire

import (
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
		spec, _ := SpecOf(kind)
		for _, field := range spec.Journal {
			for _, word := range forbidden {
				// public_key est la clé publique de l'agent.server_key : publique.
				if strings.Contains(field, word) && field != "public_key" {
					t.Errorf("%s: field %q looks like a secret or a content", kind, field)
				}
			}
		}
	}
}

func TestJournalValues_KeepsOnlyTheListedPlainFields(t *testing.T) {
	provision, err := Decode(KindResticProvision, encodeSample(t, ResticProvisionParams{
		Target: "abc", Host: "10.0.0.2", Port: 8000, User: "u", Certificate: "-----BEGIN CERTIFICATE-----",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"target": "abc", "host": "10.0.0.2", "port": "8000", "user": "u"}
	if got := provision.JournalValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("values %v, expected %v", got, want)
	}
	ping, err := Decode(KindAgentPing, nil)
	if err != nil || ping.JournalValues() != nil {
		t.Fatalf("a kind with an empty list logs nothing: %v %v", ping.JournalValues(), err)
	}
	long, err := Decode(KindResticRestore, encodeSample(t, ResticRestoreParams{Target: "m", Snapshot: "s", Path: strings.Repeat("a", 300), Stamp: "line\nbreak"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := long.JournalValues(); got["path"] != "" || got["stamp"] != "" {
		t.Fatalf("a long or unprintable value is a content, not an identifier: %v", got)
	}
	if got := (Order{Kind: KindResticProvision}).JournalValues(); got != nil {
		t.Fatalf("an order that was not decoded logs no value: %v", got)
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
