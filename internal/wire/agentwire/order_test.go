package agentwire

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// L'enveloppe v2 se lit comme les paramètres : toute variante de clé, une
// version, un acteur ou un niveau absents, ou le corps v1, ne se lisent pas.
func TestR_A1_4_TheV2EnvelopeIsReadStrictly(t *testing.T) {
	body := OrderBody{
		V: OrderVersion, RunID: "run-1", MachineID: "m", AgentID: "a", Kind: KindAgentPing,
		NotAfter: 1, Seq: 2, Actor: "operator:lucas", Level: 1,
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var read OrderBody
	if err := StrictDecode(canonical, &read); err != nil || !reflect.DeepEqual(read, body) {
		t.Fatalf("the canonical body: %+v %v", read, err)
	}
	legacy, err := json.Marshal(OrderBodyV1{RunID: "run-1", MachineID: "m", AgentID: "a", Kind: KindAgentUpdate, NotAfter: 1, Seq: 2})
	if err != nil {
		t.Fatal(err)
	}
	variants := keyVariants(t, canonical)
	variants["the v1 body"] = legacy
	for _, missing := range []string{"v", "actor", "level"} {
		variants["without "+missing] = writeFields(withoutField(t, canonical, missing))
	}
	for name, variant := range variants {
		var into OrderBody
		if err := StrictDecode(variant, &into); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%s: %s passes: %v", name, variant, err)
		}
	}
}

// withoutField rend les champs d'un corps sans celui nommé.
func withoutField(t *testing.T, canonical json.RawMessage, name string) []field {
	t.Helper()
	var kept []field
	for _, each := range topLevelFields(t, canonical) {
		if each.name != name {
			kept = append(kept, each)
		}
	}
	return kept
}

// Une signature ne vaut que pour la version de son étiquette.
func TestOrderSigningBytes_TheLabelFollowsTheVersion(t *testing.T) {
	body := []byte(`{}`)
	current := string(OrderSigningBytes(OrderVersion, body))
	legacy := string(OrderSigningBytes(LegacyOrderVersion, body))
	if current != brand.OrderSignatureDomain+"{}" || legacy != brand.LegacyOrderSignatureDomain+"{}" {
		t.Fatalf("v2 %q, v1 %q", current, legacy)
	}
}
