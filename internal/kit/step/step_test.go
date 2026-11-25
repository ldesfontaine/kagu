package step

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/goldentest"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
)

func loadCatalogs(t *testing.T) lang.Catalogs {
	t.Helper()
	catalogs, err := lang.Load()
	if err != nil {
		t.Fatal(err)
	}
	return catalogs
}

// missingLabels rend les clés que le catalogue ne connaît pas.
func missingLabels(catalog lang.Catalog, keys []Key) []Key {
	known := catalog.Keys()
	var missing []Key
	for _, key := range keys {
		if !slices.Contains(known, string(key)) {
			missing = append(missing, key)
		}
	}
	return missing
}

func TestStep_EveryDefinedKeyHasALabel(t *testing.T) {
	if len(defined) == 0 {
		t.Fatal("no step key defined: the guard sees nothing")
	}
	for code, catalog := range loadCatalogs(t) {
		if missing := missingLabels(catalog, defined); len(missing) > 0 {
			t.Errorf("%s.toml has no label for %v", code, missing)
		}
	}
}

func TestStep_AKeyWithoutALabelIsCaught(t *testing.T) {
	french := loadCatalogs(t).For(lang.French)
	missing := missingLabels(french, []Key{EnrollDocker, "step.nowhere"})
	if !slices.Equal(missing, []Key{"step.nowhere"}) {
		t.Fatalf("missing %v", missing)
	}
}

// R-GESTE-4 : le terminal (Print) et l'écran (StepTrail, qui lit
// /api/i18n) montrent le même libellé pour la même clé. labels.golden.json
// est ce catalogue pour les clés déclarées ; StepTrail.test.tsx le relit.
func TestR_GESTE_4_TerminalAndScreenShowTheSameLabel(t *testing.T) {
	catalogs := loadCatalogs(t)
	labels := map[lang.Code]map[Key]string{}
	for _, code := range lang.Codes() {
		catalog := catalogs.For(code)
		labels[code] = map[Key]string{}
		for _, key := range defined {
			label := catalog.Get(string(key))
			labels[code][key] = label
			var printed bytes.Buffer
			Print(&printed, catalog, Step{Key: key, State: StateDone, Detail: "27.3.1", At: time.Now()})
			if want := "  ✓ " + label; !strings.HasPrefix(printed.String(), want) {
				t.Errorf("%s %s: printed %q, want the screen label %q", code, key, printed.String(), label)
			}
		}
	}
	encoded, err := json.MarshalIndent(labels, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	goldentest.Compare(t, "testdata/labels.golden.json", string(encoded)+"\n")
}

func TestPrint_WritesTheMarkTheLabelAndTheDetail(t *testing.T) {
	french := loadCatalogs(t).For(lang.French)
	at := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		step Step
		want string
	}{
		{Step{Key: EnrollDocker, State: StateDone, Detail: "27.3.1", At: at}, "  ✓ Docker installé               27.3.1\n"},
		{Step{Key: EnrollRestic, State: StateSkipped, At: at}, "  – restic installé\n"},
		{Step{Key: EnrollSystem, State: StateFailed, Detail: "1 Gio libre", At: at}, "  ✗ Système reconnu               1 Gio libre\n"},
		{Step{Key: EnrollUnit, State: StateRunning, At: at}, "  … Agent démarré\n"},
	} {
		var printed bytes.Buffer
		Print(&printed, french, test.step)
		if printed.String() != test.want {
			t.Errorf("printed %q, want %q", printed.String(), test.want)
		}
	}
}

func TestDefine_RefusesAMalformedOrRepeatedKey(t *testing.T) {
	for _, key := range []string{"step.enroll.docker", "enroll.docker", "step.", "step.Docker", "step.a b", "step." + strings.Repeat("a", 64)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Define(%q) did not stop", key)
				}
			}()
			Define(key)
		}()
	}
}

func TestClean_StripsTheDetailAndRefusesWhatIsOutOfShape(t *testing.T) {
	at := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	cleaned, ok := Clean(Step{Key: EnrollDocker, State: StateDone, Detail: "27.3.1\x1b[31m\u202e", At: at})
	if !ok || cleaned.Detail != "27.3.1\ufffd[31m\ufffd" {
		t.Fatalf("cleaned %+v %v", cleaned, ok)
	}
	if _, ok := Clean(Step{Key: EnrollDocker, State: StateDone, Detail: strings.Repeat("é", MaxDetailRunes), At: at}); !ok {
		t.Fatal("a detail at the bound was refused")
	}
	for name, reported := range map[string]Step{
		"malformed key":   {Key: "docker", State: StateDone, At: at},
		"unknown state":   {Key: EnrollDocker, State: "queued", At: at},
		"no time":         {Key: EnrollDocker, State: StateDone},
		"detail too long": {Key: EnrollDocker, State: StateDone, Detail: strings.Repeat("é", MaxDetailRunes+1), At: at},
	} {
		if _, ok := Clean(reported); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
