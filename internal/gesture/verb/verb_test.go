package verb

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func valid() Verb {
	return Verb{
		ID: "thing.start", Route: "POST /api/things/{id}/actions/start", Params: []string{"id"}, Target: TargetMachine, Label: "l", Summary: "s", Reverse: "thing.stop",
		Level: 1, Token: true,
	}
}

func TestRegister_RefusesAVerbWithoutReverse(t *testing.T) {
	v := valid()
	v.Reverse = ""
	if err := (&Registry{}).Register(v); !errors.Is(err, ErrNoReverse) {
		t.Fatalf("got %v, want ErrNoReverse", err)
	}
}

func confirmable() Verb {
	return Verb{ID: "thing.delete", Route: "DELETE /api/things/{id}", Params: []string{"id"}, Target: TargetMachine, Label: "l", Summary: "s", Level: 2, Token: true}
}

// closed est un geste de niveau 3 : inscrit pour que son niveau se lise, fermé
// aux jetons.
func closed() Verb {
	return Verb{ID: "thing.purge", Route: "DELETE /api/things/{id}/all", Params: []string{"id"}, Target: TargetMachine, Label: "l", Summary: "s", Level: 3, Reason: "r"}
}

// Un verbe de niveau 2 remplace l'inverse par la confirmation : il n'en a
// pas, et sa route peut être un DELETE ou un PUT.
func TestRegister_AcceptsAVerbToConfirmWithoutReverse(t *testing.T) {
	registry := &Registry{}
	registry.MustRegister(confirmable())
	put := confirmable()
	put.ID, put.Route = "thing.replace", "PUT /api/things/{id}"
	registry.MustRegister(put)
	if err := registry.Check(); err != nil {
		t.Fatalf("a verb to confirm has no reverse to check: %v", err)
	}
}

func TestRegister_RefusesMalformedVerbsToConfirm(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Verb)
		want   error
	}{
		"with a reverse":   {func(v *Verb) { v.Reverse = "thing.create" }, ErrConfirmReverse},
		"a read":           {func(v *Verb) { v.Route = "GET /api/things/{id}" }, ErrRouteInvalid},
		"outside api":      {func(v *Verb) { v.Route = "DELETE /agent/things/{id}" }, ErrRouteInvalid},
		"not on a machine": {func(v *Verb) { v.Target = TargetProbe }, ErrConfirmTarget},
	}
	for name, c := range cases {
		v := confirmable()
		c.mutate(&v)
		if err := (&Registry{}).Register(v); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// Un DELETE ne passe pas au niveau 1 : seul un niveau plus haut l'ouvre.
func TestRegister_RefusesADeleteWithoutConfirmation(t *testing.T) {
	v := valid()
	v.Route = "DELETE /api/things/{id}"
	if err := (&Registry{}).Register(v); !errors.Is(err, ErrRouteInvalid) {
		t.Fatalf("got %v, want ErrRouteInvalid", err)
	}
}

func TestDefault_MachineDeleteAsksForAConfirmation(t *testing.T) {
	found, ok := Default.ByRoute("DELETE /api/machines/{id}")
	if !ok || found.ID != "machine.delete" || !found.AsksConfirmation() || found.Reverse != "" {
		t.Fatalf("got %+v %v", found, ok)
	}
}

func TestRegister_RefusesMalformedVerbs(t *testing.T) {
	cases := map[string]func(*Verb){
		"id without dot": func(v *Verb) { v.ID = "start" },
		"id uppercase":   func(v *Verb) { v.ID = "Thing.Start" },
		"read route":     func(v *Verb) { v.Route = "GET /api/things" },
		"outside api":    func(v *Verb) { v.Route = "POST /agent/things" },
		"no target":      func(v *Verb) { v.Target = "" },
		"unknown target": func(v *Verb) { v.Target = "disk" },
		"no label":       func(v *Verb) { v.Label = "" },
		"no summary":     func(v *Verb) { v.Summary = "" },
		"missing param":  func(v *Verb) { v.Params = nil },
		"invented param": func(v *Verb) { v.Params = []string{"id", "vmid"} },
	}
	for name, mutate := range cases {
		v := valid()
		mutate(&v)
		if err := (&Registry{}).Register(v); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
}

func TestRegister_RefusesDuplicates(t *testing.T) {
	registry := &Registry{}
	registry.MustRegister(valid())
	if err := registry.Register(valid()); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same id: %v", err)
	}
	other := valid()
	other.ID = "thing.other"
	if err := registry.Register(other); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same route: %v", err)
	}
}

func TestCheck_CatchesAReverseThatDoesNotExist(t *testing.T) {
	registry := &Registry{}
	registry.MustRegister(valid())
	if err := registry.Check(); !errors.Is(err, ErrUnknownReverse) {
		t.Fatalf("got %v, want ErrUnknownReverse", err)
	}
}

// Le garde-fou de la décision 19 : tout verbe de niveau 1 déclare un inverse
// qui existe, et l'inverse de l'inverse est le verbe lui-même quand l'inverse
// est lui aussi de niveau 1.
func TestDefault_EveryVerbHasARealReverse(t *testing.T) {
	if err := Default.Check(); err != nil {
		t.Fatal(err)
	}
	for _, v := range Default.All() {
		back, _ := Default.Lookup(v.Reverse)
		if v.Level != 1 || back.Level != 1 {
			continue
		}
		if back.Reverse != v.ID {
			t.Errorf("%s -> %s -> %s: the reverse does not come back", v.ID, back.ID, back.Reverse)
		}
	}
}

func TestDefault_AcknowledgeStaysWithTheOperator(t *testing.T) {
	if _, found := Default.Lookup("alert.acknowledge"); found {
		t.Fatal("alert.acknowledge has no reverse: it must not be offered")
	}
}

func TestByRoute_FindsTheVerbOfARoute(t *testing.T) {
	found, ok := Default.ByRoute("POST /api/probes/{id}/actions/pause")
	if !ok || found.ID != "probe.pause" {
		t.Fatalf("got %+v %v", found, ok)
	}
	if _, ok := Default.ByRoute("DELETE /api/probes/{id}"); ok {
		t.Fatal("a deletion without confirmation is a verb")
	}
}

// Params et Body sont déclarés dans le registre : chaque verbe offert dit
// les segments de son chemin sans qu'on parse de texte.
func TestDefault_ParamsMatchTheRoutePath(t *testing.T) {
	for _, v := range Default.All() {
		if got := PathParams(v.Route); !slices.Equal(got, v.Params) {
			t.Errorf("%s: params %v, route says %v", v.ID, v.Params, got)
		}
	}
}

// Le cadrage #366 : un jeton lance, vérifie, parcourt et restaure à côté ;
// il ne crée, ne modifie ni ne supprime une cible, une sauvegarde ou une
// rétention. La liste est exacte : un verbe restic de plus fait échouer ce
// test, et c'est à Lucas de le décider.
func TestDefault_ResticVerbsAreTheFourOfTheTicketAndNoWrite(t *testing.T) {
	want := []string{"restic.backup.run", "restic.backup.verify", "restic.backup.restore", "restic.backup.browse"}
	var got []string
	for _, offered := range Default.All() {
		if strings.HasPrefix(offered.ID, "restic.") {
			got = append(got, offered.ID)
		}
		route := strings.ToLower(offered.Route)
		for _, forbidden := range []string{"retain", "forget", "prune", "restic-target", "retention"} {
			if strings.Contains(route, forbidden) {
				t.Errorf("%s : la route %s ouvre %s à un jeton", offered.ID, offered.Route, forbidden)
			}
		}
		if strings.HasPrefix(offered.ID, "restic.") && strings.HasPrefix(offered.Route, "PUT ") {
			t.Errorf("%s : un verbe restic ne modifie rien", offered.ID)
		}
		if strings.HasPrefix(offered.ID, "restic.") && strings.HasPrefix(offered.Route, "DELETE ") {
			t.Errorf("%s : un verbe restic ne supprime rien", offered.ID)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("verbes restic %v, attendus %v", got, want)
	}
}

// Un verbe de dépôt restic vise le lien : {id} est la source, la cible suit.
func TestRegister_JudgesTheTargetKind(t *testing.T) {
	link := valid()
	link.Target = TargetResticLink
	if err := (&Registry{}).Register(link); err != nil {
		t.Fatalf("restic_link: %v", err)
	}
	unknown := valid()
	unknown.Target = "elsewhere"
	if err := (&Registry{}).Register(unknown); !errors.Is(err, ErrTargetInvalid) {
		t.Fatalf("unknown target: got %v, want ErrTargetInvalid", err)
	}
}

// R-A4-11 : verify et browse envoient leur ordre à la cible du dépôt, run et
// restore à la source seule.
func TestDefault_ResticVerbsThatReachTheTargetJudgeTheLink(t *testing.T) {
	for id, want := range map[string]Target{
		"restic.backup.verify": TargetResticLink, "restic.backup.browse": TargetResticLink,
		"restic.backup.run": TargetMachine, "restic.backup.restore": TargetMachine,
	} {
		found, ok := Default.Lookup(id)
		if !ok || found.Target != want {
			t.Errorf("%s: target %q, want %q", id, found.Target, want)
		}
	}
}

// R-A4-1 : chaque geste du registre a un niveau, de 1 à 4 ; le niveau 0 est
// une lecture (T11-01), et un niveau absent vaut 0 : refusé comme un inconnu.
func TestR_A4_1_EveryRegisteredGestureHasALevel(t *testing.T) {
	for _, v := range Default.All() {
		if v.Level < 1 || v.Level > 4 {
			t.Errorf("%s: level %d", v.ID, v.Level)
		}
	}
	for _, level := range []int{0, -1, 5} {
		v := valid()
		v.Level = level
		if err := (&Registry{}).Register(v); !errors.Is(err, ErrLevelInvalid) {
			t.Errorf("level %d: got %v, want ErrLevelInvalid", level, err)
		}
	}
}

// R-A4-2 : un geste de niveau 3 ou 4 n'est jamais offert à un jeton, et dit
// pourquoi. Il s'inscrit fermé, sans inverse, pour que son niveau se lise.
func TestR_A4_2_RegisterRefusesALevelThreeOrFourOpenToAToken(t *testing.T) {
	for _, level := range []int{3, 4} {
		open := closed()
		open.Level, open.Token = level, true
		if err := (&Registry{}).Register(open); !errors.Is(err, ErrTokenLevel) {
			t.Errorf("level %d open to a token: got %v, want ErrTokenLevel", level, err)
		}
		silent := closed()
		silent.Level, silent.Reason = level, ""
		if err := (&Registry{}).Register(silent); !errors.Is(err, ErrReasonMissing) {
			t.Errorf("level %d without a reason: got %v, want ErrReasonMissing", level, err)
		}
		reversible := closed()
		reversible.Level, reversible.Reverse = level, "thing.start"
		if err := (&Registry{}).Register(reversible); !errors.Is(err, ErrConfirmReverse) {
			t.Errorf("level %d with a reverse: got %v, want ErrConfirmReverse", level, err)
		}
		registry := &Registry{}
		accepted := closed()
		accepted.Level = level
		if err := registry.Register(accepted); err != nil {
			t.Errorf("level %d closed to tokens: %v", level, err)
		}
		if found, ok := registry.ByRoute(accepted.Route); !ok || found.Level != level || found.Token {
			t.Errorf("level %d: route reads %+v %v", level, found, ok)
		}
	}
	for _, v := range Default.All() {
		if v.Level >= 3 && v.Token {
			t.Errorf("%s: level %d open to a token", v.ID, v.Level)
		}
	}
}

// R-A4-4 : un verbe de niveau 1 nomme un inverse qui existe ; l'inverse peut
// être de niveau 2. Un inverse qui ne rend pas l'état exact n'en est pas un :
// supprimer un instantané passe au niveau 2, sans inverse.
func TestR_A4_4_ALevelOneVerbNamesARegisteredReverse(t *testing.T) {
	withoutReverse := valid()
	withoutReverse.Reverse = ""
	if err := (&Registry{}).Register(withoutReverse); !errors.Is(err, ErrNoReverse) {
		t.Fatalf("level 1 without a reverse: got %v, want ErrNoReverse", err)
	}
	registry := &Registry{}
	registry.MustRegister(valid())
	if err := registry.Check(); !errors.Is(err, ErrUnknownReverse) {
		t.Fatalf("unknown reverse: got %v, want ErrUnknownReverse", err)
	}
	stop := confirmable()
	stop.ID, stop.Route = "thing.stop", "POST /api/things/{id}/actions/stop"
	registry.MustRegister(stop)
	if err := registry.Check(); err != nil {
		t.Fatalf("a reverse of level 2: %v", err)
	}
	snapshot, _ := Default.Lookup("proxmox.vm.snapshot")
	deletion, _ := Default.Lookup("proxmox.vm.snapshot_delete")
	if snapshot.Level != 1 || snapshot.Reverse != deletion.ID || deletion.Level != 2 || deletion.Reverse != "" {
		t.Fatalf("snapshot %+v, snapshot_delete %+v", snapshot, deletion)
	}
	if err := Default.Check(); err != nil {
		t.Fatal(err)
	}
}
