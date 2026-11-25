package machine

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestParseOrderKinds_ReadsWhatFormatWrites(t *testing.T) {
	kinds, err := ParseOrderKinds("docker.deploy@2,agent.ping@1,sealed_secret@1")
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds.Format(); got != "agent.ping@1,docker.deploy@2,sealed_secret@1" {
		t.Fatalf("format %q", got)
	}
	again, err := ParseOrderKinds(kinds.Format())
	if err != nil || again.Format() != kinds.Format() {
		t.Fatalf("round trip %v, %v", again, err)
	}
}

// Une annonce se lit en entier ou pas du tout : le texte vient de l'agent.
func TestParseOrderKinds_RefusesAnythingOutOfShape(t *testing.T) {
	tooMany := make([]string, maxAnnouncedKinds+1)
	for index := range tooMany {
		tooMany[index] = "kind" + strconv.Itoa(index) + "@1"
	}
	for name, text := range map[string]string{
		"empty":             "",
		"no revision":       "agent.ping",
		"revision zero":     "agent.ping@0",
		"leading zero":      "agent.ping@01",
		"revision too long": "agent.ping@1000",
		"negative":          "agent.ping@-1",
		"not a number":      "agent.ping@x",
		"two revisions":     "agent.ping@1@2",
		"upper case":        "Agent.Ping@1",
		"space":             "agent.ping@1, docker.deploy@1",
		"empty item":        "agent.ping@1,,docker.deploy@1",
		"control":           "agent.ping\x1b[2J@1",
		"name too long":     strings.Repeat("a", 65) + "@1",
		"repeated":          "agent.ping@1,agent.ping@2",
		"too many":          strings.Join(tooMany, ","),
	} {
		if kinds, err := ParseOrderKinds(text); !errors.Is(err, ErrOrderKindsUnreadable) || kinds != nil {
			t.Errorf("%s: %v, %v", name, kinds, err)
		}
	}
}

// Un genre ne compte qu'annoncé, à son numéro ou au-delà.
func TestOrderKinds_AnnouncesAtItsRevisionOrAbove(t *testing.T) {
	kinds := OrderKinds{"docker.deploy": 1, "agent.ping": 2}
	for _, c := range []struct {
		name     string
		revision int
		want     bool
	}{
		{"docker.deploy", 1, true},
		{"docker.deploy", 2, false},
		{"agent.ping", 1, true},
		{"agent.update", 1, false},
	} {
		if got := kinds.Announces(c.name, c.revision); got != c.want {
			t.Errorf("%s@%d: %v", c.name, c.revision, got)
		}
	}
	if OrderKinds(nil).Announces("agent.update", 1) {
		t.Error("nothing announced announces agent.update")
	}
}
