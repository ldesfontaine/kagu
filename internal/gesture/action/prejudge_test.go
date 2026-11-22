package action_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// grantedRight écrit un droit comme l'agent le rapporte : un droit borné
// porte sa portée.
func grantedRight(name string) string {
	scopes := map[string]string{
		machine.CapabilityBackupReceive: "/srv/backups",
		machine.CapabilityBackupProduce: machine.ProducerProxmoxVzdump,
		machine.CapabilityFilesWrite:    "/srv/files",
		machine.CapabilityResticTarget:  "/srv/restic",
	}
	if scope, bounded := scopes[name]; bounded {
		return name + "=" + scope
	}
	return name
}

// everyRightBut rend tous les droits sauf missing.
func everyRightBut(missing string) string {
	var granted []string
	for _, name := range machine.CapabilityNames() {
		if name != missing {
			granted = append(granted, grantedRight(name))
		}
	}
	return strings.Join(granted, ",")
}

// Le serveur pré-juge un ordre avec le droit que le registre déclare pour son
// genre, et lui seul : un agent qui a tous les droits sauf celui-là ne reçoit
// rien ; un agent qui n'a que celui-là reçoit l'ordre.
func TestR_A1_14_TheServerPrejudgesWithTheRegistry(t *testing.T) {
	for _, kind := range agentwire.OrderKinds() {
		spec, _ := agentwire.SpecOf(kind)
		// observe est toujours tenu (machine.NormalizeCapabilities) : il ne
		// peut pas manquer.
		if spec.Right != machine.CapabilityObserve {
			missing := newBenchReporting(t, everyRightBut(spec.Right))
			if _, err := missing.service.Send(operator(), machineID, kind, nil); !errors.Is(err, action.ErrRightMissing) {
				t.Errorf("%s without %s: %v", kind, spec.Right, err)
			}
			if len(missing.pusher.sent) != 0 {
				t.Errorf("%s without %s: %d orders left", kind, spec.Right, len(missing.pusher.sent))
			}
		}
		holding := newBenchReporting(t, grantedRight(spec.Right))
		if _, err := holding.service.Send(operator(), machineID, kind, nil); err != nil {
			t.Errorf("%s with only %s: %v", kind, spec.Right, err)
		}
	}
	// Une observation n'est pas au registre : aucun droit ne la fait partir
	// comme un ordre.
	every := newBenchReporting(t, everyRightBut(""))
	if _, err := every.service.Send(operator(), machineID, agentwire.KindLogs, nil); !errors.Is(err, action.ErrUnknownKind) {
		t.Errorf("an observation sent as an order: %v", err)
	}
}
