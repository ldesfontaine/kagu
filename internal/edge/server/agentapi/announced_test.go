package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// streamCommander pousse les ordres dans le flux de la machine, comme le
// serveur (Server.Command).
type streamCommander struct {
	machines *machine.Service
}

func (c streamCommander) Command(machineID string, command agentwire.Command) error {
	event, data, err := command.Encode()
	if err != nil {
		return err
	}
	return c.machines.Push(machineID, machine.StreamEvent{Name: event, Data: data})
}

// nextOrder lit le flux jusqu'au premier ordre signé ; les observations et le
// ping passent.
func nextOrder(t *testing.T, reader *bufio.Reader) agentwire.SignedOrder {
	t.Helper()
	var name, data string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended before an order: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data += strings.TrimPrefix(line, "data: ")
		case line == "" && name == agentwire.EventOrder:
			var signed agentwire.SignedOrder
			if err := json.Unmarshal([]byte(data), &signed); err != nil {
				t.Fatalf("order event %s: %v", data, err)
			}
			return signed
		case line == "":
			name, data = "", ""
		}
	}
}

// Un agent du protocole 2 ouvre son flux sur ce serveur : pas de 426, il
// reste en ligne. Tout ordre autre qu'agent.update est refusé avant d'être
// écrit, avec « Mettre à jour l'agent » ; agent.update part, et c'est le seul
// ordre que le flux lui porte. Rejoue T01-10 (QA-18), entre deux versions de
// ce produit (QA-19).
func TestR_B2_8_AProtocol2AgentStaysAndGetsOnlyAgentUpdate(t *testing.T) {
	b := newBench(t)
	b.actions.SetCommander(streamCommander{machines: b.machines})
	enrolled, private := b.enroll(t, "legacy", remoteID)
	_, _, reader, cancel := servertest.OpenStreamSpeaking(t, b, enrolled.ID, private, agentwire.LegacyProtocolVersion)
	defer cancel()
	ctx := context.Background()

	status, err := b.machines.Get(ctx, enrolled.ID)
	if err != nil || !status.Online || status.Agent.Protocol != agentwire.LegacyProtocolVersion || status.Agent.OrderKinds != nil {
		t.Fatalf("the protocol 2 agent: online %v, protocol %q, kinds %v, %v", status.Online, status.Agent.Protocol, status.Agent.OrderKinds, err)
	}
	for _, kind := range agentwire.OrderKinds() {
		if kind == agentwire.KindAgentUpdate {
			continue
		}
		_, err := b.actions.Send(ctx, enrolled.ID, kind, nil)
		if key, _ := refusal.KeyOf(err); !errors.Is(err, action.ErrAgentOutdated) || key != "action.agent_outdated" {
			t.Errorf("%s to a protocol 2 agent: %v (key %q)", kind, err, key)
		}
	}

	params, err := json.Marshal(agentwire.AgentUpdateParams{Version: "v0.0.3", Parcel: "p", Binary: "kagu"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := b.actions.SendForService(ctx, action.ServiceOrder{MachineID: enrolled.ID, Kind: agentwire.KindAgentUpdate, Params: params})
	if err != nil || run.State != action.StateSent {
		t.Fatalf("agent.update to a protocol 2 agent: %+v, %v", run, err)
	}
	var legacy agentwire.OrderBodyV1
	if signed := nextOrder(t, reader); agentwire.StrictDecode(signed.Body, &legacy) != nil || legacy.Kind != agentwire.KindAgentUpdate || legacy.RunID != run.ID {
		t.Fatalf("the first order on the stream: %s", signed.Body)
	}
	runs, err := b.db.ListActionRuns(ctx, action.Query{MachineID: enrolled.ID, Limit: 10})
	if err != nil || len(runs) != 1 || runs[0].Kind != agentwire.KindAgentUpdate {
		t.Fatalf("runs written: %+v, %v", runs, err)
	}
}

// Le flux garde ce que l'agent annonce, et rien de ce qu'il n'annonce pas :
// une annonce illisible vaut aucune, et aucun ordre ne part.
func TestR_B2_8_TheStreamKeepsWhatTheAgentAnnounces(t *testing.T) {
	cases := map[string]struct {
		announced string
		want      machine.OrderKinds
		pingSent  bool
	}{
		"this binary":          {agentwire.AnnouncedKinds().Format(), agentwire.AnnouncedKinds(), true},
		"ping only":            {"agent.ping@1", machine.OrderKinds{"agent.ping": 1}, true},
		"ping at revision 0":   {"agent.ping@0", nil, false},
		"a number that is not": {"agent.ping@x", nil, false},
		"a hostile name":       {"agent.ping@1,<script>@1", nil, false},
		"nothing":              {"", nil, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBench(t)
			b.actions.SetCommander(streamCommander{machines: b.machines})
			enrolled, private := b.enroll(t, "current", remoteID)
			_, _, _, cancel := servertest.OpenStreamAnnouncing(t, b, enrolled.ID, private, c.announced)
			defer cancel()
			ctx := context.Background()

			status, err := b.machines.Get(ctx, enrolled.ID)
			if err != nil || status.Agent.OrderKinds.Format() != c.want.Format() || (c.want == nil) != (status.Agent.OrderKinds == nil) {
				t.Fatalf("kept %v, want %v (%v)", status.Agent.OrderKinds, c.want, err)
			}
			_, err = b.actions.Ping(ctx, enrolled.ID)
			if c.pingSent != (err == nil) {
				t.Fatalf("agent.ping: %v", err)
			}
			if !c.pingSent && !errors.Is(err, action.ErrAgentOutdated) {
				t.Fatalf("agent.ping refused for another reason: %v", err)
			}
		})
	}
}

// Seuls les protocoles 2 et 3 ouvrent le flux ; les autres lisent 426.
func TestR_B2_8_OnlyTheListedProtocolsOpenTheStream(t *testing.T) {
	b := newBench(t)
	enrolled, private := b.enroll(t, "vps-paris-1", remoteID)
	for _, protocol := range []string{"1", "4", "02", "3 ", "2,3"} {
		request := servertest.SignedStreamRequest(t, "http://example.test", enrolled.ID, private, servertest.NewNonce(t))
		request.Header.Set(agentwire.HeaderProtocol, protocol)
		recorder := httptest.NewRecorder()
		b.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUpgradeRequired || !strings.Contains(recorder.Body.String(), agentwire.CodeProtocolUnsupported) {
			t.Errorf("protocol %q: %d %s", protocol, recorder.Code, recorder.Body.String())
		}
	}
}
