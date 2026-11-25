package agentapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// sentOrders garde les ordres que le composant pousse, à la place du flux.
type sentOrders struct {
	orders []agentwire.SignedOrder
}

func (s *sentOrders) Command(_ string, command agentwire.Command) error {
	s.orders = append(s.orders, *command.Order)
	return nil
}

// Un agent du protocole 2 est encore admis, et ne reçoit qu'agent.update, dans
// l'enveloppe et sous l'étiquette v1 qu'il sait lire ; tout autre ordre vers lui
// est refusé avant d'être écrit (action.agent_outdated). Le protocole est celui
// que le flux a dit à son ouverture.
func TestR_A1_9_AProtocol2AgentOnlyReceivesAgentUpdate(t *testing.T) {
	b := newBench(t)
	sent := &sentOrders{}
	b.actions.SetCommander(sent)
	enrolled, private := b.enroll(t, "legacy", remoteID)
	_, _, _, cancel := servertest.OpenStreamSpeaking(t, b, enrolled.ID, private, agentwire.LegacyProtocolVersion)
	defer cancel()
	ctx := context.Background()

	_, err := b.actions.Ping(ctx, enrolled.ID)
	if key, _ := refusal.KeyOf(err); !errors.Is(err, action.ErrAgentOutdated) || key != "action.agent_outdated" {
		t.Fatalf("agent.ping to a protocol 2 agent: %v (key %q)", err, key)
	}
	if runs, err := b.db.ListActionRuns(ctx, action.Query{MachineID: enrolled.ID, Limit: 10}); err != nil || len(runs) != 0 || len(sent.orders) != 0 {
		t.Fatalf("a refused order was written or sent: %v, %d sent, %v", runs, len(sent.orders), err)
	}

	params, err := json.Marshal(agentwire.AgentUpdateParams{Version: "v0.0.3", Parcel: "p", Binary: "kagu"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := b.actions.SendForService(ctx, action.ServiceOrder{MachineID: enrolled.ID, Kind: agentwire.KindAgentUpdate, Params: params})
	if err != nil || run.State != action.StateSent || len(sent.orders) != 1 {
		t.Fatalf("agent.update to a protocol 2 agent: %+v, %d sent, %v", run, len(sent.orders), err)
	}
	signed := sent.orders[0]
	public, _, _ := b.actions.ServerKey()
	if !ed25519.Verify(public, agentwire.OrderSigningBytes(agentwire.LegacyOrderVersion, signed.Body), signed.Signature) {
		t.Fatal("agent.update does not verify under the v1 label")
	}
	if ed25519.Verify(public, agentwire.OrderSigningBytes(agentwire.OrderVersion, signed.Body), signed.Signature) {
		t.Fatal("agent.update to a protocol 2 agent verifies under the v2 label")
	}
	var legacy agentwire.OrderBodyV1
	if err := agentwire.StrictDecode(signed.Body, &legacy); err != nil || legacy.RunID != run.ID || legacy.Kind != agentwire.KindAgentUpdate || string(legacy.Params) != string(params) {
		t.Fatalf("the v1 body %s: %v", signed.Body, err)
	}
}

// Le même serveur, pour un agent de ce binaire : agent.ping part en v2.
func TestR_A1_9_AProtocol3AgentReceivesTheV2Envelope(t *testing.T) {
	b := newBench(t)
	sent := &sentOrders{}
	b.actions.SetCommander(sent)
	enrolled, private := b.enroll(t, "current", remoteID)
	_, _, _, cancel := b.openStream(t, enrolled.ID, private)
	defer cancel()

	run, err := b.actions.Ping(context.Background(), enrolled.ID)
	if err != nil || len(sent.orders) != 1 {
		t.Fatalf("agent.ping: %+v, %d sent, %v", run, len(sent.orders), err)
	}
	signed := sent.orders[0]
	public, _, _ := b.actions.ServerKey()
	var body agentwire.OrderBody
	if err := agentwire.StrictDecode(signed.Body, &body); err != nil || body.V != agentwire.OrderVersion || body.RunID != run.ID ||
		!ed25519.Verify(public, agentwire.OrderSigningBytes(agentwire.OrderVersion, signed.Body), signed.Signature) {
		t.Fatalf("the v2 body %s: %v", signed.Body, err)
	}
}
