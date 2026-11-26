package agent

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/wait/waittest"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// R-DROIT-2, R-A3-5 : « grant agent.update --for 5m ». Sans serveur, l'agent
// juge seul : un ordre qui exige le droit passe le juge avant l'échéance, et
// est refusé right_missing à l'échéance ; le changement est signalé pour
// rouvrir le flux. Joint, l'agent dit le droit et son échéance, puis, l'heure
// passée, rouvre son flux sans eux.
func TestR_DROIT_2_AnExpiredRightFallsWithoutTheServer(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	granted := []agentpolicy.Capability{{Name: agentpolicy.CapabilityAgentUpdate}}
	if _, err := GrantRights(b.opts, granted, agentpolicy.Term{Duration: agentpolicy.MinDuration}, accept); err != nil {
		t.Fatal(err)
	}
	rollback := func(seq int64) agentwire.ActionResult {
		body := order(seq)
		body.Kind = agentwire.KindAgentRollback
		body.NotAfter = b.clock.now.Add(time.Minute).Unix()
		return b.send(t, body, b.private)
	}
	missing := agentwire.RightMissing(agentpolicy.CapabilityAgentUpdate)
	b.clock.advance(agentpolicy.MinDuration - time.Second)
	if result := rollback(1); result.Reason == missing {
		t.Fatalf("the right fell before its five minutes: %+v", result)
	}
	<-b.runner.policyChanged
	b.clock.advance(time.Second)
	if result := rollback(2); result.State != agentwire.ActionRefused || result.Reason != missing {
		t.Fatalf("an expired right let the order through: %+v", result)
	}
	select {
	case <-b.runner.policyChanged:
	default:
		t.Fatal("the expiry was not signalled: the stream would keep reporting the right")
	}

	// Joint : le flux dit le droit et son échéance, puis se rouvre sans eux.
	until := b.clock.now
	server := &fakeServer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var elapsed atomic.Int64
	start := b.clock.now.Add(-agentpolicy.MinDuration)
	startUptime := b.clock.uptime - agentpolicy.MinDuration
	var streamRunner *orderRunner
	done := startAgentWith(t, ctx, server, &bytes.Buffer{}, nil, func(_ *Client, orders *orderRunner) {
		// Sans dossier d'état, le lanceur de mises à jour ne se juge pas.
		useHostChecks(orders, allowAll())
		orders.policyPlace = b.opts.Place
		orders.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
		orders.monotonic = func() (string, time.Duration) { return bootID, startUptime + time.Duration(elapsed.Load()) }
		orders.currentPolicy()
		streamRunner = orders
	})
	waittest.Until(t, "a first stream", func() bool {
		streams, _, _ := server.snapshot()
		return len(streams) >= 1
	})
	elapsed.Store(int64(agentpolicy.MinDuration))
	streamRunner.currentPolicy()
	waittest.Until(t, "a stream reopened", func() bool {
		streams, _, _ := server.snapshot()
		return len(streams) >= 2
	})
	server.mu.Lock()
	rights, rightsUntil := slices.Clone(server.rights), slices.Clone(server.rightsUntil)
	server.mu.Unlock()
	if rights[0] != "observe,agent.update" || rightsUntil[0] != "agent.update="+strconv.FormatInt(until.Unix(), 10) {
		t.Errorf("first stream said %q %q", rights[0], rightsUntil[0])
	}
	if rights[1] != "observe" || rightsUntil[1] != "" {
		t.Errorf("the reopened stream still said %q %q", rights[1], rightsUntil[1])
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("agent stopped with %v", err)
	}
}

// R-A3-5, N-F5 : un droit à durée posé, puis l'horloge monotone de la machine
// ne se lit plus : l'agent le tient pour échu, avant son heure, et refuse
// l'ordre qui l'exige ; au démarrage, il le dit au journal.
func TestR_A3_5_WithoutTheMonotonicClockTheAgentFailsClosed(t *testing.T) {
	b := migrate(t, newOrderBench(t))
	granted := []agentpolicy.Capability{{Name: agentpolicy.CapabilityAgentUpdate}}
	if _, err := GrantRights(b.opts, granted, agentpolicy.Term{Duration: time.Hour}, accept); err != nil {
		t.Fatal(err)
	}
	rollback := func(seq int64) agentwire.ActionResult {
		body := order(seq)
		body.Kind = agentwire.KindAgentRollback
		body.NotAfter = b.clock.now.Add(time.Minute).Unix()
		return b.send(t, body, b.private)
	}
	missing := agentwire.RightMissing(agentpolicy.CapabilityAgentUpdate)
	if result := rollback(1); result.Reason == missing {
		t.Fatalf("the right fell with the monotonic clock: %+v", result)
	}
	b.runner.monotonic = func() (string, time.Duration) { return "", 0 }
	if result := rollback(2); result.State != agentwire.ActionRefused || result.Reason != missing {
		t.Fatalf("without the monotonic clock, a right with an expiry let the order through: %+v", result)
	}

	var logs bytes.Buffer
	warnWithoutMonotonicClock(b.runner.clock(), slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "monotonic clock unreadable") {
		t.Fatalf("no line at start:\n%s", logs.String())
	}
	logs.Reset()
	warnWithoutMonotonicClock(b.clock.read(), slog.New(slog.NewTextHandler(&logs, nil)))
	if logs.Len() != 0 {
		t.Fatalf("a readable clock was logged:\n%s", logs.String())
	}
}
