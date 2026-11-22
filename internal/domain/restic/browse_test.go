package restic

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// quickSender est une cible qui répond avant même que l'envoi soit fini : le
// résultat part dans une autre goroutine, au moment où l'ordre est écrit.
type quickSender struct {
	service *Service
	report  agentwire.ResticBrowseReport
}

func (q *quickSender) Send(context.Context, string, agentwire.Kind, json.RawMessage) (action.Run, error) {
	return action.Run{}, nil
}

func (q *quickSender) SendWithSecret(_ context.Context, _ string, _ agentwire.Kind, _, _ json.RawMessage, _ string) (action.Run, error) {
	go q.service.deliverBrowse("machine", agentwire.ActionResult{RunID: "run-1", State: agentwire.ActionSucceeded, Browse: &q.report})
	return action.Run{ID: "run-1", State: action.StateSent}, nil
}

func (q *quickSender) Wait(ctx context.Context, _ string) (action.Run, error) {
	<-ctx.Done()
	return action.Run{}, ctx.Err()
}

// Un résultat qui arrive pendant l'envoi n'est pas perdu : le créneau est ouvert
// sous le même verrou que l'envoi, et la livraison l'attend.
func TestBrowse_AResultThatArrivesDuringTheSendIsNotLost(t *testing.T) {
	report := agentwire.ResticBrowseReport{Entries: []agentwire.BrowseEntry{{Name: "a.txt", Kind: "file", Size: 1}}}
	for range 300 {
		service := &Service{}
		service.sender = &quickSender{service: service, report: report}
		run, slot, err := service.sendBrowse(context.Background(), "machine", nil, agentwire.ResticBrowseSecret{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got, err := service.awaitBrowse(ctx, run, slot)
		cancel()
		if err != nil || len(got.Entries) != 1 {
			t.Fatalf("the quick answer was lost: %v %+v", err, got)
		}
		service.dropBrowseSlot(run.ID)
		if len(service.browses) != 0 {
			t.Fatal("the slot outlived the request")
		}
	}
}

// Un résultat de parcours rapporté par une autre machine que celle de l'ordre
// n'atteint pas l'écran ; celui de la bonne machine passe.
func TestR_E3_16(t *testing.T) {
	report := agentwire.ResticBrowseReport{Entries: []agentwire.BrowseEntry{{Name: "secret.txt", Kind: "file", Size: 1}}}
	result := agentwire.ActionResult{RunID: "run-1", State: agentwire.ActionSucceeded, Browse: &report}
	service := &Service{logger: slog.New(slog.DiscardHandler)}
	slot := &browseSlot{machineID: "target", done: make(chan struct{})}
	service.browses = map[string]*browseSlot{"run-1": slot}

	if !service.deliverBrowse("intruder", result) {
		t.Fatal("a foreign result of a browse run must still be consumed, not recorded elsewhere")
	}
	select {
	case <-slot.done:
		t.Fatal("a result from another machine reached the screen")
	default:
	}

	if !service.deliverBrowse("target", result) {
		t.Fatal("the result of the target was not taken")
	}
	select {
	case <-slot.done:
	default:
		t.Fatal("the result of the target did not reach the screen")
	}
}
