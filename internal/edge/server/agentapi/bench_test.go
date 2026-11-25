package agentapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/container"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/fact/resource"
	"github.com/ldesfontaine/kagu/internal/fact/update"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

var testNow = servertest.Now()

const remoteID = servertest.RemoteID

// Le banc de l'agent : les vrais composants qu'il appelle, sur une vraie
// base SQLite temporaire, et ses routes montées sur un mux comme la racine
// les monte, sans la chaîne de middlewares (server la teste de bout en bout).
type bench struct {
	http.Handler
	// socket sert les mêmes routes comme la socket des agents locaux.
	socket     http.Handler
	handler    *Handler
	logger     *slog.Logger
	machines   *machine.Service
	resources  *resource.Service
	containers *container.Tracker
	probes     *probe.Service
	updates    *update.Service
	actions    *action.Service
	db         *store.DB
}

func newBench(t *testing.T) *bench {
	t.Helper()
	db := storetest.Open(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	clock := func() time.Time { return testNow }
	machines := machine.New(db, machine.NewSessions(), logger)
	machines.SetClock(clock)
	storetest.EnsureLocalMachine(t, machines)
	resources := resource.New(db, logger)
	resources.SetClock(clock)
	containers := container.New(db, logger)
	containers.SetClock(clock)
	probes := probe.New(db, logger)
	probes.SetClock(clock)
	updates := update.New(db, logger)
	updates.SetClock(clock)
	actions := action.New(db, machines, logger)
	actions.SetClock(clock)
	actions.SetKey(action.GenerateKey())
	b := &bench{logger: logger, machines: machines, resources: resources, containers: containers, probes: probes, updates: updates, actions: actions, db: db}
	b.mount()
	return b
}

// mount refait le handler avec les composants du banc et monte ses routes.
func (b *bench) mount() {
	b.handler = New(Options{
		Logger:        b.logger,
		Machines:      b.machines,
		Resources:     b.resources,
		Containers:    b.containers,
		Probes:        b.probes,
		Updates:       b.updates,
		Actions:       b.actions,
		ClientAddress: httpx.PeerHost,
		Clock:         func() time.Time { return testNow },
	})
	b.Handler = muxOf(b.handler.Routes)
	b.socket = muxOf(b.handler.SocketRoutes)
}

// muxOf monte sur un mux les routes que déclare routes.
func muxOf(routes func(add func(method, pattern string, handler http.HandlerFunc))) *http.ServeMux {
	mux := http.NewServeMux()
	routes(func(method, pattern string, handler http.HandlerFunc) {
		if method == "*" {
			mux.HandleFunc(pattern, handler)
			return
		}
		mux.HandleFunc(method+" "+pattern, handler)
	})
	return mux
}

func (b *bench) enroll(t *testing.T, name, id string) (machine.Machine, ed25519.PrivateKey) {
	t.Helper()
	return storetest.EnrollMachineWithKey(t, b.machines, id, name)
}

func (b *bench) openStream(t *testing.T, machineID string, private ed25519.PrivateKey) (*http.Response, string, *bufio.Reader, context.CancelFunc) {
	t.Helper()
	return servertest.OpenStream(t, b, machineID, private)
}

// postJSON poste comme un agent du protocole de ce binaire.
func (b *bench) postJSON(path string, payload any) *httptest.ResponseRecorder {
	return postJSONTo(b.Handler, path, payload)
}

// postJSONTo poste comme un agent du protocole de ce binaire, sur le montage
// donné.
func postJSONTo(handler http.Handler, path string, payload any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(agentwire.HeaderProtocol, agentwire.ProtocolVersion)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
