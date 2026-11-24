package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/domain/backup"
	"github.com/ldesfontaine/kagu/internal/domain/deploy"
	"github.com/ldesfontaine/kagu/internal/domain/directory"
	"github.com/ldesfontaine/kagu/internal/domain/heartbeat"
	"github.com/ldesfontaine/kagu/internal/domain/proxmox"
	"github.com/ldesfontaine/kagu/internal/domain/restic"
	"github.com/ldesfontaine/kagu/internal/domain/settings"
	"github.com/ldesfontaine/kagu/internal/edge/server/servertest"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/container"
	"github.com/ldesfontaine/kagu/internal/fact/firewall"
	"github.com/ldesfontaine/kagu/internal/fact/firewall/opnsense"
	"github.com/ldesfontaine/kagu/internal/fact/hostconn"
	"github.com/ldesfontaine/kagu/internal/fact/lifecycle"
	"github.com/ldesfontaine/kagu/internal/fact/link"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/fact/resource"
	"github.com/ldesfontaine/kagu/internal/fact/role"
	"github.com/ldesfontaine/kagu/internal/fact/sshkeys"
	"github.com/ldesfontaine/kagu/internal/fact/systemdunits"
	"github.com/ldesfontaine/kagu/internal/fact/update"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/gesture/apitoken"
	"github.com/ldesfontaine/kagu/internal/gesture/verbrequest"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/live"
	"github.com/ldesfontaine/kagu/internal/view/status"
)

// L'horloge figée des tests : « vu il y a » se calcule depuis elle.
var testNow = servertest.Now()

type testServer struct {
	*Server
	hostConns  *hostconn.Service
	machines   *machine.Service
	heartbeats *heartbeat.Service
	resources  *resource.Service
	containers *container.Tracker
	probes     *probe.Service
	directory  *directory.Directory
	updates    *update.Service
	lifecycle  *lifecycle.Service
	support    *supportSource
	status     *status.Service
	alerts     *alert.Engine
	notifier   *alert.Notifier
	apiTokens  *apitoken.Service
	requests   *verbrequest.Service
	operator   *auth.Service
	journal    *audit.Recorder
	actions    *action.Service
	backups    *backup.Service
	restic     *restic.Service
	relay      *restic.Broker
	proxmox    *proxmox.Service
	firewalls  *firewall.Service
	state      *os.Root
	// logs garde ce que le serveur a journalisé : le banc de non-fuite le lit.
	logs *logBuffer
	// Sérialise la pose de la session du banc (operatorToken).
	sessionMu sync.Mutex
	bus       *live.Bus
	publicBus *live.Bus
	db        *store.DB
}

// Le serveur de test tourne sur le vrai composant machine et une vraie base
// SQLite temporaire, avec la machine openCloud déjà en place. Il est
// configuré comme une installation qui a passé sa première configuration : un
// compte natif, dont une session est posée sur toute requête de l'opérateur
// qui n'en porte pas, pour que les tests qui ne parlent pas de l'accès
// n'aient pas à se connecter. Ceux qui en parlent partent de
// newFirstSetupServer.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	server := newFirstSetupServer(t)
	server.enableNative(t)
	server.handler = server.asOperator(server.handler)
	return server
}

// anonymousHeader marque la requête d'un test qui joue un inconnu : le banc
// n'y pose pas de session (voir callAs).
const anonymousHeader = "X-Test-Anonymous"

// asOperator pose le cookie d'une session du compte de test sur une requête
// qui ne porte ni Authorization (un Bearer d'API, par exemple) ni cookie. Les
// routes ouvertes l'ignorent. Comme un navigateur : d'un client de boucle
// locale en HTTP (le banc e2e, le tunnel), le cookie local ; d'ailleurs,
// __Host- sur HTTPS (R-A2-3).
func (ts *testServer) asOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anonymous := r.Header.Get(anonymousHeader) != ""
		r.Header.Del(anonymousHeader)
		if !anonymous && r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			ts.presentOperatorSession(r)
		}
		next.ServeHTTP(w, r)
	})
}

func (ts *testServer) presentOperatorSession(r *http.Request) {
	cookie, ok := ts.sessionCookieKind(r)
	if !ok {
		overHTTPS(r)
		cookie = auth.CookieHost
	}
	if token := ts.operatorToken(cookie); token != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName(cookie), Value: token})
	}
}

// testSessionID et testSessionToken sont la session que le banc pose : fixes,
// pour que les réponses figées qui nomment l'opérateur (operator:<session>)
// le restent. Elle naît sous __Host- ; celle du cookie local (le banc e2e, sur
// la boucle locale) est à part : un jeton présenté sous l'autre cookie tue sa
// session (R-A2-3).
const (
	testSessionID         = "5e55105e55105e55"
	testSessionToken      = "7e57" + "000000000000000000000000000000000000000000000000000000000000"
	testLocalSessionID    = "10ca110ca110ca11"
	testLocalSessionToken = "10ca" + "000000000000000000000000000000000000000000000000000000000000"
)

// operatorToken rend le jeton de la session du banc née sous cookie, rouverte
// quand elle est morte (accès désactivé puis recréé, autres sessions fermées) ;
// rien quand le compte de test ne se connecte plus (mot de passe changé, autre
// mode), comme Basic n'ouvrait plus rien.
func (ts *testServer) operatorToken(cookie auth.CookieKind) string {
	ts.sessionMu.Lock()
	defer ts.sessionMu.Unlock()
	id, token := testSessionID, testSessionToken
	if cookie == auth.CookieLocal {
		id, token = testLocalSessionID, testLocalSessionToken
	}
	ctx := context.Background()
	state, err := ts.operator.State(ctx)
	if err != nil || state.Mode != auth.ModeNative {
		return ""
	}
	if _, alive, _ := ts.operator.ResumeSession(ctx, state, auth.PresentedToken{Value: token, Cookie: cookie}); alive {
		return token
	}
	if verified, err := ts.operator.Verify(ctx, state, testUsername, testPassword); err != nil || !verified {
		return ""
	}
	if _, err := ts.db.DeleteSession(ctx, id); err != nil {
		return ""
	}
	session := auth.Session{ID: id, Identity: testUsername, CreatedAt: testNow, SeenAt: testNow, ExpiresAt: testNow.Add(auth.SessionLifetime), Cookie: cookie}
	if err := ts.db.CreateSession(ctx, session, ident.HashToken(token)); err != nil {
		return ""
	}
	return token
}

// newFirstSetupServer est une installation neuve : mode none, aucun compte,
// rien de posé sur les requêtes.
func newFirstSetupServer(t *testing.T) *testServer {
	t.Helper()
	root, db := storetest.OpenWithStateDir(t)
	logs := &logBuffer{}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, logs), nil))
	bus := live.New()
	machines := machine.New(db, machine.NewSessions(), logger)
	machines.SetClock(func() time.Time { return testNow })
	machines.SetWatcher(bus)
	storetest.EnsureLocalMachine(t, machines)
	heartbeats := heartbeat.New(db, logger)
	heartbeats.SetClock(func() time.Time { return testNow })
	heartbeats.SetWatcher(bus)
	resources := resource.New(db, logger)
	resources.SetClock(func() time.Time { return testNow })
	resources.SetWatcher(bus)
	containers := container.New(db, logger)
	containers.SetClock(func() time.Time { return testNow })
	containers.SetWatcher(bus)
	probes := probe.New(db, logger)
	probes.SetClock(func() time.Time { return testNow })
	probes.SetWatcher(bus)
	declared := directory.New(db, logger)
	declared.SetClock(func() time.Time { return testNow })
	declared.SetWatcher(bus)
	updates := update.New(db, logger)
	updates.SetClock(func() time.Time { return testNow })
	updates.SetWatcher(bus)
	// Le même câblage que serve : l'annuaire lit les conteneurs et leurs
	// constats, le suivi des conteneurs lui demande leurs unités.
	declared.SetObserved(containers, updates)
	declared.SetRematcher(containers)
	containers.SetUnits(declared)
	links := link.New(db, logger)
	links.SetClock(func() time.Time { return testNow })
	links.SetWatcher(bus)
	declared.SetLinker(links)
	containers.SetLinks(links)
	// Les réponses figées datent d'avant la fin de support : le serveur de
	// test démarre avec le réglage coupé, et les tests qui le regardent
	// l'activent. Qu'il soit activé sur une installation neuve se vérifie
	// dans le paquet store.
	preferences := settings.New(db, logger)
	if _, err := preferences.SetLifecycleEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	support := newSupportSource()
	lifecycles := lifecycle.New(containers.Images, machines.Systems, lifecycle.NewFileCache(root), support, preferences.CurrentLifecycleEnabled, logger)
	lifecycles.SetClock(func() time.Time { return testNow })
	lifecycles.SetWatcher(bus)
	lifecycles.SetPause(0)
	publicBus := live.New()
	statusPage := status.New(db, db, machines, logger)
	statusPage.SetClock(func() time.Time { return testNow })
	statusPage.AddWatcher(bus)
	statusPage.AddWatcher(publicBus)
	catalogs, err := lang.Load()
	if err != nil {
		t.Fatal(err)
	}
	alerts := alert.New(db, logger)
	alerts.SetClock(func() time.Time { return testNow })
	alerts.SetWatcher(bus)
	notifier := alert.NewNotifier(db, catalogs, func() lang.Code { return lang.French }, logger)
	notifier.SetClock(func() time.Time { return testNow })
	alerts.SetSender(notifier)
	machines.SetAlerter(alerts)
	heartbeats.SetAlerter(alerts)
	resources.SetAlerter(alerts)
	containers.SetAlerter(alerts)
	probes.SetAlerter(alerts)
	apiTokens := apitoken.New(db, logger)
	apiTokens.SetClock(func() time.Time { return testNow })
	operator := auth.New(db, logger)
	operator.SetAlerter(alerts)
	operator.SetClock(func() time.Time { return testNow })
	// Le coût minimal de bcrypt : le coût réel ferait durer chaque test.
	operator.SetHashCost(bcrypt.MinCost)
	// Le journal d'audit, branché comme dans serve.
	journal := audit.New(db, logger)
	journal.SetClock(func() time.Time { return testNow })
	preferences.SetAuditor(journal)
	machines.SetAuditor(journal)
	heartbeats.SetAuditor(journal)
	probes.SetAuditor(journal)
	declared.SetAuditor(journal)
	links.SetAuditor(journal)
	statusPage.SetAuditor(journal)
	alerts.SetAuditor(journal)
	apiTokens.SetAuditor(journal)
	requests := verbrequest.New(db, logger)
	requests.SetClock(func() time.Time { return testNow })
	requests.SetAuditor(journal)
	requests.SetWatcher(bus)
	operator.SetAuditor(journal)
	// Les ordres, signés par une clé figée : les rendus le sont aussi.
	actions := action.New(db, machines, logger)
	actions.SetClock(func() time.Time { return testNow })
	actions.SetWatcher(bus)
	actions.SetAuditor(journal)
	actions.SetKey(testServerKey(t))
	// La sauvegarde : une vraie boîte à colis sous l'état de test, une phrase
	// scellée à bas coût.
	outbox, err := action.NewOutbox(root)
	if err != nil {
		t.Fatal(err)
	}
	actions.SetOutbox(outbox)
	backups := backup.New(db, machines, root, logger)
	backups.SetClock(func() time.Time { return testNow })
	backups.SetWorkFactor(10)
	// Les passages lancés par une requête suivent la vie du serveur : à la fin
	// du test on l'arrête, puis on attend qu'ils aient fini d'écrire, avant que
	// le dossier d'état soit effacé.
	lifetime, stopServer := context.WithCancel(context.Background())
	backups.SetLifetime(lifetime)
	backups.SetSender(actions)
	backups.SetParcels(outbox)
	backups.SetGuests(db)
	backups.SetWatcher(bus)
	backups.SetAuditor(journal)
	deployer := deploy.New(db, declared, machines, db, db, actions, logger)
	actions.SetServiceUpdates(deployer)
	sshKeys := sshkeys.New(db, logger)
	sshKeys.SetClock(func() time.Time { return testNow })
	systemd := systemdunits.New(db, logger)
	systemd.SetClock(func() time.Time { return testNow })
	systemd.SetWatcher(bus)
	declared.SetUnits(systemd)
	hostConns := hostconn.New()
	hostConns.SetClock(func() time.Time { return testNow })
	hostConns.SetWatcher(bus)
	declared.SetObserver(hostConns)
	roles := role.New(db, logger)
	roles.SetWatcher(bus)
	hypervisors := proxmox.New(db, machines, logger)
	hypervisors.SetClock(func() time.Time { return testNow })
	hypervisors.SetLifetime(lifetime)
	// Restic, branché comme dans serve : l'aperçu lit aussi ce que backup sait,
	// le relais vérifie la preuve de la source et pousse par le serveur.
	resticBackups := restic.New(db, machines, logger)
	resticBackups.SetClock(func() time.Time { return testNow })
	resticBackups.SetSender(actions)
	resticBackups.SetInventory(backups)
	resticBackups.SetWatcher(bus)
	resticBackups.SetAuditor(journal)
	resticBackups.SetAlerter(alerts)
	resticBackups.SetLifetime(lifetime)
	relay := restic.NewBroker(machines, db, nil, logger)
	t.Cleanup(func() {
		stopServer()
		backups.WaitBackground()
		hypervisors.WaitBackground()
		resticBackups.WaitBackground()
	})
	hypervisors.SetWatcher(bus)
	hypervisors.SetAuditor(journal)
	firewalls := firewall.New(db, logger)
	firewalls.SetClock(func() time.Time { return testNow })
	firewalls.SetWatcher(bus)
	firewalls.SetAuditor(journal)
	firewalls.SetConnector(firewall.KindOPNsense, opnsense.New)
	firewalls.SetTranslator(firewall.KindOPNsense, opnsense.Policy)
	backups.SetFirewalls(firewalls)
	server, err := New(Options{
		Logger:          logger,
		Version:         "v0.0.1",
		Reader:          db,
		Settings:        preferences,
		Machines:        machines,
		Heartbeats:      heartbeats,
		Resources:       resources,
		Containers:      containers,
		Probes:          probes,
		Directory:       declared,
		Manifest:        newTestManifest(declared, probes, heartbeats, db, bus, logger),
		Updates:         updates,
		Lifecycle:       lifecycles,
		Status:          statusPage,
		Alerts:          alerts,
		Notifier:        notifier,
		APITokens:       apiTokens,
		VerbRequests:    requests,
		Auth:            operator,
		Actions:         actions,
		SSHKeys:         sshKeys,
		Systemd:         systemd,
		HostConnections: hostConns,
		Links:           links,
		Roles:           roles,
		Host:            machines,
		Proxmox:         hypervisors,
		Firewalls:       firewalls,
		Backups:         backups,
		Restic:          resticBackups,
		ResticAgent:     resticBackups,
		ResticRelay:     relay,
		Deploy:          deployer,
		Live:            bus,
		PublicLive:      publicBus,
		// httptest donne Host: example.com à ses requêtes : c'est l'hôte
		// d'écoute de ce serveur, donc un Host reconnu.
		Listen: "example.com:80",
		Clock:  func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Le serveur commande les agents par leurs flux, comme dans serve.
	containers.SetCommander(server)
	probes.SetCommander(server)
	updates.SetCommander(server)
	actions.SetCommander(server)
	relay.SetPusher(server)
	return &testServer{logs: logs, restic: resticBackups, relay: relay, actions: actions, backups: backups, proxmox: hypervisors, firewalls: firewalls, state: root, Server: server, machines: machines, heartbeats: heartbeats, resources: resources, containers: containers, probes: probes, directory: declared, updates: updates, lifecycle: lifecycles, support: support, status: statusPage, alerts: alerts, notifier: notifier, apiTokens: apiTokens, requests: requests, operator: operator, journal: journal, bus: bus, publicBus: publicBus, db: db, hostConns: hostConns}
}

// logBuffer recueille le journal du serveur de test, écrit par plusieurs
// goroutines.
type logBuffer struct {
	mu      sync.Mutex
	content bytes.Buffer
}

func (b *logBuffer) Write(line []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.content.Write(line)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.content.String()
}

// testServerKey lit une clé du serveur figée, posée dans un fichier comme
// serve la pose : son empreinte est la même d'un passage à l'autre.
func testServerKey(t *testing.T) *action.Key {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	seed := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", ed25519.SeedSize)))
	if err := root.WriteFile(brand.ServerKeyFile, []byte("ed25519-v1:"+seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := action.LoadKey(root)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Enrôle une machine distante avec un id fixe, pour des rendus figés.
func (ts *testServer) enroll(t *testing.T, name, id string) (machine.Machine, ed25519.PrivateKey) {
	t.Helper()
	return storetest.EnrollMachineWithKey(t, ts.machines, id, name)
}

// signaledAt donne à l'agent de la machine son dernier signal à l'instant
// donné : testNow la rend observée, cinq heures plus tôt la perdue.
func (ts *testServer) signaledAt(t *testing.T, machineID string, at time.Time) {
	t.Helper()
	found, err := ts.machines.Get(context.Background(), machineID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.db.TouchAgent(context.Background(), found.Agent.ID, at); err != nil {
		t.Fatal(err)
	}
}

// L'identifiant de la machine distante des tests, fixe pour des rendus figés.
const remoteID = servertest.RemoteID

// L'arbre des routes est figé dans testdata/routes.txt : le modifier est
// une décision, pas un effet de bord.
func TestRoutes_MatchFrozenTree(t *testing.T) {
	server := newTestServer(t)
	var lines []string
	for _, route := range server.routes() {
		lines = append(lines, route.method+" "+route.pattern)
	}
	got := strings.Join(lines, "\n") + "\n"
	want, err := os.ReadFile("testdata/routes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("routes changed:\n%s\nwant:\n%s", got, want)
	}
}
