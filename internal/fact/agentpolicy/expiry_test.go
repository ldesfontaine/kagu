package agentpolicy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// grantFor pose ces droits avec ce terme sur l'horloge granted, puis relit la
// politique écrite : ce que l'agent lira.
func grantFor(t *testing.T, document Document, rights string, term Term, granted Clock) Document {
	t.Helper()
	capabilities, err := ParsePolicyRights(rights)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := document.Grant(capabilities, term, granted)
	if err != nil {
		t.Fatal(err)
	}
	content, err := Encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(content)
	if err != nil || !decoded.Same(changed) {
		t.Fatalf("round trip:\n%s\n%v", content, err)
	}
	return decoded
}

func holds(document Document, name string, now Clock) bool {
	rights, _ := document.LiveRights(now)
	return HasCapability(rights, name)
}

// R-A3-5, N-F5 : « grant observe.env --for 10m », puis l'horloge affichée
// recule d'une heure : le droit tombe quand dix minutes d'horloge monotone
// ont passé depuis sa pose, quelle que soit l'heure affichée.
func TestR_A3_5_ARightFallsAtItsMonotonicDurationEvenWithTheClockSetBack(t *testing.T) {
	granted := Clock{Now: grantedAt, Boot: boot, Uptime: 51234 * time.Second}
	document := grantFor(t, Document{MachineID: "m"}, CapabilityObserveEnv, Term{Duration: 10 * time.Minute}, granted)
	expiry := document.Expiries[CapabilityObserveEnv]
	if !expiry.Until.Equal(grantedAt.Add(10*time.Minute)) || expiry.Granted != granted {
		t.Fatalf("expiry %+v", expiry)
	}
	setBack := func(elapsed time.Duration) Clock {
		return Clock{Now: grantedAt.Add(-time.Hour + elapsed), Boot: boot, Uptime: granted.Uptime + elapsed}
	}
	if !holds(document, CapabilityObserveEnv, setBack(10*time.Minute-time.Second)) {
		t.Fatal("the right fell before its ten minutes")
	}
	if holds(document, CapabilityObserveEnv, setBack(10*time.Minute)) {
		t.Fatal("a clock set back an hour kept the right alive after ten monotonic minutes")
	}
	rights, until := document.LiveRights(setBack(10 * time.Minute))
	if FormatCapabilities(rights) != CapabilityObserve || len(until) != 0 {
		t.Fatalf("observe stays, alone: %v %v", rights, until)
	}
	if _, until := document.LiveRights(granted); !until[CapabilityObserveEnv].Equal(expiry.Until) {
		t.Fatalf("the live expiry is not reported: %v", until)
	}
}

// R-A3-5, N-F5 : après un redémarrage, l'horloge monotone ne se compare plus ;
// l'heure seule compte, et un droit dont granted_at est dans le futur tombe :
// l'horloge a été reculée.
func TestR_A3_5_AFutureGrantedAtAfterRebootFalls(t *testing.T) {
	granted := Clock{Now: grantedAt, Boot: boot, Uptime: time.Hour}
	document := grantFor(t, Document{MachineID: "m"}, "terminal.host", Term{Duration: time.Hour}, granted)
	rebooted := func(now time.Time) Clock { return Clock{Now: now, Boot: "rebooted", Uptime: time.Minute} }
	if !holds(document, CapabilityTerminalHost, rebooted(grantedAt.Add(30*time.Minute))) {
		t.Fatal("after a reboot, a right before its hour fell")
	}
	if holds(document, CapabilityTerminalHost, rebooted(grantedAt.Add(-time.Second))) {
		t.Fatal("after a reboot, a right granted in the future still holds")
	}
	if holds(document, CapabilityTerminalHost, rebooted(grantedAt.Add(time.Hour))) {
		t.Fatal("after a reboot, a right past its hour still holds")
	}
}

// R-A3-5, N-F5 : sur une machine dont l'horloge monotone ne se lit plus, un
// droit à durée déjà posé est échu, même avant son heure, et une clé gardée
// aussi ; aucune échéance ne s'y pose, par --for, par la durée d'un droit ou
// par -keep-old. Un droit sans échéance tient.
func TestR_A3_5_WithoutTheMonotonicClockAnExpiryFailsClosed(t *testing.T) {
	granted := Clock{Now: grantedAt, Boot: boot, Uptime: time.Hour}
	document := grantFor(t, Document{MachineID: "m"}, "terminal.host,docker.deploy", Term{}, granted)
	unreadable := Clock{Now: grantedAt.Add(time.Minute)}
	if holds(document, CapabilityTerminalHost, unreadable) {
		t.Fatal("without the monotonic clock, a right with an expiry still holds")
	}
	if !holds(document, CapabilityDockerDeploy, unreadable) {
		t.Fatal("without the monotonic clock, a right without expiry fell")
	}
	if !Lapsed(grantedAt.Add(time.Hour), granted, Clock{Now: grantedAt, Uptime: time.Hour}) {
		t.Fatal("an uptime without boot_id was taken for the monotonic clock")
	}
	kept, err := document.SetServerKey(testKey(t)).KeepServerKey(testKey(t), time.Hour, granted)
	if err != nil {
		t.Fatal(err)
	}
	if live := kept.LiveServerKeys(unreadable); len(live) != 1 {
		t.Fatalf("without the monotonic clock, the kept key still holds: %d keys", len(live))
	}

	rights, err := ParsePolicyRights("terminal.host")
	if err != nil {
		t.Fatal(err)
	}
	for _, term := range []Term{{Duration: time.Hour}, {}} {
		if _, err := document.Grant(rights, term, unreadable); !errors.Is(err, ErrNoMonotonicClock) {
			t.Errorf("term %+v without the monotonic clock: %v", term, err)
		}
	}
	if _, err := kept.KeepServerKey(testKey(t), time.Hour, unreadable); !errors.Is(err, ErrNoMonotonicClock) {
		t.Errorf("-keep-old without the monotonic clock: %v", err)
	}
	permanent, err := document.Grant(rights, Term{Permanent: true}, unreadable)
	if err != nil || !holds(permanent, CapabilityTerminalHost, unreadable) {
		t.Fatalf("a permanent grant without the monotonic clock: %v", err)
	}
}

// R-A3-5 : de cinq minutes à sept jours, ou permanent ; sans --for, chaque
// droit prend sa durée (terminal.host : deux heures, les autres : sans
// échéance). Un grant sans durée retire l'échéance, revoke aussi.
func TestGrant_TermsAndTheirBounds(t *testing.T) {
	clock := Clock{Now: grantedAt, Boot: boot, Uptime: time.Hour}
	for _, text := range []string{"0", "4m59s", "168h1s", "-5m", "7d", "soon"} {
		if _, err := ParseTerm(text); !errors.Is(err, ErrDurationOutOfBounds) {
			t.Errorf("%q: %v", text, err)
		}
	}
	for text, want := range map[string]Term{"": {}, "permanent": {Permanent: true}, "5m": {Duration: MinDuration}, "168h": {Duration: MaxDuration}} {
		if got, err := ParseTerm(text); err != nil || got != want {
			t.Errorf("%q: %+v %v", text, got, err)
		}
	}
	if _, err := (Document{MachineID: "m"}).Grant(nil, Term{Duration: time.Minute}, clock); !errors.Is(err, ErrDurationOutOfBounds) {
		t.Fatalf("an out of bounds term passed: %v", err)
	}

	document := grantFor(t, Document{MachineID: "m"}, "terminal.host,docker.deploy", Term{}, clock)
	if until := document.Expiries[CapabilityTerminalHost].Until; !until.Equal(grantedAt.Add(2 * time.Hour)) {
		t.Fatalf("terminal.host without --for: %v", until)
	}
	if _, bounded := document.Expiries[CapabilityDockerDeploy]; bounded {
		t.Fatal("docker.deploy without --for got an expiry")
	}
	document = grantFor(t, document, "terminal.host", Term{Permanent: true}, clock)
	if _, bounded := document.Expiries[CapabilityTerminalHost]; bounded {
		t.Fatal("--for permanent kept an expiry")
	}
	document = grantFor(t, document, "docker.deploy,observe", Term{Duration: MinDuration}, clock)
	if _, bounded := document.Expiries[CapabilityObserve]; bounded || len(document.Expiries) != 1 {
		t.Fatalf("expiries %v", document.Expiries)
	}
	revoked, err := document.Revoke([]string{CapabilityDockerDeploy})
	if err != nil || len(revoked.Expiries) != 0 {
		t.Fatalf("revoke kept the expiry: %v %v", revoked.Expiries, err)
	}
}

// Une échéance s'écrit entière ou pas du tout ; observe n'en porte pas.
func TestDecode_RefusesAHalfExpiry(t *testing.T) {
	head := "version = 1\nmachine_id = 'm'\n[[right]]\nname = "
	for name, block := range map[string]string{
		"until alone":         "'docker.deploy'\nuntil = 2026-11-24T15:42:00Z\n",
		"no boot":             "'docker.deploy'\nuntil = 2026-11-24T15:42:00Z\ngranted_at = 2026-11-24T14:42:00Z\n",
		"clock without until": "'docker.deploy'\ngranted_at = 2026-11-24T14:42:00Z\ngranted_boot = 'b'\n",
		"on observe":          "'observe'\nuntil = 2026-11-24T15:42:00Z\ngranted_at = 2026-11-24T14:42:00Z\ngranted_boot = 'b'\n",
	} {
		if _, err := Decode([]byte(head + block)); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Le pré-jugement du serveur : un droit qui échoit avant la fin de l'ordre
// ne suffit pas.
func TestHeldThrough_ARightThatLapsesBeforeTheOrderIsNotHeld(t *testing.T) {
	rights := []Capability{{Name: CapabilityObserve}, {Name: CapabilityDockerDeploy}}
	until := map[string]time.Time{CapabilityDockerDeploy: grantedAt}
	if !HeldThrough(rights, until, CapabilityDockerDeploy, grantedAt) || !HeldThrough(rights, nil, CapabilityDockerDeploy, grantedAt.Add(time.Hour)) {
		t.Fatal("a right held through the order was refused")
	}
	if HeldThrough(rights, until, CapabilityDockerDeploy, grantedAt.Add(time.Second)) || HeldThrough(rights, until, CapabilityFilesWrite, grantedAt) {
		t.Fatal("a right lapsing before not_after, or absent, was held")
	}
}

// Les échéances rapportées par l'agent : un nom connu, une fois, une heure.
func TestRightsUntil_RoundTripAndRefusals(t *testing.T) {
	until := map[string]time.Time{CapabilityTerminalHost: grantedAt, CapabilityObserveEnv: grantedAt.Add(time.Hour)}
	text := FormatRightsUntil(until)
	if text != "observe.env=1795534920,terminal.host=1795531320" {
		t.Fatalf("%q", text)
	}
	parsed, err := ParseRightsUntil(text)
	if err != nil || len(parsed) != 2 || !parsed[CapabilityTerminalHost].Equal(grantedAt) {
		t.Fatalf("%v %v", parsed, err)
	}
	for _, bad := range []string{"everything=1", "terminal.host", "terminal.host=soon", "terminal.host=-1", "terminal.host=1,terminal.host=2", strings.Repeat("x", 3000)} {
		if _, err := ParseRightsUntil(bad); !errors.Is(err, ErrRightsUntilUnreadable) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
