package agentpolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

var grantedAt = time.Date(2026, 11, 24, 14, 42, 0, 0, time.UTC)

const boot = "9a6c1d2e-0b7f-4e3a-8c5d-1f2e3a4b5c6d"

// R-A3-2 : la politique porte la machine, les droits, les ancres et la clé du
// serveur acceptée, une seule ; deux seulement le temps d'un --keep-old,
// l'ancienne avec son échéance et l'horloge de sa pose. Elle s'écrit et se
// relit à l'identique ; tout autre nombre ou forme de clé la rend illisible.
func TestR_A3_2_ThePolicyCarriesMachineRightsAnchorsAndOneKey(t *testing.T) {
	accepted, kept := testKey(t), testKey(t)
	document := Document{MachineID: "m", Rights: []Capability{{Name: CapabilityObserve}, {Name: CapabilityFilesWrite, Paths: []string{"/srv/a", "/srv/b"}}},
		Anchors: map[string][]string{"backup.guest": {"5012"}}}.SetServerKey(accepted)
	content, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(content)
	if err != nil || !decoded.Same(document) {
		t.Fatalf("round trip:\n%s\n%+v %v", content, decoded, err)
	}
	if !strings.Contains(string(content), "[[server_key]]\nkey = '"+base64.StdEncoding.EncodeToString(accepted)+"'") {
		t.Fatalf("the key is not written as §5 says:\n%s", content)
	}

	rotated, err := document.SetServerKey(kept).KeepServerKey(accepted, time.Hour, Clock{Now: grantedAt, Boot: boot, Uptime: 51234 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	content, err = Encode(rotated)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = Decode(content)
	if err != nil || !decoded.Same(rotated) || len(decoded.ServerKeys) != 2 || !decoded.ServerKeys[1].Until.Equal(grantedAt.Add(time.Hour)) {
		t.Fatalf("round trip with a kept key:\n%s\n%+v %v", content, decoded, err)
	}
	for _, want := range []string{"until = 2026-11-24T15:42:00Z", "granted_at = 2026-11-24T14:42:00Z", "granted_boot = '" + boot + "'", "granted_uptime = 51234"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("%q missing:\n%s", want, content)
		}
	}

	key := func(raw []byte) string {
		return "[[server_key]]\nkey = '" + base64.StdEncoding.EncodeToString(raw) + "'\n"
	}
	keptBlock := "until = 2026-11-24T15:42:00Z\ngranted_at = 2026-11-24T14:42:00Z\ngranted_boot = 'b'\n"
	unreadable := map[string]string{
		"three keys":              key(accepted) + key(kept) + keptBlock + key(testKey(t)) + keptBlock,
		"an expiry on the first":  key(accepted) + keptBlock,
		"a second without expiry": key(accepted) + key(kept),
		"a second without boot":   key(accepted) + key(kept) + "until = 2026-11-24T15:42:00Z\ngranted_at = 2026-11-24T14:42:00Z\n",
		"the same key twice":      key(accepted) + key(accepted) + keptBlock,
		"a short key":             "[[server_key]]\nkey = 'c2hvcnQ='\n",
		"not base64":              "[[server_key]]\nkey = 'pas une clé'\n",
		"an unknown field":        key(accepted) + "comment = 'x'\n",
	}
	for name, block := range unreadable {
		if _, err := Decode([]byte("version = 1\nmachine_id = 'm'\n" + block)); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if decoded, err := Decode([]byte("version = 1\nmachine_id = 'm'\n")); err != nil || len(decoded.ServerKeys) != 0 {
		t.Fatalf("no key at all reads, and accepts nothing: %+v %v", decoded, err)
	}
}

// R-A3-14 : set ne laisse qu'une clé ; --keep-old garde l'acceptée avec son
// échéance, de 5 minutes à 7 jours, et fait tomber une clé gardée plus tôt.
func TestKeepServerKey_KeepsTheAcceptedOneWithinTheBounds(t *testing.T) {
	first, second, third := testKey(t), testKey(t), testKey(t)
	clock := Clock{Now: grantedAt, Boot: boot, Uptime: time.Hour}
	document := Document{MachineID: "m"}
	if _, err := document.KeepServerKey(second, time.Hour, clock); !errors.Is(err, ErrNoServerKeyToKeep) {
		t.Fatalf("nothing to keep: %v", err)
	}
	document = document.SetServerKey(first)
	for _, duration := range []time.Duration{0, MinDuration - time.Second, MaxDuration + time.Second} {
		if _, err := document.KeepServerKey(second, duration, clock); !errors.Is(err, ErrDurationOutOfBounds) {
			t.Errorf("%v: %v", duration, err)
		}
	}
	if _, err := document.KeepServerKey(first, time.Hour, clock); !errors.Is(err, ErrServerKeyAlreadyAccepted) {
		t.Fatalf("the same key: %v", err)
	}
	kept, err := document.KeepServerKey(second, MaxDuration, clock)
	if err != nil || len(kept.ServerKeys) != 2 || !slices.Equal(kept.ServerKeys[0].Key, second) || !slices.Equal(kept.ServerKeys[1].Key, first) {
		t.Fatalf("kept %+v %v", kept, err)
	}
	again, err := kept.KeepServerKey(third, MinDuration, clock)
	if err != nil || len(again.ServerKeys) != 2 || !slices.Equal(again.ServerKeys[1].Key, second) {
		t.Fatalf("a second keep-old drops the first kept key: %+v %v", again, err)
	}
	if set := again.SetServerKey(first); len(set.ServerKeys) != 1 || !slices.Equal(set.ServerKeys[0].Key, first) {
		t.Fatalf("set %+v", set.ServerKeys)
	}
}

// R-A3-5, QA-12 : une échéance tombe à l'heure ; depuis le même démarrage,
// aussi quand le temps monotone écoulé dépasse sa durée, même si l'heure
// affichée a reculé ; après un redémarrage, seule l'heure compte, et une pose
// dans le futur tombe.
func TestLapsed_FollowsTheMonotonicClock(t *testing.T) {
	granted := Clock{Now: grantedAt, Boot: boot, Uptime: time.Hour}
	until := grantedAt.Add(10 * time.Minute)
	cases := []struct {
		name string
		now  Clock
		want bool
	}{
		{"just granted", granted, false},
		{"before the hour", Clock{Now: until.Add(-time.Second), Boot: boot, Uptime: time.Hour + 10*time.Minute - time.Second}, false},
		{"at the hour", Clock{Now: until, Boot: boot, Uptime: time.Hour + 10*time.Minute}, true},
		{"clock moved back an hour", Clock{Now: grantedAt.Add(-50 * time.Minute), Boot: boot, Uptime: time.Hour + 10*time.Minute}, true},
		{"clock moved back, time left", Clock{Now: grantedAt.Add(-50 * time.Minute), Boot: boot, Uptime: time.Hour + 9*time.Minute}, false},
		{"rebooted, before the hour", Clock{Now: grantedAt.Add(5 * time.Minute), Boot: "other", Uptime: time.Minute}, false},
		{"rebooted, granted in the future", Clock{Now: grantedAt.Add(-time.Minute), Boot: "other", Uptime: time.Minute}, true},
		{"no monotonic clock", Clock{Now: grantedAt.Add(5 * time.Minute)}, false},
	}
	for _, c := range cases {
		if got := Lapsed(until, granted, c.now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if Lapsed(time.Time{}, granted, Clock{Now: grantedAt.Add(1000 * time.Hour)}) {
		t.Fatal("no expiry lapsed")
	}
	document := Document{ServerKeys: []ServerKey{{Key: testKey(t)}, {Key: testKey(t), Until: until, Granted: granted}}}
	if live := document.LiveServerKeys(granted); len(live) != 2 {
		t.Fatalf("live %d", len(live))
	}
	if live := document.LiveServerKeys(Clock{Now: until, Boot: boot}); len(live) != 1 {
		t.Fatalf("lapsed key still live: %d", len(live))
	}
}

// Les lignes de la clé du serveur et de la migration : une commande, rien
// d'enchaîné (R-A3-15), toujours « trust set » (N-M2).
func TestServerKeyLine_IsAlwaysTrustSet(t *testing.T) {
	key := testKey(t)
	if got, want := ServerKeyLine(key), "sudo opencloud agent trust set server-key "+base64.StdEncoding.EncodeToString(key); got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if got := MigrateLine(); got != "sudo opencloud agent policy migrate" {
		t.Fatalf("%q", got)
	}
}

// Migrate recopie à l'identique ; une clé mal formée ne passe pas.
func TestMigrate_CopiesWhatIdentityHeld(t *testing.T) {
	key := testKey(t)
	legacy := Legacy{MachineID: "m", Rights: []Capability{{Name: CapabilityObserve}}, Anchors: map[string][]string{"backup.guest": {"1"}}, ServerKey: key}
	document := Migrate(legacy)
	if document.MachineID != "m" || len(document.ServerKeys) != 1 || !slices.Equal(document.ServerKeys[0].Key, key) || document.Anchors["backup.guest"][0] != "1" {
		t.Fatalf("%+v", document)
	}
	legacy.ServerKey = []byte("short")
	if document := Migrate(legacy); len(document.ServerKeys) != 0 {
		t.Fatalf("a malformed key was copied: %+v", document.ServerKeys)
	}
}
