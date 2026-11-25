package agentwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
)

// serverSamples sont les paramètres que le serveur fabrique pour chaque genre,
// par json.Marshal du type (internal/domain, internal/gesture/action), avec
// des valeurs qui éprouvent l'encodage : balises HTML, retours à la ligne,
// non-ASCII, U+2028. nil : le genre n'a pas de paramètres.
func serverSamples(t *testing.T) map[Kind]any {
	t.Helper()
	certificatePEM, _, _ := publicCertificate(t)
	files := []ParcelFile{{Name: "db.sql.age", Size: 42, SHA256: strings.Repeat("ab", 32)}}
	docker := DockerParams{
		ServiceID: "svc_1", Project: "wiki", Compose: "services:\n  app:\n    image: \"a<b>&c\"\n",
		DataDirs: []string{"app"}, EnvSent: true, Rollback: &ServiceRollback{HealthWindowSeconds: 300, StableSeconds: 120},
	}
	guest := ProxmoxGuestParams{VMID: 101, Type: GuestQEMU, Snapshot: "kagu-1"}
	return map[Kind]any{
		KindAgentPing:     nil,
		KindAgentUpdate:   AgentUpdateParams{Version: "v0.0.1", Parcel: "p1", Binary: "kagu", Files: files},
		KindAgentRollback: nil,
		KindBackupReceive: BackupReceiveParams{Parcel: "p1", Path: "/srv/receive", Files: files, Archive: ArchiveGuest},
		KindBackupPrune:   BackupPruneParams{Path: "/srv/receive", Prefix: "plan-é", Keep: 7},
		KindBackupProduce: BackupProduceParams{
			Producer: agentpolicy.ProducerProxmoxVzdump, Target: "5012", Prefix: "p", Recipient: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p", Parcel: "p2",
		},
		KindDockerDeploy:          docker,
		KindDockerUpdate:          DockerParams{ServiceID: "svc_1", Project: "wiki", Compose: "x y"},
		KindDockerRollback:        DockerRollbackParams{Project: "wiki"},
		KindProxmoxStart:          ProxmoxGuestParams{VMID: 101, Type: GuestLXC},
		KindProxmoxShutdown:       ProxmoxGuestParams{VMID: 999999999, Type: GuestQEMU},
		KindProxmoxSnapshot:       ProxmoxGuestParams{VMID: 101, Type: GuestQEMU},
		KindProxmoxSnapshotDelete: guest,
		KindResticTargetSetup: ResticTargetSetupParams{
			Listen: "0.0.0.0", Port: 8000, Hosts: []string{"nas.lan", "10.0.0.2"}, RetentionFloor: &ResticRetentionFloor{KeepDaily: 7},
		},
		KindResticUserAdd:    ResticUserAddParams{User: "m-abc"},
		KindResticUserRemove: ResticUserRemoveParams{User: "m-abc"},
		KindResticProvision:  ResticProvisionParams{Target: "m-abc", Host: "nas.lan", Port: 8000, User: "m-def", Certificate: certificatePEM},
		KindResticBackup: ResticBackupParams{
			Target: "m-abc", Scope: ResticScopeService, Service: "wiki", ForceRelay: true, Volumes: []string{"wiki_data"}, Databases: []string{"wiki-db"},
		},
		KindResticRetain:  ResticRetainParams{User: "m-abc", KeepLast: 3, KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 6, KeepYearly: 1},
		KindResticVerify:  ResticVerifyParams{User: "m-abc"},
		KindResticBrowse:  ResticBrowseParams{User: "m-abc", Snapshot: "abcd1234", Path: "/srv/<wiki>"},
		KindResticRestore: ResticRestoreParams{Target: "m-abc", Snapshot: "abcd1234", Path: "/srv/wiki", Stamp: "20261122-1200"},
		KindRightRequest:  RightRequestParams{Right: agentpolicy.CapabilityBackupProduce, Value: agentpolicy.ProducerProxmoxVzdump},
	}
}

// serverSecrets sont les secrets que le serveur signe avec les genres qui en
// portent.
var serverSecrets = map[Kind]any{
	KindDockerDeploy:    DockerSecret{Env: "A=<b>&c\nB=é"},
	KindDockerUpdate:    DockerSecret{Env: "A=1\n"},
	KindResticUserAdd:   ResticUserSecret{RESTPassword: "p"},
	KindResticProvision: ResticProvisionSecret{RESTPassword: "p", RepoPassword: "q"},
	KindResticRetain:    ResticRetainSecret{RepoPassword: "q"},
	KindResticVerify:    ResticVerifySecret{RepoPassword: "q"},
	KindResticBrowse:    ResticBrowseSecret{RepoPassword: "q"},
}

func encodeSample(t *testing.T, sample any) json.RawMessage {
	t.Helper()
	if sample == nil {
		return nil
	}
	encoded, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestR_A1_1_EachKindIsDeclaredOnceInTheRegistry(t *testing.T) {
	seen := map[Kind]bool{}
	for _, kind := range OrderKinds() {
		if seen[kind] {
			t.Errorf("%s is declared twice", kind)
		}
		seen[kind] = true
		spec, _ := SpecOf(kind)
		// Le droit est fixe, ou calculé sur l'ordre décodé : jamais les deux,
		// jamais aucun (R-A1-1).
		if (spec.Right == "") == (spec.rightOf == nil) || spec.decodeParams == nil {
			t.Errorf("%s: incomplete declaration", kind)
		}
		for _, check := range spec.Anchors {
			if _, known := anchor.Lookup(check.Anchor); !known {
				t.Errorf("%s is bounded by %q, which is not an anchor kind", kind, check.Anchor)
			}
		}
	}
	// Les observations ne sont pas signées : elles restent hors du registre.
	for _, kind := range []Kind{KindLogs, KindLogsStop, KindProbes, KindImages, KindResticRelay} {
		if kind.IsOrder() {
			t.Errorf("%s is an observation, not an order", kind)
		}
	}
	if len(seen) != len(serverSamples(t)) {
		t.Errorf("%d kinds, %d samples: every kind has its sample, and only kinds do", len(seen), len(serverSamples(t)))
	}
}

// Aller-retour : pour chaque genre, Marshal(Decode(x)) == x sur ce que le
// serveur produit.
func TestR_A1_2_ParamsAreReencodedToTheSignedBytes(t *testing.T) {
	samples := serverSamples(t)
	for _, kind := range OrderKinds() {
		sample, known := samples[kind]
		if !known {
			t.Errorf("%s: no sample of what the server sends", kind)
			continue
		}
		encoded := encodeSample(t, sample)
		order, err := Decode(kind, encoded)
		if err != nil {
			t.Errorf("%s: %s does not read back: %v", kind, encoded, err)
			continue
		}
		if sample == nil {
			if order.Params != nil {
				t.Errorf("%s: params out of nothing: %v", kind, order.Params)
			}
			continue
		}
		if again := encodeSample(t, order.Params); !bytes.Equal(again, encoded) {
			t.Errorf("%s: %s re-encodes as %s", kind, encoded, again)
		}
	}
	// Le même contenu, autrement écrit, ne passe pas.
	indented, _ := json.MarshalIndent(samples[KindBackupProduce], "", " ")
	if _, err := Decode(KindBackupProduce, indented); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("an indented body passes: %v", err)
	}
}

// field est une clé du premier niveau d'un JSON, avec sa valeur telle qu'écrite.
type field struct {
	name  string
	value json.RawMessage
}

func topLevelFields(t *testing.T, raw json.RawMessage) []field {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	var fields []field
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field{name: token.(string), value: value})
	}
	return fields
}

func writeFields(fields []field) json.RawMessage {
	parts := make([]string, 0, len(fields))
	for _, one := range fields {
		name, _ := json.Marshal(one.name)
		parts = append(parts, string(name)+":"+string(one.value))
	}
	return json.RawMessage("{" + strings.Join(parts, ",") + "}")
}

// keyVariants rend, d'un corps canonique, les écritures que R-A1-3 refuse :
// chacune garde le contenu lisible, aucune n'est ce que json.Marshal écrit.
func keyVariants(t *testing.T, canonical json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	fields := topLevelFields(t, canonical)
	first := fields[0]
	upper := field{name: strings.ToUpper(first.name), value: first.value}
	variants := map[string]json.RawMessage{
		"unknown key":                   writeFields(append(slices.Clone(fields), field{name: "extra", value: json.RawMessage(`1`)})),
		"first key repeated":            writeFields(append(slices.Clone(fields), first)),
		"first key of another case":     writeFields(append(slices.Clone(fields), upper)),
		"only the other case":           writeFields(append([]field{upper}, fields[1:]...)),
		"space after the brace":         json.RawMessage("{ " + string(canonical[1:])),
		"newline at the end":            json.RawMessage(string(canonical) + "\n"),
		"escaped key":                   json.RawMessage(`{"\u00` + hexOf(first.name[0]) + first.name[1:] + string(canonical[len(first.name)+2:])),
		"a second value after the body": json.RawMessage(string(canonical) + "{}"),
	}
	if len(fields) > 1 {
		swapped := slices.Clone(fields)
		swapped[0], swapped[1] = swapped[1], swapped[0]
		variants["keys in another order"] = writeFields(swapped)
	}
	return variants
}

func hexOf(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}

func TestR_A1_3_AnyKeyVariantIsABadOrderForEveryKind(t *testing.T) {
	samples := serverSamples(t)
	for _, kind := range OrderKinds() {
		canonical := encodeSample(t, samples[kind])
		if canonical == nil {
			for _, written := range []string{`{}`, `null`, ` `} {
				if _, err := Decode(kind, json.RawMessage(written)); !errors.Is(err, ErrNotCanonical) {
					t.Errorf("%s takes no params, %q passes: %v", kind, written, err)
				}
			}
			continue
		}
		for name, variant := range keyVariants(t, canonical) {
			if _, err := Decode(kind, variant); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("%s, %s: %s passes: %v", kind, name, variant, err)
			}
		}
	}
}

// B-H1 réglé en amont des ancres : une clé ambiguë ne présente aucune valeur,
// donc l'ordre sort de chaque ancre de son genre, sans en nommer une autre.
func TestR_A1_7_AnAmbiguousKeyPresentsNoValueToAnyAnchor(t *testing.T) {
	samples := serverSamples(t)
	for _, kind := range OrderKinds() {
		spec, _ := SpecOf(kind)
		if len(spec.Anchors) == 0 {
			continue
		}
		canonical := encodeSample(t, samples[kind])
		clean, err := Decode(kind, canonical)
		if err != nil {
			t.Fatal(err)
		}
		for _, offer := range clean.Presented() {
			if offer.Value == "" {
				t.Errorf("%s: the clean sample presents nothing to %s", kind, offer.Name)
			}
		}
		for name, variant := range keyVariants(t, canonical) {
			presented := PresentedOf(kind, variant)
			if len(presented) != len(spec.Anchors) {
				t.Errorf("%s, %s: %d anchors judged, %d declared", kind, name, len(presented), len(spec.Anchors))
			}
			for _, offer := range presented {
				if offer.Value != "" {
					t.Errorf("%s, %s: %q presented to %s", kind, name, offer.Value, offer.Name)
				}
			}
		}
	}
}

// B-M1 : restic.backup présente son vmid à backup.guest en portée vm ; la
// portée service ne lui présente rien (pas une valeur vide, qui sortirait de
// l'ancre) ; des paramètres illisibles lui présentent une valeur vide.
func TestR_A1_7_ResticBackupPresentsItsGuestOnlyInTheVMScope(t *testing.T) {
	encode := func(params ResticBackupParams) json.RawMessage { return encodeSample(t, params) }
	vm := PresentedOf(KindResticBackup, encode(ResticBackupParams{Target: "m-abc", Scope: ResticScopeVM, VMID: 105, GuestType: GuestQEMU}))
	if len(vm) != 1 || vm[0].Name != anchor.BackupGuest || vm[0].Value != "105" {
		t.Fatalf("vm scope: %+v", vm)
	}
	if service := PresentedOf(KindResticBackup, encode(ResticBackupParams{Target: "m-abc", Scope: ResticScopeService, Service: "wiki"})); len(service) != 0 {
		t.Fatalf("service scope: %+v", service)
	}
	unreadable := PresentedOf(KindResticBackup, json.RawMessage(`{"target":"m-abc","scope":"vm","scope":"service"}`))
	if len(unreadable) != 1 || unreadable[0].Value != "" {
		t.Fatalf("unreadable params: %+v", unreadable)
	}
}

// Le journal et les ancres nomment des champs que le type porte vraiment.
func TestRegistry_JournalNamesRealFields(t *testing.T) {
	samples := serverSamples(t)
	for _, kind := range OrderKinds() {
		spec, _ := SpecOf(kind)
		var names []string
		if samples[kind] != nil {
			typ := reflect.TypeOf(samples[kind])
			for index := range typ.NumField() {
				names = append(names, strings.Split(typ.Field(index).Tag.Get("json"), ",")[0])
			}
		}
		for _, name := range spec.Journal {
			if !slices.Contains(names, name) {
				t.Errorf("%s journals %q, which is not one of its fields %v", kind, name, names)
			}
		}
	}
}

func TestDecodeSecret_ReadsTheSecretStrictly(t *testing.T) {
	for _, kind := range OrderKinds() {
		secret, carries := serverSecrets[kind]
		if !carries {
			if _, err := DecodeSecret(kind, json.RawMessage(`{"rest_password":"p"}`)); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("%s carries no secret, one passes: %v", kind, err)
			}
			continue
		}
		canonical := encodeSample(t, secret)
		decoded, err := DecodeSecret(kind, canonical)
		if err != nil {
			t.Errorf("%s: the server's secret is refused: %v", kind, err)
		}
		if !reflect.DeepEqual(decoded, secret) {
			t.Errorf("%s: decoded %#v, sent %#v", kind, decoded, secret)
		}
		for name, variant := range keyVariants(t, canonical) {
			if _, err := DecodeSecret(kind, variant); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("%s secret, %s: passes: %v", kind, name, err)
			}
		}
	}
	for kind := range serverSecrets {
		if spec, _ := SpecOf(kind); spec.decodeSecret == nil {
			t.Errorf("%s: a secret sample for a kind that declares none", kind)
		}
	}
	if decoded, err := DecodeSecret(KindDockerDeploy, nil); err != nil || decoded != nil {
		t.Fatalf("an absent secret is the executor's call: %v %v", decoded, err)
	}
}

func TestDecode_AKindOutsideTheRegistryIsNotAnOrder(t *testing.T) {
	for _, kind := range []Kind{KindLogs, KindResticRelay, "docker.purge", ""} {
		if _, err := Decode(kind, json.RawMessage(`{}`)); !errors.Is(err, ErrNotAnOrder) {
			t.Errorf("%q: %v", kind, err)
		}
		if _, err := DecodeSecret(kind, nil); !errors.Is(err, ErrNotAnOrder) {
			t.Errorf("%q secret: %v", kind, err)
		}
	}
}

// looseFields rend les champs d'un type qui laisseraient deux écritures pour
// une même valeur, ou une valeur que le réencodage change : un nombre à
// virgule, un json.RawMessage, une carte, une interface.
func looseFields(typ reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if typ == reflect.TypeFor[json.RawMessage]() {
		return []string{path + " is a json.RawMessage"}
	}
	switch typ.Kind() {
	case reflect.Float32, reflect.Float64:
		return []string{path + " is a float"}
	case reflect.Map:
		return []string{path + " is a map"}
	case reflect.Interface:
		return []string{path + " is an interface"}
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return looseFields(typ.Elem(), path+"[]", seen)
	case reflect.Struct:
		if seen[typ] {
			return nil
		}
		seen[typ] = true
		var found []string
		for index := range typ.NumField() {
			one := typ.Field(index)
			found = append(found, looseFields(one.Type, path+"."+one.Name, seen)...)
		}
		return found
	}
	return nil
}

func TestR_A1_8_NoParamTypeHasAFloatARawMessageOrAFreeMap(t *testing.T) {
	samples := serverSamples(t)
	types := map[reflect.Type]bool{}
	for _, kind := range OrderKinds() {
		if samples[kind] == nil {
			continue
		}
		order, err := Decode(kind, encodeSample(t, samples[kind]))
		if err != nil {
			t.Fatal(err)
		}
		types[reflect.TypeOf(order.Params)] = true
	}
	for _, secret := range serverSecrets {
		types[reflect.TypeOf(secret)] = true
	}
	for typ := range types {
		for _, loose := range looseFields(typ, typ.Name(), map[reflect.Type]bool{}) {
			t.Error(loose)
		}
	}
	// Le témoin : le parcours voit chacune des quatre fautes, même enfouie.
	type nested struct {
		Ratio float64
		Extra map[string]string
	}
	type faulty struct {
		Raw   json.RawMessage
		Any   any
		Inner []*nested
	}
	if found := looseFields(reflect.TypeFor[faulty](), "faulty", map[reflect.Type]bool{}); len(found) != 4 {
		t.Fatalf("the walk sees %v", found)
	}
}

func TestStrictDecode_ReadsTheEnvelopeAndRefusesAnotherWriting(t *testing.T) {
	body := OrderBody{RunID: "r1", MachineID: "m", AgentID: "a", Kind: KindAgentPing, NotAfter: 10, Seq: 1,
		Params: json.RawMessage(`{"a":"<b>"}`), Secret: json.RawMessage(`{"env":"A=1"}`)}
	encoded, _ := json.Marshal(body)
	var read OrderBody
	if err := StrictDecode(encoded, &read); err != nil || read.RunID != "r1" {
		t.Fatalf("the server's envelope: %+v %v", read, err)
	}
	for name, variant := range keyVariants(t, encoded) {
		var again OrderBody
		if err := StrictDecode(variant, &again); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("envelope, %s: passes: %v", name, err)
		}
	}
}

// Ce que l'agent annonce est le registre, chaque genre à son numéro, et rien
// d'autre ; le serveur relit l'en-tête tel que l'agent l'écrit (R-B2-8).
func TestR_B2_8_TheAgentAnnouncesItsRegistry(t *testing.T) {
	announced := AnnouncedKinds()
	if len(announced) != len(OrderKinds()) {
		t.Fatalf("%d kinds announced, %d in the registry", len(announced), len(OrderKinds()))
	}
	for _, kind := range OrderKinds() {
		spec, _ := SpecOf(kind)
		if spec.Revision < 1 || !announced.Announces(string(kind), spec.Revision) {
			t.Errorf("%s: revision %d, announced %v", kind, spec.Revision, announced[string(kind)])
		}
	}
	read, err := machine.ParseOrderKinds(announced.Format())
	if err != nil || read.Format() != announced.Format() {
		t.Fatalf("the server reads %v, %v", read, err)
	}
}
