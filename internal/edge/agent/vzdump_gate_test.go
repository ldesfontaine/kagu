package agent

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// gateExchange joue une connexion de la porte : la demande, le pair admis ou
// non, un faux vzdump qui note qu'il a été lancé. Rend les trames reçues.
func gateExchange(t *testing.T, request string, allowedPeer bool) (launched [][]string, header string, data []byte, end gateEnd) {
	t.Helper()
	server, client := net.Pipe()
	launch := func(_ context.Context, args []string, stdout, stderr io.Writer) (int, error) {
		launched = append(launched, args)
		_, _ = io.WriteString(stdout, "VMA")
		_, _ = io.WriteString(stderr, "INFO: Starting Backup of VM 105 (lxc)\n")
		return 0, nil
	}
	done := make(chan error, 1)
	go func() {
		done <- serveVzdumpGate(context.Background(), server, allowedPeer, launch)
		_ = server.Close()
	}()
	go func() { _, _ = client.Write([]byte(request)) }()
	reader := bufio.NewReader(client)
	for {
		kind, payload, err := readGateFrame(reader)
		if err != nil {
			break
		}
		switch kind {
		case gateFrameHeader:
			header = string(payload)
		case gateFrameData:
			data = append(data, payload...)
		case gateFrameEnd:
			end, err = decodeGateEnd(payload)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = client.Close()
	<-done
	return launched, header, data, end
}

// Une demande de la forme fermée lance vzdump avec les options de la porte,
// et rend le flux, le type de l'invité et le code de sortie.
func TestT0409_VzdumpGate_AClosedRequestRunsVzdumpWithItsFixedOptions(t *testing.T) {
	for _, compress := range machine.VzdumpGateCompressions() {
		launched, header, data, end := gateExchange(t, "105 "+compress+"\n", true)
		want := []string{"105", "--mode", "snapshot", "--compress", compress, "--stdout", "--quiet", "1"}
		if len(launched) != 1 || !slices.Equal(launched[0], want) {
			t.Fatalf("launched %q, want %q", launched, want)
		}
		if header != gateAccepted || string(data) != "VMA" || end.Code != 0 || end.Guest != guestLXC {
			t.Fatalf("header %q data %q end %+v", header, data, end)
		}
	}
}

// Toute demande hors de la forme fermée est refusée sans que vzdump se lance :
// une option en plus, --script, un numéro qui n'en est pas un, une compression
// hors de la liste, une ligne trop longue. Un pair qui n'est ni root ni le
// compte de l'agent (le serveur, membre du groupe) aussi.
func TestT0409_VzdumpGate_AnythingOutsideTheClosedFormRunsNothing(t *testing.T) {
	for name, request := range map[string]string{
		"an extra option":       "105 zstd --script /tmp/x\n",
		"script as compression": "105 --script\n",
		"hook":                  "105 zstd --hook=/tmp/x\n",
		"dumpdir":               "105 --dumpdir=/root\n",
		"storage":               "105 0 --storage local\n",
		"a name, not a number":  "web zstd\n",
		"a negative number":     "-105 zstd\n",
		"an option as guest":    "--all zstd\n",
		"compression off list":  "105 gzip\n",
		"two spaces":            "105  zstd\n",
		"a tab":                 "105\tzstd\n",
		"nothing":               "\n",
		"too long":              strings.Repeat("1", maxGateRequestBytes+8) + " zstd\n",
		"guest too long":        "1234567890 zstd\n",
	} {
		launched, header, data, _ := gateExchange(t, request, true)
		if len(launched) != 0 || header != gateRefused || len(data) != 0 {
			t.Errorf("%s: launched %q, header %q", name, launched, header)
		}
	}
	launched, header, _, _ := gateExchange(t, "105 zstd\n", false)
	if len(launched) != 0 || header != gateRefused {
		t.Errorf("a foreign peer: launched %q, header %q", launched, header)
	}
}

// Le client lit une porte qui refuse comme gate_denied, rien de lancé.
func TestT0409_VzdumpGate_TheClientSaysARefusal(t *testing.T) {
	socket := serveFakeGate(t, func(context.Context, []string, io.Writer, io.Writer) (int, error) {
		t.Error("vzdump ran")
		return 0, nil
	})
	var out bytes.Buffer
	_, err := vzdumpGateClient{socket: socket}.dump(context.Background(), "105", "gzip", &out)
	if result := resultOf("run", nil, err); result.Reason != agentwire.ReasonGateDenied || out.Len() != 0 {
		t.Fatalf("result %+v (%v)", result, err)
	}
}

// Un ordre backup.produce que la porte refuse en route finit gate_denied,
// refusé, pas producer_failed : vzdump n'a pas tourné.
func TestT0409_VzdumpGate_ARefusalMidOrderKeepsItsReason(t *testing.T) {
	socket := serveFakeGate(t, func(context.Context, []string, io.Writer, io.Writer) (int, error) { return 0, nil })
	b := newProduceRig(t)
	runner := vzdumpProducer{gate: vzdumpGateClient{socket: socket}}
	// La porte juge la ligne : une cible que l'agent laisserait passer à tort
	// est refusée chez elle.
	b.useProducer(producer{validTarget: func(string) bool { return true }, run: func(ctx context.Context, request producerRequest) (producerResult, error) {
		request.target = "105 --script"
		return runner.run(ctx, request)
	}})
	results := b.run(t, 1, produceParams(b.identity))
	final := results[len(results)-1]
	if final.State != agentwire.ActionRefused || final.Reason != agentwire.ReasonGateDenied {
		t.Fatalf("results %+v", results)
	}
}

// grantBenchOnHost est un banc de politique sur un hôte où vzdump existe ou non.
func grantBenchOnHost(t *testing.T, hasVzdump bool) *policyBench {
	t.Helper()
	b := newPolicyBench(t)
	b.system.files[machine.VzdumpBinary] = hasVzdump
	return b
}

// La porte n'est posée que si backup.produce=proxmox-vzdump est accordé ET
// que vzdump existe : ni sans le droit, ni sans vzdump.
func TestT0409_VzdumpGate_LaidOnlyWithTheRightAndVzdump(t *testing.T) {
	withoutRight := grantBenchOnHost(t, true)
	withoutRight.grant(t, "backup.receive=/srv/backups")
	withoutVzdump := grantBenchOnHost(t, false)
	withoutVzdump.grant(t, "backup.produce=proxmox-vzdump")
	for name, b := range map[string]*policyBench{"without the right": withoutRight, "without vzdump": withoutVzdump} {
		if len(b.system.units) != 0 || slices.ContainsFunc(b.system.take(), isGateGesture) {
			t.Errorf("%s: the gate was laid: %v", name, b.system.units)
		}
	}

	b := grantBenchOnHost(t, true)
	change := b.grant(t, "backup.produce=proxmox-vzdump")
	group := currentGroup(t)
	want := []string{
		"unit " + machine.VzdumpGateSocketUnit, "unit " + machine.VzdumpGateServiceUnit,
		"systemctl daemon-reload",
		"systemctl enable " + machine.VzdumpGateSocketUnit,
		"systemctl restart " + machine.VzdumpGateSocketUnit,
	}
	if done := b.system.take(); !slices.Equal(done, want) {
		t.Fatalf("laid %q\nwant %q", done, want)
	}
	if !slices.Equal(kindsOf(change.Laid), []PrerequisiteKind{PrerequisiteVzdumpGate}) {
		t.Fatalf("laid %v: the gate does not restart the agent", kindsOf(change.Laid))
	}
	if b.system.units[machine.VzdumpGateSocketUnit] != string(machine.UnitContent(machine.VzdumpGateSocketLines(group))) ||
		b.system.units[machine.VzdumpGateServiceUnit] != string(machine.UnitContent(machine.VzdumpGateServiceLines())) {
		t.Fatalf("units %v", b.system.units)
	}
	// Déjà posée telle quelle : rien à refaire.
	b.grant(t, "backup.produce=proxmox-vzdump")
	if done := b.system.take(); len(done) != 0 {
		t.Fatalf("a second grant laid %q", done)
	}
}

// revoke retire la porte : la socket arrêtée, les deux unités ôtées.
func TestT0409_VzdumpGate_RevokeRemovesIt(t *testing.T) {
	b := grantBenchOnHost(t, true)
	b.grant(t, "backup.produce=proxmox-vzdump")
	b.system.take()
	change, err := RevokeRights(b.opts, []string{"backup.produce"}, accept)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl disable --now " + machine.VzdumpGateSocketUnit,
		"remove " + machine.UnitDir + "/" + machine.VzdumpGateSocketUnit,
		"remove " + machine.UnitDir + "/" + machine.VzdumpGateServiceUnit,
		"systemctl daemon-reload",
	}
	if done := b.system.take(); !slices.Equal(done, want) {
		t.Fatalf("laid %q\nwant %q", done, want)
	}
	if len(b.system.units) != 0 || !slices.Equal(kindsOf(change.Laid), []PrerequisiteKind{PrerequisiteVzdumpGateRemoved}) {
		t.Fatalf("units %v, laid %v", b.system.units, kindsOf(change.Laid))
	}
}

// Une machine préparée avant la porte perd la règle sudo, le script de root
// et produce.conf au premier grant, puis l'agent est relancé : il retrouve
// NoNewPrivileges=true.
func TestT0409_VzdumpGate_TheOldSudoPreparationIsRemoved(t *testing.T) {
	b := grantBenchOnHost(t, true)
	for _, path := range machine.LegacyProducePreparation() {
		b.system.files[path] = true
	}
	b.system.dropIns["produce.conf"] = "[Service]\nNoNewPrivileges=false\n"
	change := b.grant(t, "backup.produce=proxmox-vzdump")
	done := b.system.take()
	var removed []string
	for _, gesture := range done {
		if path, ok := strings.CutPrefix(gesture, "remove "); ok {
			removed = append(removed, path)
		}
	}
	if !slices.Equal(removed, machine.LegacyProducePreparation()) {
		t.Fatalf("removed %q", removed)
	}
	if !slices.Contains(kindsOf(change.Laid), PrerequisiteLegacySudoRemoved) || done[len(done)-1] != "systemctl try-restart kagu-agent.service" {
		t.Fatalf("laid %v: %q", kindsOf(change.Laid), done)
	}
	for _, step := range change.Prerequisites {
		if step.Kind == PrerequisiteOtherDropIn {
			t.Fatalf("produce.conf is said to stay: %+v", step)
		}
	}
	// Le reste parti, le grant suivant n'a plus rien à retirer.
	b.system.dropIns = map[string]string{}
	b.grant(t, "backup.produce=proxmox-vzdump")
	if done := b.system.take(); len(done) != 0 {
		t.Fatalf("a second grant laid %q", done)
	}
}

// R-B1-16 et décision du 26/11 : avec backup.produce accordé sur un hôte
// Proxmox, grant ne pose aucun produce.conf ni aucun drop-in qui desserre
// l'unité : l'agent garde NoNewPrivileges=true et aucune capacité.
func TestT0409_VzdumpGate_TheAgentUnitStaysHardenedWithTheRight(t *testing.T) {
	b := grantBenchOnHost(t, true)
	b.system.proxmox = true
	b.grantSet(t, "root")
	for name, content := range b.system.dropIns {
		if name != "droits.conf" || strings.Contains(content, "NoNewPrivileges") || strings.Contains(content, "Capabilit") {
			t.Fatalf("drop-in %s: %q", name, content)
		}
	}
	for _, gesture := range b.system.take() {
		if strings.Contains(gesture, "produce.conf") || strings.Contains(gesture, "sudoers") {
			t.Fatalf("laid %q", gesture)
		}
	}
	if len(b.system.units) != 2 {
		t.Fatalf("the gate is not laid: %v", b.system.units)
	}
	lines := machine.AgentUnitLines()
	if !slices.Contains(lines, "NoNewPrivileges=true") || !slices.Contains(lines, "CapabilityBoundingSet"+"=") {
		t.Fatal("the agent unit lost its hardening")
	}
}

func isGateGesture(gesture string) bool {
	return strings.Contains(gesture, machine.VzdumpGateSocketUnit) || strings.Contains(gesture, machine.VzdumpGateServiceUnit)
}

// currentGroup est le groupe principal du compte du test, qui possède l'état
// du banc : la socket de la porte lui est ouverte.
func currentGroup(t *testing.T) string {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return group.Name
}
