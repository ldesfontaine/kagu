package agentpolicy

import "testing"

// reported est un agent actif qui a rapporté ces droits.
func reported(t *testing.T, text string) AgentStatus {
	t.Helper()
	rights, err := ParseCapabilities(text)
	if err != nil {
		t.Fatal(err)
	}
	return AgentStatus{Active: true, Reported: true, Rights: rights}
}

// X-24 : un agent révoqué n'a aucun droit, même ceux qu'il a rapportés.
func TestFit_ARevokedAgentLacksEveryRight(t *testing.T) {
	status := reported(t, "docker.deploy,backup.receive=/srv/backups")
	status.Active = false
	for _, right := range []string{CapabilityObserve, CapabilityDockerDeploy, CapabilityBackupReceive} {
		if fit := Fit(status, right, ""); fit.State != FitMissing {
			t.Errorf("%s: %+v, want missing", right, fit)
		}
	}
}

// X-24 : un agent qui n'a pas encore parlé est inconnu ; ce que son jeton
// demandait n'y change rien.
func TestFit_AnAgentThatHasNotSpokenIsUnknown(t *testing.T) {
	status := AgentStatus{Active: true}
	if fit := Fit(status, CapabilityDockerDeploy, ""); fit.State != FitUnknown {
		t.Fatalf("%+v, want unknown", fit)
	}
}

// X-24 : un droit porté que le compte de l'agent ne peut pas exercer est
// inexerçable, avec la raison rapportée ; un autre droit reste permis.
func TestFit_ARightHeldButNotExercisableIsUnavailable(t *testing.T) {
	status := reported(t, "docker.deploy,agent.update")
	status.Unavailable = map[string]string{CapabilityDockerDeploy: "docker_denied"}
	if fit := Fit(status, CapabilityDockerDeploy, ""); fit.State != FitUnavailable || fit.Reason != "docker_denied" {
		t.Fatalf("%+v, want unavailable docker_denied", fit)
	}
	if fit := Fit(status, CapabilityAgentUpdate, ""); fit.State != FitOK || fit.Reason != "" {
		t.Fatalf("%+v, want ok", fit)
	}
}

// La valeur se juge par la portée du droit : un chemin sous celui du droit,
// un producteur nommé ; hors de la portée, le droit manque.
func TestFit_TheValueMustBeCoveredByTheRight(t *testing.T) {
	status := reported(t, "backup.receive=/srv/backups,backup.produce=proxmox-vzdump")
	cases := []struct {
		right, value string
		want         FitState
	}{
		{CapabilityBackupReceive, "/srv/backups/nuit", FitOK},
		{CapabilityBackupReceive, "/srv/backups2", FitMissing},
		{CapabilityBackupReceive, "/srv/backups/../etc", FitMissing},
		{CapabilityBackupProduce, ProducerProxmoxVzdump, FitOK},
		{CapabilityBackupProduce, "pg-dump", FitMissing},
		{CapabilityFilesWrite, "/srv/backups", FitMissing},
	}
	for _, c := range cases {
		if fit := Fit(status, c.right, c.value); fit.State != c.want {
			t.Errorf("%s=%s: %+v, want %s", c.right, c.value, fit, c.want)
		}
	}
}
