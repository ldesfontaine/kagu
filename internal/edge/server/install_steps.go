package server

import (
	"strings"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/version"
)

// Les étapes de l'installation d'un agent, dans l'ordre où on les colle sur la
// machine. Chaque bloc se joue seul, d'un coup ; le front en dit le titre
// d'après l'identifiant.
const (
	stepStop    = "stop"
	stepBinary  = "binary"
	stepPrepare = "prepare"
	stepEnroll  = "enroll"
	stepUnit    = "unit"
	stepRights  = "rights"
)

// installTarget dit pour quelle machine le jeton est émis : local, la machine
// Kagu, dont le binaire est celui que le serveur a installé et non une
// copie dans /tmp ; reenroll, une machine qui a déjà un agent.
type installTarget struct {
	local    bool
	reenroll bool
	// Les ancres de confiance locales que la ligne d'enrôlement pose.
	anchors map[string][]string
}

// installSteps donne les étapes : l'arrêt de l'agent en place (un
// ré-enrôlement seulement), le binaire (sauf sur la machine Kagu, qui
// l'a déjà), la préparation, l'enrôlement, l'unité, et les dossiers que les
// droits autorisent (seulement quand un droit écrit hors de l'état). Le jeton
// n'est que dans l'enrôlement. L'unité vient après lui : elle relit
// l'identité que le premier lancement a écrite.
func installSteps(publicURL, token string, code lang.Code, capabilities []agentpolicy.Capability, target installTarget) []installStepJSON {
	var steps []installStepJSON
	if target.reenroll {
		steps = append(steps, installStepJSON{ID: stepStop, Command: installStop()})
	}
	if !target.local {
		steps = append(steps, installStepJSON{ID: stepBinary, Command: installBinary()})
	}
	steps = append(steps,
		installStepJSON{ID: stepPrepare, Command: installPreparation(capabilities, version.Number(), target.local)},
		installStepJSON{ID: stepEnroll, Command: installCommand(publicURL, token, code, capabilities, target.anchors)},
		installStepJSON{ID: stepUnit, Command: installUnit()},
	)
	if rights := installRights(capabilities); rights != "" {
		steps = append(steps, installStepJSON{ID: stepRights, Command: rights})
	}
	return steps
}

// installStop arrête l'agent en place et oublie son identité : le jeton neuf
// en crée une autre, et la préparation se joue agent arrêté.
func installStop() string {
	return "systemctl stop " + brand.AgentUnit + "\nrm -f " + brand.AgentStateDir + "/" + brand.AgentIdentityFile
}

// installBinary télécharge le binaire publié de cette version et vérifie sa
// somme (machine.ReleaseDownloadLines) : le serveur n'offre pas le sien par
// HTTP, et rien n'est supposé déjà copié sur la machine.
func installBinary() string {
	return strings.Join(machine.ReleaseDownloadLines(version.Number()), "\n")
}

// installUnit pose l'unité de l'agent et l'active. Le contenu est celui de
// machine.AgentUnitLines ; l'heredoc entre apostrophes ne laisse le shell rien
// interpréter.
func installUnit() string {
	lines := []string{"cat > " + machine.UnitFile + " <<'EOF'"}
	lines = append(lines, machine.AgentUnitLines()...)
	lines = append(lines,
		"EOF",
		"systemctl daemon-reload",
		"systemctl enable --now "+brand.AgentUnit,
	)
	return strings.Join(lines, "\n")
}

// installRights autorise, dans un drop-in de l'unité, les dossiers où les
// droits écrivent (machine.RightsDropInLines) : sans lui, l'agent accepte
// l'ordre et ne peut pas écrire. Vide quand aucun droit n'écrit ailleurs que
// dans l'état. Les chemins sont normalisés : ils passent entre apostrophes.
func installRights(capabilities []agentpolicy.Capability) string {
	dropIn := machine.RightsDropInLines(machine.RightFolders(capabilities, brand.WorkspaceRoot))
	if dropIn == nil {
		return ""
	}
	return strings.Join([]string{
		"install -d -m 0755 " + machine.UnitDropInDir,
		printfLines(dropIn) + " | install -m 0644 /dev/stdin " + machine.RightsDropInFile,
		"systemctl daemon-reload",
		"systemctl restart " + brand.AgentUnit,
	}, "\n")
}
