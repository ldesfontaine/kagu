package update

import (
	"github.com/ldesfontaine/kagu/internal/fact/container"
	"github.com/ldesfontaine/kagu/internal/kit/shell"
)

// Command fabrique ce que l'opérateur tapera pour appliquer la mise à
// jour ; Kagu ne l'exécute jamais. Un service Compose se tire et se
// recrée depuis son dossier ; un conteneur lancé à la main se tire
// seulement : le recréer demande ses options, que Kagu ne connaît
// pas. Vide sans mise à jour : la garde contre une rétrogradation est
// dans le constat, qui ne nomme qu'un tag strictement plus récent.
func Command(found container.Container, check Check) string {
	if !check.HasUpdate() {
		return ""
	}
	if found.ComposeService != "" && found.ComposeDir != "" {
		return "cd " + shell.Quote(found.ComposeDir) + " && docker compose pull " + shell.Quote(found.ComposeService) +
			" && docker compose up -d " + shell.Quote(found.ComposeService)
	}
	return "docker pull " + shell.Quote(check.Target())
}
