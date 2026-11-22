#!/bin/sh
# Compare le relevé de dupl (fragments copiés par fichier) à la liste des
# copies admises, scripts/dupl-admises.txt : « chemin nombre », une ligne par
# fichier. Un fichier en plus ou un compte qui monte échoue ; un compte qui
# baisse demande de mettre la liste à jour. Un échange ne passe donc pas.
# Usage : dupl-releve.sh <releve dupl -plumbing, sur l'entrée standard>
set -eu
admises="$(dirname "$0")/dupl-admises.txt"

sed 's/:.*//' | sort | uniq -c | awk '{ print $2, $1 }' |
	awk -v admises="$admises" '
		BEGIN { while ((getline ligne < admises) > 0) { split(ligne, champs, " "); admis[champs[1]] = champs[2] } }
		{ today[$1] = $2 }
		END {
			for (path in today) {
				if (!(path in admis)) { print path " : " today[path] " fragments, absent de la liste"; bad = 1 }
				else if (today[path] > admis[path]) { print path " : " today[path] " fragments, la liste dit " admis[path]; bad = 1 }
			}
			for (path in admis) {
				if (today[path] < admis[path]) { print path " : " today[path] + 0 " fragments, la liste dit encore " admis[path] " : la mettre à jour"; bad = 1 }
			}
			exit bad
		}'
