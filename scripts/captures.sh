#!/bin/bash
# Prend toutes les pages de l'application, en mode sombre, sur ordinateur et
# téléphone, et laisse la branche captures/etape-NN (docs seulement).
#
#   scripts/captures.sh <commit> <NN>      aller-retour sur la VM d'essai
#   scripts/captures.sh --garde <fichier>  garde des données réelles sur un fichier
#
# Le serveur de démo (TestE2EFixtureServer, données fictives, horloge figée)
# tourne sur la VM d'essai, joint par un tunnel SSH : jamais l'installation de
# l'opérateur. Environnement :
#   CAPTURES_VM          cible SSH de la VM d'essai (obligatoire) ; « local »
#                        lance le serveur de démo sur cette machine (essai)
#   CAPTURES_NAMES_FILE  noms de machines réels à refuser, un par ligne
#                        (défaut ~/.config/kagu/captures-noms-reels.txt). Hors
#                        du dépôt : le dépôt est miroité en public.
#   CAPTURES_PORT        port du serveur de démo et du tunnel (défaut 18893)
#   CAPTURES_GOARCH      architecture de la VM (défaut amd64)
# étape: … / résultat: … / exit 0 fait, 1 échoué, 2 refusé
set -euo pipefail
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C

readonly vm="${CAPTURES_VM:-}"
readonly names_file="${CAPTURES_NAMES_FILE:-$HOME/.config/kagu/captures-noms-reels.txt}"
readonly port="${CAPTURES_PORT:-18893}"
readonly goarch="${CAPTURES_GOARCH:-amd64}"

refuse() {
	echo "résultat: refusé — $1" >&2
	exit 2
}

fail() {
	echo "résultat: échoué — $1" >&2
	exit 1
}

# Les motifs interdits, un par ligne, lus par grep -E et par le spec
# (RegExp, insensible à la casse) : le domaine de l'opérateur, son plan privé
# (les adresses en dix point dix), et chaque nom de machine du fichier (échappé, lu comme du texte).
write_patterns() {
	local target="$1"
	[ -r "$names_file" ] || refuse "le fichier des noms réels est absent : $names_file"
	{
		echo 'ldesfontaine'
		echo '(^|[^0-9.])10\.10\.'
		sed -e '/^[[:space:]]*$/d' -e 's/[][\.*^$+?(){}|/]/\\&/g' -- "$names_file"
	} >"$target"
}

# Échoue si le fichier contient un motif interdit ; dit les lignes fautives.
check_guard() {
	local patterns="$1" file="$2"
	if grep -n -E -i -f "$patterns" -- "$file"; then
		fail "$file porte des données réelles (lignes ci-dessus)"
	fi
	echo "étape: garde des données réelles — $file propre"
}

if [ "${1:-}" = "--garde" ]; then
	[ "$#" -eq 2 ] || refuse "usage : captures.sh --garde <fichier>"
	patterns="$(mktemp)"
	trap 'rm -f -- "$patterns"' EXIT
	write_patterns "$patterns"
	check_guard "$patterns" "$2"
	exit 0
fi

[ "$#" -eq 2 ] || refuse "usage : captures.sh <commit> <NN>"
[ -n "$vm" ] || refuse "CAPTURES_VM n'est pas posée (la VM d'essai, ou « local »)"
[[ "$2" =~ ^[0-9]{2}$ ]] || refuse "NN s'écrit sur deux chiffres : $2"
[[ "$port" =~ ^[0-9]+$ ]] || refuse "CAPTURES_PORT n'est pas un port : $port"
readonly stage="$2"
readonly branch="captures/etape-$stage"
commit="$(git rev-parse --verify --short "$1^{commit}")" || refuse "commit inconnu : $1"
readonly commit
git show-ref --verify --quiet "refs/heads/$branch" && refuse "la branche $branch existe déjà"

work="$(mktemp -d "${TMPDIR:-/tmp}/captures.XXXXXX")"
readonly work
readonly tree="$work/arbre"
patterns="$work/motifs-interdits.txt"
tunnel_pid=""
remote_dir="captures-kagu"
local_pid=""

cleanup() {
	[ -z "$tunnel_pid" ] || kill "$tunnel_pid" 2>/dev/null || true
	if [ "$vm" = "local" ]; then
		[ -z "$local_pid" ] || kill "$local_pid" 2>/dev/null || true
	else
		ssh -- "$vm" "[ -f $remote_dir/pid ] && kill \$(cat $remote_dir/pid); rm -rf $remote_dir" 2>/dev/null || true
	fi
	git worktree remove --force "$tree" 2>/dev/null || true
	rm -rf -- "$work"
}
trap cleanup EXIT

write_patterns "$patterns"

echo "étape: arbre du commit $commit sur la branche $branch"
git worktree add -q -b "$branch" "$tree" "$commit"
[ -f "$tree/web/e2e/captures-toutes.spec.ts" ] || fail "le commit $commit n'a pas web/e2e/captures-toutes.spec.ts"

echo "étape: front et serveur de démo ($goarch)"
(cd "$tree" && make front >/dev/null && GOARCH="$goarch" go test -c -o web/e2e/.fixture.test ./internal/edge/server)

echo "étape: serveur de démo sur $vm"
if [ "$vm" = "local" ]; then
	(cd "$tree/web/e2e" && KAGU_E2E_ADDR="127.0.0.1:$port" ./.fixture.test -test.run TestE2EFixtureServer -test.timeout 0 >"$work/serveur.log" 2>&1 &
		echo $! >"$work/pid")
	local_pid="$(cat "$work/pid")"
else
	ssh -- "$vm" "mkdir -p $remote_dir/tmp"
	scp -q -- "$tree/web/e2e/.fixture.test" "$vm:$remote_dir/fixture.test"
	ssh -- "$vm" "cd $remote_dir && chmod 700 tmp && TMPDIR=\$PWD/tmp KAGU_E2E_ADDR=127.0.0.1:$port nohup ./fixture.test -test.run TestE2EFixtureServer -test.timeout 0 >serveur.log 2>&1 </dev/null & echo \$! >pid" || fail "le serveur de démo ne démarre pas sur $vm"
	ssh -N -L "$port:127.0.0.1:$port" -- "$vm" &
	tunnel_pid=$!
fi
for _ in $(seq 1 60); do
	curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
	sleep 1
done
curl -fsS -o /dev/null "http://127.0.0.1:$port/" || fail "le serveur de démo ne répond pas sur 127.0.0.1:$port"

echo "étape: captures"
(cd "$tree/web" && npx playwright install chromium >/dev/null &&
	KAGU_E2E_EXTERNAL=1 KAGU_E2E_ADDR="127.0.0.1:$port" E2E_CAPTURES=1 \
		CAPTURES_FORBIDDEN_FILE="$patterns" CAPTURES_COMMIT="$commit" CAPTURES_DATE="$(date -u +%F)" \
		npx playwright test --config e2e/playwright.config.ts captures-toutes) || fail "le spec des captures a échoué"

check_guard "$patterns" "$tree/docs/captures.md"

echo "étape: commit sur $branch (docs seulement)"
(cd "$tree" && git add -A -- docs/captures docs/captures.md)
outside="$(cd "$tree" && git status --porcelain | grep -v -E '^[AMD] +docs/captures(/|\.md$)' || true)"
[ -z "$outside" ] || fail "des fichiers hors docs/captures bougent : $outside"
(cd "$tree" && git commit -q -m "docs(captures): toutes les pages à l'étape $stage ($commit)")
echo "résultat: fait — branche $branch, à fusionner (docs seulement)"
