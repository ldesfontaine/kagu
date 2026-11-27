#!/bin/bash
# Le lancement distant rend la main vite et pose le pid du serveur dans
# <dossier>/pid. Un faux ssh exécute la commande en local ; un faux
# fixture.test dort. Rouge si la sortie reste ouverte (ssh ne rend pas la
# main) ou si le pid n'est pas celui du serveur.
# Usage : scripts/captures-serveur-test.sh      exit 0 vert, 1 rouge
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sandbox="$(mktemp -d)"
server_pid=""
cleanup() {
	[ ! -s "$sandbox/home/local.pid" ] || kill "$(cat "$sandbox/home/local.pid")" 2>/dev/null || true
	[ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
	rm -rf -- "$sandbox"
}
trap cleanup EXIT

mkdir -p "$sandbox/bin" "$sandbox/home/captures-kagu/tmp"
cat >"$sandbox/bin/ssh" <<'FAKE'
#!/bin/bash
# ssh -- <hôte> <commande> : la commande passe par un shell, comme sur la VM.
shift
shift
exec bash -c "$*"
FAKE
chmod +x "$sandbox/bin/ssh"
printf '#!/bin/bash\nexec sleep 300\n' >"$sandbox/home/captures-kagu/fixture.test"
chmod +x "$sandbox/home/captures-kagu/fixture.test"

# Les mêmes variables en lecture seule que captures.sh, avant de sourcer : un
# `local` du même nom dans une fonction échoue, et le `|| fail` de l'appelant
# masque son code. read rend la main quand tous les écrivains ont fermé la
# sortie ; s'il en reste un ouvert au bout de 30 s (le code dépasse 128), ssh
# ne rendrait pas la main.
set +e
read -r -d '' -t 30 _ < <(HOME="$sandbox/home" PATH="$sandbox/bin:$PATH" bash -c '
	readonly vm=banc port=18999 remote_dir=captures-kagu goarch=amd64 work=/nulle-part tree=/nulle-part/arbre
	source "$1"
	cd "$HOME"
	start_remote_server "$vm" "$remote_dir" "$port"
	echo "code=$?"
	start_local_server "$HOME/captures-kagu" "$port" "$HOME/local.log" "$HOME/local.pid"
	echo "code=$?"
' _ "$here/captures-serveur.sh" 2>&1 | tee "$sandbox/sortie")
status=$?
set -e
if [ "$status" -gt 128 ]; then
	echo "ROUGE : le lancement distant garde la sortie ouverte après 30 s" >&2
	exit 1
fi
if grep -q "readonly variable" "$sandbox/sortie"; then
	echo "ROUGE : une fonction déclare un local du nom d'une variable de captures.sh :" >&2
	cat "$sandbox/sortie" >&2
	exit 1
fi
if [ "$(grep -c '^code=0$' "$sandbox/sortie")" -ne 2 ]; then
	echo "ROUGE : une fonction de lancement rend un code non nul :" >&2
	cat "$sandbox/sortie" >&2
	exit 1
fi

pidfile="$sandbox/home/captures-kagu/pid"
if [ ! -s "$pidfile" ]; then
	echo "ROUGE : $pidfile n'existe pas (le pid est écrit ailleurs)" >&2
	exit 1
fi
server_pid="$(cat "$pidfile")"
if ! tr '\0' ' ' <"/proc/$server_pid/cmdline" | grep -q '^sleep 300'; then
	echo "ROUGE : le pid $server_pid n'est pas celui du serveur" >&2
	exit 1
fi
echo "VERT : ssh a rendu la main, pid $server_pid = le serveur, écrit dans captures-kagu/pid"
