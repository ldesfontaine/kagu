#!/bin/sh
# Installe Kagu sur cette machine, en root (fiche B1). Deux usages :
#   curl -fsSL <adresse des versions>/v<version>/install.sh -o install.sh
#   sudo sh install.sh [options de setup]
# installe la machine Kagu et lance setup (R-B1-14) ;
#   curl -fsSL <adresse des versions>/install.sh |
#     sudo sh -s -- join --server https://… --server-key SHA256:… --rights <jeu>
# ajoute une machine et lance join (R-B1-12) : la ligne vient de l'écran,
# le script toujours de l'adresse des versions, jamais de serve.
# Télécharge la version, vérifie la signature globale de minisign (celle qui
# couvre le commentaire de confiance, où est écrite la version) avec les clés
# écrites ci-dessous, refuse une version plus ancienne que MIN_VERSION, vérifie
# les sommes, puis installe le binaire et lance setup ou join. Rien ne s'écrit
# hors d'un dossier temporaire avant que tout soit vérifié.
# Seul le commentaire de confiance est signé : la version ne se lit jamais
# dans une adresse ni dans un nom de fichier.
# join prend la version à la bibliothèque de serve quand l'adresse des
# versions ne répond pas : un serveur n'est qu'une source de fichiers, vérifiés
# par les mêmes clés (N-M8). Aucun jeton ne passe par ce script : join le lit
# sur le terminal ou dans --token-file.
set -eu

# La version de ce script, écrite à sa publication (release.yml). Vide : le
# script n'est pas publié et refuse.
MIN_VERSION=""
# Les clés de version de internal/kit/release/key.go, la courante et la
# secours : une version de remède signée par la secours passe aussi.
# TestInstallScriptCarriesTheEmbeddedKeys les compare.
CURRENT_KEY="RWR3td9Uebbdsc6fVgCOun/FNjBDAx5QCbN8hjrKBPtW47xwkbf1F+o3"
BACKUP_KEY="RWRNylnietSsacsUhEFv/jr4jIpQUo57JaIHu4VQWBI9jvb1rZ9aOcau"

# L'adresse des versions, réglable ; setup l'écrit dans config.toml.
KAGU_RELEASES=${KAGU_RELEASES:-https://github.com/ldesfontaine/kagu/releases/download}

# Les noms de brand (internal/kit/brand), que TestInstallScriptNamesAreTheBrands
# compare.
BINARY_PREFIX="kagu-linux-"
SUMS_FILE="SHA256SUMS"
SIGNATURE_FILE="SHA256SUMS.minisig"
INSTALLED_BINARY="/usr/local/bin/kagu"
KEPT_DIR="/var/lib/kagu-setup/release"

fail() {
	printf 'install.sh : %s\n' "$*" >&2
	exit 1
}

# hex_bytes affiche en hexadécimal count octets de file à partir de skip.
hex_bytes() {
	od -An -tx1 -j "$2" -N "$3" "$1" | tr -d ' \n'
}

machine_arch() {
	case $(uname -m) in
	x86_64) echo amd64 ;;
	aarch64) echo arm64 ;;
	*) fail "architecture non prise en charge : $(uname -m)" ;;
	esac
}

download() {
	curl -fsSL --proto-redir '=https' -o "$work/$1" "$base/$1" ||
		fail "téléchargement impossible : $base/$1"
}

# server_argument rend la valeur de --server (ou -server, la forme des options
# de Go), écrite « --server X » ou « --server=X ».
server_argument() {
	while [ $# -gt 0 ]; do
		case $1 in
		--server=* | -server=*) echo "${1#*=}"; return 0 ;;
		--server | -server) [ $# -ge 2 ] && { echo "$2"; return 0; } ;;
		esac
		shift
	done
	return 1
}

# choose_source fixe base, d'où viendront les trois fichiers, sur la réponse
# de l'adresse des versions pour les sommes. join se replie sur la bibliothèque
# de serve ; setup n'a pas de repli.
choose_source() {
	base="${KAGU_RELEASES%/}/v$MIN_VERSION"
	if curl -fsL --proto-redir '=https' -o "$work/$SUMS_FILE" "$base/$SUMS_FILE" 2>/dev/null; then
		printf "Version prise à l'adresse des versions : %s\n" "$base"
		return 0
	fi
	[ "$mode" = join ] || fail "téléchargement impossible : $base/$SUMS_FILE"
	server=$(server_argument "$@") ||
		fail "adresse des versions injoignable ($base) et pas de --server pour la bibliothèque"
	base="${server%/}/releases/v$MIN_VERSION"
	printf 'Adresse des versions injoignable : version prise à la bibliothèque du serveur, %s\n' "$base"
	download "$SUMS_FILE"
}

# decode_line écrit la ligne line du .minisig, décodée, dans file, et refuse
# une autre taille que size.
decode_line() {
	sed -n "$1p" "$work/$SIGNATURE_FILE" | base64 -d >"$2" 2>/dev/null ||
		fail "signature mal formée (ligne $1)"
	[ "$(wc -c <"$2")" -eq "$3" ] || fail "signature mal formée (ligne $1)"
}

# read_signature contrôle la forme du .minisig (quatre lignes, préfixes, pas
# de retour chariot, algorithme pré-haché « ED ») et en tire les morceaux.
read_signature() {
	file="$work/$SIGNATURE_FILE"
	[ "$(wc -l <"$file")" -eq 4 ] || fail "signature mal formée : quatre lignes attendues"
	! grep -q "$(printf '\r')" "$file" || fail "signature mal formée : retour chariot"
	case $(sed -n 1p "$file") in "untrusted comment: "*) ;; *) fail "signature mal formée : ligne 1" ;; esac
	trusted_line=$(sed -n 3p "$file")
	case $trusted_line in "trusted comment: "*) ;; *) fail "signature mal formée : ligne 3" ;; esac
	trusted_comment=${trusted_line#"trusted comment: "}
	decode_line 2 "$work/header" 74
	decode_line 4 "$work/global.sig" 64
	# « ED » : pré-haché par BLAKE2b-512 ; « Ed », l'ancien, est refusé.
	[ "$(hex_bytes "$work/header" 0 2)" = 4544 ] || fail "signature refusée : algorithme non pré-haché"
	tail -c 64 "$work/header" >"$work/sums.sig"
	{ cat "$work/sums.sig"; printf '%s' "$trusted_comment"; } >"$work/global.msg"
}

# signer_key rend la clé dont l'identifiant est celui de la signature.
signer_key() {
	wanted=$(hex_bytes "$work/header" 2 8)
	for key in "$CURRENT_KEY" "$BACKUP_KEY"; do
		[ -n "$key" ] || continue
		printf '%s' "$key" | base64 -d >"$work/key" 2>/dev/null || fail "clé de version mal formée dans ce script"
		[ "$(wc -c <"$work/key")" -eq 42 ] || fail "clé de version mal formée dans ce script"
		if [ "$(hex_bytes "$work/key" 2 8)" = "$wanted" ]; then
			echo "$key"
			return 0
		fi
	done
	fail "signature refusée : faite par une autre clé que celles de ce script"
}

# verify_with_minisign : -Q n'affiche que le commentaire de confiance, et
# seulement si la signature globale le couvre.
verify_with_minisign() {
	verified=$(minisign -V -Q -P "$1" -m "$work/$SUMS_FILE" -x "$work/$SIGNATURE_FILE") ||
		fail "signature refusée (minisign) : sommes ou commentaire de confiance changés"
	[ "$verified" = "$trusted_comment" ] || fail "signature refusée (minisign) : commentaire de confiance inattendu"
}

# verify_with_openssl refait minisign : Ed25519 sur le BLAKE2b-512 des sommes,
# puis Ed25519 sur la première signature suivie du commentaire de confiance.
verify_with_openssl() {
	# L'en-tête DER d'une clé publique Ed25519, puis ses 32 octets.
	printf '\060\052\060\005\006\003\053\145\160\003\041\000' >"$work/key.der"
	tail -c 32 "$work/key" >>"$work/key.der"
	openssl dgst -blake2b512 -binary -out "$work/sums.b2" "$work/$SUMS_FILE" ||
		fail "openssl ne sait pas calculer BLAKE2b-512"
	openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/key.der" -rawin \
		-in "$work/sums.b2" -sigfile "$work/sums.sig" >/dev/null ||
		fail "signature refusée (openssl) : sommes changées"
	openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/key.der" -rawin \
		-in "$work/global.msg" -sigfile "$work/global.sig" >/dev/null ||
		fail "signature refusée (openssl) : commentaire de confiance changé"
}

# comment_field rend la valeur du champ name du commentaire de confiance
# (« clé:valeur » séparés par des tabulations), présent une seule fois.
comment_field() {
	values=$(printf '%s\n' "$trusted_comment" | tr '\t' '\n' | sed -n "s/^$1://p")
	[ "$(printf '%s\n' "$trusted_comment" | tr '\t' '\n' | grep -c "^$1:")" -eq 1 ] ||
		fail "commentaire de confiance sans champ $1 unique"
	echo "$values"
}

# is_version : X.Y.Z, sans zéro de tête ni suffixe (release.ParseVersion).
is_version() {
	printf '%s\n' "$1" | grep -Eqx '(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})'
}

# version_at_least : $1 n'est pas plus ancienne que $2, toutes deux X.Y.Z.
version_at_least() {
	saved_ifs=$IFS
	IFS=.
	# shellcheck disable=SC2086 # le découpage sur les points est voulu
	set -- $1 $2
	IFS=$saved_ifs
	[ "$1" -ne "$4" ] && { [ "$1" -gt "$4" ]; return; }
	[ "$2" -ne "$5" ] && { [ "$2" -gt "$5" ]; return; }
	[ "$3" -ge "$6" ]
}

# check_sums_names : chaque ligne des sommes signées nomme un binaire de
# version, et celui de cette machine y est.
check_sums_names() {
	! grep -Evx "[0-9a-f]{64}  $BINARY_PREFIX[a-z0-9]+" "$work/$SUMS_FILE" >/dev/null ||
		fail "$SUMS_FILE mal formé"
	grep -q "  $BINARY_PREFIX$arch\$" "$work/$SUMS_FILE" ||
		fail "la version ne contient pas de binaire pour $arch"
}

mode=setup
if [ "${1:-}" = join ]; then
	mode=join
	shift
fi

[ "$(id -u)" -eq 0 ] || fail "à lancer en root (sudo sh install.sh)"
is_version "$MIN_VERSION" || fail "ce script n'est pas celui d'une version publiée (MIN_VERSION vide)"
arch=$(machine_arch)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

choose_source "$@"
download "$SIGNATURE_FILE"
read_signature
key=$(signer_key)
if command -v minisign >/dev/null 2>&1; then
	verify_with_minisign "$key"
else
	verify_with_openssl
fi
signed_file=$(comment_field file)
[ "$signed_file" = "$SUMS_FILE" ] || fail "commentaire de confiance : autre fichier que $SUMS_FILE"
version=$(comment_field version)
case $version in v*) ;; *) fail "commentaire de confiance : version mal formée" ;; esac
is_version "${version#v}" || fail "commentaire de confiance : version mal formée"
version_at_least "${version#v}" "$MIN_VERSION" ||
	fail "version plus ancienne que celle attendue : $version servie, v$MIN_VERSION au moins"

check_sums_names
# setup garde tous les binaires pour la bibliothèque ; join ne prend que le
# sien, et ne vérifie que sa somme.
if [ "$mode" = join ]; then
	binaries="$BINARY_PREFIX$arch"
else
	binaries=$(sed 's/^[0-9a-f]*  //' "$work/$SUMS_FILE")
fi
for binary in $binaries; do
	download "$binary"
	grep -Ex "[0-9a-f]{64}  $binary" "$work/$SUMS_FILE" >>"$work/checked.sums"
done
(cd "$work" && sha256sum --strict --quiet -c checked.sums) || fail "somme fausse : binaire changé"
printf 'Version %s vérifiée : signature globale et sommes.\n' "$version"

# Tout est vérifié : pour setup, les fichiers de la version restent pour
# qu'il les importe dans la bibliothèque (lus par le compte du serveur) ;
# puis le binaire de cette machine est posé.
if [ "$mode" = setup ]; then
	install -d -m 0755 "$KEPT_DIR"
	for file in "$SUMS_FILE" "$SIGNATURE_FILE" $binaries; do
		install -m 0644 "$work/$file" "$KEPT_DIR/$file"
	done
fi
install -m 0755 "$work/$BINARY_PREFIX$arch" "$INSTALLED_BINARY"
rm -rf "$work"
trap - EXIT

# Sous « curl | sh », l'entrée standard est le script : setup et join posent
# leurs questions sur le terminal, et s'en passent sans terminal (cloud-init).
if [ "$mode" = join ]; then
	set -- join "$@"
else
	set -- setup --releases-url "$KAGU_RELEASES" "$@"
fi
if (: </dev/tty) 2>/dev/null; then
	exec "$INSTALLED_BINARY" "$@" </dev/tty
fi
exec "$INSTALLED_BINARY" "$@" </dev/null
