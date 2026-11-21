#!/bin/sh
# Réécrit les chemins internal/<ancien> écrits hors des imports (Makefile,
# front, tests, commentaires, documents) dans les fichiers donnés.
# Bornes des deux côtés : internal/machine ne touche pas internal/machinex.
set -eu
table="$(dirname "$0")/familles.tsv"
[ "$#" -gt 0 ] || exit 0

awk -F '\t' '{ print length($1) "\t" $0 }' "$table" | sort -rn | cut -f2- |
	while IFS="$(printf '\t')" read -r old new; do
		perl -pi -e "s#(?<![\\w-])\Q$old\E(?![\\w-])#$new#g" "$@"
	done
