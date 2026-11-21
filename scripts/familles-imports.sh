#!/bin/sh
# Réécrit les imports Go selon scripts/familles.tsv (ancien → nouveau).
# Le motif garde les guillemets : internal/machine ne touche pas internal/machinex.
# Les chemins les plus longs passent d'abord.
set -eu
module="github.com/ldesfontaine/opencloud"
table="$(dirname "$0")/familles.tsv"

awk -F '\t' '{ print length($1) "\t" $0 }' "$table" | sort -rn | cut -f2- |
	while IFS="$(printf '\t')" read -r old new; do
		git grep -l -E "\"$module/$old[/\"]" -- '*.go' |
			xargs -r perl -pi -e "s#\"\Q$module/$old\E([\"/])#\"$module/$new\$1#g"
	done
gofmt -w internal cmd
