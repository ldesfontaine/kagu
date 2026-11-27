#!/bin/bash
# Lancement du serveur de démo, source par captures.sh et par son test.
# Une règle : le `&` ne porte que sur le serveur, jamais sur une liste
# `cd && … &` — la liste en arrière-plan garde la sortie du shell ouverte (ssh
# ne rend jamais la main) et `$!` n'est plus le pid du serveur.

# Les noms locaux ne heurtent aucune variable de captures.sh (vm, port,
# remote_dir… y sont en lecture seule) : `local vm=` y échouerait.

# Sur la VM : $2 est le dossier de travail distant (relatif au $HOME), où
# fixture.test et tmp/ sont déjà posés. Le pid du serveur est écrit dans
# $2/pid.
start_remote_server() {
	local target_vm="$1" target_dir="$2" server_port="$3"
	ssh -- "$target_vm" "cd $target_dir && chmod 700 tmp && { TMPDIR=\$PWD/tmp KAGU_E2E_ADDR=127.0.0.1:$server_port nohup ./fixture.test -test.run TestE2EFixtureServer -test.timeout 0 >serveur.log 2>&1 </dev/null & echo \$! >pid; }"
}

# Ici : le binaire est dans $1 ; journal et pid dans $3 et $4 (chemins absolus).
start_local_server() {
	local binary_dir="$1" server_port="$2" log_file="$3" pid_file="$4"
	cd -- "$binary_dir" || return 1
	KAGU_E2E_ADDR="127.0.0.1:$server_port" ./.fixture.test -test.run TestE2EFixtureServer -test.timeout 0 >"$log_file" 2>&1 </dev/null &
	echo $! >"$pid_file"
}
