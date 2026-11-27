# Méthode de travail

## Le cycle

1. **On développe en local**, une fonctionnalité à la fois. Ça marche ? On
   passe à la suite.
2. **La CI GitHub est la référence.** Ce qui passe en local n'est vert qu'une
   fois la CI verte.
3. **Les fonctionnalités existantes s'intègrent une par une.** Lucas donne un
   module venu d'un autre projet ; on l'analyse, on le découpe, on l'adapte au
   besoin de Kagu, puis on l'intègre proprement. Rien ne se reprend tel
   quel.

## Les branches

| Branche | Rôle |
|---|---|
| `dev` | Le tronc. Rien ne s'y pousse directement. |
| `feat/<nom-court>`, `fix/…`, `docs/…`, `ci/…`, `chore/…` | Une branche par fonctionnalité, le même préfixe que le commit, en minuscules avec des tirets. |
| `main` | Reçoit `dev` par pull request quand Lucas juge l'état stable ; toujours installable. Une version ne se tague que sur un commit de `main`, et seulement quand Lucas le décide (« Les versions »). |
| `production` | Créée le jour où Lucas le décide, pour les versions livrées. |

- **Une pull request vers `dev`.** CI verte, relecture, puis **fusion par
  `merge`**, jamais par `squash` : les commits par fonctionnalité restent
  lisibles dans l'historique.
- **Rebase sur `dev` avant la PR** si la branche a vieilli, plutôt que des
  commits de fusion dans la branche.
- **Après un déplacement de fichiers**, `.git-blame-ignore-revs` liste le
  commit à sauter ; chaque clone le déclare une fois :
  `git config blame.ignoreRevsFile .git-blame-ignore-revs`. `git blame` ne
  s'arrête plus sur le déplacement.
- Deux travaux en parallèle ne se gênent pas : chacun sa branche, le conflit
  se règle dans la PR.
- Le dépôt est public, mais aucune règle de protection n'est posée sur
  `dev` : GitHub n'applique rien, c'est une discipline.

## Les versions

**`v0.0.1`, et on y reste** tant que la direction artistique et toutes les
fonctionnalités voulues ne sont pas intégrées. Pas de `v0.1`, pas de `1.0`.
Le changement de version est une décision de Lucas.

La `v0.0.1` publiée à ce jour n'est pas signée : elle a été réécrite à la main
jusqu'ici. La vérification par signature commence à la première version
taguée par le workflow ci-dessous ; rien n'est tagué avant que Lucas décide.

### Le jour où Lucas décide d'une version

Une version est un **tag `vX.Y.Z` poussé sur un commit de `main`**. Elle
porte les binaires, `SHA256SUMS`, sa signature `SHA256SUMS.minisig`,
`install.sh` et une attestation de provenance GitHub, et **ne se réécrit
jamais**. `install.sh` n'est pas dans `SHA256SUMS` (la signature ne couvre
que les binaires) : `publish` le prend dans `rebuild` et y écrit
`MIN_VERSION`, la version du tag ; il refuse toute version signée plus
ancienne (`docs/installation.md`, « Par install.sh »). Ce pas attend le
patch `docs/projet/patch-release-T04-10.diff`, que Lucas fusionne dans
`release.yml`.

**1. Une fois : les deux paires de clés.**

| Étape | Geste |
| --- | --- |
| Tirer la paire courante | `kagu release keygen -o release.key` sur son poste ; la commande écrit la clé privée (`0600`) et affiche la clé publique |
| Tirer la paire de secours | **hors ligne**, sur le poste de Lucas : `minisign -G -p kagu-secours.pub -s kagu-secours.key` (mot de passe demandé). `kagu-secours.key` et son mot de passe vont dans le coffre de Lucas, **jamais dans GitHub** ni dans le dépôt : elle ne sert que si GitHub ou la clé courante est pris |
| Créer l'environnement | Settings › Environments › New : nom `release` ; *Required reviewers* = Lucas, **sans** cocher *Prevent self-review* (c'est Lucas qui pousse le tag et qui approuve) ; *Deployment branches and tags* = *Selected branches and tags*, une seule règle de type *Tag*, motif `v*`. Le job `sign` s'y exécute après `build` et attend l'approbation. La règle réserve l'environnement, donc la clé, aux tags de version : un job lancé d'une branche qui le nommerait est refusé ; une règle qui n'admet pas le tag fait échouer `sign`. Sans l'environnement, GitHub en crée un vide au premier usage, sans relecteur : le job échoue faute de secret et rien ne se publie, **si** le secret du dépôt n'existe pas (sinon il le lit) |
| Poser la clé privée | secret **d'environnement** `RELEASE_SIGNING_KEY` (dans `release`, pas un secret du dépôt) = contenu de `release.key` ; une copie de `release.key` dans le coffre. Supprimer le secret du dépôt s'il existe : un secret du dépôt du même nom sert quand l'environnement n'a pas le sien, et seul le job `sign`, derrière le relecteur, doit pouvoir lire la clé |
| Poser les clés publiques | dans `internal/kit/release/key.go`, par une pull request : `CurrentPublicKey` = la clé publique de `release.key`, `BackupPublicKey` = la seconde ligne de `kagu-secours.pub` ; les mêmes dans `CURRENT_KEY` et `BACKUP_KEY` d'`install.sh` (`TestInstallScriptCarriesTheEmbeddedKeys` refuse un écart). Sans courante, le binaire refuse de vérifier ; sans secours, `make release` ne compile pas (tag `release`, `key_release.go`) : rien ne se publie sans les deux |
| Régler le dépôt | ruleset de tags `v*` : création réservée aux administrateurs, ni mise à jour ni suppression ; Settings › General › « Releases immuables ». Ce sont des réglages du dépôt : le code ne peut pas les poser |

**État** : la paire courante est tirée et posée depuis le 23/10/2026 ; la
paire de secours, tirée hors ligne par Lucas le 20/11/2026, est posée dans
`BackupPublicKey`, sa clé privée est dans le coffre de Lucas.

Un binaire déjà installé garde les clés publiques qu'il embarque : perdre la
clé privée courante, ou la croire prise, c'est sortir la clé de secours
(point 4).

**2. À chaque version.**

| Étape | Geste |
| --- | --- |
| Pousser le tag | `dev` rejoint `main` par pull request, puis, sur le commit de `main` choisi : `git tag -s vX.Y.Z <commit>` et `git push origin vX.Y.Z` |
| Laisser construire | `build` (npm, tests, deux builds, paquet du front) puis `rebuild` (sans npm, octet par octet) ; `sign` passe ensuite en attente (*Waiting*) |
| Approuver | GitHub › Actions › l'exécution `release` du tag › *Review deployments* › cocher `release` › *Approve and deploy*. Seulement si `build` et `rebuild` sont verts et que le tag est le sien |
| Laisser publier | `sign` signe `SHA256SUMS` ; `publish` vérifie, atteste et publie |

**Le plancher de sécurité** (R-B2-11). Une version qui corrige une faille
porte un plancher : la version sous laquelle aucun agent ne redescend plus.
Il est signé dans le commentaire de confiance, jamais dans `SHA256SUMS` :
`release sign -floor vX.Y.Z` (pas au-dessus de la version signée). Il ne
fait que monter : une version suivante garde le même, ou un plus haut. Le
choisir est une décision de Lucas. `release.yml` ne passe pas encore
`-floor` (#903) : la modification proposée lit une variable `RELEASE_FLOOR`
de l'environnement `release`, vide par défaut.

Tout changement de `.github/**` est fusionné par Lucas : ces fichiers sont
protégés sur `main` et `dev`, règle appliquée aux administrateurs. Avant
chaque approbation d'une version, Raph lui montre le diff de `release.yml`
depuis la version précédente.

**3. Ce qui fait échouer le job** (aucune version n'est alors publiée) :

| Cause | Pourquoi |
| --- | --- |
| Le tag n'est pas sur un commit de `main` | une version vient de l'état jugé stable |
| La version existe déjà | une version ne se réécrit pas ; on en publie une autre |
| Le second build donne d'autres sommes que le premier | le binaire n'est pas reproductible |
| `rebuild` obtient d'autres octets que `build` | ce que `build` a compilé ne sort pas du seul tag et du paquet du front : une source ou un outil a changé pendant que npm tournait |
| Le paquet du front reçu par `rebuild` n'a pas l'empreinte notée, ou sort de `dist/` | le transfert n'est pas fidèle, ou l'archive n'est pas un dossier de fichiers |
| `BackupPublicKey` est vide | `make release` ne compile pas : une version sans clé de secours ne se retire plus |
| Les fichiers reçus par `sign` ne sont pas ceux que `build` a listés | une somme qui ne correspond pas, un fichier manquant ou en trop dans `dist-release` : le transfert n'est pas fidèle |
| L'environnement `release` n'a pas le secret, ou la clé est mal formée | rien à signer avec |
| Le relecteur de l'environnement refuse, ou la règle ne laisse pas passer le tag | `sign` n'a pas lieu, rien ne se publie |
| L'approbation arrive plus d'un jour après `build` | l'artefact `dist-release` a expiré : relancer tout le workflow (*Re-run all jobs*), pas seulement `sign` |
| La clé publique courante est vide, ou n'est pas celle de la clé privée | `release verify` refuse les deux binaires |
| `install.sh` ne porte pas `MIN_VERSION=""` à remplacer | `publish` n'écrit pas la version du tag : un script sans version minimale ne se publie pas |

**4. Sortir la clé de secours.** Quand la clé privée courante est perdue, ou
que GitHub (environnement, secret, workflow) est peut-être pris. Une version
signée par la clé de secours retire la courante : chaque agent qui l'installe
note l'ancienne courante comme retirée et refuse ensuite ce qu'elle signe
(`signature_invalid`), même après un retour arrière.

| Étape | Geste |
| --- | --- |
| Couper la clé prise | GitHub › Settings › Environments › `release` › *Environment secrets* : supprimer `RELEASE_SIGNING_KEY` |
| Tirer deux paires neuves | hors ligne : `kagu release keygen -o release-2.key` (la future courante) et `minisign -G -p kagu-secours-2.pub -s kagu-secours-2.key` (la future secours, au coffre) |
| Les embarquer | pull request : `CurrentPublicKey` = clé publique de `release-2.key`, `BackupPublicKey` = seconde ligne de `kagu-secours-2.pub`, et les mêmes dans `install.sh` ; jusqu'à `main` |
| Construire sur son poste | `git checkout vX.Y.Z` (tag poussé ; dans GitHub, `sign` attend : *Reject*), puis `make release VERSION=vX.Y.Z` |
| Signer hors ligne | `minisign -S -s kagu-secours.key -m dist-release/SHA256SUMS -x dist-release/SHA256SUMS.minisig -t "$(printf 'timestamp:%s\tfile:SHA256SUMS\tversion:vX.Y.Z' "$(date +%s)")"` ; avec un plancher, ajouter `\tfloor:vX.Y.Z` à la fin du texte de `-t` |
| Vérifier | avec un binaire **déjà installé** (il embarque l'ancienne secours) : `kagu release verify dist-release/kagu-linux-amd64`, idem `arm64` |
| Distribuer | `release import dist-release` sur la machine Kagu, puis mettre à jour les agents ; publier les quatre fichiers sur la page de la version à la main, avec `install.sh` où `MIN_VERSION` vaut `X.Y.Z` (et la clé de secours du script est celle qui a signé, la courante celle de `release-2.key`, comme le binaire) |
| Reprendre | `RELEASE_SIGNING_KEY` = contenu de `release-2.key` dans l'environnement `release`. La secours qui a servi est usée : les versions suivantes ne l'embarquent plus |

## Les captures

Rejouées **à chaque fin d'étape**, hors `make ci`. Résultat : `docs/captures.md`
(généré, groupé par menu, date et commit en tête) et `docs/captures/<page>-ordinateur.webp`
et `-telephone.webp` : toutes les routes de `web/src/App.tsx`, mode sombre,
1280×900 et 390×844, pleine page.

| Étape | Qui | Geste |
| --- | --- | --- |
| Remettre la VM d'essai (M-NU) à l'instantané « neuf » | Raph | avant chaque rejeu ; documenté ici, pas fait par le script |
| Rejouer | l'agent, depuis orca | `CAPTURES_VM=<cible SSH> scripts/captures.sh <commit> <NN>` |
| Fusionner | Raph | la branche `captures/etape-NN` (docs seulement) |

- Les données sont celles de `TestE2EFixtureServer` (fictives, horloge figée),
  servies sur la VM d'essai et jointes par un tunnel SSH : jamais
  l'installation de Lucas. `CAPTURES_VM=local` lance le serveur sur la machine
  du script, pour un essai.
- La liste des pages vient du routeur (`declaredRoutes`). Une route à
  paramètre prend le premier identifiant que l'interface rend dans ses liens
  (menus « … » compris) ; une route sans lien prend celui de sa route-mère.
  Une page que les données fictives n'atteignent pas est dans
  `unreachedRoutes` (`web/e2e/support/routes.ts`), avec sa raison : même liste
  que le parcours. Le test `R-CAPTURES-1` échoue pour toute autre route sans
  capture.
- **Garde des données réelles** : le texte de chaque page, puis `docs/captures.md`,
  sont lus contre le domaine de l'opérateur, son plan d'adresses privé et les noms de machines réels (liste dans `scripts/captures.sh`). Ces
  noms vivent **hors du dépôt**, dans `~/.config/kagu/captures-noms-reels.txt`
  (ou `CAPTURES_NAMES_FILE`), un par ligne : le dépôt est miroité en public
  (`TestR_NETMAPDEMO_NoRealInstallationInPublicFixtures`). Sans ce fichier, le
  script refuse de partir. `scripts/captures.sh --garde <fichier>` lit un
  fichier contre la même liste.
- Le lancement du serveur de démo est dans `scripts/captures-serveur.sh` ; `scripts/captures-serveur-test.sh` (hors `make ci`) échoue si ssh ne rend pas la main.
- Le coût : 56 routes × 2 formats pèsent environ 16 Mo de WebP à chaque rejeu
  gardé dans l'historique.

## La CI

`.github/workflows/ci.yml` joue le scan des secrets, la politique Plumber
(`.plumber.yaml`), puis les cibles du `Makefile` : c'est lui qui liste les
étapes (`make ci`) et épingle les outils, avec `web/package.json` pour le
front. Le front se compile avant les tests Go, qui l'embarquent. Les
actions GitHub sont épinglées par SHA de commit.

`.github/dependabot.yml` propose chaque semaine, vers `dev`, une pull
request par écosystème (Go, npm, actions ; il met à jour le SHA et le
commentaire de version ensemble). `make front-check` lance d'abord
`npm audit --omit=dev --audit-level=high` : une dépendance de production
du front avec une faille haute ou critique arrête la CI (il faut le réseau).
`make e2e` suit : il compile le serveur de données fictives, télécharge
Chromium si besoin (`playwright install chromium`, réseau) et joue le parcours
navigateur de `web/e2e`.
Dans `go.mod`, `go 1.26` dit ce qu'il faut pour lire le module ; la ligne
`toolchain go1.26.11` fixe le correctif que la CI et les builds utilisent.

`.github/workflows/release.yml` publie une version : les binaires Linux
amd64 et arm64 (`make release`), leurs sommes, la signature minisign des
sommes et l'attestation de provenance, après les tests, en deux jobs :
`build` (npm, tests, binaires) n'a aucun secret et ne peut rien écrire ;
`sign`, sous l'environnement `release`, recompile son signataire sans npm,
signe, vérifie et publie. **Déclenché seulement par un tag `vX.Y.Z` poussé sur
un commit de `main`** ; une version publiée n'est jamais réécrite (voir « Les
versions »).

`web/.npmrc` pose `ignore-scripts=true` : npm n'exécute aucun script
d'installation, ni en CI, ni au build de version, ni sur le poste. Seuls
`@parcel/watcher` (optionnel, pour le mode `--watch` de `sass`) et `fsevents`
(macOS) en ont un dans le verrou, et le build n'en a pas besoin ; Vite prend
son binaire natif par paquet optionnel. Si un futur paquet exige son script,
la CI échouera : l'autoriser nommément (`npm rebuild <paquet>`) plutôt que de
rouvrir tous les scripts.

**Sobriété.** La CI tourne sur chaque pull request vers `dev` ou `main`, à
la poussée sur `main`, et à la main (`workflow_dispatch`) ; plus à la fusion
dans `dev`, que la PR vient de prouver. Un compte GitHub qui enchaîne un
nombre inhabituel d'exécutions automatiques peut être suspendu en attente de
vérification : un agent pousse une branche quand elle est prête (tests locaux
verts), regroupe ses corrections avant de repousser, et n'ouvre pas plus de
quelques PR à la fois.
