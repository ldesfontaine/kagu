# Écarts entre le dossier Kagu et `dev` (T00-01)

Dossier `kagu-v2` écrit sur `18c6e37` ; code relu sur `3e79bb1` (après la série TU). Lucas tranche la section suivante.

- **Références `fichier:ligne` d'A1, A2, A3** : 168 (137 distinctes) ; **119 justes, 32 décalées, 17 changées, 0 fausse**. Échantillon de 20 références non touchées : 0 erreur.
- **Constats de `09-securite.md` visant le code du jour** (31 lignes) : **15 fermés, 4 partiellement fermés, 12 ouverts, 1 mal décrit** (le flux de journaux, aussi compté fermé). Les constats de pure conception (N-, W-, L-) sont sans objet sur le code.
- **01-regles, 02-chemins, 03-architecture** : 9 affirmations fausses sur l'existant : 5 devenues fausses par TU-03 ou TU-01, 2 fausses depuis toujours, 2 renvois glissés.
- **Décisions pour Lucas** : 13 écarts déjà connus, 9 nouveaux. Les plus lourds sont N-1 (la clé scellée de `backup.receive` s'écrase) et N-2 (le critère de l'étape 1 est déjà tenu).

## À trancher par Lucas

Recommandation : **dossier** = corriger le dossier ; **ticket** = corriger le code par un ticket ; **accepter** = garder l'écart, écrit.

### Écarts déjà connus (relevés par Raph pendant la série TU)

| N° | Ce que dit le dossier | Ce que fait le code | Recommandation |
| --- | --- | --- | --- |
| C-1 | TU-01 : une clé ambiguë est refusée en `bad_order` | Refus `anchor_outside` (`internal/anchor/anchor.go:312-331`) | Accepter jusqu'à T01-02 (décision de Lucas), puis T01-02 rend `bad_order` |
| C-2 | Un refus d'ancre nomme l'ancre en cause | Sur une clé ambiguë, il nomme la première ancre jugée | Ticket : T01-02 corrige le diagnostic |
| C-3 | TU-03 : `POST /api/auth/setup` | `POST /api/auth/actions/enable` avec `setup_code` | Dossier : A2 et 06 citent la route du jour ; T02 décide si `/api/auth/setup` naît avec les sessions |
| C-4 | TU-08 : `..%2F` → « 401 ou 400 » | 400 `bad_path` avant routage, pour tout `/api/` (`internal/server/auth_middleware.go:292-301`) | Dossier : R-A2-13 dit 400 `bad_path` |
| C-5 | TU-06 : Link et realm bornés à l'hôte du registre | Fait, avec une limite sur la lecture des versions (#533) | Ticket : #533, rattaché à D1 (étape 6) |
| C-6 | TU-10 : bornes 64 par source, 1 024 en tout ; source = pair TCP ou adresse donnée par le proxy | Bornes réglables, source jugée avec `trusted_proxies` | Dossier : A2 PR 2 quinquies dit « fait par TU-10 » et reprend les bornes du code |
| C-7 | TU-12 : borne de flux tenue au serveur | Agent : 8 ; serveur : 4 | Dossier : une borne par côté, écrite dans A4 ; voir aussi N-5 |
| C-8 | TU-15 : la sonde ouvre « À traiter » | Une alerte `probe_password_removed` (`internal/alert/alert.go:52`) | Accepter jusqu'à T05-19, qui la range dans « À traiter » |
| C-9 | TU-17 : `backup.receive` borne la taille | Plafond par type d'archive + TU-17b (place libre) | Dossier : E3 critère 17 dit « plafond par type » ; voir N-1 |
| C-10 | TU-18 : doc et code de mcp-maison | Ce dépôt : doc et page « Nouveau jeton » seulement | Accepter : la part mcp-maison se fait dans son dépôt |
| C-11 | TU-02 : une clé de version et une clé de secours | Deux clés plus une liste de clés retirées (`internal/release/key.go:65`) ; plancher absent | Dossier : B2 décrit les deux clés ; le plancher reste à T04-15 |
| C-12 | 13-reutiliser §5 : « Go 1.26 installé (`go.mod` le demande) » | `go 1.26.11` (GO-2026-6859, PR #534) | Dossier : citer 1.26.11 |
| C-13 | D3 R-D3-12 : le découpeur du navigateur suit « les règles du `.env` de Compose » d'`envSecrets` (`internal/agent/docker.go:552-570`), avec des cas dorés communs | `envSecrets` lit le `.env` par `compose-spec/compose-go/v2/dotenv` v2.17.0 (`internal/agent/docker.go:583-604`, TU-07b) | Dossier : D3 dit que le Go suit la bibliothèque de Compose et que les cas dorés tiennent le front contre elle |

### Écarts nouveaux

| N° | Ce que dit le dossier | Ce que fait le code | Recommandation |
| --- | --- | --- | --- |
| N-1 | TU-17 : « `backup.receive` ne remplace rien » | Une archive se prend en exclusif, mais **la clé scellée se remplace** par `Rename` (`internal/agent/backup.go:309-311`) : un serveur pris peut écraser la clé qui ouvre les sauvegardes gardées | Ticket (urgent, type TU) : refuser une clé déjà présente, ou garder l'ancienne à côté ; Lucas choisit lequel |
| N-2 | Critère de l'étape 1 : « un test rejoue `{"target":"a","Target":"b"}` et l'agent refuse » ; 03 §2 A1 : « une autre casse contourne les ancres » | Déjà tenu par TU-01 (`TestR_A1_3_…`, `internal/agent/anchors_test.go`) ; reste la double lecture (ancre, puis exécuteur par `json.Unmarshal`) | Dossier : le critère de l'étape 1 devient « l'exécuteur reçoit la structure jugée, sans relire les octets » |
| N-3 | A2 PR 5 et R-A2-11 : « socket limitée à l'annuaire » ; ses routes `/control/admin/` passent par `OnlyUID(…, 0)` | La socket sert déjà `POST /control/admin/setup-code` (`internal/server/control.go:17`, `:40`) à tout pair qui l'ouvre (compte du service ou root) | Dossier : le départ d'A2 PR 5 le dit ; le test `OnlyUID` couvre aussi `setup-code` |
| N-4 | Des PR de fiche partent d'un état que les TU ont fermé : A2 PR 1 (code), PR 2 bis (`%2F`), PR 2 ter (SMTP), PR 2 quinquies (W-F7) ; A3 PR 0 (`agent trust`) | Faits par TU-03, 08, 09, 10, 05 | Dossier : ces PR sont marquées « faites par TU-xx » et retirées de 12-tickets, ou réduites à leur reste |
| N-5 | Constat TU-12 : « le nombre de `logs` ouverts n'est pas borné côté agent » | Sur `18c6e37`, l'agent bornait déjà à 4 (`container.MaxFollowsPerMachine`) ; TU-12 a ajouté les 15 min et **relevé** la borne à 8 (`internal/dockerwatch/logs.go:27`) | Dossier : le constat est mal décrit ; dire si 8 est voulu, sinon ticket pour revenir à 4 |
| N-6 | C-3 (TU-06) : le registre ne fait plus partir l'agent ailleurs | Un `realm` en `https` vers **tout** hôte, réseau local compris, reçoit encore un GET anonyme, sans identifiants (`internal/registry/client.go:258-262`) | Ticket : dans #533 ou D1 (étape 6), sondes d'adresse comme pour l'egress ; sinon accepter, écrit |
| N-7 | 01 R-DROIT-1 : le rôle « Hôte Docker » « coche une quinzaine de droits » | 3 droits (`internal/machine/role.go:43-50`) ; 15 est le total des droits proposés | Dossier ; A3 migre rôle → jeu depuis 3 droits |
| N-8 | `internal/verb/restic.go:33-34` (commentaire) : l'opérateur confirme « avec le chemin exact de la copie » | L'écran ne montre ni chemin ni instantané (A-3 ouvert) | Ticket : le commentaire se corrige dans la PR d'A-3 (A4, étape 11) |
| N-9 | W-M2 : la confirmation rejouait des champs réservés (`variables`) sous l'identité de la personne | Aucun verbe à confirmation n'a de champ réservé ; l'effet réel était une portée rétrécie ou un jeton retiré. Le test `variables` passe par un handler factice | Accepter ; le test se refait sur un vrai verbe quand un tel verbe en aura un |

Les 32 références décalées, les 17 changées et les renvois de 01 à 03 : **corriger le dossier une seule fois, après T00-02**, avec la table des chemins de `13-reutiliser.md` §5, et non deux fois.

## Méthode

| Étape | Ce qui a été fait |
| --- | --- |
| Extraction | Même motif que `poc/integration/verifier-references.py`, plus les renvois courts (`` `:146` ``) rattachés au fichier qui précède |
| Fichier non touché par `git diff 18c6e37..3e79bb1` (96) | Présumé juste ; échantillon de 20 références distinctes lu, 0 erreur |
| Fichier touché, mêmes lignes (23) | Lu : juste |
| Fichier touché, lignes déplacées ou changées (49) | Nouvelles lignes trouvées par le contenu exact ; sens relu à la main |
| Constats, 01 à 03 | Relus dans le code par deux relecteurs indépendants (Opus) ; les écarts nouveaux N-1 et N-5 revérifiés |

## Références

### Références décalées

| Fiche:ligne | Référence (18c6e37) | Lignes sur 3e79bb1 | Remarque |
| --- | --- | --- | --- |
| A1:38 | `internal/anchor/anchor.go:77-108` | 79-110 | — |
| A1:40 | `internal/agent/docker.go:152` | 169 | — |
| A1:43 | `internal/brand/brand.go:170` | 174 | — |
| A1:46 | `internal/anchor/anchor.go:90` | 92 | — |
| A1:49 | `cmd/opencloud/apply.go:436-440` | 435-439 | — |
| A1:50 | `cmd/opencloud/apply.go:351` | 350 | — |
| A1:50 | `cmd/opencloud/apply.go:422` | 421 | — |
| A1:50 | `cmd/opencloud/apply.go:437-440` | 436-439 | — |
| A1:76 | `internal/audit/event.go:246` | 249 | — |
| A1:191 | `internal/audit/event.go:89-244` | 89-247 (90 actions) | — |
| A2:49 | `internal/server/auth_middleware.go:137-140` | 135-138 | — |
| A2:49 | `internal/server/auth_middleware.go:278-313` | 303-338 | — |
| A2:49 | `web/src/api/auth.ts:45-56` | 48-59 | — |
| A2:50 | `internal/auth/service.go:46-66` | 51-71 | — |
| A2:51 | `internal/server/auth_middleware.go:40-42` | 41-43 | W-M4 toujours ouvert |
| A2:52 | `internal/server/auth_middleware.go:359-391` | 384-416 | — |
| A2:53 | `internal/server/auth_middleware.go:126-129` | 124-127 | un commentaire ajouté au-dessus (TU-03) |
| A2:55 | `internal/server/api_auth.go:185-196` | 187-198 | — |
| A2:56 | `internal/server/api_auth.go:198-210` | 200-212 | la première configuration rouverte exige le code (TU-03) |
| A2:57 | `internal/server/auth_middleware.go:249-259` | 247-257 | — |
| A2:59 | `internal/server/api.go:131-138` | 132-139 | — |
| A2:63 | `internal/server/auth_middleware.go:40-42` | 41-43 | W-M4 toujours ouvert |
| A2:63 | `internal/server/auth_middleware.go:288-289` | 313-314 | — |
| A2:97 | `internal/server/auth_middleware.go:359-391` | 384-416 | — |
| A2:99 | `internal/server/auth_middleware.go:40-42` | 41-43 | — |
| A2:101 | `cmd/opencloud/serve.go:323-335` | 326-338 | ce que la fiche fait « gagner » à `newHTTPServer` est déjà fait par TU-10 (`listenLimited`, `routes.go:353-361`) |
| A2:215 | `serve.go:318-322` | 321-325 | le commentaire au-dessus (315-320) dit aussi `WriteTimeout` depuis TU-10 |
| A2:246 | `internal/server/auth_middleware.go:40-42` | 41-43 | — |
| A3:72 | `internal/agent/trust.go:58-96` | `RequireTrustRoot` 59-64, `Trust` 67-105 (TU-05 : la garde root extraite, patron intact) | — |
| A3:81 | `internal/anchor/anchor.go:251` | 253 | — |
| A3:81 | `internal/anchor/anchor.go:267` | 269 | — |
| A3:197 | `internal/anchor/anchor.go:251` | 253 | — |

### Références changées

| Fiche:ligne | Référence (18c6e37) | Changée par | Sur 3e79bb1 | Ce qui a changé |
| --- | --- | --- | --- | --- |
| A1:39 | `internal/anchor/anchor.go:310-329` | TU-01 (PR #535) | `valueOf` 312-331, `readFields` 333-370 | l'ancre lit toujours par clé exacte, mais une clé répétée ou égale à la casse près rend les paramètres illisibles : refus |
| A1:45 | `internal/anchor/anchor.go:310-331` | TU-01 (PR #535) | `readFields` 333-370 | B-H1 fermé : `{"target":…,"Target":…}` n'est plus lu |
| A1:55 | `internal/audit/event.go:89-246` | TU-03 (#536), TU-04 (#538) | 89-249 | 90 actions d'audit, et non 88 (`auth.setup_code_issue`, `verb.lapse`) |
| A2:54 | `internal/server/auth_middleware.go:78-84` | TU-03 (PR #536) | 80-86 (liste inchangée) | en `none`, la création exige le code de `admin setup-code` : le premier venu ne crée plus le compte |
| A2:54 | `cmd/opencloud/serve.go:251-256` | TU-03 (PR #536) | `logInterfaceAccess` 259-270 | `WARN` toujours, avec la commande `admin setup-code` ; plus d'`INFO` sur la boucle locale |
| A2:56 | `cmd/opencloud/auth.go:82-100` | TU-03 (PR #536) | 83-103 | rouvre la première configuration, qui exige désormais un code |
| A2:58 | `internal/server/control.go:11-38` | TU-03 (PR #536) | 11-43 ; `setupCodePath` 17, route 40 | la socket ne sert plus seulement `/api/manifest/` : aussi `POST /control/admin/setup-code`, sans `OnlyUID` |
| A2:60 | `internal/server/auth_middleware.go:114-116` | TU-08 (PR #546) | exemption retirée de `requireOperator` ; `openCompiledAssets` 265-273 | A-2 fermé |
| A2:60 | `internal/server/auth_middleware.go:266-276` | TU-08 (PR #546) | `isCompiledAsset` 277-287 (`EscapedPath`) ; `refuseEncodedSlash` 292-301 | A-2 fermé |
| A2:60 | `internal/server/routes.go:302-303` | TU-08 (PR #546) | 344-348 | exemption posée sur la seule route du front |
| A2:62 | `internal/settings/service.go:87-92` | TU-09 (PR #543) | 91-105 | C-2 fermé côté SMTP : `ErrMailPasswordRequired` (98-99) |
| A2:62 | `internal/alert/manage.go:62-78` | TU-09 (PR #543) | 62-85 ; refus 65 | C-2 fermé côté Matrix : `ErrChannelSecretRequired` |
| A2:64 | `cmd/opencloud/serve.go:311-335` | TU-10 (PR #547) | `newHTTPServer` 326-338 ; `listenLimited` 243-254 ; durées par route `internal/server/routes.go:353-361` | W-F7 fermé : plafond de connexions et durée d'écriture hors flux |
| A2:118 | `cmd/opencloud/auth.go:82-100` | TU-03 (PR #536) | 83-103 | « à qui atteint le port » est faux : le code est exigé |
| A2:211 | `cmd/opencloud/serve.go:311-335` | TU-10 (PR #547) | idem | le « Départ » de cette PR est déjà l'arrivée de TU-10 |
| A3:80 | `cmd/opencloud/trust.go:22-55` | TU-05 (PR #537) | `runAgentTrust` 22-65 ; `confirmTrustChange` 69-84 | N-M3 fermé : montre le changement et demande confirmation (`--yes` sans terminal) |
| A3:285 | `cmd/opencloud/trust.go:22-55` | TU-05 (PR #537) | idem | le « Départ » de cette PR est déjà l'arrivée de TU-05 |

## Constats de `09-securite.md` sur `3e79bb1`

Lignes sur `3e79bb1`. Tests lus, pas lancés.

### §2 : revue du 11 novembre

| Id | État | Correctif | Test qui le tient |
| --- | --- | --- | --- |
| B-H1 | Fermé par TU-01 (PR #535) | `internal/anchor/anchor.go:313`, `:337-370` (`readFields`) | `internal/anchor/anchor_test.go` `TestR_A1_3_AKeyRepeatedOrOfAnotherCaseIsNeverRead`, `TestR_A1_7_…` ; `internal/agent/anchors_test.go` `TestR_A1_3_TheProducerIsNeverCalledOnAKeyOfAnotherCaseOrRepeated` |
| A-1 | Fermé par TU-03 (PR #536, + PR #541) | `internal/auth/setupcode.go:78-101` ; `internal/server/control.go:40` | `internal/server/auth_setup_code_test.go` `TestR_A2_5`, `TestR_CNX_3`, `TestR_A2_5_OnlyOneActivationWins` ; `internal/auth/setupcode_test.go` |
| B-M1 | Fermé par T01-04 | `internal/wire/agentwire/registry.go` : `AnchoredWhen(anchor.BackupGuest, …)` sur `restic.backup`, portée `vm` seulement | `internal/edge/agent/anchors_test.go` `TestR_A1_7_ResticBackupOfAGuestOutsideTheAnchorsNeverRunsSudo` ; `internal/wire/agentwire/registry_test.go` `TestR_A1_7_ResticBackupPresentsItsGuestOnlyInTheVMScope` |
| C-1 | Ouvert | `cmd/opencloud/apply.go:438-439` imprime `+ <nom>` seul | — |
| A-2 | Fermé par TU-08 (PR #546) | `internal/server/auth_middleware.go:265-274`, `:277-287`, `:292-302` ; `internal/server/routes.go:347` ; `internal/server/server.go:651` | `internal/server/spa_test.go` `TestR_A2_13` |
| A-3 | Ouvert | Toute demande ouvre `DeleteMachineDialog` (`web/src/components/VerbRequestsCard.tsx:63-69`) ; ni instantané ni chemin (`web/src/lib/verbRequests.ts:9-14`) | — |
| A-4 | Fermé par TU-11 (PR #545) | `internal/verb/restic.go:28`, `:43` ; `internal/server/api_tokens.go:212-237` | `internal/server/api_token_restic_reach_test.go` `TestR_A4_11` |
| A-5 | Fermé par T02-05 | `internal/edge/server/ping/ping.go` (`admitPing`) ; `internal/kit/ratelimit/limiter.go` (`NewCapped`, `MaxSources`) | `internal/edge/server/ping` `TestR_A2_15_UnknownTokensLeaveNoBucket` ; `internal/kit/ratelimit` `TestR_A2_15_ALimiterStopsAtItsCap` |
| A-6 | Ouvert | 16 places partagées, rien par jeton : `internal/server/api_containers.go:25`, `:299` | — |
| B-F1 | Ouvert | `internal/agent/restic_restore.go:109-114`, puis `os.Rename` `:146`, sans rejuger `files.write` | — |
| B-F2 | Ouvert | `internal/machine/sign.go:77-92` : casse et tirets libres | — |
| C-2 | Fermé par TU-09 (PR #543) | `internal/settings/service.go:98` (hôte, port, TLS) ; `internal/alert/manage.go:63-65` | `internal/settings/service_test.go` `TestR_A2_14`, `TestR_SEC_7` ; `internal/alert/channel_secret_test.go` `TestR_A2_14` |
| C-3 | Partiellement fermé par TU-06 (PR #540) | `internal/registry/client.go:113-135`, `:258`, `:262` ; reste le `realm` `https` vers tout hôte (N-6) et #533 (C-5) | `internal/registry/client_test.go` `TestR_D1_10` |
| C-4 | Ouvert | Longueur seule : `internal/probe/probe.go:451`, `internal/heartbeat/heartbeat.go:162` ; aucun filtre dans `cmd/opencloud/apply.go:439` | — |
| C-5 | Fermé par TU-07 (PR #542) et TU-07b (PR #559) | `internal/agent/docker.go:583-604` ; appels `:466`, `internal/agent/service_update.go:470`, `:518`, `:576` | `internal/agent/docker_test.go` `TestR_D3_9`, `TestR_SEC_6`, `TestEnvSecrets_ReadsLikeCompose` |
| C-6 | Ouvert | `internal/egress/dial.go:43-55` : `64:ff9b::/96`, `2002::/16` | — |
| C-7 | Ouvert | `internal/egress/dial.go:28-38` : AWS et Alibaba seules | — |

### §2 bis : ce qui vise le code du jour

| Id | État | Correctif | Test qui le tient |
| --- | --- | --- | --- |
| W-M2 | Fermé par TU-04 (PR #538) | `internal/server/api_verb_requests.go:182-256` ; `migrations/043_verb_request_lapsed.sql` | `internal/server/api_verb_requests_test.go` `TestR_A4_16`, `TestR_GESTE_8` (voir N-9) |
| W-M3 | Partiellement fermé par TU-18 (PR #557) | `docs/installation/compose.mcp-maison.yml` ; `web/src/pages/settings/APITokensBlock.tsx` ; reste dans mcp-maison (C-10) | `internal/lang/token_home_test.go` `TestR_G2_8`, `TestR_GESTE_9` |
| W-M6 | Fermé par TU-02 (PR #544) | `.github/workflows/release.yml:114-228` ; `internal/release/key.go:39`, `:65` ; `internal/agent/update.go:239-250` | `internal/agent/update_test.go` `TestR_B2_10` ; `internal/release/key_test.go` |
| N-F10 | Partiellement fermé par TU-02 (PR #544) | Plancher absent (C-11, T04-15) | — |
| W-F7, serveur HTTP | Fermé par TU-10 (PR #547) | `cmd/opencloud/serve.go:243-254` ; `internal/server/limits.go:64`, `:146` ; `internal/server/routes.go:264-268` | `internal/server/limits_test.go` `TestR_A2_18`, `TestR_A2_18_StreamRoutesLiftTheDeadlineOthersKeepIt` |
| W-F7, webhook rejouable | Ouvert | `internal/alert/notifier.go:269-270` : corps signé sans horodatage | — |
| W-F7, mots de passe de sonde | Fermé par TU-15 (PR #551) et TU-15b (PR #555) | `internal/probe/service.go:428-456` ; `cmd/opencloud/serve.go:193` ; `internal/store/store.go:68`, `:83` | `internal/server/probe_passwords_test.go` `TestR_D5_19` ; `cmd/opencloud/legacy_passwords_test.go` |
| W-F6 (HSTS, COOP) | Fermé par TU-14 (PR #549) | `internal/server/headers.go:56-67` | `internal/server/headers_test.go` `TestR_D5_17` |
| N-F6 (dossier en 0755) | Fermé par TU-13 (PR #548) | `internal/agent/docker.go:55`, `:257`, `:441-449` | `internal/agent/docker_test.go` `TestR_D1_14` |
| N-M3 | Fermé par TU-05 (PR #537), pour le code du jour | `cmd/opencloud/trust.go:50-53`, `:69-84` ; `cmd/opencloud/confirm.go:34-48` | `cmd/opencloud/trust_test.go` `TestR_A3_15`, `TestR_DROIT_8` |
| Flux de journaux de l'agent | Fermé par TU-12 (PR #550) ; **mal décrit** (N-5) | `internal/dockerwatch/logs.go:27` ; `internal/agent/commands.go:90` | `internal/dockerwatch/logs_test.go` `TestR_A4_22` ; `internal/agent/commands_test.go` |
| `deliverBrowse` sans machine | Fermé par TU-16 (PR #552) | `internal/restic/browse.go:76-86` | `internal/restic/browse_test.go` `TestR_E3_16` |
| `backup.receive` sans borne | Partiellement fermé par TU-17 (PR #554) et TU-17b (PR #556) : la clé scellée s'écrase (N-1) | `internal/agent/backup.go:34`, `:128-157`, `:308-327` | `internal/agent/backup_test.go` `TestR_E3_17`, `TestR_E3_17_TheCapFollowsTheSignedArchiveKind` |
| Unité de l'agent à durcir | Ouvert | `docs/installation/opencloud-agent.service:78-104` : ni `CapabilityBoundingSet=`, ni `SystemCallFilter=`, ni `PrivateDevices=` | — |
| Autres N-, W-, L- | Conception, sans objet sur le code du jour | — | — |

## 01-regles, 02-chemins, 03-architecture : ce qui est faux sur l'existant

| Document:ligne | Ce qu'il affirme | Ce que fait le code (`3e79bb1`) | Depuis |
| --- | --- | --- | --- |
| 01:270 (R-CNX-3) | « Le premier venu crée le compte » | Code de première configuration (`internal/auth/setupcode.go`, `cmd/opencloud/admin.go:19-30`) | TU-03 (PR #536) |
| 01:268 (R-DROIT-1) | Le rôle « Hôte Docker » coche « une quinzaine de droits » | 3 droits (`internal/machine/role.go:45`) | Toujours (N-7) |
| 02:14 (chemin 2) | « Gestes aujourd'hui : 1, sans protection » | La création exige le code tiré par root | TU-03 (PR #536) |
| 03:36 (§1, canal local) | Socket « pour `export` et `apply` » | Sert aussi `POST /control/admin/setup-code` (`internal/server/control.go:17`, `:40`) | TU-03 (PR #536) (N-3) |
| 03:47 (§2, A1) | « Une autre casse contourne les ancres » | Fermé (`internal/anchor/anchor.go:337-370`) ; la double lecture reste | TU-01 (PR #535) (N-2) |
| 03:48 (§2, A2) | « Le premier venu crée le compte » | Code exigé | TU-03 (PR #536) |
| 03:48 (§2, A2) | « Aucun moyen de refaire un mot de passe perdu » | `opencloud auth disable` (`cmd/opencloud/auth.go:22-35`) ; 01:271 le dit déjà | Toujours |
| 03:53 (§2, A5) | Règle `sudo` à `docs/installation.md:1105-1121` | Désormais `docs/installation.md:1138-1170` | TU-03, TU-05 (renvoi) |
| 03:63 (§3) | Version vérifiée à `internal/agent/update.go:312-334` | `verifyDownload`, `internal/agent/update.go:377` | TU-02 (renvoi) |

## Non vérifié

- Aucun test lancé : « le test tient le correctif » est jugé à la lecture.
- 96 références présumées justes parce que leur fichier n'a pas bougé ; seules 20 ont été lues.
- Les références des autres fiches (B à G) et de `18-a-la-place-de-raph.md` ne sont pas relues ici.
- W-M6 : que `RELEASE_SIGNING_KEY` vive dans l'environnement `release`, avec un relecteur exigé (réglage GitHub).
- TU-10, critère `?wait=` : aucun paramètre `wait` dans le code ; il relève de D8.
- B-H1 : l'égalité entre `strings.EqualFold` et le repli de casse de `encoding/json` (`ſ`, signe Kelvin) est raisonnée, pas essayée.
- 02 : la colonne « Gestes aujourd'hui » n'est pas recomptée ; 01 §15 et 03 §7 (mémoire mesurée le 11 novembre) non rejoués.
- #533 : son périmètre exact par rapport à N-6 n'a pas été lu sur Forgejo.
