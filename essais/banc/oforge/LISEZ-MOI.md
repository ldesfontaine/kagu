# O-FORGE — banc d'essai E00-04

Simule un serveur openCloud compromis : un attaquant qui a `server.key`
forge un ordre à ses paramètres, et le fait livrer à un vrai agent comme
le ferait `serve`.

**Jamais livré.** Cette branche ne sera pas fusionnée dans `dev`. Elle
touche volontairement à `internal/server/control.go` (route
`POST /control/forge`, marquée « banc d'essai, jamais livré » dans son
commentaire) ; nulle part ailleurs hors de `essais/banc/oforge/`.

## Ce que l'outil contourne

`oforge` écrit le run et signe l'ordre lui-même, sans passer par
`action.Service.Send`. Il saute donc tous les contrôles que `Send` fait
avant de signer (`internal/action/service.go:254`, fonction `send`) :

- le genre connu et que c'est bien un ordre (`:259`) ;
- le droit de l'agent couvre ce genre, `coversOrder` (`:272`,
  `internal/action/action.go`) ;
- les ancres de confiance de l'agent, `anchor.JudgeReported` (`:277`) ;
- que l'agent est en ligne (`:280`).

Un serveur compromis n'a pas à passer par son propre code de garde : il a
la clé, il signe ce qu'il veut. `oforge` signe directement avec
`action.Key.Sign` (`internal/action/key.go:225`), chargée par
`action.LoadKey` (`:121`).

## Pourquoi `-params` prend du JSON brut

`-params` est repris tel quel dans `json.RawMessage`, jamais décodé dans
une `map[string]any` ni ré-encodé. Un décodage en map effacerait les clés
répétées et ne garderait qu'une casse pour une clé qui existe en deux
casses (`target` / `Target`) — l'essai ne prouverait alors plus rien sur
ce que `server.key` seule permet d'écrire. Le test
`TestDryRun_KeepsBothDifferentlyCasedKeys` (`main_test.go`) vérifie que
`{"target":"5012","Target":"9999"}` donné à `-dry-run` ressort intact dans
le corps signé.

## La route `/control/forge`

`Service.Send` ne livre que par le flux ouvert de l'agent
(`internal/action/service.go:329`, `deliver` → `Server.Command` →
`machine.Sessions.Push`), un canal mémoire qui n'existe que dans le
processus `serve`. Aucun ordre `queued` en base n'est rejoué à l'ouverture
d'un flux ni relu par une boucle de fond : hors du flux ouvert, un ordre
écrit en base ne part jamais.

`oforge` ne peut donc pas livrer en écrivant seul dans la base : il lui
faut passer par le processus `serve` qui tient le flux. La route
`POST /control/forge`, ajoutée sur `internal/server/control.go`
(socket `state_dir/control.sock`, 0600, locale, sans jeton), reçoit
`{machine_id, kind, order}` — `order` déjà signé par `oforge` — et appelle
directement `Server.Command`, le même point que `Service.deliver` utilise
pour pousser l'ordre dans le flux de l'agent. La route elle-même ne signe
rien et ne fait aucun contrôle de droits ni d'ancres.

## Séquence de livraison

1. **`serve` tourne**, normalement, sur la config visée. Ne pas l'arrêter :
   la socket de contrôle et le flux de l'agent n'existent que pendant
   qu'il tourne.
2. Lancer `oforge` avec `-config` pointant sur le même `config.toml`
   (donc le même `state_dir`, donc le même `server.key` et la même base).
3. `oforge` :
   - lit la machine et son agent en base (`db.GetMachine`) ;
   - écrit le run en base (`db.InsertRun`), comme `Send` le fait, pour que
     le rapport de l'agent s'y attache ;
   - signe l'ordre avec `server.key`, épinglée par l'agent (ou la clé
     précédente avec `-pinned`, pendant une rotation) ;
   - marque le run `sent` (`db.SetRunState`) ;
   - poste `{machine_id, kind, order}` sur `state_dir/control.sock`,
     route `/control/forge` ;
   - `serve` livre par le flux ouvert, exactement comme un ordre légitime ;
   - `oforge` relit le run en base jusqu'à 20 s, puis imprime l'état et la
     raison rapportés par l'agent (`db.GetActionRun`).
4. Rien à relancer : `serve` reste le même processus du début à la fin.

## Options

- `-config <config.toml>` : le `config.toml` de `serve` (donne `state_dir`).
- `-machine <id>` : la machine visée.
- `-kind <genre>` : le genre de l'ordre, par exemple `backup.produce`.
- `-params '<JSON brut>'` : les paramètres, signés octet pour octet.
- `-pinned <empreinte>` : l'empreinte que l'agent a épinglée, si c'est la
  clé précédente d'une rotation en cours (par défaut, la courante ou celle
  que la base dit que l'agent a épinglée).
- `-dry-run` : imprime le corps signé, ne dépose ni n'envoie rien.

## Commande d'exemple

Pour forger `backup.produce` avec
`{"producer":"proxmox-vzdump","target":"5012","Target":"9999"}` sur une
installation dont la config est `/home/ldesfontaine/essai/config.toml` :

```sh
go run ./essais/banc/oforge \
  -config /home/ldesfontaine/essai/config.toml \
  -machine <id-de-la-machine> \
  -kind backup.produce \
  -params '{"producer":"proxmox-vzdump","target":"5012","Target":"9999"}'
```

`serve` doit déjà tourner sur cette config ; ne pas l'arrêter avant, ni le
relancer après.
