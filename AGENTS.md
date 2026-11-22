# Travailler sur openCloud avec un agent

## Lire d'abord

1. [`docs/projet/12-methode.md`](docs/projet/12-methode.md) — branches,
   versions, CI, intégration des fonctionnalités.
2. [`docs/projet/17-conventions-code.md`](docs/projet/17-conventions-code.md)
   — conventions de code.
3. [`docs/projet/21-direction-artistique.md`](docs/projet/21-direction-artistique.md)
   — l'interface : couleurs, typographie, composants, ton, marque.
4. [`docs/projet/22-fonctionnement.md`](docs/projet/22-fonctionnement.md)
   — comment l'application tourne : acteurs, flux, ce qui est chiffré, ce qui
   est stocké. **Chaque fonctionnalité intégrée le met à jour.**

## Règles

- **Français** dans les documents et tout ce que voit l'opérateur ; **anglais**
  dans le code. Phrases courtes, tableaux, pas d'explication longue.
- **SSO** pour le mode `forward` (Authelia, Authentik…) ; *mandataire* est réservé
  au reverse proxy de `trusted_proxies`.
- **Vocabulaire interdit** : « nœud de contrôle » (dire *la machine openCloud*),
  « parc », « palier », « hors openCloud ».
- Chaque fait vit à un seul endroit ; les autres documents y renvoient.
- Le coût d'un choix se dit franchement, à côté de ce qu'il rapporte.
- Une décision se propose avec sa contrepartie ; **elle se prend par Lucas**.
- **Les fonctionnalités s'intègrent une par une, sur demande de Lucas** :
  analyser, décortiquer, adapter au besoin, puis intégrer proprement. Rien ne
  se reprend tel quel d'un autre projet.
- Ne jamais committer ni pousser sans demande. Pas de trailer d'IA.
- Commits courts, `type(portée): sujet` en français, sans corps ; **un commit
  par fonctionnalité** (`docs/projet/17-conventions-code.md`).
- **Jamais sur `dev` directement** : une branche par fonctionnalité
  (`feat/<nom>`, `fix/<nom>`), une pull request vers `dev`, CI verte, fusion
  par `merge`. `main` reçoit `dev` quand Lucas juge l'état stable ;
  `production` viendra plus tard pour les versions livrées
  (`docs/projet/12-methode.md`).
- **La version reste `v0.0.1`** tant que Lucas n'a pas décidé autrement.

## Sous-agents

Lancés avec **Sonnet** (mécanique : extraction, cartographie, vérification) ou
**Opus** (jugement : adaptation, synthèse, revue), jamais en héritant le modèle
de la session. Prompt précis : contexte, fichiers, format de sortie, style.
Si le résultat est mauvais, ré-itérer avec le même agent et un prompt plus ciblé/cadré.

## Code

Les conventions complètes sont dans
[`docs/projet/17-conventions-code.md`](docs/projet/17-conventions-code.md).
L'essentiel :

- **Lisible par un humain avant d'être court.** Une fonction fait une chose,
  se lit de haut en bas, tient à l'écran. Pas d'astuce, pas de one-liner
  malin, pas de générique inutile.
- **Le nommage fait le travail** : dossiers, fonctions et variables disent ce
  qu'ils sont. Verbe + objet pour une fonction ; jamais `m`, `tmp`, `data2`.
- **Identifiants en anglais, commentaires en français**, courts. Le pourquoi,
  jamais le quoi. Pas de commentaire par méthode par principe.
- Bibliothèque standard d'abord ; pas de réflexion, pas de cadre opaque.
- **Les couches tiennent** : le SQL dans `internal/edge/store`, les règles dans
  le composant, le handler lit, appelle, répond. Lire un autre domaine par la
  base pour dériver ; écrire toujours par son composant. Un refus déclare sa
  clé avec l'erreur (`internal/kit/refusal`). Le patron d'un composant est
  `probe.Service`.
- **Une logique, une définition.** Avant d'écrire un refus, une fonction de
  forme (nom, chemin, empreinte, port, durée, troncature), une borne, un type
  d'état ou un petit geste de test, chercher s'il existe (nom *et* corps).
  Un fait d'un autre domaine se refuse avec sa sentinelle, jamais avec une
  copie sous sa propre clé. Les gardes `TestOneDefinition_*`
  (`internal/edge/server/onedefinition_test.go`) lisent le source ; une exception
  s'y déclare avec sa raison.
- **Chercher avant d'écrire** : par le nom, par le corps, et par la question à
  laquelle le code répond (« a-t-il le droit ? », « est-ce l'heure ? », « quel
  état ? »), en Go et dans `web/src/lib`. Méthode : `13-reutiliser.md` du
  dossier v2, §2 et §6.
- **Chaque PR a une section « Réutilise / Étend / Nouveau »** : une ligne par
  chose construite, avec le `fichier:ligne` repris ; pour un « Nouveau », la
  recherche faite.
- **Familles** : `internal/{kit,fact,wire,gesture,domain,view,edge}`. Un paquet
  n'importe que sa famille ou une plus basse ; `kit` n'importe que `kit`.
  Un paquet nouveau naît dans sa famille. `TestLayers_*`
  (`internal/edge/server/layers_test.go`) le tient. La table ancien -> nouveau
  chemin est `scripts/familles.tsv`.
- **Un composant, une fois** : un écran se compose avec `web/src/components` ;
  une variante est une propriété, pas une copie ; une page n'écrit ni balise de
  base (`<button>`, `<table>`, `<input>`) ni style. On compose, on n'hérite pas.
  `web/src/components/composition.test.ts` le tient ; `web/src/styles/tokens.test.ts`
  (valeurs en dur) sera posé par T05-01.
- **Une règle, un côté** : ce que le serveur sait (état, droit, forme d'un nom,
  catégorie), l'API le rend ; le front l'affiche sans le recalculer.
- **Une règle `R-…` = un test qui porte son nom** (`TestR_OBJ_6_…`).
- **Un geste a son niveau (0 à 4) dans le registre avant d'avoir une route** ;
  un niveau 3 ou 4 y porte la raison qui le ferme aux jetons. Les niveaux dans
  `internal/gesture/verb` sont posés par T02-02.
- **Le texte venu d'ailleurs est non fiable** : borné et nettoyé par
  `internal/kit/untrusted` (posé par T01-01), rendu aux jetons sous la forme
  marquée, affiché en texte brut.
- **Vocabulaire d'écran** : les mots de `05-vocabulaire.md` du dossier v2, et eux
  seuls ; « mode », « observé », « géré », « libre » ne s'affichent jamais.
- **Le nom du produit vient d'une variable** : `brand.ProductName`
  (`internal/kit/brand`) côté Go, `productName()` côté écran. Jamais un
  littéral ; `TestProductNameIsNotALiteral` (posé par T00-09) le tient ; d'ici
  là, `TestNameOnlyInBrand` (`internal/kit/brand/literals_test.go`). Le signe et
  le mot-symbole sont ceux de `branding/` du dossier v2 : on ne les redessine
  pas.
- `gofmt`, `goimports`, `staticcheck` : la machine tient le style, l'humain
  garde l'attention pour le sens.
- Le front (`web/`, React + TypeScript + SCSS) suit les mêmes règles ;
  `make front` le compile et l'embarque, `make front-check` le vérifie. Aucune
  chaîne visible en dur : tout passe par les catalogues `internal/kit/lang`.
