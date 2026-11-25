-- Ce que vaut le compte de l'agent sur sa machine (fiche A3, R-A3-12) : 1
-- quand il est root, dans le groupe docker, ou porte terminal.host ; redit à
-- chaque ouverture du flux. 0 tant que l'agent n'a rien dit (un agent
-- d'avant) : l'onglet Droits le dira « vaut root » sous Déployer.
ALTER TABLE agents ADD COLUMN root_equivalent INTEGER NOT NULL DEFAULT 0 CHECK (root_equivalent IN (0, 1));
