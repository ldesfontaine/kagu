-- L'échéance de chacun des droits que l'agent rapporte et qui en a une
-- (fiche A3, R-A3-5) : un objet JSON, nom du droit -> heure RFC 3339. Redite
-- à chaque ouverture du flux ; NULL quand aucun droit n'échoit, et tant que
-- l'agent n'a rien dit (un agent d'avant). Le serveur ne pré-juge pas un
-- ordre dont le droit échoit avant sa fin (not_after).
ALTER TABLE agents ADD COLUMN rights_until TEXT CHECK (json_valid(rights_until) AND json_type(rights_until) = 'object');
