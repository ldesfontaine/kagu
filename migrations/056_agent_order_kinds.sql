-- Les genres d'ordres que l'agent annonce à chaque ouverture du flux (fiche
-- B2, R-B2-8) : un objet JSON, genre -> numéro (« docker.deploy » -> 2), et ce
-- qu'il sait lire de l'enveloppe. NULL tant qu'il n'a rien annoncé (un agent
-- du protocole 2) : le serveur ne lui signe alors qu'agent.update.
ALTER TABLE agents ADD COLUMN order_kinds TEXT CHECK (json_valid(order_kinds) AND json_type(order_kinds) = 'object');
