-- Le protocole que l'agent a annoncé à sa dernière ouverture du flux
-- (en-tête OpenCloud-Agent-Protocol), gardé en base : « secrets
-- rotate-server-key », lancé hors du serveur, refuse une rotation tant qu'une
-- machine est à un protocole plus ancien que le sien (décision de Lucas,
-- #588). NULL tant que l'agent n'est pas revenu depuis cette migration : on
-- ne sait pas, la rotation le compte en retard.
ALTER TABLE agents ADD COLUMN protocol TEXT CHECK (protocol GLOB '[1-9]*' AND length(protocol) <= 3);
