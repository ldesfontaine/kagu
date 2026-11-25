-- L'instant du dernier essai de mot de passe admis (A2 R-A2-16, secondes
-- Unix) : un compte ralenti n'admet le suivant qu'un intervalle plus tard.
-- Gardé en base et non en mémoire de serve : un redémarrage ne rend aucun
-- essai. Nul : aucun essai depuis la dernière remise à zéro.
ALTER TABLE auth_settings ADD COLUMN password_last_attempt INTEGER;
