-- La sorte du cookie sous lequel la session est née (A2 R-A2-3) : host pour
-- __Host-kagu_session (HTTPS), local pour kagu_session_local (boucle locale).
-- Une session ne se reprend que présentée sous ce même cookie. Celles nées
-- avant gardent '' : jamais reprises, l'opérateur se reconnecte.
ALTER TABLE operator_sessions ADD COLUMN cookie_kind TEXT NOT NULL DEFAULT '' CHECK (cookie_kind IN ('', 'host', 'local'));
