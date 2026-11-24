-- Les champs qu'un agent a dits de lui et que le serveur a refusés (A1
-- R-A1-13) : nom d'hôte, système, architecture, version. La valeur refusée
-- n'est jamais gardée ; son refus l'est, la fiche de la machine le lit. Un
-- champ redit valable, ou un ré-enrôlement, l'efface.
-- Une base d'avant n'a jamais été jugée : à cette migration, le store rejuge
-- chaque valeur gardée par le juge de machine (store.rejudgeReportedFields),
-- efface celles qu'il refuse et note leur refus ici.
CREATE TABLE machine_report_refusals (
    machine_id TEXT NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    field      TEXT NOT NULL CHECK (field IN ('hostname', 'system', 'arch', 'version')),
    PRIMARY KEY (machine_id, field)
) WITHOUT ROWID;
