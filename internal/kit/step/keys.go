package step

// Les étapes d'arrivée d'une machine, dans l'ordre où join les coche : la
// seule liste (B1 §3). Le terminal et la tuile « en cours d'arrivée » cochent
// celle-ci.
var (
	EnrollSystem    = Define("step.enroll.system")
	EnrollDocker    = Define("step.enroll.docker")
	EnrollRestic    = Define("step.enroll.restic")
	EnrollAccount   = Define("step.enroll.account")
	EnrollRights    = Define("step.enroll.rights")
	EnrollEnrolled  = Define("step.enroll.enrolled")
	EnrollUnit      = Define("step.enroll.unit")
	EnrollWorkspace = Define("step.enroll.workspace")
	EnrollReady     = Define("step.enroll.ready")
)

// Les lignes de setup qui ne sont pas des étapes d'arrivée d'une machine :
// setup les coche entre les siennes, dans l'ordre de B1 §5 (Système reconnu
// et Dossier des services sont les étapes d'arrivée ci-dessus).
var (
	SetupAccount = Define("step.setup.account")
	SetupServer  = Define("step.setup.server")
	SetupAgent   = Define("step.setup.agent")
)

// Les coches de la montée du serveur (upgrade), dans l'ordre de B2 §5.
var (
	UpgradeFound     = Define("step.upgrade.found")
	UpgradeSpace     = Define("step.upgrade.space")
	UpgradeCopied    = Define("step.upgrade.copied")
	UpgradeReplaced  = Define("step.upgrade.replaced")
	UpgradeRestarted = Define("step.upgrade.restarted")
	UpgradeAnswers   = Define("step.upgrade.answers")
	UpgradeUnits     = Define("step.upgrade.units")
	UpgradePolicy    = Define("step.upgrade.policy")
	// Le retour arrière, quand la nouvelle version ne répond pas (R-B2-3).
	UpgradeRolledBack = Define("step.upgrade.rolled_back")
)
