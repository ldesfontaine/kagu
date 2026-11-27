package brand

import "strings"

// A. Affichage.

// ProductName est le nom que voit l'opérateur. Renommer le produit
// n'abîme rien d'installé : seuls les textes changent. Les catalogues
// écrivent « de {product} », « que {product} » : un nom à voyelle initiale
// demanderait de relire les élisions.
const ProductName = "Kagu"

// B. Identifiant technique.

// ID est la forme technique du nom : chemins, fichiers, noms d'unités. Le
// changer déplace tous les chemins ci-dessous ; une installation existante
// ne se relit pas, elle se réinstalle (aucune double lecture).
const ID = "kagu"

const (
	ConfigDir  = "/etc/" + ID
	ConfigPath = ConfigDir + "/config.toml"
	// Ce que setup retient d'une installation : ses réponses et ses étapes
	// faites (root, 0600, aucun secret) ; la montée de version le relit.
	SetupStateFile = ConfigDir + "/setup.json"
	// Les fichiers de la version qu'install.sh a vérifiée (sommes, signature,
	// binaires) : setup les fait importer par serve dans la bibliothèque.
	SetupReleaseDir = "/var/lib/" + ID + "-setup/release"
	// Le verrou de setup : un second setup lancé pendant le premier s'arrête.
	SetupLockPath = "/run/" + ID + "-setup.lock"
	StateDir      = "/var/lib/" + ID
	// La montée du serveur (upgrade), en root : son unité transitoire, qui
	// survit au terminal ; son verrou ; son dossier (root, 0755), où vivent
	// son état (0600) et la version vérifiée qu'elle installe, lisible du
	// compte du serveur qui l'importe ; l'ancien binaire, gardé à côté.
	UpgradeUnit      = ID + "-upgrade"
	UpgradeLockPath  = "/run/" + ID + "-upgrade.lock"
	UpgradeStateDir  = "/var/lib/" + ID + "-upgrade"
	UpgradeStateFile = UpgradeStateDir + "/state.json"
	PreviousBinary   = "/usr/local/lib/" + ID + "/" + Command + ".previous"
	// Le compte système sous lequel tourne serve.
	ServerAccount = ID
	// Le binaire installé, que l'unité du serveur lance et dont setup copie
	// l'agent de la machine Kagu et son lanceur stable.
	InstalledBinary = "/usr/local/bin/" + Command
	// L'état de l'agent (au compte de l'agent, root si on le lui demande,
	// 0700). Hors de StateDir : sur la machine Kagu, StateDir appartient
	// au compte du serveur, qui pourrait renommer un dossier dessous et en
	// poser un autre.
	AgentStateDir = "/var/lib/" + ID + "-agent"
	// La racine des services déployés, un dossier par projet Compose ; réglable
	// par -root-dir au premier lancement de l'agent.
	WorkspaceRoot = "/srv/workspace"
	DatabaseFile  = ID + ".db"
	// La clé qui chiffre les secrets saisis dans l'interface, à côté de la
	// base et jamais dedans.
	SecretKeyFile = "secret.key" // #nosec G101 -- un nom de fichier, pas un secret.
	// La clé qui signe les ordres envoyés aux agents, à côté de secret.key :
	// sa moitié publique est épinglée par chaque agent à l'enrôlement.
	ServerKeyFile = "server.key" // #nosec G101 -- un nom de fichier, pas un secret.
	// La socket de commande, dans state_dir : serve y sert les routes du
	// fichier de l'annuaire à la commande locale, sans rien ouvrir au réseau.
	ControlSocketFile = "control.sock"
	// La socket des agents locaux : serve y sert les seules routes de l'agent
	// à l'agent de la machine Kagu, sans adresse publique (R-B1-7). Le dossier
	// est le RuntimeDirectory de l'unité du serveur.
	RuntimeDir      = "/run/" + ID
	AgentSocketPath = RuntimeDir + "/agent.sock"
	// Le dossier des colis à destination des agents, dans state_dir : vidé au
	// démarrage, rien n'y reste plus de quelques heures.
	OutgoingDir = "outgoing"
	// Les versions importées par `release import`, dans state_dir : un
	// dossier par version, dont l'agent se met à jour sans rien télécharger
	// d'Internet.
	ReleasesDir = "releases"
	// Les copies de la base faites par serve avant une montée, dans
	// state_dir : UpgradeCopyPrefix + la version qui tournait + ".db". La
	// base d'une montée ratée y est gardée par upgrade : UpgradeFailedPrefix
	// + la version visée + ".db".
	UpgradeDir          = "upgrade"
	UpgradeCopyPrefix   = "avant-"
	UpgradeFailedPrefix = "echec-"
	// Sur chaque machine, dans l'état de l'agent : les binaires installés
	// (AgentBinaryPrefix + version) et le lien que l'unité lance.
	AgentBinDir       = "bin"
	AgentCurrentLink  = "current"
	AgentBinaryPrefix = ID + "-"
	// Le binaire que la ligne d'installation et l'unité lancent. Ce n'est pas
	// /usr/local/bin/kagu : ce lien, root le lancerait, et le compte de
	// l'agent peut remplacer ce qu'il vise.
	AgentCurrentPath = AgentStateDir + "/" + AgentBinDir + "/" + AgentCurrentLink
	// Le lien vers le binaire d'avant la dernière bascule : ce à quoi l'agent
	// revient, seul ou sur ordre, et l'état de la mise à jour en attente de
	// confirmation (dans l'état de l'agent, à lui, 0600).
	AgentPreviousLink = "previous"
	AgentUpdateMarker = "update.json"
	// Les clés de version que l'agent ne croit plus, une par ligne (dans son
	// état, 0600) : la courante, retirée quand il installe une version signée
	// par la clé de secours. Elle le reste, même après un retour arrière.
	AgentRetiredKeysFile = "release-keys-retired"
	// Le plancher de sécurité des versions que l'agent a installées (R-B2-11),
	// vX.Y.Z (dans son état, 0600) : il ne fait que monter, et tient après un
	// retour arrière. Il ne vient que d'une version signée, jamais d'un ordre.
	AgentReleaseFloorFile = "release-floor"
	AgentGuardBinary      = ID + "-guard"
	// Le lanceur stable : une copie du binaire posée une fois par root, hors
	// de bin/, que l'agent ne se met jamais à jour lui-même. L'unité lance
	// lui, et lui lance bin/current ; il dit à l'agent qu'il est là par
	// AgentGuardEnv.
	AgentGuardDir  = "/usr/local/lib/" + ID + "-agent"
	AgentGuardPath = AgentGuardDir + "/" + AgentGuardBinary
	// Le dossier où l'agent de la machine Kagu reçoit les sauvegardes de la
	// base (backup.receive), dans son état : setup y pose le droit, quel que
	// soit le jeu (R-SAUV-2).
	AgentDatabaseBackupsDir = AgentStateDir + "/database-backups"
	// Là où l'agent range ce qu'il produit (backup.produce), dans son état : à
	// lui, 0700.
	AgentProduceDir = "produce"
	// L'identité de l'agent, dans son état : ce que le premier lancement écrit,
	// et que l'opérateur supprime pour ré-enrôler.
	AgentIdentityFile = "identity.json"
	// La politique de l'agent (fiche A3) : ce que root lui permet. Un dossier
	// à root (0755) hors de son état, que son compte ne peut ni créer ni
	// effacer ; le fichier à root, lisible du groupe de l'agent (0640).
	AgentPolicyDir  = "/etc/" + ID + "-agent"
	AgentPolicyFile = "policy.toml"
	// Le jeton Proxmox local de l'agent (proxmox.power, proxmox.snapshot), dans
	// son état : posé par l'opérateur sur l'hôte, à l'agent seul, 0600. Il ne
	// voyage jamais, le serveur ne le garde pas.
	AgentProxmoxFile = "proxmox.json"
	// Les instantanés que l'agent crée portent ce préfixe : il ne supprime que
	// ceux-là, jamais ceux de l'opérateur.
	SnapshotPrefix = TokenPrefix + "-"
	// La socket de la porte vzdump (backup.produce), à root et au groupe de
	// l'agent.
	VzdumpGateSocket = "/run/" + ID + "-vzdump.sock"
	// Le nom d'une sauvegarde est le préfixe de son plan (celui de la base est
	// ID), un instant UTC et « .tar.age » ; la clé scellée qui
	// l'accompagne porte le préfixe ci-dessous et l'empreinte.
	BackupKeyFilePrefix = ID + "-key-"

	// Le nom de la machine qui héberge le serveur, dans la base.
	LocalMachineName = ID
	// Préfixe des identifiants de transaction envoyés à Matrix.
	MatrixTransactionPrefix = ID + "-"
)

// EnvPrefix précède les variables d'environnement qui portent le nom : ID en
// capitales, qu'une constante ne sait pas calculer.
var EnvPrefix = strings.ToUpper(ID) + "_"

// AgentGuardEnv est la variable par laquelle le lanceur stable dit à l'agent
// qu'il est là.
var AgentGuardEnv = EnvPrefix + "AGENT_GUARD"

// repositoryURL est le dépôt publié, qui porte le nom du produit.
const repositoryURL = "https://github.com/ldesfontaine/" + ID

// Les fichiers d'une version publiée, et le commentaire de sa signature.
// ReleaseBaseURL est l'adresse des versions par défaut : releases_url de la
// configuration la remplace, install.sh la lit dans KAGU_RELEASES.
const (
	ReleaseBaseURL = repositoryURL + "/releases/download"
	// La page de la dernière version : elle renvoie vers celle de son tag,
	// d'où upgrade lit le numéro.
	ReleaseLatestURL        = repositoryURL + "/releases/latest"
	ReleaseBinaryPrefix     = ID + "-linux-"
	ReleaseSumsFile         = "SHA256SUMS"
	ReleaseSignatureFile    = ReleaseSumsFile + ".minisig"
	ReleaseSignatureComment = "signature from " + ID + " release key"
	// Le script publié avec chaque version, que les lignes d'installation et
	// d'ajout lancent.
	ReleaseInstallScript = "install.sh"
)

// SecretKeyIDDomain sépare l'identifiant d'une clé de toute autre empreinte
// de la même clé. Il entre dans le calcul de l'identifiant inscrit dans
// chaque secret chiffré : le changer rend les secrets déjà chiffrés
// illisibles.
const SecretKeyIDDomain = ID + "-key-id\x00"

// OrderSignatureDomain précède le corps d'un ordre (enveloppe v2) dans ce que
// la clé du serveur signe : une signature d'ordre ne vaut pour rien d'autre.
// Dérivé de ID comme SecretKeyIDDomain : le changer, c'est que les agents
// installés refusent les ordres signés sous l'ancienne étiquette.
const OrderSignatureDomain = ID + "-order/v2\x00"

// LabelPrefix est lu par l'agent sur les conteneurs. Dérivé de ID comme les
// chemins : le changer, c'est que les conteneurs déjà étiquetés ne sont plus
// lus et retombent aux niveaux Compose et nom.
const LabelPrefix = ID + "."

// InstallDocURL est la page d'installation, que l'unité de l'agent cite.
const InstallDocURL = repositoryURL + "/blob/dev/docs/installation.md"

// AgentUnit est l'unité de l'agent : la page d'un droit qui écrit hors de
// l'état dit à l'opérateur laquelle compléter (ReadWritePaths).
const AgentUnit = ID + "-agent.service"

// AgentAccount est le compte système sous lequel l'installation recommandée
// lance l'agent : propriétaire de son état et des dossiers où ses droits
// écrivent. Son dossier personnel est AgentStateDir.
const AgentAccount = ID + "-agent"

// ServerUnit est l'unité du serveur : la restauration dit de la démarrer.
const ServerUnit = ID + ".service"

// WorkspaceMarker est le fichier témoin que l'agent pose à la création de la
// racine des services : une racine qui existe, n'est pas vide et n'en porte
// pas n'est pas à Kagu, l'agent n'y écrit rien.
const WorkspaceMarker = "." + ID

// Command est le nom du binaire : le Makefile le construit sous ce nom
// (-o bin/…), qu'il faut changer avec ID.
const Command = ID

// Les User-Agent envoyés aux services externes. Ils suivent le nom affiché :
// un tiers qui filtrait sur l'ancien nom voit le nouveau.
const (
	UserAgent          = ProductName
	RegistryUserAgent  = ProductName + "-agent"
	LifecycleUserAgent = ID
)

// C. Empreinte du protocole.
//
// Dérivés du nom comme le reste, sans double lecture : les changer casse les
// agents installés, les récepteurs de webhooks et les jetons déjà émis. Un
// changement de nom se fait en réinstallant (décision du 12 novembre).
const (
	HeaderPrefix           = ProductName + "-"
	WebhookEventHeader     = HeaderPrefix + "Event"
	WebhookSignatureHeader = HeaderPrefix + "Signature"
	// L'en-tête où le mandataire d'authentification pose le secret qu'il
	// partage avec le serveur : le mode forward ne croit l'identité que d'une
	// requête qui le porte. Le nom est dans la configuration du mandataire.
	ProxySecretHeader = "X-" + HeaderPrefix + "Proxy-Secret" // #nosec G101 -- un nom d'en-tête, pas un secret.
	// L'étiquette de l'enveloppe v1, que lit un agent du protocole 2 : gardée
	// pour le seul agent.update qui le met à jour, elle disparaît à la version
	// suivante.
	LegacyOrderSignatureDomain = ID + "-order/v1\x00"
	// Précède ce que l'agent signe pour ouvrir son flux (protocole 2) : la
	// preuve ne vaut pour rien d'autre.
	AgentProofDomain = ID + "-agent-proof/v2\x00"
)

// Les préfixes de jetons : reconnaissables dans un journal ou un
// presse-papier, jamais confondus entre eux (le jeton de ping, hb_, n'est
// pas une marque et reste dans internal/domain/heartbeat).
const (
	TokenPrefix           = "kg"
	EnrollmentTokenScheme = TokenPrefix + "_"  // #nosec G101 -- un préfixe, pas un secret.
	APITokenScheme        = TokenPrefix + "k_" // #nosec G101 -- un préfixe, pas un secret.
)

// Les cookies de session de l'opérateur (A2, R-A2-3). Le préfixe __Host-
// oblige le navigateur à ne l'accepter que Secure, sans Domain, sur Path=/ ;
// le cookie local, sans Secure, sert le tunnel SSH en HTTP sur la boucle
// locale.
const (
	SessionCookie      = "__Host-" + ID + "_session"
	LocalSessionCookie = ID + "_session_local"
)

// Début de l'empreinte de l'identifiant d'une machine, pour reconnaître
// un agent installé sur la machine du serveur.
const HostFingerprintPrefix = ID + "-host:"

// Docker et restic, que setup installe après un oui (R-B1-4, décision de
// sécurité 15) : ces sources, ces versions et ces sommes, inscrites dans la
// version signée de Kagu, et rien d'autre ; jamais « la dernière ». Les
// changer demande une version de Kagu.
const (
	// Le dépôt APT de Docker, et l'empreinte OpenPGP de la clé qui le signe :
	// une clé téléchargée qui n'a pas celle-ci ne s'installe pas.
	DockerRepositoryURL  = "https://download.docker.com/linux"
	DockerKeyFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
	// Les versions des paquets, sans le suffixe que le dépôt ajoute pour chaque
	// système (« ~debian.12~bookworm »).
	DockerVersion        = "5:29.10.0-1"
	ContainerdVersion    = "2.4.2-3"
	DockerComposeVersion = "5.7.2-1"
	// restic : son binaire officiel, compressé en bzip2.
	ResticVersion    = "0.19.1"
	ResticReleaseURL = "https://github.com/restic/restic/releases/download"
)

// ResticArchiveSums : la somme SHA-256 de restic_<version>_linux_<arch>.bz2
// par architecture, relue sur le SHA256SUMS que l'équipe de restic signe.
var ResticArchiveSums = map[string]string{
	"amd64": "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c",
	"arm64": "a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465",
}
