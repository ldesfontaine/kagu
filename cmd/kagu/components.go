package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/domain/backup"
	"github.com/ldesfontaine/kagu/internal/domain/deploy"
	"github.com/ldesfontaine/kagu/internal/domain/directory"
	"github.com/ldesfontaine/kagu/internal/domain/heartbeat"
	"github.com/ldesfontaine/kagu/internal/domain/proxmox"
	"github.com/ldesfontaine/kagu/internal/domain/restic"
	"github.com/ldesfontaine/kagu/internal/domain/settings"
	"github.com/ldesfontaine/kagu/internal/edge/config"
	"github.com/ldesfontaine/kagu/internal/edge/server"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/container"
	"github.com/ldesfontaine/kagu/internal/fact/firewall"
	"github.com/ldesfontaine/kagu/internal/fact/firewall/opnsense"
	"github.com/ldesfontaine/kagu/internal/fact/hostconn"
	"github.com/ldesfontaine/kagu/internal/fact/lifecycle"
	"github.com/ldesfontaine/kagu/internal/fact/link"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/probe"
	"github.com/ldesfontaine/kagu/internal/fact/resource"
	"github.com/ldesfontaine/kagu/internal/fact/role"
	"github.com/ldesfontaine/kagu/internal/fact/sshkeys"
	"github.com/ldesfontaine/kagu/internal/fact/systemdunits"
	"github.com/ldesfontaine/kagu/internal/fact/update"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/gesture/apitoken"
	"github.com/ldesfontaine/kagu/internal/gesture/verbrequest"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/clocksync"
	"github.com/ldesfontaine/kagu/internal/kit/lang"
	"github.com/ldesfontaine/kagu/internal/kit/mail"
	"github.com/ldesfontaine/kagu/internal/kit/release"
	"github.com/ldesfontaine/kagu/internal/kit/version"
	"github.com/ldesfontaine/kagu/internal/view/manifest"
	"github.com/ldesfontaine/kagu/internal/view/status"
)

// components sont les composants que serve construit, déjà branchés entre
// eux : un composant ajouté se branche ici, une fois. Ce qui ne vaut que
// pour serve (le direct, les boucles, les commandeurs, la machine openCloud)
// reste dans serve.go.
type components struct {
	db           *store.DB
	actions      *action.Service
	sshKeys      *sshkeys.Service
	systemd      *systemdunits.Service
	links        *link.Service
	hostConns    *hostconn.Service
	roles        *role.Service
	proxmox      *proxmox.Service
	firewalls    *firewall.Service
	backups      *backup.Service
	restic       *restic.Service
	relay        *restic.Broker
	deployer     *deploy.Service
	logger       *slog.Logger
	preferences  *settings.Service
	machines     *machine.Service
	heartbeats   *heartbeat.Service
	resources    *resource.Service
	containers   *container.Tracker
	probes       *probe.Service
	declared     *directory.Directory
	updates      *update.Service
	statusPage   *status.Service
	alerts       *alert.Engine
	clockWatch   *alert.ClockWatch
	notifier     *alert.Notifier
	apiTokens    *apitoken.Service
	verbRequests *verbrequest.Service
	operator     *auth.Service
	support      *lifecycle.Service
	manifests    *manifest.Manifest
}

// buildComponents construit les composants sur la base ouverte. Rien n'y
// tourne encore : aucune boucle, aucune écriture.
func buildComponents(cfg config.Config, stateDir *os.Root, db *store.DB, logger *slog.Logger) (*components, error) {
	// Les réglages de l'opérateur : relus dans la base à chaque usage.
	preferences := settings.New(db, logger)
	machines := machine.New(db, machine.NewSessions(), logger)
	heartbeats := heartbeat.New(db, logger)
	resources := resource.New(db, logger)
	containers := container.New(db, logger)
	probes := probe.New(db, logger)
	declared := directory.New(db, logger)
	updates := update.New(db, logger)
	// L'annuaire lit ce que les machines montrent ; le suivi des conteneurs lui
	// demande les unités à chaque rapport, et l'annuaire lui demande de
	// rattacher de nouveau après chaque écriture.
	declared.SetObserved(containers, updates)
	declared.SetRematcher(containers)
	// La politique de mise à jour vit sur l'unité : l'annuaire dit au suivi
	// des images de redire à la machine ce qu'elle ne doit plus interroger.
	declared.SetAssigner(updates)
	containers.SetUnits(declared)
	// Les liens entre instances : les conteneurs lui disent ce que leur
	// configuration déclare et lisent ce qu'il garde ; l'annuaire écrit ceux
	// de l'opérateur.
	links := link.New(db, logger)
	declared.SetLinker(links)
	containers.SetLinks(links)
	// Qui joint les ports de l'hôte : les agents le relèvent, l'annuaire le
	// rapproche des instances qui publient ces ports.
	hostConns := hostconn.New()
	declared.SetObserver(hostConns)
	statusPage := status.New(db, db, machines, logger)
	// Les alertes : chaque composant lui donne ses faits, le notifieur livre
	// aux canaux dans la langue de l'interface.
	catalogs, err := lang.Load()
	if err != nil {
		return nil, fmt.Errorf("load languages: %w", err)
	}
	alerts := alert.New(db, logger)
	alerts.SetReminderDelay(preferences.CurrentDangerReminder)
	// L'horloge de la machine : non synchronisée trop longtemps, elle alerte.
	clockWatch := alert.NewClockWatch(alerts, clocksync.Synced)
	notifier := alert.NewNotifier(db, catalogs, preferences.CurrentLanguage, logger)
	notifier.SetPublicURL(cfg.PublicURL)
	notifier.SetMail(preferences.CurrentMailRelay, mail.NewSender(alert.MailTimeout))
	alerts.SetSender(notifier)
	machines.SetAlerter(alerts)
	heartbeats.SetAlerter(alerts)
	resources.SetAlerter(alerts)
	containers.SetAlerter(alerts)
	probes.SetAlerter(alerts)
	// Les jetons d'API que mcp-maison présente : leur purge.
	apiTokens := apitoken.New(db, logger)
	// Les demandes des verbes à confirmation : un jeton dépose, l'opérateur décide.
	verbRequests := verbrequest.New(db, logger)
	// L'accès de l'opérateur à l'interface : relu à chaque requête.
	operator := auth.New(db, logger)
	// Les échecs comptés par compte : les seuils du fichier de configuration,
	// et l'alerte du code suspendu.
	operator.SetAccountLimits(cfg.AccountLimits())
	operator.SetAlerter(alerts)
	// Le journal d'audit : chaque composant y écrit ses gestes, sous l'acteur
	// que le contexte porte. Les alertes le purgent avec leur historique.
	journal := audit.New(db, logger)
	preferences.SetAuditor(journal)
	machines.SetAuditor(journal)
	heartbeats.SetAuditor(journal)
	probes.SetAuditor(journal)
	declared.SetAuditor(journal)
	links.SetAuditor(journal)
	statusPage.SetAuditor(journal)
	alerts.SetAuditor(journal)
	// Le journal part aussi vers les canaux qui le reçoivent ; sans notifieur
	// (une commande hors ligne), les livraisons attendent le prochain serve.
	journal.SetForwarder(alerts)
	apiTokens.SetAuditor(journal)
	verbRequests.SetAuditor(journal)
	operator.SetAuditor(journal)
	// Les ordres aux agents : écrits, journalisés, puis signés par la clé du
	// serveur, que serve seul charge (sans elle, rien ne part).
	actions := action.New(db, machines, logger)
	actions.SetAuditor(journal)
	actions.SetAlerter(alerts)
	// Les mises à jour des agents : la bibliothèque des versions importées, lue
	// avec les clés de version embarquées. Sans clé (binaire de développement),
	// rien ne se vérifie et la fiche ne propose rien.
	if releaseKeys, keyErr := release.TrustedPublicKeys(); keyErr == nil {
		actions.SetReleases(release.NewLibrary(stateDir, releaseKeys), version.Number())
	} else {
		logger.Info("no release key embedded: agent updates are off")
	}
	// Les clés SSH autorisées que les agents relèvent, en lecture seule.
	sshKeys := sshkeys.New(db, logger)
	// Les unités systemd que les agents relèvent, en lecture seule.
	systemd := systemdunits.New(db, logger)
	declared.SetUnits(systemd)
	roles := role.New(db, logger)
	// Les hôtes Proxmox que des machines déclarent, lus en lecture seule ; la
	// boucle de relevé est à serve seul.
	hypervisors := proxmox.New(db, machines, logger)
	hypervisors.SetAuditor(journal)
	// Démarrer, arrêter proprement, prendre un instantané : des ordres à l'agent
	// de l'hôte, qui a son propre jeton local. Le serveur n'écrit jamais dans
	// Proxmox.
	hypervisors.SetOrders(actions)
	hypervisors.SetViewer(db)
	// Les pare-feu que l'opérateur déclare, lus en lecture seule ; la boucle de
	// relevé est à serve seul. Un autre constructeur ajoute ici son connecteur.
	firewalls := firewall.New(db, logger)
	firewalls.SetAuditor(journal)
	firewalls.SetConnector(firewall.KindOPNsense, opnsense.New)
	firewalls.SetTranslator(firewall.KindOPNsense, opnsense.Policy)
	// La sauvegarde de la base part par ces ordres. Le dépôt des colis
	// (SetParcels) et la boucle sont à serve seul.
	backups := backup.New(db, machines, stateDir, logger)
	backups.SetSender(actions)
	// « all », pour un plan machine, prend les invités que l'hôte Proxmox de la
	// source a relevés.
	backups.SetGuests(db)
	// L'export de la configuration d'un pare-feu déclaré : le serveur lit,
	// avec la clé qu'il garde ; rien n'en part vers un agent.
	backups.SetFirewalls(firewalls)
	backups.SetAuditor(journal)
	// Les sauvegardes restic : des ordres aux agents des sources et des
	// cibles, l'aperçu de la page Sauvegardes, qui lit aussi ce que backup
	// sait. Le relais vérifie la preuve de la source par machines et lit le
	// dépôt dans la base ; le serveur, qui tient les flux, le branche (serve).
	resticBackups := restic.New(db, machines, logger)
	resticBackups.SetSender(actions)
	resticBackups.SetInventory(backups)
	resticBackups.SetAuditor(journal)
	resticBackups.SetAlerter(alerts)
	relay := restic.NewBroker(machines, db, nil, logger)
	// Le déploiement des services déclarés part par les mêmes ordres signés.
	deployer := deploy.New(db, declared, machines, db, db, actions, logger)
	actions.SetServiceUpdates(deployer)
	// La fin de support : activée tant que l'opérateur ne la coupe pas sous
	// Paramètres. La machine openCloud lit endoflife.date une fois par jour,
	// deux au plus, pour les produits des images présentes et les systèmes
	// des machines : c'est une boucle de serve.
	support := lifecycle.New(containers.Images, machines.Systems, lifecycle.NewFileCache(stateDir), lifecycle.NewHTTPSource(), preferences.CurrentLifecycleEnabled, logger)
	// Le fichier de l'annuaire lit et écrit par les mêmes composants que
	// l'interface : les agents reçoivent leurs sondes, le rapprochement se
	// refait, les alertes suivent.
	manifests := manifest.New(manifest.Dependencies{
		Directory: declared, Probes: probes, Heartbeats: heartbeats, Reader: db, Journal: db,
	}, logger)
	return &components{
		db: db, logger: logger, preferences: preferences,
		machines: machines, heartbeats: heartbeats, resources: resources, containers: containers,
		probes: probes, declared: declared, updates: updates, statusPage: statusPage,
		alerts: alerts, clockWatch: clockWatch, notifier: notifier, apiTokens: apiTokens, verbRequests: verbRequests, operator: operator,
		support: support, manifests: manifests, actions: actions, sshKeys: sshKeys, systemd: systemd, links: links, hostConns: hostConns, roles: roles, proxmox: hypervisors, firewalls: firewalls, backups: backups, restic: resticBackups, relay: relay, deployer: deployer,
	}, nil
}

// serverOptions rend les options communes du serveur. Le direct (Live,
// PublicLive) et le secret du mandataire sont à la charge de l'appelant.
func (c *components) serverOptions(cfg config.Config) server.Options {
	return server.Options{
		Logger:          c.logger,
		Version:         version.Number(),
		Commit:          version.Commit(),
		Reader:          c.db,
		Settings:        c.preferences,
		Machines:        c.machines,
		Heartbeats:      c.heartbeats,
		Resources:       c.resources,
		Containers:      c.containers,
		Probes:          c.probes,
		Directory:       c.declared,
		Manifest:        c.manifests,
		Updates:         c.updates,
		Lifecycle:       c.support,
		Status:          c.statusPage,
		Alerts:          c.alerts,
		Notifier:        c.notifier,
		APITokens:       c.apiTokens,
		VerbRequests:    c.verbRequests,
		Auth:            c.operator,
		Actions:         c.actions,
		SSHKeys:         c.sshKeys,
		Systemd:         c.systemd,
		Links:           c.links,
		HostConnections: c.hostConns,
		Roles:           c.roles,
		Host:            c.machines,
		Proxmox:         c.proxmox,
		Firewalls:       c.firewalls,
		Backups:         c.backups,
		Restic:          c.restic,
		ResticAgent:     c.restic,
		ResticRelay:     c.relay,
		Deploy:          c.deployer,
		PublicURL:       cfg.PublicURL,
		Listen:          cfg.Listen,
		TrustedProxies:  cfg.TrustedPrefixes(),
		ForwardUsers:    cfg.ForwardUsers,
		MCPURL:          cfg.MCPURL,
	}
}
