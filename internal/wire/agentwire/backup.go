package agentwire

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// BackupReceiveParams sont les paramètres de backup.receive : le colis à
// télécharger, le dossier où écrire, les fichiers attendus avec leur taille
// et leur somme. Rien ici n'est un secret : le contenu est déjà chiffré.
//
// Archive dit ce que le colis porte (ArchiveDatabase, ArchiveFirewall,
// ArchiveGuest) : l'agent en tire son plafond de taille, jamais du nom du
// fichier. Absent, c'est la base.
type BackupReceiveParams struct {
	Parcel  string       `json:"parcel"`
	Path    string       `json:"path"`
	Files   []ParcelFile `json:"files"`
	Archive string       `json:"archive,omitempty"`
}

// Les types d'archive d'un colis de sauvegarde. Seule l'archive d'un invité
// (vzdump) n'a pas de plafond de taille en dur.
const (
	ArchiveDatabase = "database"
	ArchiveFirewall = "firewall"
	ArchiveGuest    = "guest"
)

// IsArchiveKind dit si un type d'archive est connu : vide (la base), ou l'un
// des trois.
func IsArchiveKind(kind string) bool {
	return kind == "" || kind == ArchiveDatabase || kind == ArchiveFirewall || kind == ArchiveGuest
}

// BackupPruneParams sont ceux de backup.prune : le dossier, le préfixe des
// fichiers d'un plan (BackupFilePrefix), et combien de sauvegardes de ce
// préfixe y garder. Sans préfixe l'ordre est refusé : l'élagage ne touche
// que les fichiers d'un plan, jamais ceux des autres.
type BackupPruneParams struct {
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
	Keep   int    `json:"keep"`
}

const (
	backupFileTimeLayout = "20060102-150405"
	backupFileSuffix     = ".tar.age"
	backupKeySuffix      = ".age"
	// DatabaseSubject est le sujet du plan de la base : ses fichiers gardent
	// le nom d'avant les plans multiples (opencloud-AAAAMMJJ-HHMMSS.tar.age).
	DatabaseSubject = "database"
	// Le préfixe tient dans un nom de fichier, avec l'instant et le suffixe.
	maxBackupPrefix = 64

	// PrefixSinceVersion est la première version d'agent qui lit le préfixe de
	// backup.prune. Un agent plus ancien l'ignore et élague « opencloud-… »
	// avec le nombre à garder de n'importe quel plan : le serveur ne lui envoie
	// pas l'élagage d'un plan machine.
	PrefixSinceVersion = "v0.2.0"
)

var (
	backupFilePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*-\d{8}-\d{6}\.tar\.age$`)
	backupPrefixPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	backupStampPattern   = regexp.MustCompile(`^\d{8}-\d{6}\.tar\.age$`)
	backupKeyFilePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(brand.BackupKeyFilePrefix) + `([0-9a-f]{16})(\.[1-9][0-9]*)?` + regexp.QuoteMeta(backupKeySuffix) + `$`)
)

// BackupFilePrefix est ce que les fichiers d'un plan ont en commun : le
// sujet, suivi d'un suffixe quand une source produit plusieurs archives
// (une par machine virtuelle). Le plan de la base garde « opencloud ».
func BackupFilePrefix(subject, suffix string) string {
	prefix := subject
	if subject == DatabaseSubject {
		prefix = brand.ID
	}
	if suffix != "" {
		prefix += "-" + suffix
	}
	return prefix
}

// IsBackupPrefix dit si un texte peut préfixer des fichiers de sauvegarde :
// l'agent n'élague jamais sous un préfixe qui n'a pas cette forme.
func IsBackupPrefix(prefix string) bool {
	return len(prefix) <= maxBackupPrefix && backupPrefixPattern.MatchString(prefix)
}

// BackupFileName nomme la sauvegarde du plan faite à cet instant, en UTC : le
// tri par nom est le tri par date.
func BackupFileName(subject string, at time.Time) string {
	return BackupFilePrefix(subject, "") + "-" + at.UTC().Format(backupFileTimeLayout) + backupFileSuffix
}

// IsBackupFile dit si un nom a la forme d'une sauvegarde : un préfixe, un
// instant, « .tar.age ». L'élagage n'efface rien d'autre (ni une clé
// déposée, ni un fichier de l'opérateur).
func IsBackupFile(name string) bool {
	return backupFilePattern.MatchString(name)
}

// IsBackupFileOf dit si la sauvegarde appartient à ce préfixe : ce qui suit
// le préfixe est exactement l'instant. « pve » ne prend donc jamais
// « pve-vm-100-… », dont le reste n'est pas un instant. Un préfixe qui n'en
// est pas un (vide, une majuscule, un chemin) ne prend rien.
func IsBackupFileOf(name, prefix string) bool {
	if !IsBackupPrefix(prefix) {
		return false
	}
	rest, found := strings.CutPrefix(name, prefix+"-")
	return found && backupStampPattern.MatchString(rest)
}

// BackupKeyFileName nomme la clé scellée déposée à côté des sauvegardes
// qu'elle ouvre.
func BackupKeyFileName(fingerprint string) string {
	return brand.BackupKeyFilePrefix + fingerprint + backupKeySuffix
}

// BackupKeyFileVersion nomme la version numéro version d'une clé reçue sous
// name : l'agent y pose une clé qui diffère de celle qu'il garde déjà sous ce
// nom, sans jamais la remplacer. Le nom finit toujours par « .age ».
func BackupKeyFileVersion(name string, version int) string {
	return strings.TrimSuffix(name, backupKeySuffix) + "." + strconv.Itoa(version) + backupKeySuffix
}

// IsBackupKeyFile : la forme exacte d'une clé déposée, la clé reçue ou l'une
// de ses versions gardées à côté. L'élagage n'en touche aucune.
func IsBackupKeyFile(name string) bool {
	return backupKeyFilePattern.MatchString(name)
}

// IsSentBackupKeyFile : la clé telle que le serveur la nomme, sans numéro de
// version. Avec IsBackupFile, ce sont les deux seuls noms que backup.receive
// accepte : seul l'agent numérote une version.
func IsSentBackupKeyFile(name string) bool {
	match := backupKeyFilePattern.FindStringSubmatch(name)
	return match != nil && match[2] == ""
}

// BackupKeyFingerprint rend l'empreinte que porte le nom d'une clé, vide si
// le nom n'est pas celui d'une clé.
func BackupKeyFingerprint(name string) string {
	match := backupKeyFilePattern.FindStringSubmatch(name)
	if match == nil {
		return ""
	}
	return match[1]
}
