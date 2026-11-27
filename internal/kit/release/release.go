package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

var (
	// ErrNotListed : le nom du fichier n'est pas dans les sommes de la version.
	ErrNotListed = errors.New("release: file not listed in the version")
	// ErrDigestMismatch : la somme du fichier n'est pas celle de la version.
	ErrDigestMismatch = refusal.Invalid("release.digest_mismatch", "release: file does not match the version")
)

// Un fichier de sommes ou de signature tient en quelques centaines d'octets.
const maxSmallFileSize = 1 << 20

// Le champ du commentaire de confiance qui porte le plancher (QA-17) : jamais
// dans SHA256SUMS, que ParseSums et « sha256sum --strict » liraient comme une
// somme fausse.
const floorField = "floor"

// Release est une version dont les sommes sont signées par une clé de confiance.
type Release struct {
	Version Version
	Sums    map[string]string
	// ByBackup : la clé de secours l'a signée ; elle devient la courante.
	ByBackup bool
	// Floor est le plancher de sécurité de la version (R-B2-11) : un agent
	// qui l'a confirmée ne redescend plus sous lui. Zéro : pas de plancher.
	Floor Version
}

// VerifySums vérifie la signature des sommes, puis lit la version et son
// plancher dans le commentaire de confiance : c'est la seule partie du fichier
// de signature que la signature couvre en plus des sommes, et la seule source
// des deux. Un plancher au-dessus de sa propre version est refusé.
func VerifySums(sums, signature []byte, keys Keys) (Release, error) {
	comment, byBackup, err := Verify(sums, signature, keys)
	if err != nil {
		return Release{}, err
	}
	fields, err := parseTrustedComment(comment)
	if err != nil {
		return Release{}, err
	}
	if fields["file"] != brand.ReleaseSumsFile {
		return Release{}, fmt.Errorf("%w: trusted comment names another file", ErrMalformed)
	}
	version, err := ParseVersion(fields["version"])
	if err != nil {
		return Release{}, err
	}
	floor, err := parseFloor(fields, version)
	if err != nil {
		return Release{}, err
	}
	parsed, err := ParseSums(sums)
	if err != nil {
		return Release{}, err
	}
	return Release{Version: version, Sums: parsed, ByBackup: byBackup, Floor: floor}, nil
}

// parseFloor lit le champ « floor » : absent (une version signée avant le
// plancher), il vaut zéro.
func parseFloor(fields map[string]string, version Version) (Version, error) {
	text, present := fields[floorField]
	if !present {
		return Version{}, nil
	}
	floor, err := ParseVersion(text)
	if err != nil {
		return Version{}, err
	}
	if IsBelowFloor(version, floor) {
		return Version{}, fmt.Errorf("%w: floor %s above version %s", ErrMalformed, floor, version)
	}
	return floor, nil
}

// TrustedComment écrit le commentaire de confiance d'une version : l'instant,
// le fichier signé, la version, et le plancher s'il y en a un.
func TrustedComment(timestamp int64, version, floor Version) string {
	comment := fmt.Sprintf("timestamp:%d\tfile:%s\tversion:%s", timestamp, brand.ReleaseSumsFile, version)
	if floor != (Version{}) {
		comment += "\t" + floorField + ":" + floor.String()
	}
	return comment
}

// parseTrustedComment lit les paires « clé:valeur » séparées par des tabulations.
func parseTrustedComment(comment string) (map[string]string, error) {
	fields := make(map[string]string)
	for _, pair := range strings.Split(comment, "\t") {
		name, value, found := strings.Cut(pair, ":")
		if !found {
			return nil, fmt.Errorf("%w: trusted comment field %q", ErrMalformed, pair)
		}
		if _, seen := fields[name]; seen {
			return nil, fmt.Errorf("%w: trusted comment field %q twice", ErrMalformed, name)
		}
		fields[name] = value
	}
	return fields, nil
}

// Check lit content en entier et vérifie sa somme contre celle que la version
// donne à name.
func (release Release) Check(name string, content io.Reader) error {
	want, listed := release.Sums[name]
	if !listed {
		return fmt.Errorf("%w: %s", ErrNotListed, name)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, content); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != want {
		return fmt.Errorf("%w: %s", ErrDigestMismatch, name)
	}
	return nil
}

// VerifyFile vérifie que path appartient à la version signée par keys : les
// sommes et leur signature se lisent aux chemins donnés, le fichier est
// cherché sous son nom de base.
func VerifyFile(path, sumsPath, signaturePath string, keys Keys) (Release, error) {
	sums, err := readSmallFile(sumsPath)
	if err != nil {
		return Release{}, err
	}
	signature, err := readSmallFile(signaturePath)
	if err != nil {
		return Release{}, err
	}
	signed, err := VerifySums(sums, signature, keys)
	if err != nil {
		return Release{}, err
	}
	file, err := os.Open(path) // #nosec G304 -- chemin donné par l'opérateur
	if err != nil {
		return Release{}, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()
	if err := signed.Check(filepath.Base(path), file); err != nil {
		return Release{}, err
	}
	return signed, nil
}

func readSmallFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- chemin donné par l'opérateur
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()
	return readSmall(file, filepath.Base(path))
}

// readSmall lit un fichier de sommes ou de signature, borné.
func readSmall(file io.Reader, name string) ([]byte, error) {
	content, err := fsx.ReadLimited(file, maxSmallFileSize)
	if errors.Is(err, fsx.ErrTooLarge) {
		return nil, fmt.Errorf("%w: %s is too long", ErrMalformed, name)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return content, nil
}
