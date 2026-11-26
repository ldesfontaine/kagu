package release

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

var (
	// ErrNoRelease : cette version, ou ce binaire de cette architecture, n'a
	// pas été importé.
	ErrNoRelease = errors.New("release: version not imported")
	// ErrVersionConflict : la version est déjà importée avec d'autres sommes.
	// Une version ne se réécrit jamais.
	ErrVersionConflict = refusal.Conflict("release.version_conflict", "release: version already imported with other files")
	// ErrNothingToImport : le dossier ne porte aucun binaire de la version.
	ErrNothingToImport = refusal.Invalid("release.nothing_to_import", "release: the version lists no binary")
	// ErrFolderNotAbsolute : le dossier à importer se nomme par un chemin
	// absolu ; un chemin relatif se lirait depuis le dossier courant de serve.
	ErrFolderNotAbsolute = refusal.Invalid("release.folder_not_absolute", "release: the folder path is not absolute")
	// ErrFolderUnreadable : le dossier, ou l'un de ses fichiers, manque ou
	// n'est pas lisible du compte qui importe (serve n'a pas le /tmp de root).
	ErrFolderUnreadable = refusal.Invalid("release.folder_unreadable", "release: the folder or one of its files cannot be read")
)

const (
	// Lisible du compte qui lance le serveur et de son groupe, pas des autres.
	libraryDirMode  = 0o750
	libraryFileMode = 0o640
	// Un binaire tient en dizaines de Mio ; au-delà, ce n'est pas le nôtre.
	maxBinarySize = 256 << 20
)

// Library est l'ensemble des versions importées, sous <état>/releases/<version>/ :
// SHA256SUMS, sa signature et les binaires. Le serveur n'y télécharge rien ;
// c'est l'opérateur qui y dépose, par Import. Les clés de confiance sont celles
// du binaire (TrustedPublicKeys) : les tests en injectent.
type Library struct {
	root *os.Root
	keys Keys
}

// NewLibrary lit et écrit sous stateDir, la racine de l'état du serveur.
func NewLibrary(stateDir *os.Root, keys Keys) *Library {
	return &Library{root: stateDir, keys: keys}
}

// UpgradeLine est la ligne que root lance sur la machine du serveur pour
// installer la plus récente des versions importées.
func UpgradeLine() string {
	return "sudo " + brand.Command + " upgrade"
}

// BinaryName est le nom, dans une version, du binaire d'une architecture.
func BinaryName(arch string) string {
	return brand.ReleaseBinaryPrefix + arch
}

func versionDir(version Version) string {
	return path.Join(brand.ReleasesDir, version.String())
}

// Import copie sous l'état la version que contient dir, un chemin absolu
// (SHA256SUMS, sa signature et chaque binaire listé), après avoir tout
// vérifié (ReadVerified). Rien n'est écrit d'une version qui ne passe pas.
// Importer deux fois la même version ne change rien ; la même version avec
// d'autres sommes est refusée.
func (library *Library) Import(dir string) (Release, error) {
	if !filepath.IsAbs(dir) {
		return Release{}, ErrFolderNotAbsolute
	}
	source, err := os.OpenRoot(dir)
	if err != nil {
		return Release{}, unreadable(fmt.Errorf("open release folder: %w", err))
	}
	defer source.Close()
	verified, err := ReadVerified(RootOpener(source), library.keys)
	if err != nil {
		return Release{}, unreadable(err)
	}
	if err := library.refuseOtherSums(verified.Version, verified.SumsFile); err != nil {
		return Release{}, err
	}
	if err := library.store(verified); err != nil {
		return Release{}, err
	}
	return verified.Release, nil
}

// Opener ouvre un fichier d'une version par son nom : dans un dossier, ou à
// l'adresse des versions.
type Opener func(name string) (io.ReadCloser, error)

// RootOpener ouvre les fichiers sous root, sans jamais en sortir.
func RootOpener(root *os.Root) Opener {
	return func(name string) (io.ReadCloser, error) {
		return root.Open(name)
	}
}

// Verified est une version lue en entier et vérifiée : ses sommes, leur
// signature et chacun de ses binaires, tels qu'ils ont été vérifiés.
type Verified struct {
	Release
	SumsFile  []byte
	Signature []byte
	Binaries  map[string][]byte
}

// ReadVerified lit SHA256SUMS et sa signature, les vérifie avec keys, puis lit
// chaque binaire listé et vérifie sa somme. Les octets rendus sont ceux qui
// ont été vérifiés : celui qui les pose ne relit rien. Rien n'est rendu d'une
// version qui ne passe pas.
func ReadVerified(open Opener, keys Keys) (Verified, error) {
	sums, err := readSmallFrom(open, brand.ReleaseSumsFile)
	if err != nil {
		return Verified{}, err
	}
	signature, err := readSmallFrom(open, brand.ReleaseSignatureFile)
	if err != nil {
		return Verified{}, err
	}
	signed, err := VerifySums(sums, signature, keys)
	if err != nil {
		return Verified{}, err
	}
	binaries, err := readBinaries(open, signed)
	if err != nil {
		return Verified{}, err
	}
	return Verified{Release: signed, SumsFile: sums, Signature: signature, Binaries: binaries}, nil
}

// unreadable fait d'un fichier absent ou interdit du dossier importé le refus
// ErrFolderUnreadable ; toute autre erreur reste ce qu'elle est.
func unreadable(err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: %w", ErrFolderUnreadable, err)
	}
	return err
}

// BinaryNames rend, dans l'ordre, les binaires que la version liste.
func (release Release) BinaryNames() []string {
	var names []string
	for name := range release.Sums {
		if strings.HasPrefix(name, brand.ReleaseBinaryPrefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// readBinaries lit chaque binaire listé et vérifie sa somme ; tous sont
// attendus dans le dossier.
func readBinaries(open Opener, signed Release) (map[string][]byte, error) {
	names := signed.BinaryNames()
	if len(names) == 0 {
		return nil, ErrNothingToImport
	}
	binaries := make(map[string][]byte, len(names))
	for _, name := range names {
		file, err := open(name)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		content, err := fsx.ReadLimited(file, maxBinarySize)
		_ = file.Close()
		if errors.Is(err, fsx.ErrTooLarge) {
			return nil, fmt.Errorf("%w: %s is too long", ErrMalformed, name)
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if err := signed.Check(name, bytes.NewReader(content)); err != nil {
			return nil, err
		}
		binaries[name] = content
	}
	return binaries, nil
}

// refuseOtherSums : une version déjà là avec d'autres sommes ne se remplace pas.
func (library *Library) refuseOtherSums(version Version, sums []byte) error {
	existing, err := library.root.ReadFile(path.Join(versionDir(version), brand.ReleaseSumsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read imported sums: %w", err)
	}
	if !bytes.Equal(existing, sums) {
		return fmt.Errorf("%w: %s", ErrVersionConflict, version)
	}
	return nil
}

// store écrit chaque fichier qui diffère de celui déjà là. Les sommes viennent
// en dernier : une coupure laisse une version sans SHA256SUMS, que la
// bibliothèque dit non importée, et que la reprise de l'import complète.
func (library *Library) store(verified Verified) error {
	dir := versionDir(verified.Version)
	if err := library.root.MkdirAll(dir, libraryDirMode); err != nil {
		return fmt.Errorf("create release folder: %w", err)
	}
	for _, name := range verified.BinaryNames() {
		if err := library.write(path.Join(dir, name), verified.Binaries[name]); err != nil {
			return err
		}
	}
	if err := library.write(path.Join(dir, brand.ReleaseSignatureFile), verified.Signature); err != nil {
		return err
	}
	return library.write(path.Join(dir, brand.ReleaseSumsFile), verified.SumsFile)
}

func (library *Library) write(name string, content []byte) error {
	existing, err := library.root.ReadFile(name)
	if err == nil && bytes.Equal(existing, content) {
		return nil
	}
	if err := fsx.WriteAtomic(library.root, name, content, libraryFileMode); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// Artifact est le binaire d'une version importée pour une architecture, tel
// que le serveur le tend à un agent. Les chemins sont relatifs à l'état.
type Artifact struct {
	Version       Version
	Name          string
	Path          string
	SumsPath      string
	SignaturePath string
	SHA256        string
	Size          int64
}

// Artifact relit et revérifie la version à chaque appel : la signature, puis
// la somme du binaire. Un octet changé depuis l'import est une erreur, jamais
// un binaire envoyé. ErrNoRelease si la version, ou ce binaire, manque.
func (library *Library) Artifact(version Version, arch string) (Artifact, error) {
	dir := versionDir(version)
	sumsPath := path.Join(dir, brand.ReleaseSumsFile)
	signaturePath := path.Join(dir, brand.ReleaseSignatureFile)
	signed, err := library.verifiedSums(version)
	if err != nil {
		return Artifact{}, err
	}
	name := BinaryName(arch)
	digest, listed := signed.Sums[name]
	if !listed {
		return Artifact{}, fmt.Errorf("%w: %s has no %s", ErrNoRelease, version, name)
	}
	binaryPath := path.Join(dir, name)
	size, err := library.checkBinary(signed, name, binaryPath)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Version: version, Name: name, Path: binaryPath, SumsPath: sumsPath, SignaturePath: signaturePath,
		SHA256: digest, Size: size,
	}, nil
}

// verifiedSums relit les sommes d'une version importée et leur signature, et
// vérifie que le dossier porte bien la version qu'il nomme.
func (library *Library) verifiedSums(version Version) (Release, error) {
	dir := versionDir(version)
	sums, err := library.readImported(path.Join(dir, brand.ReleaseSumsFile))
	if err != nil {
		return Release{}, err
	}
	signature, err := library.readImported(path.Join(dir, brand.ReleaseSignatureFile))
	if err != nil {
		return Release{}, err
	}
	signed, err := VerifySums(sums, signature, library.keys)
	if err != nil {
		return Release{}, err
	}
	if signed.Version != version {
		return Release{}, fmt.Errorf("%w: folder %s holds %s", ErrMalformed, version, signed.Version)
	}
	return signed, nil
}

// Versions rend les versions importées, de la plus ancienne à la plus
// récente : celles dont les sommes passent la signature. Un dossier coupé
// avant ses sommes, ou qui ne passe plus la vérification, n'en est pas une.
func (library *Library) Versions() ([]Version, error) {
	folder, err := library.root.Open(brand.ReleasesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open releases folder: %w", err)
	}
	defer folder.Close()
	entries, err := folder.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("read releases folder: %w", err)
	}
	var versions []Version
	for _, entry := range entries {
		version, err := ParseVersion(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		if _, err := library.verifiedSums(version); err != nil {
			continue
		}
		versions = append(versions, version)
	}
	slices.SortFunc(versions, Version.Compare)
	return versions, nil
}

// Read relit une version importée en entier et la revérifie (ReadVerified) :
// ce que la montée du serveur installe. ErrNoRelease si elle manque.
func (library *Library) Read(version Version) (Verified, error) {
	folder, err := library.root.OpenRoot(versionDir(version))
	if errors.Is(err, fs.ErrNotExist) {
		return Verified{}, fmt.Errorf("%w: %s", ErrNoRelease, version)
	}
	if err != nil {
		return Verified{}, fmt.Errorf("open %s: %w", versionDir(version), err)
	}
	defer folder.Close()
	verified, err := ReadVerified(RootOpener(folder), library.keys)
	if err != nil {
		return Verified{}, err
	}
	if verified.Version != version {
		return Verified{}, fmt.Errorf("%w: folder %s holds %s", ErrMalformed, version, verified.Version)
	}
	return verified, nil
}

func (library *Library) checkBinary(signed Release, name, binaryPath string) (int64, error) {
	file, err := library.root.Open(binaryPath)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("%w: %s", ErrNoRelease, binaryPath)
	}
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", name, err)
	}
	if err := signed.Check(name, file); err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// readImported lit un fichier de sommes ou de signature de la bibliothèque ;
// absent, c'est que la version n'est pas importée.
func (library *Library) readImported(name string) ([]byte, error) {
	content, err := readSmallFrom(RootOpener(library.root), name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoRelease, name)
	}
	return content, err
}

func readSmallFrom(open Opener, name string) ([]byte, error) {
	file, err := open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer file.Close()
	return readSmall(file, name)
}
