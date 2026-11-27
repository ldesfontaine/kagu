// Package releasetest écrit des versions signées pour les tests, avec une clé
// tirée par le test : jamais la clé de confiance du binaire.
package releasetest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/release"
)

// Binaries rend, pour chaque architecture, un contenu de binaire qui dit sa
// version et son architecture.
func Binaries(version string, arches ...string) map[string][]byte {
	binaries := make(map[string][]byte, len(arches))
	for _, arch := range arches {
		binaries[release.BinaryName(arch)] = []byte("the " + arch + " binary of " + version)
	}
	return binaries
}

// Write écrit dans un dossier neuf les binaires, SHA256SUMS et sa signature
// faite avec private pour cette version, et rend le dossier : c'est ce que
// `release import` reçoit.
func Write(t testing.TB, private release.PrivateKey, version string, binaries map[string][]byte) string {
	t.Helper()
	return WriteWithFloor(t, private, version, "", binaries)
}

// WriteWithFloor est Write pour une version qui porte un plancher de sécurité
// (vX.Y.Z) dans son commentaire de confiance ; vide, aucun.
func WriteWithFloor(t testing.TB, private release.PrivateKey, version, floor string, binaries map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	names := make([]string, 0, len(binaries))
	for name := range binaries {
		names = append(names, name)
	}
	slices.Sort(names)
	var sums string
	for _, name := range names {
		digest := sha256.Sum256(binaries[name])
		sums += hex.EncodeToString(digest[:]) + "  " + name + "\n"
		write(t, filepath.Join(dir, name), binaries[name])
	}
	write(t, filepath.Join(dir, brand.ReleaseSumsFile), []byte(sums))
	signature, err := release.Sign([]byte(sums), private, trustedComment(t, version, floor))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, brand.ReleaseSignatureFile), signature)
	return dir
}

// trustedComment écrit le commentaire de confiance ; une version qui ne se
// lit pas y est écrite telle quelle, pour les tests qui la veulent refusée.
func trustedComment(t testing.TB, version, floor string) string {
	t.Helper()
	parsed, err := release.ParseVersion(version)
	if err != nil {
		return "timestamp:1\tfile:" + brand.ReleaseSumsFile + "\tversion:" + version
	}
	var floorVersion release.Version
	if floor != "" {
		if floorVersion, err = release.ParseVersion(floor); err != nil {
			t.Fatal(err)
		}
	}
	return release.TrustedComment(1, parsed, floorVersion)
}

func write(t testing.TB, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(name, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
