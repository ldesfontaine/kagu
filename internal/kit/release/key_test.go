package release

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTrustedPublicKeys_ParseAndTheBackupIsAnotherKey(t *testing.T) {
	keys, err := TrustedPublicKeys()
	if CurrentPublicKey == "" {
		if !errors.Is(err, ErrNoTrustedKey) {
			t.Fatalf("empty key: %v", err)
		}
		return
	}
	if err != nil || keys.Current.String() != CurrentPublicKey {
		t.Fatalf("embedded keys do not parse: %v", err)
	}
	if keys.HasBackup() != (BackupPublicKey != "") {
		t.Fatalf("backup key set %v, parsed %v", BackupPublicKey != "", keys.HasBackup())
	}
	if !keys.HasBackup() {
		return
	}
	backup, err := ParsePublicKey(BackupPublicKey)
	if err != nil || backup.String() != BackupPublicKey {
		t.Fatalf("backup key does not parse: %v", err)
	}
	// Même identifiant, et Verify ne saurait plus laquelle a signé.
	if backup.Equal(keys.Current) || backup.id == keys.Current.id {
		t.Fatal("the backup key is, or shares its id with, the current key")
	}
}

// testKeys tire une courante et une secours, et rend aussi leurs clés privées.
func testKeys(t *testing.T) (Keys, PrivateKey, PrivateKey) {
	t.Helper()
	current, currentPrivate, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	backup, backupPrivate, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return Keys{Current: current, Backup: backup}, currentPrivate, backupPrivate
}

func signSums(t *testing.T, private PrivateKey) []byte {
	t.Helper()
	signature, err := Sign([]byte(vectorSums), private, vectorComment)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestVerify_AcceptsEitherKeyAndSaysWhichSigned(t *testing.T) {
	keys, currentPrivate, backupPrivate := testKeys(t)
	_, byBackup, err := Verify([]byte(vectorSums), signSums(t, currentPrivate), keys)
	if err != nil || byBackup {
		t.Fatalf("current key: backup %v, %v", byBackup, err)
	}
	_, byBackup, err = Verify([]byte(vectorSums), signSums(t, backupPrivate), keys)
	if err != nil || !byBackup {
		t.Fatalf("backup key: backup %v, %v", byBackup, err)
	}
	_, strangerPrivate, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify([]byte(vectorSums), signSums(t, strangerPrivate), keys); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("unknown key: %v", err)
	}
	// Sans secours posée (binaire de développement), sa signature ne passe pas.
	if _, _, err := Verify([]byte(vectorSums), signSums(t, backupPrivate), Keys{Current: keys.Current}); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("backup without backup key: %v", err)
	}
}

func TestKeysWithout_TheBackupReplacesARetiredCurrentAndNothingIsAdded(t *testing.T) {
	keys, currentPrivate, backupPrivate := testKeys(t)
	stranger, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	same, err := keys.Without([]PublicKey{stranger})
	if err != nil || !same.Current.Equal(keys.Current) || !same.Backup.Equal(keys.Backup) {
		t.Fatalf("retired a key this binary lacks: %v", err)
	}
	rotated, err := keys.Without([]PublicKey{keys.Current})
	if err != nil || !rotated.Current.Equal(keys.Backup) || rotated.HasBackup() {
		t.Fatalf("retired the current key: %v", err)
	}
	if _, _, err := Verify([]byte(vectorSums), signSums(t, currentPrivate), rotated); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("retired key: %v", err)
	}
	if _, byBackup, err := Verify([]byte(vectorSums), signSums(t, backupPrivate), rotated); err != nil || byBackup {
		t.Fatalf("former backup, now current: backup %v, %v", byBackup, err)
	}
	if _, err := keys.Without([]PublicKey{keys.Current, keys.Backup}); !errors.Is(err, ErrNoTrustedKey) {
		t.Fatalf("both retired: %v", err)
	}
	if _, err := (Keys{Current: keys.Current}).Without([]PublicKey{keys.Current}); !errors.Is(err, ErrNoTrustedKey) {
		t.Fatalf("current retired without a backup: %v", err)
	}
}

// Une version (-tags release) ne se construit pas sans clé de secours ; un
// binaire de développement, si. Le paquet est compilé avec key.go remplacé
// (go build -overlay) : la preuve ne dépend pas de la clé posée aujourd'hui.
func TestReleaseBuild_RefusesAnEmptyBackupKey(t *testing.T) {
	if testing.Short() {
		t.Skip("compile le paquet")
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain: %v", err)
	}
	source, err := os.ReadFile("key.go")
	if err != nil {
		t.Fatal(err)
	}
	backup, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	build := func(backupKey string, tags ...string) (string, error) {
		return buildWithBackupKey(t, goBinary, source, backupKey, tags)
	}
	if output, err := build("", "release"); err == nil || !strings.Contains(output, "key_release.go") || !strings.Contains(output, "overflows") {
		t.Fatalf("release build without a backup key: %v\n%s", err, output)
	}
	if output, err := build(backup.String(), "release"); err != nil {
		t.Fatalf("release build with a backup key: %v\n%s", err, output)
	}
	if output, err := build(""); err != nil {
		t.Fatalf("development build without a backup key: %v\n%s", err, output)
	}
}

var backupKeyLine = regexp.MustCompile(`(?m)^(\s*BackupPublicKey\s*=\s*)"[^"]*"`)

// buildWithBackupKey compile ce paquet, key.go portant backupKey.
func buildWithBackupKey(t *testing.T, goBinary string, source []byte, backupKey string, tags []string) (string, error) {
	t.Helper()
	if !backupKeyLine.Match(source) {
		t.Fatal("key.go has no BackupPublicKey line")
	}
	replaced := backupKeyLine.ReplaceAll(source, []byte(`${1}"`+backupKey+`"`))
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.go")
	if err := os.WriteFile(keyFile, replaced, 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := filepath.Abs("key.go")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]map[string]string{"Replace": {original: keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	overlayFile := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayFile, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"build", "-overlay", overlayFile}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	command := exec.Command(goBinary, append(args, ".")...) // #nosec G204 -- la chaîne d'outils go, des arguments du test
	output, err := command.CombinedOutput()
	return string(output), err
}
