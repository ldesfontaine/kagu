package pgpkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// La clé du dépôt de Docker, telle que download.docker.com la sert : son
// empreinte est celle que gpg affiche (gpg --show-keys).
const dockerFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

func readDockerKey(t *testing.T) []byte {
	t.Helper()
	key, err := os.ReadFile("testdata/docker.asc")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPrimaryFingerprints_ReadsTheDockerKey(t *testing.T) {
	got, err := PrimaryFingerprints(readDockerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{dockerFingerprint}) {
		t.Fatalf("fingerprints %v", got)
	}
}

// Une clé de test bien formée (example.org, tirée pour ce test, sans usage
// réel) : son empreinte est celle que gpg affichait à sa création.
func TestPrimaryFingerprints_ReadsAnotherWellFormedKey(t *testing.T) {
	key, err := os.ReadFile("testdata/other.asc")
	if err != nil {
		t.Fatal(err)
	}
	got, err := PrimaryFingerprints(key)
	if err != nil || !slices.Equal(got, []string{"A809C659C665E0062CD8911F927550AC795CC5C2"}) {
		t.Fatalf("fingerprints %v, %v", got, err)
	}
}

// Une clé dont un octet change n'a plus la même empreinte ; une seconde clé
// collée à la suite paraît : l'appelant exige une seule clé, la bonne.
func TestPrimaryFingerprints_ChangedOrAppendedKeysShow(t *testing.T) {
	packets, err := dearmor(readDockerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(packets)
	changed[20] ^= 0x01
	got, err := PrimaryFingerprints(armor(changed))
	if err != nil || len(got) != 1 || got[0] == dockerFingerprint {
		t.Fatalf("a changed key gives %v, %v", got, err)
	}
	got, err = PrimaryFingerprints(armor(append(bytes.Clone(packets), changed...)))
	if err != nil || len(got) != 2 {
		t.Fatalf("an appended key gives %v, %v", got, err)
	}
}

func TestPrimaryFingerprints_RefusesWhatIsNotAKey(t *testing.T) {
	packets, err := dearmor(readDockerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string][]byte{
		"empty":        nil,
		"no armor":     packets,
		"bad base64":   []byte(armorBegin + "\n\n!!!!\n" + armorEnd + "\n"),
		"truncated":    armor(packets[:len(packets)/2]),
		"not a packet": armor([]byte{0x01, 0x02}),
		"two blocks":   append(readDockerKey(t), readDockerKey(t)...),
		"text before":  append([]byte("une autre clé\n"), readDockerKey(t)...),
	} {
		if _, err := PrimaryFingerprints(block); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	version3 := bytes.Clone(packets)
	version3[3] = 3
	if _, err := PrimaryFingerprints(armor(version3)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("a version 3 key: %v", err)
	}
}

func armor(packets []byte) []byte {
	return []byte(armorBegin + "\n\n" + strings.TrimSpace(base64.StdEncoding.EncodeToString(packets)) + "\n" + armorEnd + "\n")
}
