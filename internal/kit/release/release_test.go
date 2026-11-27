package release

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySums_ReadsTheVersionFromTheTrustedComment(t *testing.T) {
	signed, err := VerifySums([]byte(vectorSums), []byte(vectorSignature()), Keys{Current: mustPublicKey(t, vectorPublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	// Une version signée avant le plancher se lit comme avant : sans plancher.
	if signed.Version != (Version{0, 0, 2}) || len(signed.Sums) != 2 || signed.Floor != (Version{}) {
		t.Fatalf("release %+v", signed)
	}
	if signed.Sums["kagu-linux-arm64"] != "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b" {
		t.Fatalf("sums %v", signed.Sums)
	}
}

func TestVerifySums_RefusesACommentWithoutVersionOrFile(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	comments := map[string]string{
		"no version":        "timestamp:1\tfile:SHA256SUMS",
		"no file":           "timestamp:1\tversion:v0.0.2",
		"another file":      "timestamp:1\tfile:other\tversion:v0.0.2",
		"bad version":       "timestamp:1\tfile:SHA256SUMS\tversion:0.0.2",
		"version twice":     "file:SHA256SUMS\tversion:v0.0.2\tversion:v0.0.3",
		"field without key": "file:SHA256SUMS\tversion:v0.0.2\tstray",
		"bad floor":         "file:SHA256SUMS\tversion:v0.0.2\tfloor:0.0.1",
		"floor twice":       "file:SHA256SUMS\tversion:v0.0.2\tfloor:v0.0.1\tfloor:v0.0.2",
		"floor above":       "file:SHA256SUMS\tversion:v0.0.2\tfloor:v0.0.3",
	}
	for name, comment := range comments {
		signature, err := Sign([]byte(vectorSums), privateKey, comment)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySums([]byte(vectorSums), signature, Keys{Current: publicKey}); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// R-B2-11, QA-17 : le plancher se lit dans le commentaire de confiance signé,
// celui que TrustedComment écrit ; il peut valoir la version elle-même.
func TestVerifySums_ReadsTheFloorFromTheTrustedComment(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, floor := range []Version{{0, 0, 1}, {0, 0, 2}} {
		signature, err := Sign([]byte(vectorSums), privateKey, TrustedComment(1, Version{0, 0, 2}, floor))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := VerifySums([]byte(vectorSums), signature, Keys{Current: publicKey})
		if err != nil || signed.Floor != floor {
			t.Fatalf("floor %s: %+v, %v", floor, signed, err)
		}
	}
	if comment := TrustedComment(1, Version{0, 0, 2}, Version{}); strings.Contains(comment, "floor") {
		t.Fatalf("a version without floor signs %q", comment)
	}
}

// QA-17 : le plancher n'a pas sa place dans SHA256SUMS ; une ligne de plus y
// est refusée, comme « sha256sum --strict -c » et chaque agent d'avant la
// refuseraient.
func TestParseSums_RefusesAFloorLine(t *testing.T) {
	sums := vectorSums + "floor: v0.0.2\n"
	if _, err := ParseSums([]byte(sums)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a floor line in the sums: %v", err)
	}
}

func TestVerifySums_RefusesSignedSumsThatDoNotParse(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sums := []byte("not a sums file\n")
	signature, err := Sign(sums, privateKey, "file:SHA256SUMS\tversion:v0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySums(sums, signature, Keys{Current: publicKey}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unparsable sums: %v", err)
	}
}

func TestCheck_RefusesAFileNotListedOrDifferent(t *testing.T) {
	// sha256("abc")
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	signed := Release{Version: Version{0, 0, 2}, Sums: map[string]string{"file": abc}}
	if err := signed.Check("file", strings.NewReader("abc")); err != nil {
		t.Fatalf("same content: %v", err)
	}
	if err := signed.Check("file", strings.NewReader("abd")); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("other content: %v", err)
	}
	if err := signed.Check("other", strings.NewReader("abc")); !errors.Is(err, ErrNotListed) {
		t.Fatalf("not listed: %v", err)
	}
}

func TestParseSums_RefusesAPathABadDigestOrADuplicate(t *testing.T) {
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	good := digest + "  a\n" + digest + " *b\n"
	sums, err := ParseSums([]byte(good))
	if err != nil || len(sums) != 2 || sums["a"] != digest || sums["b"] != digest {
		t.Fatalf("good sums: %v %v", sums, err)
	}
	if _, err := ParseSums([]byte(strings.TrimSuffix(good, "\n"))); err != nil {
		t.Fatalf("no final newline: %v", err)
	}
	bad := map[string]string{
		"empty":             "",
		"path":              digest + "  dir/a\n",
		"parent":            digest + "  ../a\n",
		"backslash":         digest + "  dir\\a\n",
		"empty name":        digest + "  \n",
		"upper case digest": strings.ToUpper(digest) + "  a\n",
		"short digest":      digest[:63] + "  a\n",
		"one space":         digest + " a\n",
		"duplicate":         digest + "  a\n" + digest + "  a\n",
		"blank line":        digest + "  a\n\n" + digest + "  b\n",
		"final blank lines": digest + "  a\n\n",
	}
	for name, content := range bad {
		if _, err := ParseSums([]byte(content)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseVersion_AndCompare(t *testing.T) {
	good := map[string]Version{"v0.0.1": {0, 0, 1}, "v1.20.300": {1, 20, 300}, "v99999.0.0": {99999, 0, 0}}
	for text, want := range good {
		got, err := ParseVersion(text)
		if err != nil || got != want || got.String() != text {
			t.Errorf("%s: %v %v", text, got, err)
		}
	}
	for _, text := range []string{"", "0.0.1", "v1", "v1.2", "v1.2.3.4", "v01.0.0", "v1.0.0-rc1", "v1.0.0\n", " v1.0.0", "v100000.0.0", "v-1.0.0", "V1.0.0"} {
		if _, err := ParseVersion(text); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", text, err)
		}
	}
	older, newer := Version{0, 0, 9}, Version{0, 0, 10}
	if newer.Compare(older) != 1 || older.Compare(newer) != -1 || older.Compare(older) != 0 {
		t.Fatal("v0.0.10 must come after v0.0.9")
	}
	if (Version{1, 0, 0}).Compare(Version{0, 99, 99}) != 1 || (Version{0, 2, 0}).Compare(Version{0, 1, 9}) != 1 {
		t.Fatal("major and minor weigh more than patch")
	}
}

func TestVerifyFile_FindsTheFileUnderItsBaseName(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "tool-linux-amd64")
	if err := os.WriteFile(binary, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	sums := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  tool-linux-amd64\n"
	signature, err := Sign([]byte(sums), privateKey, "timestamp:1\tfile:SHA256SUMS\tversion:v0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	sumsPath, signaturePath := filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.minisig")
	if err := os.WriteFile(sumsPath, []byte(sums), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	signed, err := VerifyFile(binary, sumsPath, signaturePath, Keys{Current: publicKey})
	if err != nil || signed.Version != (Version{0, 0, 7}) {
		t.Fatalf("verify file: %+v %v", signed, err)
	}
	if err := os.WriteFile(binary, []byte("abd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(binary, sumsPath, signaturePath, Keys{Current: publicKey}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("changed file: %v", err)
	}
	if _, err := VerifyFile(binary, filepath.Join(dir, "absent"), signaturePath, Keys{Current: publicKey}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing sums: %v", err)
	}
}
