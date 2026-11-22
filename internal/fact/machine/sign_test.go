package machine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// Le protocole 2 signe l'étiquette, l'aléa, l'identifiant précédé de sa
// longueur et l'horodatage : octet pour octet, figé. La machine openCloud
// (« local ») signe comme les autres.
func TestSignedPayload_IsByteExact(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, NonceSize)
	payload, err := SignedPayload(nonce, "local", 1)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("opencloud-agent-proof/v2\x00"), nonce...)
	want = append(want, 0, 0, 0, 5)
	want = append(want, "local"...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 1)
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload %x\nwant    %x", payload, want)
	}
	if _, err := SignedPayload(nonce[:5], "local", 1); !errors.Is(err, ErrBadProof) {
		t.Errorf("short nonce: %v", err)
	}
	if _, err := SignedPayload(nonce, "", 1); !errors.Is(err, ErrBadID) {
		t.Errorf("empty id: %v", err)
	}
	if _, err := SignedPayload(nonce, strings.Repeat("a", 65), 1); !errors.Is(err, ErrBadID) {
		t.Errorf("long id: %v", err)
	}
}

func TestVerify_DoesNotPanicOnAMalformedKey(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte("x")
	signature := Sign(private, payload)
	if !Verify(public, payload, signature) {
		t.Fatal("valid signature refused")
	}
	if Verify([]byte("short"), payload, signature) || Verify(nil, payload, signature) {
		t.Fatal("malformed key accepted")
	}
}

func TestNewID_IsAVersion4UUID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[14] != '4' || ValidateID(id) != nil {
		t.Fatalf("id %q", id)
	}
}

// R-A1-11 : un identifiant de machine n'a que la forme de NewID. Majuscules,
// tirets déplacés ou absents nommeraient la même machine autrement : refusés
// à l'enrôlement (ErrBadID, bad_request), avant le jeton.
func TestR_A1_11_AnIDOfAnotherCaseOrDashLayoutIsRefused(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateID(id); err != nil {
		t.Fatalf("the form NewID writes was refused: %v", err)
	}
	bare := strings.ReplaceAll(id, "-", "")
	letter := strings.IndexAny(id, "abcdef")
	others := []string{
		strings.ToUpper(id),
		id[:letter] + strings.ToUpper(id[letter:letter+1]) + id[letter+1:],
		bare,
		bare[:4] + "-" + bare[4:12] + "-" + bare[12:16] + "-" + bare[16:20] + "-" + bare[20:],
		id + "-",
		"-" + id,
		strings.Replace(id, "-", "--", 1),
		LocalID,
	}
	h := newHarness(t)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range others {
		if err := ValidateID(other); !errors.Is(err, ErrBadID) {
			t.Errorf("ValidateID(%q) = %v, want ErrBadID", other, err)
		}
		if _, err := h.service.Enroll(context.Background(), Enrollment{MachineID: other, PublicKey: public}); !errors.Is(err, ErrBadID) {
			t.Errorf("Enroll(%q) = %v, want ErrBadID", other, err)
		}
	}
}
