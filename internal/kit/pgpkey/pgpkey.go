package pgpkey

import (
	"bufio"
	"bytes"
	"crypto/sha1" // #nosec G505 -- l'empreinte d'une clé OpenPGP v4 est, par la RFC 4880, un SHA-1.
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// Les balises d'un paquet OpenPGP (RFC 4880, §4.3) : seule la clé principale
// compte ; les sous-clés sont liées à elle par signature.
const (
	tagPublicKey = 6
	keyVersion4  = 4
)

const (
	armorBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	armorEnd   = "-----END PGP PUBLIC KEY BLOCK-----"
)

var (
	ErrNotArmored  = errors.New("not an armored OpenPGP public key block")
	ErrBadPacket   = errors.New("malformed OpenPGP packet")
	ErrUnsupported = errors.New("only version 4 OpenPGP keys are read")
)

// PrimaryFingerprints rend l'empreinte, en hexadécimal majuscule, de chaque
// clé principale du bloc, dans l'ordre. Un bloc mal formé est refusé en entier.
func PrimaryFingerprints(armored []byte) ([]string, error) {
	packets, err := dearmor(armored)
	if err != nil {
		return nil, err
	}
	var fingerprints []string
	for len(packets) > 0 {
		tag, body, rest, err := nextPacket(packets)
		if err != nil {
			return nil, err
		}
		packets = rest
		if tag != tagPublicKey {
			continue
		}
		fingerprint, err := fingerprintOf(body)
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	return fingerprints, nil
}

// dearmor rend les octets du bloc : les lignes en base64 entre l'en-tête de
// l'armure (et ses lignes « Clé: valeur ») et la somme de contrôle « = ». Un
// seul bloc, rien autour : un second bloc collé après le premier serait lu
// par apt sans que son empreinte ait été vue.
func dearmor(armored []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(armored))
	inBlock, inBody, ended := false, false, false
	var encoded strings.Builder
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case ended || (!inBlock && line != armorBegin):
			if line != "" {
				return nil, ErrNotArmored
			}
		case !inBlock:
			inBlock = true
		case !inBody:
			inBody = line == ""
		case line == armorEnd:
			ended = true
		case strings.HasPrefix(line, "="):
			// La somme CRC24 de l'armure : l'empreinte couvre déjà la clé.
		default:
			encoded.WriteString(line)
		}
	}
	if !ended || encoded.Len() == 0 {
		return nil, ErrNotArmored
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, ErrNotArmored
	}
	return decoded, nil
}

// nextPacket lit un paquet, ancien ou nouveau format, et rend sa balise, son
// corps et ce qui le suit. Une longueur partielle ou indéterminée n'a pas sa
// place dans une clé : refusée.
func nextPacket(data []byte) (tag int, body, rest []byte, err error) {
	header := data[0]
	if header&0x80 == 0 {
		return 0, nil, nil, ErrBadPacket
	}
	var length, used int
	if header&0x40 != 0 {
		tag = int(header & 0x3f)
		length, used, err = newFormatLength(data[1:])
	} else {
		tag = int(header>>2) & 0x0f
		length, used, err = oldFormatLength(data[1:], header&0x03)
	}
	if err != nil {
		return 0, nil, nil, err
	}
	start := 1 + used
	if length < 0 || len(data)-start < length {
		return 0, nil, nil, ErrBadPacket
	}
	return tag, data[start : start+length], data[start+length:], nil
}

func newFormatLength(data []byte) (length, used int, err error) {
	if len(data) < 1 {
		return 0, 0, ErrBadPacket
	}
	first := int(data[0])
	switch {
	case first < 192:
		return first, 1, nil
	case first < 224 && len(data) >= 2:
		return (first-192)<<8 + int(data[1]) + 192, 2, nil
	case first == 255 && len(data) >= 5:
		return int(binary.BigEndian.Uint32(data[1:5])), 5, nil
	}
	return 0, 0, ErrBadPacket
}

func oldFormatLength(data []byte, lengthType byte) (length, used int, err error) {
	switch {
	case lengthType == 0 && len(data) >= 1:
		return int(data[0]), 1, nil
	case lengthType == 1 && len(data) >= 2:
		return int(binary.BigEndian.Uint16(data[:2])), 2, nil
	case lengthType == 2 && len(data) >= 4:
		return int(binary.BigEndian.Uint32(data[:4])), 4, nil
	}
	return 0, 0, ErrBadPacket
}

// fingerprintOf : le SHA-1 de 0x99, de la longueur sur deux octets et du
// corps de la clé (RFC 4880, §12.2).
func fingerprintOf(body []byte) (string, error) {
	if len(body) == 0 || body[0] != keyVersion4 {
		return "", ErrUnsupported
	}
	if len(body) > 0xffff {
		return "", ErrBadPacket
	}
	hash := sha1.New() // #nosec G401 -- voir l'import.
	prefix := []byte{0x99, 0, 0}
	binary.BigEndian.PutUint16(prefix[1:], uint16(len(body))) // #nosec G115 -- borné à 0xffff juste au-dessus.
	hash.Write(prefix)
	hash.Write(body)
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil))), nil
}
