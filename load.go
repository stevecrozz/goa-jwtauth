package jwtauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
)

var pemBlock = regexp.MustCompile("^---+ *BEGIN")

// Load is a helper function that transforms raw key material into a properly-
// typed key.
//
// Load returns a different type of key depending on the value of input:
//
// If material is a []byte that contains a PEM-encoded PKIX key (e.g. "BEGIN
// PUBLIC KEY"), Load parses it and returns a single public or private key
// of an algorithm-specific type.
//
// If material is any other []byte, Load returns it unmodified so that it can
// be used as an HMAC key.
//
// Because Load is designed to be used at startup, it panics if the PEM block
// is malformed.
func Load(material []byte) interface{} {
	if pemBlock.Match(material) {
		parsed, err := parseKey(material)
		if err != nil {
			panic(err)
		}
		return parsed
	} else {
		return material
	}
}

// Parse a public key from a block of PEM-formatted ASCII text.
func parseKey(pemBlock []byte) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemBlock))

	if block != nil {
		switch block.Type {
		case "RSA PUBLIC KEY": // PKCS1 RSA public key
			key := rsa.PublicKey{N: new(big.Int), E: 0}
			_, err := asn1.Unmarshal(block.Bytes, &key)
			return &key, err
		case "PUBLIC KEY": // PKIX algorithm-neutral key
			return x509.ParsePKIXPublicKey(block.Bytes)
		default:
			return nil, fmt.Errorf("Unsupported PEM block type: %s", block.Type)
		}
	}

	return nil, fmt.Errorf("Input does not appear to be a PEM block")
}
