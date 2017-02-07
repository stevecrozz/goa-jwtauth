package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
)

// Load is a helper function that builds a keystore with trust in one or more
// keys, loading files as necessary to parse PEM-encoded public and private
// keys.
//
// Load returns a different type of keystore depending on the value of keys:.
//
// If keys is a []byte that contains a PEM-encoded PKIX key (i.e. "BEGIN
// PUBLIC KEY"), parse it and trust a single public key; panic if the key
// is malformed.
//
// It keys is any other []byte, trust a single HMAC key.
//
// If keys is an ecdsa or rsa key, trust a single public key.
//
// If keys is a map[string]interface{}, the result is a set of named keys,
// each of which may have any of the above supported types.
//
// If keys is anything else, Load panics.
func Load(keys interface{}) Keystore {
	switch tk := keys.(type) {
	case map[string]interface{}:
		ks := &NamedKeystore{}
		for k, v := range tk {
			ks.Trust(k, loadKey(v))
		}
		return ks
	default:
		return &SimpleKeystore{Key: loadKey(tk)}
	}
}

var pemBlock = regexp.MustCompile("^---+ *BEGIN")

// loadKey is a helper function that returns a valid key type or panics.
func loadKey(key interface{}) interface{} {
	switch tk := key.(type) {
	case *ecdsa.PrivateKey, *ecdsa.PublicKey, *rsa.PrivateKey, *rsa.PublicKey:
		return tk
	case []byte:
		if pemBlock.Match(tk) {
			// single PEM-encoded key
			parsed, err := parseKey(tk)
			if err != nil {
				panic(err)
			}
			return loadKey(parsed)
		} else {
			// single HMAC key
			return tk
		}
	default:
		panic(fmt.Sprintf("unsupported key type %T; expected []byte, ecdsa/rsa key, or map[string]interface{}", key))
	}
}

// Parse a public key from a block of PEM-formatted ASCII text.
func parseKey(pemBlock []byte) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemBlock))

	if block != nil {
		switch block.Type {
		case "RSA PUBLIC KEY": // PKCS1 RSA public key
			key := rsa.PublicKey{new(big.Int), 0}
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
