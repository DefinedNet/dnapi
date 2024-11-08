package dnapi

import (
	"crypto/ed25519"

	"github.com/slackhq/nebula/cert"
)

func Ed25519PublicKeysToPEM(keys []ed25519.PublicKey) []byte {
	result := []byte{}
	for _, key := range keys {
		result = append(result, cert.MarshalEd25519PublicKey(key)...)
	}
	return result
}

func Ed25519PublicKeysFromPEM(pemKeys []byte) ([]ed25519.PublicKey, error) {
	keys := []ed25519.PublicKey{}

	for len(pemKeys) > 0 {
		var err error
		var pubkey ed25519.PublicKey
		pubkey, pemKeys, err = cert.UnmarshalEd25519PublicKey(pemKeys)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pubkey)
	}

	return keys, nil
}

// Credentials contains information necessary to make requests against the DNClient API.
type Credentials struct {
	HostID      string
	PrivateKey  PrivateKey
	Counter     uint
	TrustedKeys []ed25519.PublicKey
}
