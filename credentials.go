package dnapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/pem"
)

// TrustedPublicKey is an interface used to generically verify signatures
// returned from the DN API regardless of whether the key is P256 or 25519.
type TrustedPublicKey interface {
	Verify(data []byte, sig []byte) bool
	Unwrap() any
	MarshalPEM() ([]byte, error)
}

type Ed25519TrustedPublicKey struct {
	ed25519.PublicKey
}

func (key Ed25519TrustedPublicKey) Verify(data []byte, sig []byte) bool {
	return ed25519.Verify(key.PublicKey, data, sig)
}

func (key Ed25519TrustedPublicKey) Unwrap() any {
	return key.PublicKey
}

func (key Ed25519TrustedPublicKey) MarshalPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: NebulaEd25519PublicKeyBanner, Bytes: key.PublicKey}), nil
}

type P256TrustedPublicKey struct {
	*ecdsa.PublicKey
}

func (key P256TrustedPublicKey) Verify(data []byte, sig []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(key.PublicKey, hash[:], sig)
}

func (key P256TrustedPublicKey) Unwrap() any {
	return key.PublicKey
}

func (key P256TrustedPublicKey) MarshalPEM() ([]byte, error) {
	b := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	return pem.EncodeToMemory(&pem.Block{Type: NebulaECDSAP256PublicKeyBanner, Bytes: b}), nil
}

func TrustedPublicKeysToPEM(keys []TrustedPublicKey) ([]byte, error) {
	result := []byte{}
	for _, key := range keys {
		pem, err := key.MarshalPEM()
		if err != nil {
			return nil, err
		}
		result = append(result, pem...)
	}
	return result, nil
}

func TrustedPublicKeysFromPEM(pemKeys []byte) ([]TrustedPublicKey, error) {
	keys := []TrustedPublicKey{}
	for len(pemKeys) > 0 {
		var err error
		var pubkey TrustedPublicKey
		pubkey, pemKeys, err = UnmarshalTrustedPublicKey(pemKeys)
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
	TrustedKeys []TrustedPublicKey
}
