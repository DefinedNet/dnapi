package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
)

// TrustedKey is an interface used to generically verify signatures returned
// from the DN API regardless of whether the key is P256 or 25519.
type TrustedKey interface {
	Verify(data []byte, sig []byte) bool
	Unwrap() any
	MarshalPEM() ([]byte, error)
}

func NewTrustedKey(k any) (TrustedKey, error) {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return P256TrustedKey{k}, nil
	case ed25519.PublicKey:
		return Ed25519TrustedKey{k}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}

// Ed25519TrustedKey is the Ed25519 implementation of TrustedKey.
type Ed25519TrustedKey struct {
	ed25519.PublicKey
}

func (key Ed25519TrustedKey) Verify(data []byte, sig []byte) bool {
	return ed25519.Verify(key.PublicKey, data, sig)
}

func (key Ed25519TrustedKey) Unwrap() any {
	return key.PublicKey
}

func (key Ed25519TrustedKey) MarshalPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: NebulaEd25519PublicKeyBanner, Bytes: key.PublicKey}), nil
}

// P256TrustedKey is the P256 implementation of TrustedKey.
type P256TrustedKey struct {
	*ecdsa.PublicKey
}

func (key P256TrustedKey) Verify(data []byte, sig []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(key.PublicKey, hash[:], sig)
}

func (key P256TrustedKey) Unwrap() any {
	return key.PublicKey
}

func (key P256TrustedKey) MarshalPEM() ([]byte, error) {
	b := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	return pem.EncodeToMemory(&pem.Block{Type: NebulaECDSAP256PublicKeyBanner, Bytes: b}), nil
}

// TrustedKeysToPEM converts a slice of TrustedKey to a PEM-encoded byte slice.
func TrustedKeysToPEM(keys []TrustedKey) ([]byte, error) {
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

// TrustedKeysFromPEM converts a PEM-encoded byte slice to a slice of TrustedKey.
func TrustedKeysFromPEM(pemKeys []byte) ([]TrustedKey, error) {
	keys := []TrustedKey{}
	for len(pemKeys) > 0 {
		var err error
		var pubkey TrustedKey
		pubkey, pemKeys, err = UnmarshalTrustedKey(pemKeys)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pubkey)
	}

	return keys, nil
}
