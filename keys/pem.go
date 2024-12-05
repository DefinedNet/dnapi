package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const HostEd25519PublicKeyBanner = "DEFINED HOST ED25519 PUBLIC KEY"
const HostEd25519PrivateKeyBanner = "DEFINED HOST ED25519 PRIVATE KEY"
const HostP256PublicKeyBanner = "DEFINED HOST P256 PUBLIC KEY"
const HostP256PrivateKeyBanner = "DEFINED HOST P256 PRIVATE KEY"

const NebulaECDSAP256PublicKeyBanner = "NEBULA ECDSA P256 PUBLIC KEY"
const NebulaEd25519PublicKeyBanner = "NEBULA ED25519 PUBLIC KEY"

func MarshalHostEd25519PublicKey(k ed25519.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  HostEd25519PublicKeyBanner,
		Bytes: b,
	}), nil
}

func MarshalHostEd25519PrivateKey(k ed25519.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  HostEd25519PrivateKeyBanner,
		Bytes: b,
	}), nil
}

func MarshalHostP256PublicKey(k *ecdsa.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  HostP256PublicKeyBanner,
		Bytes: b,
	}), nil
}

func MarshalHostP256PrivateKey(k *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  HostP256PrivateKeyBanner,
		Bytes: b,
	}), nil
}

func UnmarshalHostEd25519PublicKey(b []byte) (ed25519.PublicKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != HostEd25519PublicKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper DN Ed25519 public key banner")
	}

	pkey, err := x509.ParsePKIXPublicKey(k.Bytes)
	if err != nil {
		return nil, r, fmt.Errorf("failed to parse public key: %s", err)
	}

	return pkey.(ed25519.PublicKey), r, nil
}

func UnmarshalHostEd25519PrivateKey(b []byte) (ed25519.PrivateKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != HostEd25519PrivateKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper DN Ed25519 private key banner")
	}

	pkey, err := x509.ParsePKCS8PrivateKey(k.Bytes)
	if err != nil {
		return nil, r, fmt.Errorf("failed to parse private key: %s", err)
	}

	return pkey.(ed25519.PrivateKey), r, nil
}

func UnmarshalHostP256PublicKey(b []byte) (*ecdsa.PublicKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != HostP256PublicKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper DN P256 public key banner")
	}

	pkey, err := x509.ParsePKIXPublicKey(k.Bytes)
	if err != nil {
		return nil, r, fmt.Errorf("failed to parse public key: %s", err)
	}

	return pkey.(*ecdsa.PublicKey), r, nil
}

func UnmarshalHostP256PrivateKey(b []byte) (*ecdsa.PrivateKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != HostP256PrivateKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper DN P256 private key banner")
	}

	pkey, err := x509.ParseECPrivateKey(k.Bytes)
	if err != nil {
		return nil, r, fmt.Errorf("failed to parse private key: %s", err)
	}

	return pkey, r, nil
}

func UnmarshalTrustedKey(b []byte) (TrustedKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}

	switch k.Type {
	case NebulaECDSAP256PublicKeyBanner:
		if len(k.Bytes) != 65 {
			return nil, r, fmt.Errorf("key was not 65 bytes, is invalid P256 public key")
		}

		x, y := elliptic.Unmarshal(elliptic.P256(), k.Bytes)
		return P256TrustedKey{&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()}}, r, nil
	case NebulaEd25519PublicKeyBanner:
		if len(k.Bytes) != ed25519.PublicKeySize {
			return nil, r, fmt.Errorf("key was not 32 bytes, is invalid ed25519 public key")
		}

		return Ed25519TrustedKey{ed25519.PublicKey(k.Bytes)}, r, nil
	default:
		return nil, r, fmt.Errorf("input did not contain a valid public key banner")
	}
}
