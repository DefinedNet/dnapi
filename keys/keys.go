package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
)

// Keys contains a set of P256 and X25519/Ed25519 keys. Only one set is used,
// depending on the network the host is enrolled in. At the time of enrollment
// clients do not know which curve the network uses, so both keys must be
// generated.
//
// Nebula keys are returned in PEM format as the public keys is sent off to the
// DN API and the private Nebula key is written to disk and parsed by the
// Nebula library. The host keys will be used to sign requests.
type Keys struct {
	// 25519 Curve
	NebulaX25519PublicKeyPEM  []byte     // ECDH (Nebula)
	NebulaX25519PrivateKeyPEM []byte     // ECDH (Nebula)
	HostEd25519PublicKey      PublicKey  // EdDSA (DN API)
	HostEd25519PrivateKey     PrivateKey // EdDSA (DN API)

	// P256 Curve
	NebulaP256PublicKeyPEM  []byte     // ECDH (Nebula)
	NebulaP256PrivateKeyPEM []byte     // ECDH (Nebula)
	HostP256PublicKey       PublicKey  // ECDSA (DN API)
	HostP256PrivateKey      PrivateKey // ECDSA (DN API)
}

func New() (*Keys, error) {
	x25519PublicKeyPEM, x25519PrivateKeyPEM, ed25519PublicKey, ed25519PrivateKey, err := newKeys25519()
	if err != nil {
		return nil, err
	}

	ed25519PublicKeyI, err := NewPublicKey(ed25519PublicKey)
	if err != nil {
		return nil, err
	}

	ed25519PrivateKeyI, err := NewPrivateKey(ed25519PrivateKey)
	if err != nil {
		return nil, err
	}

	ecdhP256PublicKeyPEM, ecdhP256PrivateKeyPEM, ecdsaP256PublicKey, ecdsaP256PrivateKey, err := newKeysP256()
	if err != nil {
		return nil, err
	}

	ecdsaP256PublicKeyI, err := NewPublicKey(ecdsaP256PublicKey)
	if err != nil {
		return nil, err
	}

	ecdsaP256PrivateKeyI, err := NewPrivateKey(ecdsaP256PrivateKey)
	if err != nil {
		return nil, err
	}

	return &Keys{
		NebulaX25519PublicKeyPEM:  x25519PublicKeyPEM,
		NebulaX25519PrivateKeyPEM: x25519PrivateKeyPEM,
		HostEd25519PublicKey:      ed25519PublicKeyI,
		HostEd25519PrivateKey:     ed25519PrivateKeyI,
		NebulaP256PublicKeyPEM:    ecdhP256PublicKeyPEM,
		NebulaP256PrivateKeyPEM:   ecdhP256PrivateKeyPEM,
		HostP256PublicKey:         ecdsaP256PublicKeyI,
		HostP256PrivateKey:        ecdsaP256PrivateKeyI,
	}, nil
}

// PublicKey is a wrapper around public keys.
type PublicKey interface {
	// Unwrap returns the internal public key object (e.g. *ecdsa.PublicKey or ed25519.PublicKey.)
	Unwrap() interface{}

	// MarshalPEM returns the public key in PEM format.
	MarshalPEM() ([]byte, error)
}

func NewPublicKey(k any) (PublicKey, error) {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return P256PublicKey{k}, nil
	case ed25519.PublicKey:
		return Ed25519PublicKey{k}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	}
}

// PrivateKey is an interface used to generically sign messages regardless of
// the network curve (P256/25519.)
type PrivateKey interface {
	// Sign signs the message with the private key and returns the signature.
	Sign(msg []byte) ([]byte, error)

	// Unwrap returns the internal private key object (e.g. *ecdsa.PrivateKey or ed25519.PrivateKey.)
	Unwrap() interface{}

	// MarshalPEM returns the private key in PEM format.
	MarshalPEM() ([]byte, error)

	// Public returns the public key associated with the private key.
	Public() PublicKey
}

func NewPrivateKey(k any) (PrivateKey, error) {
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		return P256PrivateKey{k}, nil
	case ed25519.PrivateKey:
		return Ed25519PrivateKey{k}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}
