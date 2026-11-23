package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"io"
)

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

// Close releases the resources of k, if k implements io.Closer
func Close(k PrivateKey) error {
	if c, ok := k.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
