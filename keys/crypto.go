package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
)

// Ed25519PublicKey is a wrapper around an Ed25519 public key that implements
// the PublicKey interface.
type Ed25519PublicKey struct {
	ed25519.PublicKey
}

func (k Ed25519PublicKey) Unwrap() interface{} {
	return k.PublicKey
}

func (k Ed25519PublicKey) MarshalPEM() ([]byte, error) {
	return MarshalHostEd25519PublicKey(k.PublicKey)
}

// P256PublicKey is a wrapper around an ECDSA public key that implements the
// PublicKey interface.
type P256PublicKey struct {
	*ecdsa.PublicKey
}

func (k P256PublicKey) Unwrap() interface{} {
	return k.PublicKey
}

func (k P256PublicKey) MarshalPEM() ([]byte, error) {
	return MarshalHostP256PublicKey(k.PublicKey)
}

// Ed25519PrivateKey is a wrapper around an Ed25519 private key that implements
// the PrivateKey interface.
type Ed25519PrivateKey struct {
	ed25519.PrivateKey
}

func (k Ed25519PrivateKey) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(k.PrivateKey, msg), nil
}

func (k Ed25519PrivateKey) Unwrap() interface{} {
	return k.PrivateKey
}

func (k Ed25519PrivateKey) MarshalPEM() ([]byte, error) {
	return MarshalHostEd25519PrivateKey(k.PrivateKey)
}

func (k Ed25519PrivateKey) Public() PublicKey {
	return Ed25519PublicKey{k.PrivateKey.Public().(ed25519.PublicKey)}
}

// P256PrivateKey is a wrapper around an ECDSA private key that implements the
// PrivateKey interface.
type P256PrivateKey struct {
	*ecdsa.PrivateKey
}

func (k P256PrivateKey) Sign(msg []byte) ([]byte, error) {
	hashed := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, k.PrivateKey, hashed[:])
}

func (k P256PrivateKey) Unwrap() interface{} {
	return k.PrivateKey
}

func (k P256PrivateKey) MarshalPEM() ([]byte, error) {
	return MarshalHostP256PrivateKey(k.PrivateKey)
}

func (k P256PrivateKey) Public() PublicKey {
	return P256PublicKey{k.PrivateKey.Public().(*ecdsa.PublicKey)}
}
