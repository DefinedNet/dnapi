package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
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

// newKeys25519 returns a new set of Nebula (Diffie-Hellman) keys and a new set of Ed25519 (request signing) keys.
func newKeys25519() ([]byte, []byte, ed25519.PublicKey, ed25519.PrivateKey, error) {
	dhPubkeyPEM, dhPrivkeyPEM, err := newNebulaX25519KeypairPEM()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Nebula keypair: %s", err)
	}

	edPubkey, edPrivkey, err := newEd25519Keypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Ed25519 keypair: %s", err)
	}

	return dhPubkeyPEM, dhPrivkeyPEM, edPubkey, edPrivkey, nil
}

// newKeysP256 returns a new set of Nebula (Diffie-Hellman) ECDH P256 keys and a new set of ECDSA (request signing) keys.
func newKeysP256() ([]byte, []byte, *ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	ecdhPubkeyPEM, ecdhPrivkeyPEM, err := newNebulaP256KeypairPEM()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Nebula keypair: %s", err)
	}

	ecdsaPubkey, ecdsaPrivkey, err := newP256Keypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Ed25519 keypair: %s", err)
	}

	return ecdhPubkeyPEM, ecdhPrivkeyPEM, ecdsaPubkey, ecdsaPrivkey, nil
}

// newX25519Keypair create a pair of X25519 public key and private key and returns them, in that order.
func newX25519Keypair() ([]byte, []byte, error) {
	var privkey = make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		return nil, nil, err
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return pubkey, privkey, nil
}

// newEd25519Keypair returns a new Ed25519 (pubkey, privkey) pair usable for signing.
func newEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// newP256Keypair create a pair of P256 public key and private key and returns them, in that order.
func newP256Keypair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating ecdsa keys: %s", err)
	}

	return privkey.Public().(*ecdsa.PublicKey), privkey, nil
}

// newNebulaX25519KeypairPEM returns a new Nebula keypair (X25519) in PEM format.
func newNebulaX25519KeypairPEM() ([]byte, []byte, error) {
	pubkey, privkey, err := newX25519Keypair()
	if err != nil {
		return nil, nil, err
	}
	pubkey, privkey = cert.MarshalX25519PublicKey(pubkey), cert.MarshalX25519PrivateKey(privkey)

	return pubkey, privkey, nil
}

// newNebulaP256KeypairPEM returns a new Nebula keypair (P256) in PEM format.
func newNebulaP256KeypairPEM() ([]byte, []byte, error) {
	rawPrivkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating ecdsa keys: %s", err)
	}

	ecdhPrivkey, err := rawPrivkey.ECDH()
	if err != nil {
		return nil, nil, err
	}

	pubkey := cert.MarshalPublicKey(cert.Curve_P256, ecdhPrivkey.PublicKey().Bytes())
	privkey := cert.MarshalPrivateKey(cert.Curve_P256, ecdhPrivkey.Bytes())

	return pubkey, privkey, nil
}
