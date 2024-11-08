package dnapi

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

const ECDSAP256PublicKeyBanner = "NEBULA ECDSA PUBLIC KEY"

// MarshalECDSAP256PublicKey is a simple helper to PEM encode an ECDSA P256 public key
func MarshalEd25519PublicKey(key ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256PublicKeyBanner, Bytes: key})
}

type initialKeys struct {
	x25519PublicKeyPEM    []byte             // ECDH
	x25519PrivateKeyPEM   []byte             // ECDH
	ed25519PublicKey      ed25519.PublicKey  // EdDSA
	ed25519PrivateKey     ed25519.PrivateKey // EdDSA
	ecdhP256PublicKeyPEM  []byte             // ECDH
	ecdhP256PrivateKeyPEM []byte             // ECDH
	ecdsaP256PublicKey    []byte             // ECDSA
	ecdsaP256PrivateKey   []byte             // ECDSA
}

func newInitialKeys() (*initialKeys, error) {
	x25519PublicKeyPEM, x25519PrivateKeyPEM, ed25519PublicKey, ed25519PrivateKey, err := new25519Keys()
	if err != nil {
		return nil, err
	}

	ecdhP256PublicKeyPEM, ecdhP256PrivateKeyPEM, ecdsaP256PublicKey, ecdsaP256PrivateKey, err := newP256Keys()
	if err != nil {
		return nil, err
	}

	return &initialKeys{
		x25519PublicKeyPEM:    x25519PublicKeyPEM,
		x25519PrivateKeyPEM:   x25519PrivateKeyPEM,
		ed25519PublicKey:      ed25519PublicKey,
		ed25519PrivateKey:     ed25519PrivateKey,
		ecdhP256PublicKeyPEM:  ecdhP256PublicKeyPEM,
		ecdhP256PrivateKeyPEM: ecdhP256PrivateKeyPEM,
		ecdsaP256PublicKey:    ecdsaP256PublicKey,
		ecdsaP256PrivateKey:   ecdsaP256PrivateKey,
	}, nil
}

// new25519Keys returns a new set of Nebula (Diffie-Hellman) keys and a new set of Ed25519 (request signing) keys.
func new25519Keys() ([]byte, []byte, ed25519.PublicKey, ed25519.PrivateKey, error) {
	dhPubkeyPEM, dhPrivkeyPEM, err := newNebulaX25519Keypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Nebula keypair: %s", err)
	}

	edPubkey, edPrivkey, err := newEd25519Keypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Ed25519 keypair: %s", err)
	}

	return dhPubkeyPEM, dhPrivkeyPEM, edPubkey, edPrivkey, nil
}

// newP256Keys returns a new set of Nebula (Diffie-Hellman) keys and a new set of Ed25519 (request signing) keys.
func newP256Keys() ([]byte, []byte, []byte, []byte, error) {
	ecdhPubkeyPEM, ecdhPrivkeyPEM, err := newNebulaP256Keypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Nebula keypair: %s", err)
	}

	ecdsaPubkey, ecdsaPrivkey, err := newP256Keypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Ed25519 keypair: %s", err)
	}

	return ecdhPubkeyPEM, ecdhPrivkeyPEM, ecdsaPubkey, ecdsaPrivkey, nil
}

// newNebulaX25519Keypair returns a new Nebula keypair (X25519) in PEM format.
func newNebulaX25519Keypair() ([]byte, []byte, error) {
	pubkey, privkey, err := newX25519Keypair()
	if err != nil {
		return nil, nil, err
	}
	pubkey, privkey = cert.MarshalX25519PublicKey(pubkey), cert.MarshalX25519PrivateKey(privkey)

	return pubkey, privkey, nil
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

// newNebulaP256Keypair returns a new Nebula keypair (P256) in PEM format.
func newNebulaP256Keypair() ([]byte, []byte, error) {
	pubkey, privkey, err := newP256Keypair()
	if err != nil {
		return nil, nil, err
	}
	pubkey, privkey = cert.MarshalPublicKey(cert.Curve_P256, pubkey), cert.MarshalPrivateKey(cert.Curve_P256, privkey)

	return pubkey, privkey, nil
}

// newP256Keypair create a pair of P256 public key and private key and returns them, in that order.
func newP256Keypair() ([]byte, []byte, error) {
	privkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubkey := privkey.PublicKey()
	return pubkey.Bytes(), privkey.Bytes(), nil
}

func nonce() []byte {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return nonce
}
