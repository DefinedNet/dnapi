package dnapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// newKeys returns a new set of Nebula (Diffie-Hellman) keys and a new set of Ed25519 (request signing) keys.
func newKeys() ([]byte, []byte, ed25519.PublicKey, ed25519.PrivateKey, error) {
	dhPubkeyPEM, dhPrivkeyPEM, err := newNebulaKeypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Nebula keypair: %s", err)
	}

	edPubkey, edPrivkey, err := newEdKeypair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate Ed25519 keypair: %s", err)
	}

	return dhPubkeyPEM, dhPrivkeyPEM, edPubkey, edPrivkey, nil
}

// newNebulaKeypair returns a new Nebula keypair (X25519) in PEM format.
func newNebulaKeypair() ([]byte, []byte, error) {
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

// newEdKeypair returns a new Ed 25519 (pubkey, privkey) pair usable for signing.
func newEdKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func nonce() []byte {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return nonce
}
