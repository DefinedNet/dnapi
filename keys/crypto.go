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

// PrivateKey is an interface used to generically sign messages regardless of
// the network curve (P256/25519.)
type PrivateKey interface {
	// Sign signs the message with the private key and returns the signature.
	Sign(msg []byte) ([]byte, error)

	// Unwrap returns the internal private key object (e.g. *ecdsa.PrivateKey or ed25519.PrivateKey.)
	Unwrap() interface{}

	// MarshalPEM returns the private key in PEM format.
	MarshalPEM() ([]byte, error)
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
	return MarshalEd25519HostPrivateKey(k.PrivateKey)
}

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
	return MarshalP256HostPrivateKey(k.PrivateKey)
}

// Keys contains a set of P256 and X25519/Ed25519 keys. Only one set is used,
// depending on the network the host is enrolled in. At the time of enrollment
// clients do not know which curve the network uses, so both keys must be
// generated.
//
// Most keys are returned in PEM format as the public keys are sent off to the
// DN API and the private Nebula key is written to disk and parsed by the
// Nebula library. The host private key is not marshalled to PEM here because
// we will need it to sign requests.
type Keys struct {
	// 25519 Curve
	NebulaX25519PublicKeyPEM  []byte     // ECDH (Nebula)
	NebulaX25519PrivateKeyPEM []byte     // ECDH (Nebula)
	HostEd25519PublicKeyPEM   []byte     // EdDSA (DN API)
	HostEd25519PrivateKey     PrivateKey // EdDSA (DN API)

	// P256 Curve
	NebulaP256PublicKeyPEM  []byte     // ECDH (Nebula)
	NebulaP256PrivateKeyPEM []byte     // ECDH (Nebula)
	HostP256PublicKeyPEM    []byte     // ECDSA (DN API)
	HostP256PrivateKey      PrivateKey // ECDSA (DN API)
}

func New() (*Keys, error) {
	x25519PublicKeyPEM, x25519PrivateKeyPEM, ed25519PublicKey, ed25519PrivateKey, err := newKeys25519()
	if err != nil {
		return nil, err
	}

	ecdhP256PublicKeyPEM, ecdhP256PrivateKeyPEM, ecdsaP256PublicKey, ecdsaP256PrivateKey, err := newKeysP256()
	if err != nil {
		return nil, err
	}

	ed25519PublicKeyPEM, err := MarshalEd25519HostPublicKey(ed25519PublicKey)
	if err != nil {
		return nil, err
	}

	ecdsaP256PublicKeyPEM, err := MarshalP256HostPublicKey(ecdsaP256PublicKey)
	if err != nil {
		return nil, err
	}

	ed25519PrivateKeyI, err := NewPrivateKey(ed25519PrivateKey)
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
		HostEd25519PublicKeyPEM:   ed25519PublicKeyPEM,
		HostEd25519PrivateKey:     ed25519PrivateKeyI,
		NebulaP256PublicKeyPEM:    ecdhP256PublicKeyPEM,
		NebulaP256PrivateKeyPEM:   ecdhP256PrivateKeyPEM,
		HostP256PublicKeyPEM:      ecdsaP256PublicKeyPEM,
		HostP256PrivateKey:        ecdsaP256PrivateKeyI,
	}, nil
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
