package dnapi

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/DefinedNet/dnapi/keys"
	"github.com/DefinedNet/dnapi/message"
	"github.com/slackhq/nebula/cert"
)

// KeyMaker creates the keys a host offers the API: a Nebula key and a host key on the network's
// curve. DefaultKeyMaker makes software keys. A caller that keeps keys somewhere else, for example
// in a TPM, supplies its own.
//
// Enroll asks for keys on every curve, since it does not know the network's curve yet, and uses
// the pair on the network's curve. DoUpdate and DoConfigUpdate ask only for the host's curve.
//
// The client closes the host keys that it does not use, if they implement io.Closer.
type KeyMaker interface {
	// NewNebulaKey creates a Nebula key pair on curve, as PEMs. It returns ErrCurveUnsupported if
	// it can not make keys on curve.
	NewNebulaKey(curve message.NetworkCurve) (pub, priv []byte, err error)

	// NewHostKey creates a host key on curve. It returns ErrCurveUnsupported if it can not make
	// keys on curve.
	NewHostKey(curve message.NetworkCurve) (keys.PrivateKey, error)
}

// ErrCurveUnsupported is the error from a KeyMaker that can not make keys on a curve. An enrollment
// does not offer keys on such a curve; it fails if that is P256.
var ErrCurveUnsupported = errors.New("the KeyMaker can not make keys on this curve")

var DefaultKeyMaker KeyMaker = defaultKeyMaker{}

// defaultKeyMaker makes software keys. In FIPS 140 mode it does not make Curve25519 keys, because
// they are not approved.
type defaultKeyMaker struct{}

func (defaultKeyMaker) NewNebulaKey(curve message.NetworkCurve) ([]byte, []byte, error) {
	switch curve {
	case message.NetworkCurve25519:
		if fips140.Enabled() {
			return nil, nil, fmt.Errorf("FIPS 140 mode does not make Curve25519 keys: %w", ErrCurveUnsupported)
		}
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, k.PublicKey().Bytes()), cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, k.Bytes()), nil
	case message.NetworkCurveP256:
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return cert.MarshalPublicKeyToPEM(cert.Curve_P256, k.PublicKey().Bytes()), cert.MarshalPrivateKeyToPEM(cert.Curve_P256, k.Bytes()), nil
	}
	return nil, nil, fmt.Errorf("unsupported curve %q", curve)
}

func (defaultKeyMaker) NewHostKey(curve message.NetworkCurve) (keys.PrivateKey, error) {
	switch curve {
	case message.NetworkCurve25519:
		if fips140.Enabled() {
			return nil, fmt.Errorf("FIPS 140 mode does not make Ed25519 host keys: %w", ErrCurveUnsupported)
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return keys.NewPrivateKey(priv)
	case message.NetworkCurveP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return keys.NewPrivateKey(priv)
	}
	return nil, fmt.Errorf("unsupported curve %q", curve)
}
