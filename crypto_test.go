package dnapi

import (
	"crypto/ed25519"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
)

func TestNewKeys(t *testing.T) {
	// TestNewKeys tests the creation of new keys
	t.Parallel()
	ik, err := newKeys()
	require.NoError(t, err)
	b, err := MarshalECDSAP256PublicKey(ik.ecdsaP256PublicKey)
	require.NoError(t, err)

	t.Logf("ecdhP256PublicKeyPEM: %s, ecdsaP256PublicKey: %s, ed25519PublicKey: %s", ik.ecdhP256PublicKeyPEM, b, cert.MarshalEd25519PublicKey(ed25519.PublicKey(ik.ed25519PublicKey)))
}
