package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCrypto(t *testing.T) {
	keys, err := New()
	require.NoError(t, err)

	t.Logf("ed25519 host pubkey: %s", keys.HostEd25519PublicKeyPEM)
}
