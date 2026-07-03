package keys

import (
	"crypto/fips140"
	"testing"
)

// TestNewFIPSAware verifies that New() adapts its key generation to FIPS mode.
//
// The FIPS-approved P256 keys are always generated. The non-FIPS-approved
// X25519/Ed25519 keys must only be generated when FIPS is not enabled - under
// GODEBUG=fips140=only, crypto/ecdh refuses to generate an X25519 key at all,
// so generating them would make New() (and therefore enrollment) fail.
//
// This test adapts to the mode it runs under. CI exercises both branches by
// running the package normally (non-FIPS) and again with
// GOFIPS140=v1.0.0 GODEBUG=fips140=only.
func TestNewFIPSAware(t *testing.T) {
	k, err := New()
	if err != nil {
		t.Fatalf("New() failed (fips140.Enabled=%v): %v", fips140.Enabled(), err)
	}

	// P256 keys are always expected, in either mode.
	if len(k.NebulaP256PublicKeyPEM) == 0 || len(k.NebulaP256PrivateKeyPEM) == 0 {
		t.Error("expected P256 Nebula (ECDH) keys to be generated")
	}
	if k.HostP256PublicKey == nil || k.HostP256PrivateKey == nil {
		t.Error("expected P256 host (ECDSA) keys to be generated")
	}

	if fips140.Enabled() {
		// Under FIPS the 25519 keys must be omitted entirely.
		if k.NebulaX25519PublicKeyPEM != nil || k.NebulaX25519PrivateKeyPEM != nil {
			t.Error("expected X25519 Nebula keys to be omitted under FIPS")
		}
		if k.HostEd25519PublicKey != nil || k.HostEd25519PrivateKey != nil {
			t.Error("expected Ed25519 host keys to be omitted under FIPS")
		}
	} else {
		// Without FIPS, both key sets are generated (unchanged behavior).
		if len(k.NebulaX25519PublicKeyPEM) == 0 || len(k.NebulaX25519PrivateKeyPEM) == 0 {
			t.Error("expected X25519 Nebula keys to be generated when not in FIPS mode")
		}
		if k.HostEd25519PublicKey == nil || k.HostEd25519PrivateKey == nil {
			t.Error("expected Ed25519 host keys to be generated when not in FIPS mode")
		}
	}
}
