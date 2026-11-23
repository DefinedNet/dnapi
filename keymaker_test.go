package dnapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi/dnapitest"
	"github.com/DefinedNet/dnapi/internal/testutil"
	"github.com/DefinedNet/dnapi/keys"
	"github.com/DefinedNet/dnapi/message"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// fakeKey is a host key that a KeyMaker other than DefaultKeyMaker made, and that holds a
// resource: it records whether it was closed. It signs with a software key, so the test server
// accepts its requests.
type fakeKey struct {
	keys.PrivateKey
	closed bool
}

func (k *fakeKey) Close() error {
	k.closed = true
	return nil
}

// fakeKeyMaker makes fakeKeys, on both curves unless p256Only is set.
type fakeKeyMaker struct {
	p256Only bool
	made     []*fakeKey
	// curves are the curves NewHostKey was asked for
	curves []message.NetworkCurve
}

func (m *fakeKeyMaker) wrap(k keys.PrivateKey) *fakeKey {
	fk := &fakeKey{PrivateKey: k}
	m.made = append(m.made, fk)
	return fk
}

func (m *fakeKeyMaker) NewNebulaKey(curve message.NetworkCurve) ([]byte, []byte, error) {
	if m.p256Only && curve != message.NetworkCurveP256 {
		return nil, nil, ErrCurveUnsupported
	}
	return DefaultKeyMaker.NewNebulaKey(curve)
}

func (m *fakeKeyMaker) NewHostKey(curve message.NetworkCurve) (keys.PrivateKey, error) {
	m.curves = append(m.curves, curve)
	if m.p256Only && curve != message.NetworkCurveP256 {
		return nil, ErrCurveUnsupported
	}
	k, err := DefaultKeyMaker.NewHostKey(curve)
	if err != nil {
		return nil, err
	}
	return m.wrap(k), nil
}

// open returns the keys m made that are not closed.
func (m *fakeKeyMaker) open() []*fakeKey {
	var out []*fakeKey
	for _, k := range m.made {
		if !k.closed {
			out = append(out, k)
		}
	}
	return out
}

// keyMakerTest is a test API server for a network on curve. The server verifies the signature of
// each DNClient request with the most recent host key that it received.
type keyMakerTest struct {
	ts        *dnapitest.Server
	c         *Client
	ca        cert.Certificate
	caPEM     []byte
	caPrivkey *ecdsa.PrivateKey
	network   message.HostNetworkMetadata
	// offered is the curve of the keys the server expects in an enrollment, the network's curve
	// unless set
	offered message.NetworkCurve
	ctx     context.Context
}

func newKeyMakerTest(t *testing.T, curve message.NetworkCurve) *keyMakerTest {
	t.Helper()
	ts := dnapitest.NewServer("testClient")
	t.Cleanup(func() { ts.Close() })
	ca, caPrivkey := dnapitest.NebulaCACertP256()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return &keyMakerTest{
		ts:        ts,
		c:         NewClient("testClient", ts.URL),
		ca:        ca,
		caPEM:     caPEM,
		caPrivkey: caPrivkey,
		network:   message.HostNetworkMetadata{ID: "qux", Name: "net", Curve: curve},
		ctx:       ctx,
	}
}

// enroll enrolls a host with km, and returns the request and the credentials.
func (e *keyMakerTest) enroll(t *testing.T, km KeyMaker) (message.EnrollRequest, *keys.Credentials, error) {
	t.Helper()
	var req message.EnrollRequest
	offered := e.offered
	if offered == "" {
		offered = e.network.Curve
	}
	e.ts.ExpectEnrollment("foobar", offered, func(r message.EnrollRequest) []byte {
		req = r
		cfg, err := yaml.Marshal(m{"pki": m{"ca": string(e.caPEM)}})
		require.NoError(t, err)
		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{HostID: "foobar", Counter: 1, Config: cfg, TrustedKeys: e.ca.MarshalPublicKeyPEM(), Network: e.network},
		})
	})
	_, _, creds, _, err := e.c.Enroll(e.ctx, testutil.NewTestLogger(), "foobar", "", km)
	return req, creds, err
}

// signed returns a DNClient API response with a CA signature, as from the API.
func (e *keyMakerTest) signed(t *testing.T, res any) []byte {
	t.Helper()
	raw := jsonMarshal(res)
	hashed := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, e.caPrivkey, hashed[:])
	require.NoError(t, err)
	return jsonMarshal(message.SignedResponseWrapper{Data: message.SignedResponse{Version: 1, Message: raw, Signature: sig}})
}

func (e *keyMakerTest) expectUpdate(t *testing.T, status int, counter uint) {
	e.ts.ExpectDNClientRequest(message.DoUpdate, status, func(r message.RequestWrapper) []byte {
		if status != http.StatusOK {
			return []byte("{}")
		}
		return e.signed(t, message.DoUpdateResponse{
			Config: dnapitest.NebulaCfg(e.caPEM), Counter: counter, Nonce: dnapitest.GetNonce(r),
			TrustedKeys: e.ca.MarshalPublicKeyPEM(), Network: e.network,
		})
	})
}

func (e *keyMakerTest) expectConfigUpdate(t *testing.T, status int, counter uint) {
	e.ts.ExpectDNClientRequest(message.DoConfigUpdate, status, func(r message.RequestWrapper) []byte {
		if status != http.StatusOK {
			return []byte("{}")
		}
		return e.signed(t, message.DoConfigUpdateResponse{
			Config: dnapitest.NebulaCfg(e.caPEM), Counter: counter, Nonce: dnapitest.GetNonce(r),
			TrustedKeys: e.ca.MarshalPublicKeyPEM(), Network: e.network,
		})
	})
}

// TestEnrollKeyMaker enrolls with keys from a KeyMaker: the key on the network's curve is kept, the
// other is closed.
func TestEnrollKeyMaker(t *testing.T) {
	for _, tc := range []struct {
		curve    message.NetworkCurve
		keptP256 bool
	}{{message.NetworkCurveP256, true}, {message.NetworkCurve25519, false}} {
		t.Run(string(tc.curve), func(t *testing.T) {
			e := newKeyMakerTest(t, tc.curve)
			km := &fakeKeyMaker{}
			req, creds, err := e.enroll(t, km)
			require.NoError(t, err)
			require.Empty(t, e.ts.Errors())
			require.Equal(t, []message.NetworkCurve{message.NetworkCurveP256, message.NetworkCurve25519}, km.curves)
			assert.NotEmpty(t, req.HostPubkeyP256)
			assert.NotEmpty(t, req.HostPubkeyEd25519)

			require.Len(t, km.made, 2)
			kept := km.made[1] // Ed25519
			if tc.keptP256 {
				kept = km.made[0]
			}
			require.Same(t, kept, creds.PrivateKey)
			require.Equal(t, []*fakeKey{kept}, km.open())
		})
	}
}

// TestEnrollKeyMakerP256Only enrolls with a KeyMaker that can not make 25519 keys, to a server
// that does not refuse it although the network is Curve25519: the client refuses the
// enrollment, and closes the keys.
func TestEnrollKeyMakerP256Only(t *testing.T) {
	e := newKeyMakerTest(t, message.NetworkCurve25519)
	e.offered = message.NetworkCurveP256
	km := &fakeKeyMaker{p256Only: true}
	req, _, err := e.enroll(t, km)
	require.ErrorContains(t, err, "network uses curve 25519, but no keys on it were offered")
	assert.Empty(t, req.HostPubkeyEd25519)
	assert.Empty(t, km.open())
}

// TestDoUpdateKeyMaker replaces a host's keys with keys from its KeyMaker. A failed update closes
// them all; a successful one keeps the key on the host's curve.
func TestDoUpdateKeyMaker(t *testing.T) {
	e := newKeyMakerTest(t, message.NetworkCurveP256)
	km := &fakeKeyMaker{}
	_, creds, err := e.enroll(t, km)
	require.NoError(t, err)
	hostPub, err := creds.PrivateKey.Public().MarshalPEM()
	require.NoError(t, err)

	// The test server sets the new host key of each update request as current, also when the
	// request fails. Thus, set the current key again before the next request
	e.expectUpdate(t, http.StatusInternalServerError, 0)
	_, _, _, _, err = e.c.DoUpdate(e.ctx, *creds, km)
	require.Error(t, err)
	require.Len(t, km.made, 3)
	require.Equal(t, []*fakeKey{km.made[0]}, km.open(), "a failed update left its new key open")
	require.NoError(t, e.ts.SetP256Pubkey(hostPub))

	e.expectUpdate(t, http.StatusOK, 2)
	_, _, newCreds, _, err := e.c.DoUpdate(e.ctx, *creds, km)
	require.NoError(t, err)
	require.Empty(t, e.ts.Errors())
	// Enrollment asked for both curves, each update only for the host's
	require.Equal(t, []message.NetworkCurve{message.NetworkCurveP256, message.NetworkCurve25519, message.NetworkCurveP256, message.NetworkCurveP256}, km.curves)
	require.Same(t, km.made[3], newCreds.PrivateKey)
	require.Equal(t, []*fakeKey{km.made[0], km.made[3]}, km.open())
	assert.Equal(t, 0, e.ts.RequestsRemaining())
}

// TestDoConfigUpdateKeyMaker replaces a host key with one from its KeyMaker, and closes the new key
// when the update fails or the KeyMaker makes a key on the wrong curve.
func TestDoConfigUpdateKeyMaker(t *testing.T) {
	e := newKeyMakerTest(t, message.NetworkCurveP256)
	km := &fakeKeyMaker{}
	_, creds, err := e.enroll(t, km)
	require.NoError(t, err)
	hostPub, err := creds.PrivateKey.Public().MarshalPEM()
	require.NoError(t, err)

	e.expectConfigUpdate(t, http.StatusInternalServerError, 0)
	_, _, _, err = e.c.DoConfigUpdate(e.ctx, *creds, km)
	require.Error(t, err)
	require.Equal(t, []*fakeKey{km.made[0]}, km.open(), "a failed update left its new key open")
	require.NoError(t, e.ts.SetP256Pubkey(hostPub))

	_, _, _, err = e.c.DoConfigUpdate(e.ctx, *creds, wrongCurveKeyMaker{km})
	require.ErrorContains(t, err, "made a keys.Ed25519PublicKey host key for curve P256")
	require.Equal(t, []*fakeKey{km.made[0]}, km.open(), "a key on the wrong curve was left open")

	e.expectConfigUpdate(t, http.StatusOK, 2)
	_, newCreds, _, err := e.c.DoConfigUpdate(e.ctx, *creds, km)
	require.NoError(t, err)
	require.Empty(t, e.ts.Errors())
	require.Same(t, km.made[len(km.made)-1], newCreds.PrivateKey)
	require.Equal(t, message.NetworkCurveP256, km.curves[len(km.curves)-1])
	assert.Equal(t, 0, e.ts.RequestsRemaining())
}

// wrongCurveKeyMaker makes Ed25519 host keys whatever it replaces.
type wrongCurveKeyMaker struct{ *fakeKeyMaker }

func (m wrongCurveKeyMaker) NewHostKey(message.NetworkCurve) (keys.PrivateKey, error) {
	k, err := DefaultKeyMaker.NewHostKey(message.NetworkCurve25519)
	if err != nil {
		return nil, err
	}
	return m.wrap(k), nil
}

// TestDefaultKeyMakerFIPS checks that DefaultKeyMaker adapts to FIPS 140 mode. It always makes
// the approved P256 keys. It makes Curve25519 keys only outside FIPS mode, and returns
// ErrCurveUnsupported in it, so an enrollment offers only P256 keys: under GODEBUG=fips140=only,
// crypto/ecdh refuses to generate an X25519 key at all, which would fail the enrollment.
//
// The test adapts to the mode it runs under. CI runs it normally and again with
// GOFIPS140=v1.0.0 GODEBUG=fips140=only.
func TestDefaultKeyMakerFIPS(t *testing.T) {
	_, _, err := DefaultKeyMaker.NewNebulaKey(message.NetworkCurveP256)
	require.NoError(t, err)
	_, err = DefaultKeyMaker.NewHostKey(message.NetworkCurveP256)
	require.NoError(t, err)

	_, _, nebulaErr := DefaultKeyMaker.NewNebulaKey(message.NetworkCurve25519)
	_, hostErr := DefaultKeyMaker.NewHostKey(message.NetworkCurve25519)
	if fips140.Enabled() {
		require.ErrorIs(t, nebulaErr, ErrCurveUnsupported)
		require.ErrorIs(t, hostErr, ErrCurveUnsupported)
	} else {
		require.NoError(t, nebulaErr)
		require.NoError(t, hostErr)
	}
}

func TestNilKeyMaker(t *testing.T) {
	c := NewClient("testClient", "http://127.0.0.1:1")
	p256Host, err := DefaultKeyMaker.NewHostKey(message.NetworkCurveP256)
	require.NoError(t, err)
	creds := keys.Credentials{HostID: "foobar", PrivateKey: p256Host, Counter: 1}
	_, _, _, _, err = c.Enroll(context.Background(), testutil.NewTestLogger(), "foobar", "", nil)
	require.ErrorContains(t, err, "no KeyMaker")
	_, _, _, _, err = c.DoUpdate(context.Background(), creds, nil)
	require.ErrorContains(t, err, "no KeyMaker")
	_, _, _, err = c.DoConfigUpdate(context.Background(), creds, nil)
	require.ErrorContains(t, err, "no KeyMaker")
}
