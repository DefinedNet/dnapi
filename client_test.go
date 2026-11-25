package dnapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

type m map[string]interface{}

// dropTimeAttr is a slog.HandlerOptions.ReplaceAttr that drops the time
// attribute from a record, so JSON output is deterministic in tests.
func dropTimeAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

func TestEnroll(t *testing.T) {
	t.Parallel()

	useragent := "dnclientUnitTests/1.0.0 (not a real client)"
	ts := dnapitest.NewServer(useragent)
	client := NewClient(useragent, ts.URL)
	// attempting to defer ts.Close() will trigger early due to parallel testing - use T.Cleanup instead
	t.Cleanup(func() { ts.Close() })

	// Happy path enrollment
	code := "abcdef"
	orgID := "foobaz"
	orgName := "foobar's foo org"
	netID := "qux"
	netName := "the best network"
	netCurve := message.NetworkCurve25519
	netCIDR := "192.168.100.0/24"
	hostID := "foobar"
	hostName := "foo host"
	hostIP := "192.168.100.1"
	oidcEmail := "demo@defined.net"
	oidcExpiresAt := time.Now()
	counter := uint(5)
	hostname := "test-machine.local"
	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.NebulaPubkeyX25519, "hostname": req.Hostname},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      hostID,
				Counter:     counter,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   orgID,
					Name: orgName,
				},
				Network: message.HostNetworkMetadata{
					ID:    netID,
					Name:  netName,
					Curve: netCurve,
					CIDR:  netCIDR,
				},
				Host: message.HostHostMetadata{
					ID:        hostID,
					Name:      hostName,
					IPAddress: hostIP,
					Ephemeral: true,
				},
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email:     oidcEmail,
					ExpiresAt: &oidcExpiresAt,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, creds, meta, err := client.Enroll(ctx, testutil.NewTestLogger(), code, hostname)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	tk, err := keys.NewTrustedKey(ed25519.PublicKey(ca.PublicKey()))
	require.NoError(t, err)

	assert.Equal(t, hostID, creds.HostID)
	assert.Equal(t, counter, creds.Counter)
	assert.Equal(t, []keys.TrustedKey{tk}, creds.TrustedKeys)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, pkey)

	var y struct {
		PKI struct {
			Key string `yaml:"key"`
		} `yaml:"pki"`
		Test struct {
			Code     string `yaml:"code"`
			DHPubkey []byte `yaml:"dhPubkey"`
			Hostname string `yaml:"hostname"`
		} `yaml:"test"`
	}
	err = yaml.Unmarshal(cfg, &y)
	require.NoError(t, err)
	_, rest, _, err := cert.UnmarshalPublicKeyFromPEM(y.Test.DHPubkey)
	assert.NoError(t, err)
	assert.Len(t, rest, 0)
	assert.Equal(t, code, y.Test.Code)
	assert.Equal(t, hostname, y.Test.Hostname)

	// ensure private key was not inserted into config
	assert.Empty(t, y.PKI.Key)

	// test meta
	assert.Equal(t, orgID, meta.Org.ID)
	assert.Equal(t, orgName, meta.Org.Name)
	assert.Equal(t, netID, meta.Network.ID)
	assert.Equal(t, netName, meta.Network.Name)
	assert.Equal(t, hostID, meta.Host.ID)
	assert.Equal(t, hostName, meta.Host.Name)
	assert.Equal(t, []string{hostIP}, meta.Host.IPAddresses)
	assert.True(t, meta.Host.Ephemeral)
	assert.Equal(t, oidcEmail, meta.EndpointOIDC.Email)
	assert.WithinDuration(t, oidcExpiresAt, *meta.EndpointOIDC.ExpiresAt, 1*time.Second)

	// Test error handling
	errorMsg := "invalid enrollment code"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Errors: message.APIResponseErrors{{
				Code:    "ERR_INVALID_ENROLLMENT_CODE",
				Message: errorMsg,
			}},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, creds, meta, err = client.Enroll(ctx, testutil.NewTestLogger(), code, "")
	require.EqualError(t, err, "unexpected error during enrollment: "+errorMsg)

	assert.Nil(t, cfg)
	assert.Nil(t, pkey)
	assert.Nil(t, creds)
	assert.Nil(t, meta)
	apiError := &APIError{}
	reqIDErrPresent := errors.As(err, &apiError)
	require.True(t, reqIDErrPresent)
	assert.Equal(t, apiError.ReqID, "SupaDoopaRequestIdentifier")
}

func TestDoUpdate(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.NebulaPubkeyX25519},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurve25519,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "quux",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
	require.NoError(t, err)

	// convert privkey to private key
	pubkey, err := keys.MarshalHostEd25519PublicKey(creds.PrivateKey.Public().Unwrap().(ed25519.PublicKey))
	require.NoError(t, err)

	// make sure all credential values were set
	assert.NotEmpty(t, creds.HostID)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, creds.TrustedKeys)
	assert.NotEmpty(t, creds.Counter)

	// make sure we got a config back
	assert.NotEmpty(t, config)
	assert.NotEmpty(t, pkey)

	// Invalid request signature should return a specific error
	ts.ExpectDNClientRequest(message.CheckForUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		return []byte("")
	})

	// Create a new, invalid requesting authentication key
	nk, err := keys.New()
	require.NoError(t, err)

	invalidCreds := keys.Credentials{
		HostID:      creds.HostID,
		PrivateKey:  nk.HostEd25519PrivateKey,
		Counter:     creds.Counter,
		TrustedKeys: creds.TrustedKeys,
	}

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = c.CheckForUpdate(ctx, invalidCreds)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	serverErrs := ts.Errors() // This consumes/resets the server errors
	require.Len(t, serverErrs, 1)

	// Invalid signature
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     2,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: ca.MarshalPublicKeyPEM(),
			Organization: message.HostOrgMetadata{
				ID:   "foobaz",
				Name: "foobar's foo org",
			},
			Network: message.HostNetworkMetadata{
				ID:    "qux",
				Name:  "the best network",
				Curve: message.NetworkCurve25519,
				CIDR:  "192.168.100.0/24",
			},
			Host: message.HostHostMetadata{
				ID:        "quux",
				Name:      "foo host",
				IPAddress: "192.168.100.2",
			},
		}
		rawRes := jsonMarshal(newConfigResponse)

		nk, err := keys.New()
		require.NoError(t, err)

		// XXX the mock server will update the ed pubkey for us, but this is problematic because
		// we are rejecting the update. reset the key
		err = ts.SetEdPubkey(pubkey)
		require.NoError(t, err)

		sig, err := nk.HostEd25519PrivateKey.Sign(rawRes)
		require.NoError(t, err)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: sig,
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, newCreds, _, err := c.DoUpdate(ctx, *creds)
	require.EqualError(t, err, "failed to verify signed API result")
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// Invalid counter
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     0,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: ca.MarshalPublicKeyPEM(),
			Organization: message.HostOrgMetadata{
				ID:   "foobaz",
				Name: "foobar's foo org",
			},
			Network: message.HostNetworkMetadata{
				ID:    "qux",
				Name:  "the best network",
				Curve: message.NetworkCurve25519,
				CIDR:  "192.168.100.0/24",
			},
			Host: message.HostHostMetadata{
				ID:        "quux",
				Name:      "foo host",
				IPAddress: "192.168.100.2",
			},
		}
		rawRes := jsonMarshal(newConfigResponse)

		// XXX the mock server will update the ed pubkey for us, but this is problematic because
		// we are rejecting the update. reset the key
		err := ts.SetEdPubkey(pubkey)
		require.NoError(t, err)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: ed25519.Sign(caPrivkey, rawRes),
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, newCreds, _, err = c.DoUpdate(ctx, *creds)
	require.Error(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	orgID := "foobaz"
	orgName := "foobar's foo org"
	netID := "qux"
	netName := "the best network"
	netCurve := message.NetworkCurve25519
	netCIDR := "192.168.100.0/24"
	hostID := "foobar"
	hostName := "foo host"
	hostIP := "192.168.100.1"
	oidcEmail := "demo@defined.net"

	// This time sign the response with the correct CA key.
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     3,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: ca.MarshalPublicKeyPEM(),
			Organization: message.HostOrgMetadata{
				ID:   orgID,
				Name: orgName,
			},
			Network: message.HostNetworkMetadata{
				ID:    netID,
				Name:  netName,
				Curve: netCurve,
				CIDR:  netCIDR,
			},
			Host: message.HostHostMetadata{
				ID:        hostID,
				Name:      hostName,
				IPAddress: hostIP,
				Ephemeral: true,
			},
			EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
				Email:     oidcEmail,
				ExpiresAt: nil,
			},
		}
		rawRes := jsonMarshal(newConfigResponse)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: ed25519.Sign(caPrivkey, rawRes),
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, _, meta, err := c.DoUpdate(ctx, *creds)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	// test meta
	assert.Equal(t, orgID, meta.Org.ID)
	assert.Equal(t, orgName, meta.Org.Name)
	assert.Equal(t, netID, meta.Network.ID)
	assert.Equal(t, netName, meta.Network.Name)
	assert.Equal(t, hostID, meta.Host.ID)
	assert.Equal(t, hostName, meta.Host.Name)
	assert.Equal(t, []string{hostIP}, meta.Host.IPAddresses)
	assert.True(t, meta.Host.Ephemeral)
	assert.Equal(t, oidcEmail, meta.EndpointOIDC.Email)
	assert.Nil(t, meta.EndpointOIDC.ExpiresAt)

}

func TestDoConfigUpdate(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			"pki": m{"ca": string(caPEM)},
		})
		require.NoError(t, err)

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurve25519,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "quux",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), code, "")
	require.NoError(t, err)

	orgID := "foobaz"
	orgName := "foobar's foo org"
	netID := "qux"
	netName := "the best network"
	hostID := "foobar"
	hostName := "foo host"
	hostIP := "192.168.100.1"
	oidcEmail := "demo@defined.net"
	oidcExpiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	ts.ExpectDNClientRequest(message.DoConfigUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoConfigUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     2,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: ca.MarshalPublicKeyPEM(),
			Organization: message.HostOrgMetadata{
				ID:   orgID,
				Name: orgName,
			},
			Network: message.HostNetworkMetadata{
				ID:    netID,
				Name:  netName,
				Curve: message.NetworkCurve25519,
				CIDR:  "192.168.100.0/24",
			},
			Host: message.HostHostMetadata{
				ID:        hostID,
				Name:      hostName,
				IPAddress: hostIP,
				Ephemeral: true,
			},
			EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
				Email:     oidcEmail,
				ExpiresAt: &oidcExpiresAt,
			},
		}
		rawRes := jsonMarshal(newConfigResponse)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: ed25519.Sign(caPrivkey, rawRes),
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, meta, err := c.DoConfigUpdate(ctx, *creds)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	assert.Equal(t, orgID, meta.Org.ID)
	assert.Equal(t, orgName, meta.Org.Name)
	assert.Equal(t, netID, meta.Network.ID)
	assert.Equal(t, netName, meta.Network.Name)
	assert.Equal(t, hostID, meta.Host.ID)
	assert.Equal(t, hostName, meta.Host.Name)
	assert.Equal(t, []string{hostIP}, meta.Host.IPAddresses)
	assert.True(t, meta.Host.Ephemeral)
	require.NotNil(t, meta.EndpointOIDC)
	assert.Equal(t, oidcEmail, meta.EndpointOIDC.Email)
	require.NotNil(t, meta.EndpointOIDC.ExpiresAt)
	assert.WithinDuration(t, oidcExpiresAt, *meta.EndpointOIDC.ExpiresAt, time.Second)
}

func TestDoUpdate_P256(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACertP256()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurveP256, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "p256Pubkey": req.NebulaPubkeyP256},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurveP256,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "quux",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
	require.NoError(t, err)

	// convert private key to public key
	pubkey, err := keys.MarshalHostP256PublicKey(creds.PrivateKey.Public().Unwrap().(*ecdsa.PublicKey))
	require.NoError(t, err)

	// make sure all credential values were set
	assert.NotEmpty(t, creds.HostID)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, creds.TrustedKeys)
	assert.NotEmpty(t, creds.Counter)

	// make sure we got a config back
	assert.NotEmpty(t, config)
	assert.NotEmpty(t, pkey)

	// Invalid request signature should return a specific error
	ts.ExpectDNClientRequest(message.CheckForUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		return []byte("")
	})

	// Create a new, invalid requesting authentication key
	nk, err := keys.New()
	require.NoError(t, err)
	invalidCreds := keys.Credentials{
		HostID:      creds.HostID,
		PrivateKey:  nk.HostP256PrivateKey,
		Counter:     creds.Counter,
		TrustedKeys: creds.TrustedKeys,
	}

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = c.CheckForUpdate(ctx, invalidCreds)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	serverErrs := ts.Errors() // This consumes/resets the server errors
	require.Len(t, serverErrs, 1)

	// Invalid signature
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:  dnapitest.NebulaCfg(caPEM),
			Counter: 2,
			Nonce:   dnapitest.GetNonce(r),
		}
		rawRes := jsonMarshal(newConfigResponse)

		nk, err := keys.New()
		require.NoError(t, err)

		// XXX the mock server will update the ed pubkey for us, but this is problematic because
		// we are rejecting the update. reset the key
		err = ts.SetP256Pubkey(pubkey)
		require.NoError(t, err)

		sig, err := nk.HostP256PrivateKey.Sign(rawRes)
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_SIGN_MESSAGE",
					Message: "failed to sign message",
				}},
			})
		}

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: sig,
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, newCreds, _, err := c.DoUpdate(ctx, *creds)
	require.EqualError(t, err, "failed to verify signed API result")
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// Invalid counter
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:  dnapitest.NebulaCfg(caPEM),
			Counter: 0,
			Nonce:   dnapitest.GetNonce(r),
		}
		rawRes := jsonMarshal(newConfigResponse)

		// XXX the mock server will update the host pubkey for us, but this is problematic because
		// we are rejecting the update. reset the key
		err := ts.SetP256Pubkey(pubkey)
		require.NoError(t, err)

		hashed := sha256.Sum256(rawRes)
		sig, err := ecdsa.SignASN1(rand.Reader, caPrivkey, hashed[:])
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_SIGN_MESSAGE",
					Message: "failed to sign message",
				}},
			})
		}

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: sig,
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, newCreds, _, err = c.DoUpdate(ctx, *creds)
	require.Error(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// This time sign the response with the correct CA key.
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     3,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: ca.MarshalPublicKeyPEM(),
			Organization: message.HostOrgMetadata{
				ID:   "foobaz",
				Name: "foobar's foo org",
			},
			Network: message.HostNetworkMetadata{
				ID:    "qux",
				Name:  "the best network",
				Curve: message.NetworkCurve25519,
				CIDR:  "192.168.100.0/24",
			},
			Host: message.HostHostMetadata{
				ID:        "quux",
				Name:      "foo host",
				IPAddress: "192.168.100.2",
			},
		}
		rawRes := jsonMarshal(newConfigResponse)
		hashed := sha256.Sum256(rawRes)
		sig, err := ecdsa.SignASN1(rand.Reader, caPrivkey, hashed[:])
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_SIGN_MESSAGE",
					Message: "failed to sign message",
				}},
			})
		}

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: sig,
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, _, _, err = c.DoUpdate(ctx, *creds)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

}

func TestCommandResponse(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.NebulaPubkeyX25519},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurve25519,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "quux",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, meta, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
	require.NoError(t, err)

	// make sure all credential values were set
	assert.NotEmpty(t, creds.HostID)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, creds.TrustedKeys)
	assert.NotEmpty(t, creds.Counter)

	// make sure we got a config back
	assert.NotEmpty(t, config)
	assert.NotEmpty(t, pkey)

	// no EndpointOIDC for standard host enrollments
	assert.Nil(t, meta.EndpointOIDC)

	// This time sign the response with the correct CA key.
	responseToken := "abc123"
	res := map[string]any{"msg": "Hello, world!"}
	ts.ExpectDNClientRequest(message.CommandResponse, http.StatusOK, func(r message.RequestWrapper) []byte {
		var val map[string]any
		err := json.Unmarshal(r.Value, &val)
		require.NoError(t, err)
		require.Contains(t, val, "responseToken")
		require.Equal(t, responseToken, val["responseToken"])
		require.Contains(t, val, "response")
		require.Equal(t, res, val["response"])
		return jsonMarshal(struct{}{})
	})

	err = c.CommandResponse(context.Background(), *creds, responseToken, res)
	require.NoError(t, err)

	// Test error handling
	errorMsg := "sample error"
	ts.ExpectDNClientRequest(message.CommandResponse, http.StatusBadRequest, func(r message.RequestWrapper) []byte {
		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Errors: message.APIResponseErrors{{
				Code:    "ERR_INVALID_VALUE",
				Message: errorMsg,
			}},
		})
	})

	err = c.CommandResponse(context.Background(), *creds, "responseToken", map[string]any{"msg": "Hello, world!"})
	require.Error(t, err)
}

func TestStreamCommandResponse(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.NebulaPubkeyX25519},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurve25519,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "quux",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
	require.NoError(t, err)

	// make sure all credential values were set
	assert.NotEmpty(t, creds.HostID)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, creds.TrustedKeys)
	assert.NotEmpty(t, creds.Counter)

	// make sure we got a config back
	assert.NotEmpty(t, config)
	assert.NotEmpty(t, pkey)

	// Buffer that will store the logs sent to the service for verification
	var buf bytes.Buffer

	// This time sign the response with the correct CA key.
	ts.ExpectStreamingRequest(message.CommandResponse, http.StatusOK, func(r message.RequestWrapper) []byte {
		return jsonMarshal(struct{}{})
	})

	sc, err := c.StreamCommandResponse(context.Background(), *creds, "responseToken")
	require.NoError(t, err)

	// Configure a logger to write to a buffer and the stream
	logger := slog.New(slog.NewJSONHandler(io.MultiWriter(sc, &buf), &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: dropTimeAttr,
	}))

	logger.Info("Hello, world! info!")
	logger.Warn("Hello, world! warning!")

	err = sc.Close()
	require.NoError(t, err)
	require.NoError(t, sc.Err())

	require.Equal(t, buf.Bytes(), ts.LastStreamedBody())

	// Test error handling
	errorMsg := "sample error"
	ts.ExpectStreamingRequest(message.CommandResponse, http.StatusBadRequest, func(r message.RequestWrapper) []byte {
		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Errors: message.APIResponseErrors{{
				Code:    "ERR_INVALID_VALUE",
				Message: errorMsg,
			}},
		})
	})

	buf.Reset()

	sc, err = c.StreamCommandResponse(context.Background(), *creds, "responseToken")
	require.NoError(t, err)

	logger = slog.New(slog.NewJSONHandler(io.MultiWriter(sc, &buf), &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: dropTimeAttr,
	}))

	logger.Info("Hello, world! info!")
	logger.Warn("Hello, world! warning!")

	// Close shouldn't return an error - that's only if the writer fails to close
	assert.NoError(t, sc.Close())
	// Err should return the error from the server
	assert.Error(t, sc.Err())

	// A proxy's JSON error page has no errors array.
	ts.ExpectStreamingRequest(message.CommandResponse, http.StatusServiceUnavailable, func(r message.RequestWrapper) []byte {
		return []byte(`{}`)
	})
	sc, err = c.StreamCommandResponse(context.Background(), *creds, "responseToken")
	require.NoError(t, err)
	_, err = sc.Write([]byte("log line"))
	require.NoError(t, err)
	assert.NoError(t, sc.Close())
	assert.Error(t, sc.Err())

	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining(), ts.ExpectedRequests())
}

func TestReauthenticate(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.NebulaPubkeyX25519},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurve25519,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "quux",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
	require.NoError(t, err)

	// make sure all credential values were set
	assert.NotEmpty(t, creds.HostID)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, creds.TrustedKeys)
	assert.NotEmpty(t, creds.Counter)

	// make sure we got a config back
	assert.NotEmpty(t, config)
	assert.NotEmpty(t, pkey)

	// This time sign the response with the correct CA key.
	ts.ExpectDNClientRequest(message.Reauthenticate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.ReauthenticateResponse{
			LoginURL: "https://auth.example.com/login?authcode=123",
		}
		rawRes := jsonMarshal(newConfigResponse)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: ed25519.Sign(caPrivkey, rawRes),
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	resp, err := c.Reauthenticate(ctx, *creds)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	// make sure we got a login URL back
	assert.NotEmpty(t, resp)
	assert.NotEmpty(t, resp.LoginURL)
	assert.Equal(t, "https://auth.example.com/login?authcode=123", resp.LoginURL)

}

// signResponse returns a signed response of the given version carrying msg, signed by caKey.
func signResponse(t *testing.T, caKey keys.PrivateKey, version int, msg []byte) []byte {
	sig, err := caKey.Sign(msg)
	require.NoError(t, err)
	return jsonMarshal(message.SignedResponseWrapper{
		Data: message.SignedResponse{Version: version, Message: msg, Signature: sig},
	})
}

// signedResponseV2 returns a version 2 signed response to r for hostID carrying value.
func signedResponseV2(t *testing.T, caKey keys.PrivateKey, r message.RequestWrapper, hostID string, value any) []byte {
	return signResponse(t, caKey, 2, jsonMarshal(message.SignedResponseEnvelope{
		Version: 2,
		Nonce:   r.Nonce,
		HostID:  hostID,
		Type:    r.Type,
		Value:   jsonMarshal(value),
	}))
}

func jsonMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestTimeout(t *testing.T) {
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(250 * time.Millisecond)
			fmt.Fprintln(w, "OK")
		}))
	defer ts.Close()

	useragent := "TestTimeout agent"
	c := NewClient(useragent, ts.URL)
	// The default timeout is 1 minutes. Assert the default value.
	assert.Equal(t, c.client.Timeout, 2*time.Minute)
	// The default streaming timeout is 15 minutes. Assert the default value.
	assert.Equal(t, c.streamingClient.Timeout, 15*time.Minute)
	// Overwrite the default value with a 10 millisecond timeout for test brevity.
	c.client.Timeout = 10 * time.Millisecond
	// DO IT
	_, err := c.client.Get(ts.URL + "/lol")
	require.Error(t, err)
}

func TestOverrideTimeout(t *testing.T) {
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(250 * time.Millisecond)
			fmt.Fprintln(w, "OK")
		}))
	defer ts.Close()

	useragent := "TestTimeout agent"
	c := NewClient(useragent, ts.URL)
	// DO IT
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	_, _, _, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "ABC123", "")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestDialWithFallback(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(ts.Close)
	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)

	// .invalid never resolves (RFC 2606), so the pinned address must be used
	dial := dialWithFallback(map[string][]string{"api.invalid": {"127.0.0.1"}})
	conn, err := dial(context.Background(), "tcp", "api.invalid:"+port)
	require.NoError(t, err)
	assert.Equal(t, ts.Listener.Addr().String(), conn.RemoteAddr().String())
	conn.Close()

	// hosts without a fallback surface the DNS error unchanged
	var dnsErr *net.DNSError
	_, err = dial(context.Background(), "tcp", "other.invalid:"+port)
	require.ErrorAs(t, err, &dnsErr)
}

func TestGetOidcPollCode(t *testing.T) {
	t.Parallel()

	useragent := "dnclientUnitTests/1.0.0 (not a real client)"
	ts := dnapitest.NewServer(useragent)
	client := NewClient(useragent, ts.URL)
	// attempting to defer ts.Close() will trigger early due to parallel testing - use T.Cleanup instead
	t.Cleanup(func() { ts.Close() })
	const expectedCode = "123456"
	ts.ExpectAPIRequest(http.StatusOK, func(req any) []byte {
		return jsonMarshal(message.APIResponse[message.PreAuthData]{Data: message.PreAuthData{PollToken: expectedCode, LoginURL: "https://example.com"}})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	resp, err := client.EndpointPreAuth(ctx)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, expectedCode, resp.PollToken)
	assert.Equal(t, "https://example.com", resp.LoginURL)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	//unhappy path
	ts.ExpectAPIRequest(http.StatusInternalServerError, func(req any) []byte {
		return jsonMarshal(message.APIResponse[message.PreAuthData]{
			Errors: message.APIResponseErrors{{
				Code:    "ERR_INTERNAL_SERVER_ERROR",
				Message: "internal server error",
			}},
		})
	})
	resp, err = client.EndpointPreAuth(ctx)
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
}

func TestDoOidcPoll(t *testing.T) {
	t.Parallel()

	useragent := "dnclientUnitTests/1.0.0 (not a real client)"
	ts := dnapitest.NewServer(useragent)
	client := NewClient(useragent, ts.URL)
	// attempting to defer ts.Close() will trigger early due to parallel testing - use T.Cleanup instead
	t.Cleanup(func() { ts.Close() })
	const expectedCode = "123456"
	ts.ExpectAPIRequest(http.StatusOK, func(r any) []byte {
		return jsonMarshal(message.APIResponse[message.EndpointAuthPollData]{Data: message.EndpointAuthPollData{
			Status:         message.EndpointAuthStarted,
			EnrollmentCode: expectedCode,
		}})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	resp, err := client.EndpointAuthPoll(ctx, expectedCode)
	require.NoError(t, err)
	assert.Equal(t, message.EndpointAuthStarted, resp.Status)
	assert.Equal(t, expectedCode, resp.EnrollmentCode)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	//unhappy path
	ts.ExpectAPIRequest(http.StatusBadRequest, func(r any) []byte {
		return nil
	})
	resp, err = client.EndpointAuthPoll(ctx, "") //blank code should error!
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	//complete path
	ts.ExpectAPIRequest(http.StatusOK, func(r any) []byte {
		return jsonMarshal(message.APIResponse[message.EndpointAuthPollData]{Data: message.EndpointAuthPollData{
			Status:         message.EndpointAuthCompleted,
			EnrollmentCode: "deadbeef",
		}})
	})
	resp, err = client.EndpointAuthPoll(ctx, expectedCode)
	require.NoError(t, err)
	assert.Equal(t, resp.Status, message.EndpointAuthCompleted)
	assert.Equal(t, resp.EnrollmentCode, "deadbeef")
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
}

func TestEndpointTokenFlowV2(t *testing.T) {
	t.Parallel()

	useragent := "dnclientUnitTests/1.0.0 (not a real client)"
	ts := dnapitest.NewServer(useragent)
	client := NewClient(useragent, ts.URL)
	t.Cleanup(func() { ts.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	secrets, err := NewEndpointAuthSecrets()
	require.NoError(t, err)
	const redirectURI = "http://127.0.0.1:49152/callback"

	// every endpoint comes from the server metadata
	meta := ts.OAuthServerMetadata("https://auth.example.com/oauth/authorize")
	ts.ExpectAPIRequest(http.StatusOK, func(r any) []byte {
		req := r.(dnapitest.APIRequest)
		assert.Equal(t, "GET", req.Method)
		assert.Equal(t, message.OAuthServerMetadataEndpoint, req.Path)
		return jsonMarshal(meta)
	})

	// the pushed authorization request sends the client, redirect URI, PKCE challenge, state, and
	// login hint as a form
	ts.ExpectAPIRequest(http.StatusCreated, func(r any) []byte {
		req := r.(dnapitest.APIRequest)
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, dnapitest.OAuthPushedRequestPath, req.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
		form, err := url.ParseQuery(string(req.Body))
		require.NoError(t, err)
		assert.Equal(t, url.Values{
			"client_id":             {message.OAuthClientDNClient},
			"response_type":         {"code"},
			"redirect_uri":          {redirectURI},
			"scope":                 {message.OAuthScopeEndpointHosts},
			"code_challenge":        {secrets.CodeChallenge},
			"code_challenge_method": {"S256"},
			"state":                 {secrets.State},
			"login_hint":            {"user@example.com"},
		}, form)
		return jsonMarshal(message.PushedAuthorizationData{RequestURI: "urn:ietf:params:oauth:request_uri:oapar-x", ExpiresIn: 60})
	})
	authorizeURL, err := client.EndpointAuthorize(ctx, message.OAuthClientDNClient, redirectURI, secrets, "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/oauth/authorize?client_id=dnclient&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aoapar-x", authorizeURL)

	// an endpoint that is missing or not a web URL is refused, before anything is pushed: there is
	// no default path to fall back to
	bad := []string{"", "/oauth/par", "file:///etc/passwd", "javascript:alert(1)", "http://auth.example.com/oauth/authorize", "https://user@auth.example.com/oauth/authorize"}
	for _, field := range []struct {
		name string
		set  func(*message.OAuthServerMetadata, string)
	}{
		{"authorization", func(m *message.OAuthServerMetadata, v string) { m.AuthorizationEndpoint = v }},
		{"pushed authorization request", func(m *message.OAuthServerMetadata, v string) { m.PushedAuthorizationRequestEndpoint = v }},
		{"token", func(m *message.OAuthServerMetadata, v string) { m.TokenEndpoint = v }},
	} {
		for _, endpoint := range bad {
			badMeta := meta
			field.set(&badMeta, endpoint)
			ts.ExpectAPIRequest(http.StatusOK, func(any) []byte { return jsonMarshal(badMeta) })
			_, err = client.EndpointAuthorize(ctx, message.OAuthClientDNClient, redirectURI, secrets, "")
			require.ErrorContains(t, err, "unexpected "+field.name+" endpoint", endpoint)
		}
	}

	// metadata for another issuer is refused, before anything is pushed
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte {
		evil := meta
		evil.Issuer = "https://evil.example"
		return jsonMarshal(evil)
	})
	_, err = client.EndpointAuthorize(ctx, message.OAuthClientDNClient, redirectURI, secrets, "")
	require.ErrorContains(t, err, "issuer")

	// the browser returns to the redirect URI with a code
	code, err := secrets.ParseCallback(url.Values{"code": {"eaexch-code"}, "state": {secrets.State}, "iss": {ts.URL}}, client.OAuthIssuer())
	require.NoError(t, err)

	// the token request goes to the token endpoint from the metadata, and sends the code, client,
	// redirect URI and verifier
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte { return jsonMarshal(meta) })
	ts.ExpectAPIRequest(http.StatusOK, func(r any) []byte {
		req := r.(dnapitest.APIRequest)
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, dnapitest.OAuthTokenPath, req.Path)
		form, err := url.ParseQuery(string(req.Body))
		require.NoError(t, err)
		assert.Equal(t, url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {message.OAuthClientDNClient},
			"code":          {"eaexch-code"},
			"redirect_uri":  {redirectURI},
			"code_verifier": {secrets.CodeVerifier},
		}, form)
		assert.Empty(t, req.Header.Get("Authorization"))
		return jsonMarshal(message.OAuthTokenData{
			AccessToken: "eou-token", TokenType: "Bearer", ExpiresIn: 900, Scope: message.OAuthScopeEndpointHosts,
			Email: "alice@example.com", NetworkID: "network-1", NetworkName: "Corp",
		})
	})
	tok, err := client.EndpointAuthToken(ctx, message.OAuthClientDNClient, redirectURI, code, secrets)
	require.NoError(t, err)
	assert.Equal(t, &message.OAuthTokenData{
		AccessToken: "eou-token", TokenType: "Bearer", ExpiresIn: 900, Scope: message.OAuthScopeEndpointHosts,
		Email: "alice@example.com", NetworkID: "network-1", NetworkName: "Corp",
	}, tok)

	// a failed redemption is an OAuthError
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte { return jsonMarshal(meta) })
	ts.ExpectAPIRequest(http.StatusBadRequest, func(any) []byte {
		return jsonMarshal(message.OAuthErrorData{Error: "invalid_grant", ErrorDescription: "invalid authorization code"})
	})
	_, err = client.EndpointAuthToken(ctx, message.OAuthClientDNClient, redirectURI, code, secrets)
	var oerr *OAuthError
	require.ErrorAs(t, err, &oerr)
	assert.Equal(t, "invalid_grant", oerr.Code)
	assert.Equal(t, http.StatusBadRequest, oerr.StatusCode)

	// a successful response that fails to decode doesn't put the token in the error
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte { return jsonMarshal(meta) })
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte {
		return []byte(`{"access_token":"eou-leaked","token_type":"Bearer","expires_in":"900"}`)
	})
	_, err = client.EndpointAuthToken(ctx, message.OAuthClientDNClient, redirectURI, code, secrets)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "eou-leaked")

	// list hosts (empty)
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte {
		return jsonMarshal(message.APIResponse[message.EndpointAuthHostsData]{Data: message.EndpointAuthHostsData{Hosts: []message.EndpointAuthHost{}}})
	})
	hosts, err := client.ListEndpointHosts(ctx, tok.AccessToken)
	require.NoError(t, err)
	assert.Empty(t, hosts.Hosts)

	// create a host
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte {
		return jsonMarshal(message.APIResponse[message.EndpointAuthEnrollData]{Data: message.EndpointAuthEnrollData{HostID: "host-1", EnrollmentCode: "code-new"}})
	})
	created, err := client.CreateEndpointHost(ctx, tok.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "host-1", created.HostID)
	assert.Equal(t, "code-new", created.EnrollmentCode)

	// renew the existing host: no enrollment code, just a fresh network-access window
	until := time.Now().Add(8 * time.Hour).UTC().Truncate(time.Second)
	ts.ExpectAPIRequest(http.StatusOK, func(any) []byte {
		return jsonMarshal(message.APIResponse[message.EndpointAuthRenewData]{Data: message.EndpointAuthRenewData{HostID: "host-1", NetworkAccessUntil: &until}})
	})
	renew, err := client.RenewEndpointHost(ctx, tok.AccessToken, "host-1")
	require.NoError(t, err)
	assert.Equal(t, "host-1", renew.HostID)
	require.NotNil(t, renew.NetworkAccessUntil)
	assert.True(t, until.Equal(*renew.NetworkAccessUntil))

	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
}

func TestDownloads(t *testing.T) {
	t.Parallel()

	useragent := "dnclientUnitTests/1.0.0 (not a real client)"
	ts := dnapitest.NewServer(useragent)
	client := NewClient(useragent, ts.URL)
	t.Cleanup(func() { ts.Close() })

	// Happy path - successful downloads response
	ts.ExpectAPIRequest(http.StatusOK, func(r any) []byte {
		return []byte(downloadsResponse)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	resp, err := client.Downloads(ctx)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	// Verify DNClient downloads - this list is not exhaustive but tests some of the more common platforms.
	require.NotNil(t, resp)
	require.Contains(t, resp.DNClient, "0.8.4")
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/freebsd/amd64/dnclient", resp.DNClient["0.8.4"]["freebsd-amd64"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/freebsd/arm64/dnclient", resp.DNClient["0.8.4"]["freebsd-arm64"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/linux/amd64/dnclient", resp.DNClient["0.8.4"]["linux-amd64"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/linux/arm64/dnclient", resp.DNClient["0.8.4"]["linux-arm64"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/windows/amd64/DNClient-Desktop.msi", resp.DNClient["0.8.4"]["windows-amd64-desktop"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/windows/amd64/DNClient-Server.msi", resp.DNClient["0.8.4"]["windows-amd64-server"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/windows/arm64/DNClient-Desktop.msi", resp.DNClient["0.8.4"]["windows-arm64-desktop"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/windows/arm64/DNClient-Server.msi", resp.DNClient["0.8.4"]["windows-arm64-server"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/macos/dnclient", resp.DNClient["0.8.4"]["macos-universal-server"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/macos/DNClient-Server.dmg", resp.DNClient["0.8.4"]["macos-universal-server-dmg"])
	assert.Equal(t, "https://dl.defined.net/290ff4b6/v0.8.4/macos/DNClient-Desktop.dmg", resp.DNClient["0.8.4"]["macos-universal-desktop"])

	// Verify the latest release info
	require.Contains(t, resp.DNClient, "latest")
	require.Equal(t, resp.DNClient["latest"], resp.DNClient["0.8.4"])

	// Verify mobile downloads
	assert.Equal(t, "https://play.google.com/store/apps/details?id=net.defined.mobile_nebula", resp.Mobile.Android)
	assert.Equal(t, "https://apps.apple.com/us/app/mobile-nebula/id1509587936", resp.Mobile.IOS)

	// Verify container downloads
	assert.Equal(t, "https://hub.docker.com/r/definednet/dnclient/", resp.Container.Docker)

	// Verify version info
	require.Contains(t, resp.VersionInfo.DNClient, "0.8.4")
	assert.True(t, resp.VersionInfo.DNClient["0.8.4"].Latest)
	assert.Equal(t, "2025-10-10", resp.VersionInfo.DNClient["0.8.4"].ReleaseDate)

	// Verify latest versions
	assert.Equal(t, "0.8.4", resp.VersionInfo.Latest.DNClient)
	assert.Equal(t, "0.5.1", resp.VersionInfo.Latest.Mobile)
}

func TestEnroll_PluralMeta(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	client := NewClient(useragent, ts.URL)
	t.Cleanup(func() { ts.Close() })

	code := "abcdef"
	orgID := "foobaz"
	orgName := "foobar's foo org"
	netID := "qux"
	netName := "the best network"
	netCIDRs := []string{"192.168.100.0/24", "10.0.0.0/16"}
	hostID := "foobar"
	hostName := "foo host"
	hostIPs := []string{"192.168.100.1", "10.0.0.1"}
	counter := uint(5)
	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			"pki": m{"ca": string(caPEM)},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      hostID,
				Counter:     counter,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   orgID,
					Name: orgName,
				},
				Network: message.HostNetworkMetadata{
					ID:    netID,
					Name:  netName,
					Curve: message.NetworkCurve25519,
					CIDRs: netCIDRs,
				},
				Host: message.HostHostMetadata{
					ID:          hostID,
					Name:        hostName,
					IPAddresses: hostIPs,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, _, meta, err := client.Enroll(ctx, testutil.NewTestLogger(), code, "")
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	// test meta
	assert.Equal(t, orgID, meta.Org.ID)
	assert.Equal(t, orgName, meta.Org.Name)
	assert.Equal(t, netID, meta.Network.ID)
	assert.Equal(t, netName, meta.Network.Name)
	assert.Equal(t, hostID, meta.Host.ID)
	assert.Equal(t, hostName, meta.Host.Name)
	assert.Equal(t, hostIPs, meta.Host.IPAddresses)
}

func TestDoUpdate_PluralMeta(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			"pki": m{"ca": string(caPEM)},
		})
		if err != nil {
			return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
				Errors: message.APIResponseErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Organization: message.HostOrgMetadata{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
				Network: message.HostNetworkMetadata{
					ID:    "qux",
					Name:  "the best network",
					Curve: message.NetworkCurve25519,
					CIDR:  "192.168.100.0/24",
				},
				Host: message.HostHostMetadata{
					ID:        "foobar",
					Name:      "foo host",
					IPAddress: "192.168.100.2",
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), code, "")
	require.NoError(t, err)

	orgID := "foobaz"
	orgName := "foobar's foo org"
	netID := "qux"
	netName := "the best network"
	netCIDRs := []string{"192.168.100.0/24", "10.0.0.0/16"}
	hostID := "foobar"
	hostName := "foo host"
	hostIPs := []string{"192.168.100.1", "10.0.0.1"}

	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     3,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: ca.MarshalPublicKeyPEM(),
			Organization: message.HostOrgMetadata{
				ID:   orgID,
				Name: orgName,
			},
			Network: message.HostNetworkMetadata{
				ID:    netID,
				Name:  netName,
				Curve: message.NetworkCurve25519,
				CIDRs: netCIDRs,
			},
			Host: message.HostHostMetadata{
				ID:          hostID,
				Name:        hostName,
				IPAddresses: hostIPs,
			},
		}
		rawRes := jsonMarshal(newConfigResponse)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: ed25519.Sign(caPrivkey, rawRes),
			},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, _, meta, err := c.DoUpdate(ctx, *creds)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	// test meta
	assert.Equal(t, orgID, meta.Org.ID)
	assert.Equal(t, orgName, meta.Org.Name)
	assert.Equal(t, netID, meta.Network.ID)
	assert.Equal(t, netName, meta.Network.Name)
	assert.Equal(t, hostID, meta.Host.ID)
	assert.Equal(t, hostName, meta.Host.Name)
	assert.Equal(t, hostIPs, meta.Host.IPAddresses)
}

func TestNebulaPemBanners(t *testing.T) {
	const NebulaECDSAP256PublicKeyBanner = "NEBULA ECDSA P256 PUBLIC KEY"
	const NebulaEd25519PublicKeyBanner = "NEBULA ED25519 PUBLIC KEY"
	ca, _ := dnapitest.NebulaCACert()
	pub := ca.MarshalPublicKeyPEM()
	assert.Contains(t, string(pub), NebulaEd25519PublicKeyBanner)

	ca, _ = dnapitest.NebulaCACertP256()
	pub = ca.MarshalPublicKeyPEM()
	assert.Contains(t, string(pub), NebulaECDSAP256PublicKeyBanner)
}

func TestUnenroll(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	ts.ExpectEnrollment("foobar", message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{"pki": m{"ca": string(caPEM)}})
		require.NoError(t, err)
		return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: ca.MarshalPublicKeyPEM(),
				Network:     message.HostNetworkMetadata{Curve: message.NetworkCurve25519},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
	require.NoError(t, err)

	caKey := keys.Ed25519PrivateKey{PrivateKey: caPrivkey}

	ts.ExpectDNClientRequest(message.Unenroll, http.StatusOK, func(r message.RequestWrapper) []byte {
		assert.JSONEq(t, "{}", string(r.Value))
		return signedResponseV2(t, caKey, r, creds.HostID, message.UnenrollResponse{HostID: creds.HostID})
	})
	require.NoError(t, c.Unenroll(ctx, *creds))

	_, otherPrivkey := dnapitest.NebulaCACert()
	for name, respond := range map[string]func(r message.RequestWrapper) []byte{
		"unsigned": func(message.RequestWrapper) []byte { return []byte(`{"data":{}}`) },
		"wrong signature": func(r message.RequestWrapper) []byte {
			return signedResponseV2(t, keys.Ed25519PrivateKey{PrivateKey: otherPrivkey}, r, creds.HostID, message.UnenrollResponse{HostID: creds.HostID})
		},
	} {
		ts.ExpectDNClientRequest(message.Unenroll, http.StatusOK, respond)
		assert.Error(t, c.Unenroll(ctx, *creds), name)
	}

	ts.ExpectDNClientRequest(message.Unenroll, http.StatusForbidden, func(r message.RequestWrapper) []byte {
		return jsonMarshal(message.APIResponse[struct{}]{
			Errors: message.APIResponseErrors{{
				Code:    "ERR_UNENROLL_NOT_EPHEMERAL",
				Message: "only hosts enrolled with an ephemeral join key can unenroll themselves",
			}},
		})
	})
	assert.ErrorIs(t, c.Unenroll(ctx, *creds), ErrNotEphemeral)

	ts.ExpectDNClientRequest(message.Unenroll, http.StatusForbidden, func(r message.RequestWrapper) []byte {
		return jsonMarshal(message.APIResponse[struct{}]{
			Errors: message.APIResponseErrors{
				{Code: "ERR_OTHER", Message: "something else"},
				{Code: "ERR_UNENROLL_NOT_EPHEMERAL", Message: "not ephemeral"},
			},
		})
	})
	assert.ErrorIs(t, c.Unenroll(ctx, *creds), ErrNotEphemeral)

	ts.ExpectDNClientRequest(message.Unenroll, http.StatusUnauthorized, func(r message.RequestWrapper) []byte {
		return []byte("Unauthorized")
	})
	assert.ErrorIs(t, c.Unenroll(ctx, *creds), ErrInvalidCredentials)

	ts.ExpectDNClientRequest(message.Unenroll, http.StatusInternalServerError, func(r message.RequestWrapper) []byte {
		return jsonMarshal(message.APIResponse[struct{}]{
			Errors: message.APIResponseErrors{{Code: "ERR_INTERNAL", Message: "boom"}},
		})
	})
	err = c.Unenroll(ctx, *creds)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotEphemeral)
	assert.NotErrorIs(t, err, ErrInvalidCredentials)

	// A proxy's JSON error page has no errors array and must not read as success.
	for _, body := range []string{`{"message":"Service Unavailable"}`, `{}`, `null`} {
		ts.ExpectDNClientRequest(message.Unenroll, http.StatusServiceUnavailable, func(r message.RequestWrapper) []byte {
			return []byte(body)
		})
		assert.Error(t, c.Unenroll(ctx, *creds), body)
	}

	// A proxy that redirects to a login page answers 200 without the API's body.
	for _, body := range []string{`<html>Sign in</html>`, `{}`} {
		ts.ExpectDNClientRequest(message.Unenroll, http.StatusOK, func(r message.RequestWrapper) []byte {
			return []byte(body)
		})
		assert.Error(t, c.Unenroll(ctx, *creds), body)
	}

	longBody := "<html>" + strings.Repeat("x", 1000) + "</html>"
	ts.ExpectDNClientRequest(message.Unenroll, http.StatusBadGateway, func(r message.RequestWrapper) []byte {
		return []byte(longBody)
	})
	err = c.Unenroll(ctx, *creds)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), longBody)
	assert.Contains(t, err.Error(), longBody[:maxErrorBodyLen]+"...")

	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
}

func TestTruncateBody(t *testing.T) {
	t.Parallel()

	exact := strings.Repeat("a", maxErrorBodyLen)
	assert.Equal(t, "", truncateBody(nil))
	assert.Equal(t, exact, truncateBody([]byte(exact)))
	assert.Equal(t, exact+"...", truncateBody([]byte(exact+"b")))
}

func TestNormalizeIssuer(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.defined.net":         "https://api.defined.net",
		"https://api.defined.net/":        "https://api.defined.net",
		"https://API.defined.net:443/":    "https://api.defined.net",
		"HTTPS://api.defined.net":         "https://api.defined.net",
		"https://api.defined.net:8443":    "https://api.defined.net:8443",
		"http://127.0.0.1:80":             "http://127.0.0.1",
		"http://127.0.0.1:9001/":          "http://127.0.0.1:9001",
		"http://[::1]:9001":               "http://[::1]:9001",
		"https://example.com/Tenant/":     "https://example.com/Tenant",
		"https://example.com/path/issuer": "https://example.com/path/issuer",
		"not a url/":                      "not a url",
	} {
		assert.Equal(t, want, normalizeIssuer(in), in)
	}
}

func TestSignedResponseV2(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		curve       message.NetworkCurve
		hostID      string
		canonicalID string
	}{
		{message.NetworkCurve25519, "host-YQ5WCXXPRTTXV2XDQZSKN5BWYQ", "host-YQ5WCXXPRTTXV2XDQZSKN5BWYQ"},
		{message.NetworkCurveP256, "host-YQ5WCXXPRTTXV2XDQZSKN5BWYQ", "host-YQ5WCXXPRTTXV2XDQZSKN5BWYQ"},
		// Hosts enrolled before prefixed IDs keep this spelling, which the API echoes as sent.
		{message.NetworkCurve25519, "3q2-7_7erb7v7q3e3q2-7w", "host-32W3537632W3537OVXPN5LN654"},
		{message.NetworkCurveP256, "3q2-7_7erb7v7q3e3q2-7w", "host-32W3537632W3537OVXPN5LN654"},
	} {
		curve := tt.curve
		t.Run(string(curve)+"/"+tt.hostID, func(t *testing.T) {
			t.Parallel()

			useragent := "testClient"
			ts := dnapitest.NewServer(useragent)
			t.Cleanup(func() { ts.Close() })

			var ca cert.Certificate
			var caKey keys.PrivateKey
			if curve == message.NetworkCurveP256 {
				var priv *ecdsa.PrivateKey
				ca, priv = dnapitest.NebulaCACertP256()
				caKey = keys.P256PrivateKey{PrivateKey: priv}
			} else {
				var priv ed25519.PrivateKey
				ca, priv = dnapitest.NebulaCACert()
				caKey = keys.Ed25519PrivateKey{PrivateKey: priv}
			}
			caPEM, err := ca.MarshalPEM()
			require.NoError(t, err)

			c := NewClient(useragent, ts.URL)
			ts.ExpectEnrollment("foobar", curve, func(req message.EnrollRequest) []byte {
				cfg, err := yaml.Marshal(m{"pki": m{"ca": string(caPEM)}})
				require.NoError(t, err)
				return jsonMarshal(message.APIResponse[message.EnrollResponseData]{
					Data: message.EnrollResponseData{
						HostID:      tt.hostID,
						Counter:     1,
						Config:      cfg,
						TrustedKeys: ca.MarshalPublicKeyPEM(),
						Network:     message.HostNetworkMetadata{Curve: curve},
					},
				})
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar", "")
			require.NoError(t, err)
			require.Equal(t, tt.hostID, creds.HostID)

			// Unsigned commands keep the version 1 request with no nonce.
			ts.ExpectDNClientRequest(message.CheckForUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
				assert.Nil(t, r.Nonce)
				return jsonMarshal(message.CheckForUpdateResponseWrapper{})
			})
			_, err = c.CheckForUpdate(ctx, *creds)
			require.NoError(t, err)

			ts.ExpectDNClientRequest(message.Reauthenticate, http.StatusOK, func(r message.RequestWrapper) []byte {
				assert.Len(t, r.Nonce, 16)
				return signedResponseV2(t, caKey, r, creds.HostID, message.ReauthenticateResponse{LoginURL: "https://example.com/login"})
			})
			reauth, err := c.Reauthenticate(ctx, *creds)
			require.NoError(t, err)
			assert.Equal(t, "https://example.com/login", reauth.LoginURL)

			ts.ExpectDNClientRequest(message.Unenroll, http.StatusOK, func(r message.RequestWrapper) []byte {
				assert.Len(t, r.Nonce, 16)
				// The API's value always carries the canonical spelling, even for a legacy ID.
				return signedResponseV2(t, caKey, r, creds.HostID, message.UnenrollResponse{HostID: tt.canonicalID})
			})
			require.NoError(t, c.Unenroll(ctx, *creds))

			// The inner nonce of DoUpdate and DoConfigUpdate is the request nonce.
			ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
				assert.Len(t, r.Nonce, 16)
				assert.Equal(t, r.Nonce, dnapitest.GetNonce(r))
				return signedResponseV2(t, caKey, r, creds.HostID, message.DoUpdateResponse{
					Config:      dnapitest.NebulaCfg(caPEM),
					Network:     message.HostNetworkMetadata{Curve: curve},
					Counter:     2,
					Nonce:       dnapitest.GetNonce(r),
					TrustedKeys: ca.MarshalPublicKeyPEM(),
				})
			})
			var meta *ConfigMeta
			_, _, creds, meta, err = c.DoUpdate(ctx, *creds)
			require.NoError(t, err)
			assert.EqualValues(t, 2, creds.Counter)
			// TestDoUpdate covers an ephemeral host; this one is not.
			assert.False(t, meta.Host.Ephemeral)

			ts.ExpectDNClientRequest(message.DoConfigUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
				assert.Len(t, r.Nonce, 16)
				assert.Equal(t, r.Nonce, dnapitest.GetNonce(r))
				return signedResponseV2(t, caKey, r, creds.HostID, message.DoConfigUpdateResponse{
					Config:      dnapitest.NebulaCfg(caPEM),
					Network:     message.HostNetworkMetadata{Curve: curve},
					Counter:     3,
					Nonce:       dnapitest.GetNonce(r),
					TrustedKeys: ca.MarshalPublicKeyPEM(),
				})
			})
			_, creds, _, err = c.DoConfigUpdate(ctx, *creds)
			require.NoError(t, err)
			assert.EqualValues(t, 3, creds.Counter)

			// The outer version is unsigned, so a genuine version 2 response can be relabeled version 1.
			ts.ExpectDNClientRequest(message.Reauthenticate, http.StatusOK, func(r message.RequestWrapper) []byte {
				return signResponse(t, caKey, 1, jsonMarshal(message.SignedResponseEnvelope{
					Version: 2,
					Nonce:   r.Nonce,
					HostID:  creds.HostID,
					Type:    r.Type,
					Value:   jsonMarshal(message.ReauthenticateResponse{LoginURL: "https://example.com/login"}),
				}))
			})
			_, err = c.Reauthenticate(ctx, *creds)
			assert.EqualError(t, err, "version 1 signed response carries a version 2 envelope")

			// Each negative case changes one thing in an otherwise valid, correctly signed response.
			envelope := func(r message.RequestWrapper) message.SignedResponseEnvelope {
				return message.SignedResponseEnvelope{
					Version: 2,
					Nonce:   r.Nonce,
					HostID:  creds.HostID,
					Type:    r.Type,
					Value:   jsonMarshal(message.UnenrollResponse{HostID: creds.HostID}),
				}
			}
			withoutField := func(field string) func(r message.RequestWrapper) []byte {
				return func(r message.RequestWrapper) []byte {
					var fields map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(jsonMarshal(envelope(r)), &fields))
					require.Contains(t, fields, field)
					delete(fields, field)
					return signResponse(t, caKey, 2, jsonMarshal(fields))
				}
			}
			for _, tc := range []struct {
				name    string
				respond func(r message.RequestWrapper) []byte
				wantErr string
			}{
				{"valid", func(r message.RequestWrapper) []byte {
					return signResponse(t, caKey, 2, jsonMarshal(envelope(r)))
				}, ""},
				{"wrong nonce", func(r message.RequestWrapper) []byte {
					env := envelope(r)
					env.Nonce = nonce()
					return signResponse(t, caKey, 2, jsonMarshal(env))
				}, "nonce does not match"},
				// Another host on the network can obtain a response signed by the same CA.
				{"wrong host", func(r message.RequestWrapper) []byte {
					env := envelope(r)
					env.HostID = "otherhost"
					return signResponse(t, caKey, 2, jsonMarshal(env))
				}, `is for host "otherhost"`},
				{"wrong type", func(r message.RequestWrapper) []byte {
					env := envelope(r)
					env.Type = message.Reauthenticate
					return signResponse(t, caKey, 2, jsonMarshal(env))
				}, "is for a Reauthenticate request"},
				{"envelope version mismatch", func(r message.RequestWrapper) []byte {
					env := envelope(r)
					env.Version = 3
					return signResponse(t, caKey, 2, jsonMarshal(env))
				}, "envelope version 3"},
				{"unknown outer version", func(r message.RequestWrapper) []byte {
					return signResponse(t, caKey, 3, jsonMarshal(envelope(r)))
				}, "unsupported signed response version 3"},
				{"version 1 unenroll", func(r message.RequestWrapper) []byte {
					return signResponse(t, caKey, 1, jsonMarshal(message.UnenrollResponse{HostID: creds.HostID}))
				}, "requires a version 2 signed response"},
				{"missing nonce", withoutField("nonce"), "missing a field"},
				{"missing hostID", withoutField("hostID"), "missing a field"},
				{"missing type", withoutField("type"), "missing a field"},
				{"missing value", withoutField("value"), "missing a field"},
			} {
				ts.ExpectDNClientRequest(message.Unenroll, http.StatusOK, tc.respond)
				err := c.Unenroll(ctx, *creds)
				if tc.wantErr == "" {
					assert.NoError(t, err, tc.name)
				} else {
					assert.ErrorContains(t, err, tc.wantErr, tc.name)
				}
			}

			// Run last: the mock server adopts the new key of a DoUpdate it answers, even a rejected one.
			ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
				return signResponse(t, caKey, 1, jsonMarshal(message.SignedResponseEnvelope{
					Version: 2,
					Nonce:   r.Nonce,
					HostID:  creds.HostID,
					Type:    r.Type,
					Value: jsonMarshal(message.DoUpdateResponse{
						Config:      dnapitest.NebulaCfg(caPEM),
						Counter:     4,
						Nonce:       r.Nonce,
						TrustedKeys: ca.MarshalPublicKeyPEM(),
					}),
				}))
			})
			_, _, _, _, err = c.DoUpdate(ctx, *creds)
			// Only failures to make the call carry the API call prefix.
			assert.EqualError(t, err, "version 1 signed response carries a version 2 envelope")

			ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, nil)
			_, _, _, _, err = c.DoUpdate(ctx, *creds)
			assert.ErrorIs(t, err, ErrInvalidCredentials)
			assert.ErrorContains(t, err, "failed to make API call to Defined Networking: ")
			assert.Len(t, ts.Errors(), 1, "the old key is now rejected")

			assert.Empty(t, ts.Errors())
			assert.Equal(t, 0, ts.RequestsRemaining())
		})
	}
}

// TestSignRequestNonce pins the request wrapper's nonce key, which the API reads by name, and keeps
// it out of SignRequestV1 requests, whose callers parse version 1 responses themselves.
func TestSignRequestNonce(t *testing.T) {
	t.Parallel()

	k, err := keys.New()
	require.NoError(t, err)

	wrapperFields := func(body []byte) map[string]json.RawMessage {
		var req message.RequestV1
		require.NoError(t, json.Unmarshal(body, &req))
		raw, err := base64.StdEncoding.DecodeString(req.Message)
		require.NoError(t, err)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &fields))
		return fields
	}

	body, err := signRequest(message.Unenroll, []byte("{}"), []byte{1, 2, 3}, "host-1", 1, k.HostEd25519PrivateKey)
	require.NoError(t, err)
	assert.JSONEq(t, `"AQID"`, string(wrapperFields(body)["nonce"]))

	body, err = SignRequestV1(message.Unenroll, []byte("{}"), "host-1", 1, k.HostEd25519PrivateKey)
	require.NoError(t, err)
	assert.NotContains(t, wrapperFields(body), "nonce")
}
