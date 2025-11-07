package dnapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi/dnapitest"
	"github.com/DefinedNet/dnapi/internal/testutil"
	"github.com/DefinedNet/dnapi/keys"
	"github.com/DefinedNet/dnapi/message"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

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
	counter := uint(5)
	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
	require.NoError(t, err)

	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.NebulaPubkeyX25519},
		})
		if err != nil {
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.EnrollResponse{
			Data: message.EnrollResponseData{
				HostID:      hostID,
				Counter:     counter,
				Config:      cfg,
				TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
				},
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email: &oidcEmail,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, creds, meta, err := client.Enroll(ctx, testutil.NewTestLogger(), code)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	tk, err := keys.NewTrustedKey(ed25519.PublicKey(ca.Details.PublicKey))
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
		} `yaml:"test"`
	}
	err = yaml.Unmarshal(cfg, &y)
	require.NoError(t, err)
	_, rest, err := cert.UnmarshalX25519PublicKey(y.Test.DHPubkey)
	assert.NoError(t, err)
	assert.Len(t, rest, 0)
	assert.Equal(t, code, y.Test.Code)

	// ensure private key was not inserted into config
	assert.Empty(t, y.PKI.Key)

	// test meta
	assert.Equal(t, orgID, meta.Org.ID)
	assert.Equal(t, orgName, meta.Org.Name)
	assert.Equal(t, netID, meta.Network.ID)
	assert.Equal(t, netName, meta.Network.Name)
	assert.Equal(t, hostID, meta.Host.ID)
	assert.Equal(t, hostName, meta.Host.Name)
	assert.Equal(t, hostIP, meta.Host.IPAddress)
	assert.Equal(t, hostIP, meta.Host.IPAddress)

	// Test error handling
	errorMsg := "invalid enrollment code"
	ts.ExpectEnrollment(code, message.NetworkCurve25519, func(req message.EnrollRequest) []byte {
		return jsonMarshal(message.EnrollResponse{
			Errors: message.APIErrors{{
				Code:    "ERR_INVALID_ENROLLMENT_CODE",
				Message: errorMsg,
			}},
		})
	})

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, creds, meta, err = client.Enroll(ctx, testutil.NewTestLogger(), code)
	require.Errorf(t, err, fmt.Sprintf("unexpected error during enrollment: %s", errorMsg))

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
	oidcEmail := "demo@defined.net"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.EnrollResponse{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email: &oidcEmail,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar")
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
			TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
			EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
				Email: &oidcEmail,
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
	require.Error(t, err)
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
			TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
			EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
				Email: &oidcEmail,
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

	// This time sign the response with the correct CA key.
	ts.ExpectDNClientRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:      dnapitest.NebulaCfg(caPEM),
			Counter:     3,
			Nonce:       dnapitest.GetNonce(r),
			TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
			},
			EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
				Email: &oidcEmail,
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
	assert.Equal(t, hostIP, meta.Host.IPAddress)

}

func TestDoUpdate_P256(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	oidcEmail := "demo@defined.net"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACertP256()
	caPEM, err := ca.MarshalToPEM()
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.EnrollResponse{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email: &oidcEmail,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar")
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
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
	require.Error(t, err)
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
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
			TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
			EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
				Email: &oidcEmail,
			},
		}
		rawRes := jsonMarshal(newConfigResponse)
		hashed := sha256.Sum256(rawRes)
		sig, err := ecdsa.SignASN1(rand.Reader, caPrivkey, hashed[:])
		if err != nil {
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
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
	oidcEmail := "demo@defined.net"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.EnrollResponse{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email: &oidcEmail,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar")
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
		return jsonMarshal(message.EnrollResponse{
			Errors: message.APIErrors{{
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
	oidcEmail := "demo@defined.net"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.EnrollResponse{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email: &oidcEmail,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar")
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
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(io.MultiWriter(sc, &buf))
	logger.SetLevel(logrus.DebugLevel)

	logger.Info("Hello, world! info!")
	logger.Warn("Hello, world! warning!")

	err = sc.Close()
	require.NoError(t, err)
	require.NoError(t, sc.Err())

	require.Equal(t, buf.Bytes(), ts.LastStreamedBody())

	// Test error handling
	errorMsg := "sample error"
	ts.ExpectStreamingRequest(message.CommandResponse, http.StatusBadRequest, func(r message.RequestWrapper) []byte {
		return jsonMarshal(message.EnrollResponse{
			Errors: message.APIErrors{{
				Code:    "ERR_INVALID_VALUE",
				Message: errorMsg,
			}},
		})
	})

	buf.Reset()

	sc, err = c.StreamCommandResponse(context.Background(), *creds, "responseToken")
	require.NoError(t, err)

	logger.SetOutput(io.MultiWriter(sc, &buf))

	logger.Info("Hello, world! info!")
	logger.Warn("Hello, world! warning!")

	// Close shouldn't return an error - that's only if the writer fails to close
	assert.NoError(t, sc.Close())
	// Err should return the error from the server
	assert.Error(t, sc.Err())

	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining(), ts.ExpectedRequests())
}

func TestReauthenticate(t *testing.T) {
	t.Parallel()

	useragent := "testClient"
	oidcEmail := "demo@defined.net"
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
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
			return jsonMarshal(message.EnrollResponse{
				Errors: message.APIErrors{{
					Code:    "ERR_FAILED_TO_MARSHAL_YAML",
					Message: "failed to marshal test response config",
				}},
			})
		}

		return jsonMarshal(message.EnrollResponse{
			Data: message.EnrollResponseData{
				HostID:      "foobar",
				Counter:     1,
				Config:      cfg,
				TrustedKeys: marshalCAPublicKey(ca.Details.Curve, ca.Details.PublicKey),
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
				EndpointOIDCMeta: &message.HostEndpointOIDCMetadata{
					Email: &oidcEmail,
				},
			},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar")
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
	_, _, _, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "ABC123")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func marshalCAPublicKey(curve cert.Curve, pubkey []byte) []byte {
	switch curve {
	case cert.Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: keys.NebulaEd25519PublicKeyBanner, Bytes: pubkey})
	case cert.Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: keys.NebulaECDSAP256PublicKeyBanner, Bytes: pubkey})
	default:
		panic("unsupported curve")
	}
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
		return jsonMarshal(message.PreAuthResponse{Data: message.PreAuthData{PollToken: expectedCode, LoginURL: "https://example.com"}})
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
	ts.ExpectAPIRequest(http.StatusBadGateway, func(req any) []byte {
		return jsonMarshal(message.PreAuthResponse{Data: message.PreAuthData{PollToken: expectedCode, LoginURL: "https://example.com"}})
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
		return jsonMarshal(message.EndpointAuthPollResponse{Data: message.EndpointAuthPollData{
			Status:         message.EndpointAuthStarted,
			EnrollmentCode: "",
		}})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	resp, err := client.EndpointAuthPoll(ctx, expectedCode)
	require.NoError(t, err)
	assert.Equal(t, resp.Status, message.EndpointAuthStarted)
	assert.Equal(t, resp.EnrollmentCode, "")
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
		return jsonMarshal(message.EndpointAuthPollResponse{Data: message.EndpointAuthPollData{
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
