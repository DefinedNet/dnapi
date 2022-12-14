package dnapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi/dnapitest"
	"github.com/DefinedNet/dnapi/internal/testutil"
	"github.com/DefinedNet/dnapi/message"
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
	hostID := "foobar"
	orgID := "foobaz"
	orgName := "foobar's foo org"
	counter := uint(5)
	ca, _ := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
	require.NoError(t, err)

	ts.ExpectEnrollment(code, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.DHPubkey},
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
				TrustedKeys: cert.MarshalEd25519PublicKey(ca.Details.PublicKey),
				Organization: message.EnrollResponseDataOrg{
					ID:   orgID,
					Name: orgName,
				},
			},
		})
	})

	cfg, pkey, creds, meta, err := client.EnrollWithTimeout(context.Background(), 1*time.Second, testutil.NewTestLogger(), code)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

	assert.Equal(t, hostID, creds.HostID)
	assert.Equal(t, counter, creds.Counter)
	assert.Equal(t, []ed25519.PublicKey{ca.Details.PublicKey}, creds.TrustedKeys)
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
	assert.Equal(t, orgID, meta.OrganizationID)
	assert.Equal(t, orgName, meta.OrganizationName)

	// Test error handling
	errorMsg := "invalid enrollment code"
	ts.ExpectEnrollment(code, func(req message.EnrollRequest) []byte {
		return jsonMarshal(message.EnrollResponse{
			Errors: message.APIErrors{{
				Code:    "ERR_INVALID_ENROLLMENT_CODE",
				Message: errorMsg,
			}},
		})
	})

	cfg, pkey, creds, meta, err = client.EnrollWithTimeout(context.Background(), 1*time.Second, testutil.NewTestLogger(), code)
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
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, caPrivkey := dnapitest.NebulaCACert()
	caPEM, err := ca.MarshalToPEM()
	require.NoError(t, err)

	c := NewClient(useragent, ts.URL)

	code := "foobar"
	ts.ExpectEnrollment(code, func(req message.EnrollRequest) []byte {
		cfg, err := yaml.Marshal(m{
			// we need to send this or we'll get an error from the api client
			"pki": m{"ca": string(caPEM)},
			// here we reflect values back to the client for test purposes
			"test": m{"code": req.Code, "dhPubkey": req.DHPubkey},
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
				TrustedKeys: cert.MarshalEd25519PublicKey(ca.Details.PublicKey),
				Organization: message.EnrollResponseDataOrg{
					ID:   "foobaz",
					Name: "foobar's foo org",
				},
			},
		})
	})

	config, pkey, creds, _, err := c.EnrollWithTimeout(context.Background(), 1*time.Second, testutil.NewTestLogger(), "foobar")
	require.NoError(t, err)

	pubkey := cert.MarshalEd25519PublicKey(creds.PrivateKey.Public().(ed25519.PublicKey))

	// make sure all credential values were set
	assert.NotEmpty(t, creds.HostID)
	assert.NotEmpty(t, creds.PrivateKey)
	assert.NotEmpty(t, creds.TrustedKeys)
	assert.NotEmpty(t, creds.Counter)

	// make sure we got a config back
	assert.NotEmpty(t, config)
	assert.NotEmpty(t, pkey)

	// Invalid request signature should return a specific error
	ts.ExpectRequest(message.CheckForUpdate, func(r message.RequestWrapper) []byte {
		return []byte("")
	})

	// Create a new, invalid requesting authentication key
	_, invalidPrivKey, err := newEdKeypair()
	require.NoError(t, err)
	invalidCreds := Credentials{
		HostID:      creds.HostID,
		PrivateKey:  invalidPrivKey,
		Counter:     creds.Counter,
		TrustedKeys: creds.TrustedKeys,
	}
	_, err = c.CheckForUpdateWithTimeout(context.Background(), 1*time.Second, invalidCreds)
	assert.Error(t, err)
	invalidCredsErrorType := InvalidCredentialsError{}
	assert.ErrorAs(t, err, &invalidCredsErrorType)
	serverErrs := ts.Errors() // This consumes/resets the server errors
	require.Len(t, serverErrs, 1)

	// Invalid signature
	ts.ExpectRequest(message.DoUpdate, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:  dnapitest.NebulaCfg(caPEM),
			Counter: 2,
			Nonce:   dnapitest.GetNonce(r),
		}
		rawRes := jsonMarshal(newConfigResponse)

		_, newPrivkey, err := newEdKeypair()
		require.NoError(t, err)

		// XXX the mock server will update the ed pubkey for us, but this is problematic because
		// we are rejecting the update. reset the key
		err = ts.SetEdPubkey(pubkey)
		require.NoError(t, err)

		return jsonMarshal(message.SignedResponseWrapper{
			Data: message.SignedResponse{
				Version:   1,
				Message:   rawRes,
				Signature: ed25519.Sign(newPrivkey, rawRes),
			},
		})
	})
	cfg, pkey, newCreds, err := c.DoUpdateWithTimeout(context.Background(), 1*time.Second, *creds)
	require.Error(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// Invalid counter
	ts.ExpectRequest(message.DoUpdate, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:  dnapitest.NebulaCfg(caPEM),
			Counter: 0,
			Nonce:   dnapitest.GetNonce(r),
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
	cfg, pkey, newCreds, err = c.DoUpdateWithTimeout(context.Background(), 1*time.Second, *creds)
	require.Error(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// This time sign the response with the correct CA key.
	ts.ExpectRequest(message.DoUpdate, func(r message.RequestWrapper) []byte {
		newConfigResponse := message.DoUpdateResponse{
			Config:  dnapitest.NebulaCfg(caPEM),
			Counter: 3,
			Nonce:   dnapitest.GetNonce(r),
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

	_, _, _, err = c.DoUpdateWithTimeout(context.Background(), 1*time.Second, *creds)
	require.NoError(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())

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
	// The default timeout is 1 minute. Assert the default value.
	assert.Equal(t, c.http.Timeout, time.Minute)
	// Overwrite the default value with a 10 millisecond timeout for test brevity.
	c.http.Timeout = 10 * time.Millisecond
	// DO IT
	_, err := c.http.Get(ts.URL + "/lol")
	require.Error(t, err)
}

func TestRequestTimeout(t *testing.T) {
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(250 * time.Millisecond)
			fmt.Fprintln(w, "OK")
		}))
	defer ts.Close()

	useragent := "TestTimeout agent"
	c := NewClient(useragent, ts.URL)
	// DO IT
	_, _, _, _, err := c.EnrollWithTimeout(context.Background(), 1*time.Millisecond, testutil.NewTestLogger(), "ABC123")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
