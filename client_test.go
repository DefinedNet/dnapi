package dnapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DefinedNet/dnapi/dnapitest"
	"github.com/DefinedNet/dnapi/internal/testutil"
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

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, creds, meta, err := client.Enroll(ctx, testutil.NewTestLogger(), code)
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

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	config, pkey, creds, _, err := c.Enroll(ctx, testutil.NewTestLogger(), "foobar")
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
	ts.ExpectRequest(message.CheckForUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
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

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = c.CheckForUpdate(ctx, invalidCreds)
	assert.Error(t, err)
	invalidCredsErrorType := InvalidCredentialsError{}
	assert.ErrorAs(t, err, &invalidCredsErrorType)
	serverErrs := ts.Errors() // This consumes/resets the server errors
	require.Len(t, serverErrs, 1)

	// Invalid signature
	ts.ExpectRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
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

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, newCreds, err := c.DoUpdate(ctx, *creds)
	require.Error(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// Invalid counter
	ts.ExpectRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
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

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	cfg, pkey, newCreds, err = c.DoUpdate(ctx, *creds)
	require.Error(t, err)
	assert.Empty(t, ts.Errors())
	assert.Equal(t, 0, ts.RequestsRemaining())
	require.Nil(t, newCreds)
	require.Nil(t, cfg)
	require.Nil(t, pkey)

	// This time sign the response with the correct CA key.
	ts.ExpectRequest(message.DoUpdate, http.StatusOK, func(r message.RequestWrapper) []byte {
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

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _, _, err = c.DoUpdate(ctx, *creds)
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
	ts.ExpectRequest(message.CommandResponse, http.StatusOK, func(r message.RequestWrapper) []byte {
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
	ts.ExpectRequest(message.CommandResponse, http.StatusBadRequest, func(r message.RequestWrapper) []byte {
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
	ts := dnapitest.NewServer(useragent)
	t.Cleanup(func() { ts.Close() })

	ca, _ := dnapitest.NebulaCACert()
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
