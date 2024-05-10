// Package dnapi handles communication with the Defined Networking cloud API server.
package dnapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/DefinedNet/dnapi/message"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
)

// Client communicates with the API server.
type Client struct {
	http     *http.Client
	dnServer string
}

// NewClient returns new Client configured with the given useragent.
// It also supports reading Proxy information from the environment.
func NewClient(useragent string, dnServer string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: 1 * time.Minute,
			Transport: &uaTransport{
				T: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
				},
				useragent: useragent,
			},
		},
		dnServer: dnServer,
	}
}

// APIError contains an error, and a hidden wrapped error that contains the RequestID
// contained in the X-Request-ID header of an API response. Defaults to empty string
// if the header is not in the response.
type APIError struct {
	e     error
	ReqID string
}

func (e *APIError) Error() string {
	return e.e.Error()
}

func (e *APIError) Unwrap() error {
	return e.e
}

type InvalidCredentialsError struct{}

func (e InvalidCredentialsError) Error() string {
	return "invalid credentials"
}

type EnrollMeta struct {
	OrganizationID   string
	OrganizationName string
}

func (c *Client) EnrollWithTimeout(ctx context.Context, t time.Duration, logger logrus.FieldLogger, code string) ([]byte, []byte, *Credentials, *EnrollMeta, error) {
	toCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	return c.Enroll(toCtx, logger, code)
}

// Enroll issues an enrollment request against the REST API using the given enrollment code, passing along a locally
// generated DH X25519 public key to be signed by the CA, and an Ed 25519 public key for future API call authentication.
// On success it returns the Nebula config generated by the server, a Nebula private key PEM to be inserted into the
// config (see api.InsertConfigPrivateKey), credentials to be used in DNClient API requests, and a meta object
// containing organization info.
func (c *Client) Enroll(ctx context.Context, logger logrus.FieldLogger, code string) ([]byte, []byte, *Credentials, *EnrollMeta, error) {
	logger.WithFields(logrus.Fields{"server": c.dnServer}).Debug("Making enrollment request to API")

	// Generate initial Ed25519 keypair for API communication
	dhPubkeyPEM, dhPrivkeyPEM, edPubkey, edPrivkey, err := newKeys()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Make a request to the API with the enrollment code
	jv, err := json.Marshal(message.EnrollRequest{
		Code:      code,
		DHPubkey:  dhPubkeyPEM,
		EdPubkey:  cert.MarshalEd25519PublicKey(edPubkey),
		Timestamp: time.Now(),
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.dnServer+message.EnrollEndpoint, bytes.NewBuffer(jv))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer resp.Body.Close()

	// Log the request ID returned from the server
	reqID := resp.Header.Get("X-Request-ID")
	logger.WithFields(logrus.Fields{"reqID": reqID}).Info("Enrollment request complete")

	// Decode the response
	r := message.EnrollResponse{}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, nil, &APIError{e: fmt.Errorf("error reading response body: %s", err), ReqID: reqID}
	}

	if err := json.Unmarshal(b, &r); err != nil {
		return nil, nil, nil, nil, &APIError{e: fmt.Errorf("error decoding JSON response: %s\nbody: %s", err, b), ReqID: reqID}
	}

	// Check for any errors returned by the API
	if err := r.Errors.ToError(); err != nil {
		return nil, nil, nil, nil, &APIError{e: fmt.Errorf("unexpected error during enrollment: %v", err), ReqID: reqID}
	}

	meta := &EnrollMeta{
		OrganizationID:   r.Data.Organization.ID,
		OrganizationName: r.Data.Organization.Name,
	}

	trustedKeys, err := Ed25519PublicKeysFromPEM(r.Data.TrustedKeys)
	if err != nil {
		return nil, nil, nil, nil, &APIError{e: fmt.Errorf("failed to load trusted keys from bundle: %s", err), ReqID: reqID}
	}

	creds := &Credentials{
		HostID:      r.Data.HostID,
		PrivateKey:  edPrivkey,
		Counter:     r.Data.Counter,
		TrustedKeys: trustedKeys,
	}
	return r.Data.Config, dhPrivkeyPEM, creds, meta, nil
}

func (c *Client) CheckForUpdateWithTimeout(ctx context.Context, t time.Duration, creds Credentials) (bool, error) {
	toCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	return c.CheckForUpdate(toCtx, creds)
}

// CheckForUpdate sends a signed message to the DNClient API to learn if there is a new configuration available.
func (c *Client) CheckForUpdate(ctx context.Context, creds Credentials) (bool, error) {
	respBody, err := c.postDNClient(ctx, message.CheckForUpdate, nil, creds.HostID, creds.Counter, creds.PrivateKey)
	if err != nil {
		return false, fmt.Errorf("failed to post message to dnclient api: %w", err)
	}
	result := message.CheckForUpdateResponseWrapper{}
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		return false, fmt.Errorf("failed to interpret API response: %s", err)
	}
	return result.Data.UpdateAvailable, nil
}

// LongPollWait sends a signed message to a DNClient API endpoint that will block, returning only
// if there is an action the client should take before the timeout (config updates, debug commands)
func (c *Client) LongPollWait(ctx context.Context, creds Credentials, supportedActions []string, clientInfo message.ClientInfo) (string, error) {
	value, err := json.Marshal(message.LongPollWaitRequest{
		Client:           clientInfo,
		SupportedActions: supportedActions,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal DNClient message: %s", err)
	}

	respBody, err := c.postDNClient(ctx, message.LongPollWait, value, creds.HostID, creds.Counter, creds.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to post message to dnclient api: %w", err)
	}
	result := message.LongPollWaitResponseWrapper{}
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		return "", fmt.Errorf("failed to interpret API response: %s", err)
	}
	return result.Data.Action, nil
}

func (c *Client) DoUpdateWithTimeout(ctx context.Context, t time.Duration, creds Credentials) ([]byte, []byte, *Credentials, error) {
	toCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	return c.DoUpdate(toCtx, creds)
}

// DoUpdate sends a signed message to the DNClient API to fetch the new configuration update. During this call a new
// DH X25519 keypair is generated for the new Nebula certificate as well as a new Ed25519 keypair for DNClient API
// communication. On success it returns the new config, a Nebula private key PEM to be inserted into the config (see
// api.InsertConfigPrivateKey) and new DNClient API credentials.
func (c *Client) DoUpdate(ctx context.Context, creds Credentials) ([]byte, []byte, *Credentials, error) {
	// Rotate keys
	dhPubkeyPEM, dhPrivkeyPEM, edPubkey, edPrivkey, err := newKeys()
	if err != nil {
		return nil, nil, nil, err
	}

	updateKeys := message.DoUpdateRequest{
		EdPubkeyPEM: cert.MarshalEd25519PublicKey(edPubkey),
		DHPubkeyPEM: dhPubkeyPEM,
		Nonce:       nonce(),
	}

	updateKeysBlob, err := json.Marshal(updateKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal DNClient message: %s", err)
	}

	// Make API call
	resp, err := c.postDNClient(ctx, message.DoUpdate, updateKeysBlob, creds.HostID, creds.Counter, creds.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to make API call to Defined Networking: %w", err)
	}
	resultWrapper := message.SignedResponseWrapper{}
	err = json.Unmarshal(resp, &resultWrapper)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal signed response wrapper: %s", err)
	}

	// Verify the signature
	valid := false
	for _, caPubkey := range creds.TrustedKeys {
		if ed25519.Verify(caPubkey, resultWrapper.Data.Message, resultWrapper.Data.Signature) {
			valid = true
			break
		}
	}
	if !valid {
		return nil, nil, nil, fmt.Errorf("failed to verify signed API result")
	}

	// Consume the verified message
	result := message.DoUpdateResponse{}
	err = json.Unmarshal(resultWrapper.Data.Message, &result)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal response (%s): %s", resultWrapper.Data.Message, err)
	}

	// Verify the nonce
	if !bytes.Equal(result.Nonce, updateKeys.Nonce) {
		return nil, nil, nil, fmt.Errorf("nonce mismatch between request (%s) and response (%s)", updateKeys.Nonce, result.Nonce)
	}

	// Verify the counter
	if result.Counter <= creds.Counter {
		return nil, nil, nil, fmt.Errorf("counter in request (%d) should be less than counter in response (%d)", creds.Counter, result.Counter)
	}

	trustedKeys, err := Ed25519PublicKeysFromPEM(result.TrustedKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load trusted keys from bundle: %s", err)
	}

	newCreds := &Credentials{
		HostID:      creds.HostID,
		Counter:     result.Counter,
		PrivateKey:  edPrivkey,
		TrustedKeys: trustedKeys,
	}

	return result.Config, dhPrivkeyPEM, newCreds, nil
}

// postDNClient wraps and signs the given dnclientRequestWrapper message, and makes the API call.
// On success, it returns the response message body. On error, the error is returned.
func (c *Client) postDNClient(ctx context.Context, reqType string, value []byte, hostID string, counter uint, privkey ed25519.PrivateKey) ([]byte, error) {
	encMsg, err := json.Marshal(message.RequestWrapper{
		Type:      reqType,
		Value:     value,
		Timestamp: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	signedMsg := base64.StdEncoding.EncodeToString(encMsg)
	sig := ed25519.Sign(privkey, []byte(signedMsg))
	body := message.RequestV1{
		Version:   1,
		HostID:    hostID,
		Counter:   counter,
		Message:   signedMsg,
		Signature: sig,
	}
	postBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.dnServer+message.EndpointV1, bytes.NewReader(postBody))
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call dnclient endpoint: %s", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body: %s", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return respBody, nil
	case http.StatusUnauthorized:
		return nil, InvalidCredentialsError{}
	default:
		var errors struct {
			Errors message.APIErrors
		}
		if err := json.Unmarshal(respBody, &errors); err != nil {
			return nil, fmt.Errorf("dnclient endpoint returned bad status code '%d', body: %s", resp.StatusCode, respBody)
		}
		return nil, errors.Errors.ToError()
	}
}

type uaTransport struct {
	useragent string
	T         http.RoundTripper
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.useragent)
	return t.T.RoundTrip(req)
}
