package dnapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

// ErrEndpointAuthStateMismatch is returned by EndpointAuthSecrets.ParseCallback when a request to the
// redirect URI does not carry this login's state. Such a request did not come from this auth (it
// may be forged, e.g. a web page trying to inject someone else's code) and should be ignored while
// continuing to wait for the real one.
var ErrEndpointAuthStateMismatch = errors.New("endpoint auth callback state does not match")

// ErrEndpointAuthIssuerMismatch is returned by EndpointAuthSecrets.ParseCallback when the
// authorization response names a different authorization server than the one the login was started
// with (RFC 9207), or none.
var ErrEndpointAuthIssuerMismatch = errors.New("endpoint auth callback issuer does not match")

// EndpointAuthCallbackError is returned by EndpointAuthSecrets.ParseCallback when the authorization
// response reports that the login failed. Code is the API error code (e.g. ERR_OIDC_MISSING_CLAIMS)
// when the server gave one, or else the OAuth error code (e.g. access_denied). Description is the
// server's human-readable explanation, if any.
type EndpointAuthCallbackError struct {
	Code        string
	Description string
}

func (e *EndpointAuthCallbackError) Error() string {
	return fmt.Sprintf("endpoint auth failed: %s", e.Code)
}

// EndpointAuthSecrets holds the per-login secrets of an endpoint SSO login: the PKCE code verifier
// and its S256 challenge (RFC 7636), and the state value that ties the browser's redirect back to
// this login. Create a fresh set for every login with NewEndpointAuthSecrets and keep it in memory
// only.
type EndpointAuthSecrets struct {
	CodeVerifier  string
	CodeChallenge string
	State         string
}

// NewEndpointAuthSecrets generates a fresh set of secrets for an endpoint SSO login.
func NewEndpointAuthSecrets() (*EndpointAuthSecrets, error) {
	verifier, err := randomURLString()
	if err != nil {
		return nil, err
	}
	state, err := randomURLString()
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256([]byte(verifier))
	return &EndpointAuthSecrets{
		CodeVerifier:  verifier,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		State:         state,
	}, nil
}

// ParseCallback validates the authorization response, the query string of a request to the
// redirect URI, and returns the authorization code to pass to EndpointAuthToken. issuer is the
// authorization server the login was started with (Client.OAuthIssuer). It returns
// ErrEndpointAuthStateMismatch if the request does not belong to this login,
// ErrEndpointAuthIssuerMismatch if it names another authorization server, an
// *EndpointAuthCallbackError if the login failed, or another error if the request is malformed.
func (s *EndpointAuthSecrets) ParseCallback(query url.Values, issuer string) (string, error) {
	// Check state first: an error report is only trustworthy if it belongs to this login.
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(s.State)) != 1 {
		return "", ErrEndpointAuthStateMismatch
	}
	if query.Get("iss") != issuer {
		return "", ErrEndpointAuthIssuerMismatch
	}

	if e := query.Get("error"); e != "" {
		// The API puts its own error code in a parameter of its own; error_description is text for
		// people (RFC 6749 section 4.1.2.1).
		cbErr := &EndpointAuthCallbackError{Code: e, Description: query.Get("error_description")}
		if dnErr := query.Get("dn_error"); dnErr != "" {
			cbErr.Code = dnErr
		}
		return "", cbErr
	}

	code := query.Get("code")
	if code == "" {
		return "", errors.New("endpoint auth callback is missing a code")
	}
	return code, nil
}

// randomURLString returns 32 random bytes as unpadded base64url: 43 characters, which is both a
// valid PKCE code verifier and a suitably unguessable state.
func randomURLString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
