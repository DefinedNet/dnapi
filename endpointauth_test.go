package dnapi

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEndpointAuthSecrets(t *testing.T) {
	t.Parallel()

	s, err := NewEndpointAuthSecrets()
	require.NoError(t, err)

	// RFC 7636: a 43-128 character verifier, and an S256 challenge of it.
	assert.Len(t, s.CodeVerifier, 43)
	sum := sha256.Sum256([]byte(s.CodeVerifier))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), s.CodeChallenge)
	assert.Len(t, s.State, 43)

	// Every auth gets fresh secrets.
	s2, err := NewEndpointAuthSecrets()
	require.NoError(t, err)
	assert.NotEqual(t, s.CodeVerifier, s2.CodeVerifier)
	assert.NotEqual(t, s.State, s2.State)
}

func TestEndpointAuthSecrets_ParseCallback(t *testing.T) {
	t.Parallel()

	const iss = "https://api.example.com"
	s := &EndpointAuthSecrets{State: "the-state"}

	code, err := s.ParseCallback(url.Values{"code": {"eaexch-abc"}, "state": {"the-state"}, "iss": {iss}}, iss)
	require.NoError(t, err)
	assert.Equal(t, "eaexch-abc", code)

	// A request without this login's state is not ours, whatever else it carries.
	for _, q := range []url.Values{
		{"code": {"eaexch-abc"}, "iss": {iss}},
		{"code": {"eaexch-abc"}, "state": {"other-state"}, "iss": {iss}},
		{"error": {"access_denied"}, "error_description": {"ERR_OIDC_EXCHANGE_CODE"}, "state": {"other-state"}, "iss": {iss}},
	} {
		_, err := s.ParseCallback(q, iss)
		assert.ErrorIs(t, err, ErrEndpointAuthStateMismatch, "query %v", q)
	}

	// A response from another authorization server, or one that does not say, is refused (RFC 9207).
	for _, q := range []url.Values{
		{"code": {"eaexch-abc"}, "state": {"the-state"}},
		{"code": {"eaexch-abc"}, "state": {"the-state"}, "iss": {"https://evil.example"}},
	} {
		_, err := s.ParseCallback(q, iss)
		assert.ErrorIs(t, err, ErrEndpointAuthIssuerMismatch, "query %v", q)
	}

	// A failure, reported with the API's error code in the description.
	_, err = s.ParseCallback(url.Values{"error": {"access_denied"}, "error_description": {"ERR_OIDC_MISSING_CLAIMS"}, "state": {"the-state"}, "iss": {iss}}, iss)
	var cbErr *EndpointAuthCallbackError
	require.ErrorAs(t, err, &cbErr)
	assert.Equal(t, "ERR_OIDC_MISSING_CLAIMS", cbErr.Code)

	// Without a description, the OAuth error code.
	_, err = s.ParseCallback(url.Values{"error": {"server_error"}, "state": {"the-state"}, "iss": {iss}}, iss)
	require.ErrorAs(t, err, &cbErr)
	assert.Equal(t, "server_error", cbErr.Code)

	// Neither a code nor an error.
	_, err = s.ParseCallback(url.Values{"state": {"the-state"}, "iss": {iss}}, iss)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrEndpointAuthStateMismatch)
}
