package message

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// An error-only APIResponse must round-trip without emitting a zero-valued
// data object, whose empty curve would fail NetworkCurve validation on decode
// and mask the errors.
func TestAPIResponseErrorOnlyRoundTrip(t *testing.T) {
	b, err := json.Marshal(APIResponse[EnrollResponseData]{
		Errors: APIResponseErrors{{Code: "ERR_TEST", Message: "test error"}},
	})
	require.NoError(t, err)
	require.NotContains(t, string(b), `"data"`)

	var r APIResponse[EnrollResponseData]
	require.NoError(t, json.Unmarshal(b, &r))
	require.EqualError(t, r.Errors.Err(), "test error")
}

// A data-only APIResponse must omit the errors key, matching the API.
func TestAPIResponseDataOnlyOmitsErrors(t *testing.T) {
	b, err := json.Marshal(APIResponse[EnrollResponseData]{
		Data: EnrollResponseData{
			HostID: "foobar",
			// a valid curve is required for the decode below, as on the real API
			Network: HostNetworkMetadata{Curve: NetworkCurve25519},
		},
	})
	require.NoError(t, err)
	require.NotContains(t, string(b), `"errors"`)

	var r APIResponse[EnrollResponseData]
	require.NoError(t, json.Unmarshal(b, &r))
	require.NoError(t, r.Errors.Err())
	require.Equal(t, "foobar", r.Data.HostID)
}
