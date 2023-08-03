package message

import (
	"errors"
	"strings"
	"time"
)

// EnrollEndpoint is the REST enrollment endpoint.
const EnrollEndpoint = "/v2/enroll"

// APIError represents a single error returned in an API error response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path"` // may or may not be present
}

type APIErrors []APIError

func (errs APIErrors) ToError() error {
	if len(errs) == 0 {
		return nil
	}

	s := make([]string, len(errs))
	for i := range errs {
		s[i] = errs[i].Message
	}

	return errors.New(strings.Join(s, ", "))
}

// EnrollRequest is issued to the EnrollEndpoint.
type EnrollRequest struct {
	Code      string    `json:"code"`
	DHPubkey  []byte    `json:"dhPubkey"`
	EdPubkey  []byte    `json:"edPubkey"`
	Timestamp time.Time `json:"timestamp"`
}

// EnrollResponse represents a response from the enrollment endpoint.
type EnrollResponse struct {
	// Only one of Data or Errors should be set in a response
	Data EnrollResponseData `json:"data"`

	Errors APIErrors `json:"errors"`
}

// EnrollResponseData is included in the EnrollResponse.
type EnrollResponseData struct {
	Config       []byte                `json:"config"`
	HostID       string                `json:"hostID"`
	Counter      uint                  `json:"counter"`
	TrustedKeys  []byte                `json:"trustedKeys"`
	Organization EnrollResponseDataOrg `json:"organization"`
}

// EnrollResponseDataOrg is included in EnrollResponseData.
type EnrollResponseDataOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
