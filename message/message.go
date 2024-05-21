package message

import (
	"errors"
	"strings"
	"time"
)

// DNClient API message types
const (
	CheckForUpdate  = "CheckForUpdate"
	DoUpdate        = "DoUpdate"
	LongPollWait    = "LongPollWait"
	CommandResponse = "CommandResponse"
)

// EndpointV1 is the version 1 DNClient API endpoint.
const EndpointV1 = "/v1/dnclient"

// RequestV1 is the version 1 DNClient request message.
// Ver is always 1, HostID is the calling dnclient hostID.
// Msg is a base64-encoded message, and Signature is an ed25519
// signature over the message, which can be verified using the
// host's previously enrolled ed25519 public key.
type RequestV1 struct {
	Version   int    `json:"version"`
	HostID    string `json:"hostID"`
	Counter   uint   `json:"counter"`
	Message   string `json:"message"`
	Signature []byte `json:"signature"`
}

// RequestWrapper wraps a DNClient request message. It consists of a
// type and value, with the type string indicating how to interpret the value blob.
type RequestWrapper struct {
	Type      string    `json:"type"`
	Value     []byte    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}

// SignedResponseWrapper contains a response message and a signature to validate inside "data."
type SignedResponseWrapper struct {
	Data SignedResponse `json:"data"`
}

// SignedResponse contains a response message and a signature to validate.
type SignedResponse struct {
	Version   int    `json:"version"`
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

// CheckForUpdateResponseWrapper contains a response to CheckForUpdate inside "data."
type CheckForUpdateResponseWrapper struct {
	Data CheckForUpdateResponse `json:"data"`
}

// CheckForUpdateResponse is the response generated for a CheckForUpdate request.
type CheckForUpdateResponse struct {
	UpdateAvailable bool `json:"updateAvailable"`
}

// DoUpdateRequest is the request sent for a DoUpdate request.
type DoUpdateRequest struct {
	EdPubkeyPEM []byte `json:"edPubkeyPEM"`
	DHPubkeyPEM []byte `json:"dhPubkeyPEM"`
	Nonce       []byte `json:"nonce"`
}

// DoUpdateResponse is the response generated for a DoUpdate request.
type DoUpdateResponse struct {
	Config      []byte `json:"config"`
	Counter     uint   `json:"counter"`
	Nonce       []byte `json:"nonce"`
	TrustedKeys []byte `json:"trustedKeys"`
}

// LongPollWaitResponseWrapper contains a response to LongPollWait inside "data."
type LongPollWaitResponseWrapper struct {
	Data LongPollWaitResponse `json:"data"`
}

// LongPollWaitRequest is the request message associated with a LongPollWait call.
type LongPollWaitRequest struct {
	SupportedActions []string `json:"supportedActions"`
}

// LongPollWaitResponse is the response message associated with a LongPollWait call.
type LongPollWaitResponse struct {
	Action string `json:"action"` // e.g. NoOp, StreamLogs, DoUpdate
}

// CommandResponseResponseWrapper contains a response to CommandResponse inside "data."
type CommandResponseResponseWrapper struct {
	Data CommandResponseResponse `json:"data"`
}

// CommandResponseRequest is the request message associated with a CommandResponse call.
type CommandResponseRequest struct {
	ResponseToken string `json:"responseToken"`
}

// DNClientCommandResponseResponse is the response message associated with a CommandResponse call.
type CommandResponseResponse struct{}

type ClientInfo struct {
	Identifier   string `json:"identifier"`
	Version      string `json:"version"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// EnrollEndpoint is the REST enrollment endpoint.
const EnrollEndpoint = "/v2/enroll"

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
