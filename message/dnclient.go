package message

import "time"

// DNClient API message types
const (
	CheckForUpdate = "CheckForUpdate"
	DoUpdate       = "DoUpdate"
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
