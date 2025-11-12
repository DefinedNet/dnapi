package message

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// DNClient API message types
const (
	CheckForUpdate  = "CheckForUpdate"
	DoUpdate        = "DoUpdate"
	DoConfigUpdate  = "DoConfigUpdate"
	LongPollWait    = "LongPollWait"
	CommandResponse = "CommandResponse"
	Reauthenticate  = "Reauthenticate"
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
	HostPubkeyEd25519  []byte `json:"edPubkeyPEM"`         // X25519 (used for key exchange)
	NebulaPubkeyX25519 []byte `json:"dhPubkeyPEM"`         // Ed25519 (used for signing)
	HostPubkeyP256     []byte `json:"p256HostPubkeyPEM"`   // P256 (used for signing)
	NebulaPubkeyP256   []byte `json:"p256NebulaPubkeyPEM"` // P256 (used for key exchange)
	Nonce              []byte `json:"nonce"`
}

// DoUpdateResponse is the response generated for a DoUpdate request.
type DoUpdateResponse struct {
	Config           []byte                    `json:"config"`
	Counter          uint                      `json:"counter"`
	Nonce            []byte                    `json:"nonce"`
	TrustedKeys      []byte                    `json:"trustedKeys"`
	Organization     HostOrgMetadata           `json:"organization"`
	Network          HostNetworkMetadata       `json:"network"`
	Host             HostHostMetadata          `json:"host"`
	EndpointOIDCMeta *HostEndpointOIDCMetadata `json:"endpointOIDC"`
}

// DoConfigUpdateRequest is the request sent for a DoConfigUpdate request.
type DoConfigUpdateRequest struct {
	HostPubkeyEd25519 []byte `json:"edPubkeyPEM"`       // X25519 (used for signing)
	HostPubkeyP256    []byte `json:"p256HostPubkeyPEM"` // P256 (used for signing)
	Nonce             []byte `json:"nonce"`
}

// DoConfigUpdateResponse is the response generated for a DoConfigUpdate request.
type DoConfigUpdateResponse struct {
	Config       []byte              `json:"config"`
	Counter      uint                `json:"counter"`
	Nonce        []byte              `json:"nonce"`
	TrustedKeys  []byte              `json:"trustedKeys"`
	Organization HostOrgMetadata     `json:"organization"`
	Network      HostNetworkMetadata `json:"network"`
	Host         HostHostMetadata    `json:"host"`
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
	Action        json.RawMessage `json:"action"` // e.g. NoOp, StreamLogs, DoUpdate
	ResponseToken string          `json:"responseToken"`
}

// CommandResponseResponseWrapper contains a response to CommandResponse inside "data."
type CommandResponseResponseWrapper struct {
	Data CommandResponseResponse `json:"data"`
}

// CommandResponseRequest is the request message associated with a CommandResponse call.
type CommandResponseRequest struct {
	ResponseToken string `json:"responseToken"`
	Response      any    `json:"response"`
}

// CommandResponseResponse is the response message associated with a CommandResponse call.
type CommandResponseResponse struct{}

type ClientInfo struct {
	Identifier   string `json:"identifier"`
	Version      string `json:"version"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// ReauthenticateRequest is the request sent for a Reauthenticate request.
type ReauthenticateRequest struct {
	// Add fields as needed
}

// ReauthenticateResponse is the response message associated with a Reauthenticate request.
type ReauthenticateResponse struct {
	LoginURL string `json:"loginURL"`
}

// APIResponse is a standard format for the DN API. It does not apply to the DNClient API.
type APIResponse[T any] struct {
	Data   T                 `json:"data"`
	Errors APIResponseErrors `json:"errors"`
}

// APIResponseError represents a single error returned in an API error response.
type APIResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path"` // may or may not be present
}

// APIResponseErrors is used to parse errors but is not a Golang error itself.
// It may or may not contain actual errors - if it doesn't, it should not be
// converted to an error. This should not be returned from the dnapi package.
type APIResponseErrors []APIResponseError

func (m APIResponseErrors) Err() error {
	if len(m) > 0 {
		return APIErrors(m)
	}
	return nil
}

// APIErrors facilitates converting multiple API errors into a single Golang
// error to be returned to callers.
type APIErrors APIResponseErrors

func (errs APIErrors) Error() string {
	if len(errs) == 0 { // this shouldn't happen
		panic("no errors")
	}

	s := make([]string, len(errs))
	for i := range errs {
		s[i] = errs[i].Message
	}

	return strings.Join(s, ", ")
}

// EnrollEndpoint is the REST enrollment endpoint.
const EnrollEndpoint = "/v2/enroll"

// EnrollRequest is issued to the EnrollEndpoint.
type EnrollRequest struct {
	Code               string    `json:"code"`
	NebulaPubkeyX25519 []byte    `json:"dhPubkey"`         // X25519 (used for key exchange)
	HostPubkeyEd25519  []byte    `json:"edPubkey"`         // Ed25519 (used for signing)
	NebulaPubkeyP256   []byte    `json:"nebulaPubkeyP256"` // P256 (used for key exchange)
	HostPubkeyP256     []byte    `json:"hostPubkeyP256"`   // P256 (used for signing)
	Timestamp          time.Time `json:"timestamp"`
}

// EnrollResponseData is included in the EnrollResponse.
type EnrollResponseData struct {
	Config           []byte                    `json:"config"`
	HostID           string                    `json:"hostID"`
	Counter          uint                      `json:"counter"`
	TrustedKeys      []byte                    `json:"trustedKeys"`
	Organization     HostOrgMetadata           `json:"organization"`
	Network          HostNetworkMetadata       `json:"network"`
	Host             HostHostMetadata          `json:"host"`
	EndpointOIDCMeta *HostEndpointOIDCMetadata `json:"endpointOIDC"`
}

// HostOrgMetadata is included in EnrollResponseData.
type HostOrgMetadata struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// HostNetworkMetadata is included in EnrollResponseData.
type HostNetworkMetadata struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Curve NetworkCurve `json:"curve"`
	CIDR  string       `json:"cidr"`
}

// HostHostMetadata is included in EnrollResponseData.
type HostHostMetadata struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IPAddress string `json:"ipAddress"`
}

// HostEndpointOIDCMetadata is included in EnrollResponseData.
type HostEndpointOIDCMetadata struct {
	Email string `json:"email"`
}

// PreAuthEndpoint is called when starting an OIDC auth flow.
const PreAuthEndpoint = "/v1/endpoint-auth/preauth"

type PreAuthData struct {
	PollToken string `json:"pollToken"`
	LoginURL  string `json:"loginURL"`
}

const AuthPollEndpoint = "/v1/endpoint-auth/poll"

type EndpointAuthState string

const (
	EndpointAuthWaiting   EndpointAuthState = "WAITING"
	EndpointAuthStarted   EndpointAuthState = "STARTED"
	EndpointAuthCompleted EndpointAuthState = "COMPLETED"
)

type EndpointAuthPollData struct {
	Status         EndpointAuthState `json:"state"`
	EnrollmentCode string            `json:"enrollmentCode"`
}

const DownloadsEndpoint = "/v1/downloads"

type DownloadsData struct {
	// DNClient maps versions to a map of platforms' download links.
	DNClient map[string]map[string]string `json:"dnclient"`
	// Mobile maps platforms to their download links (i.e. App Store / Play Store.)
	Mobile DownloadsMobile `json:"mobile"`
	// Links to container repositories like Docker
	Container DownloadsContainers `json:"container"`

	// VersionInfo contains information about past versions.
	VersionInfo DownloadsVersionInfo `json:"versionInfo"`
}

type DownloadsVersionInfo struct {
	// DNClient maps versions to their version info.
	DNClient map[string]DNClientVersionInfo `json:"dnclient"`
	// Latest returns the latest versions for each platform.
	Latest DownloadsLatest `json:"latest"`
}

type DownloadsMobile struct {
	Android string `json:"android"`
	IOS     string `json:"ios"`
}

type DownloadsContainers struct {
	Docker string `json:"docker"`
}

type DownloadsLatest struct {
	DNClient string `json:"dnclient"`
	Mobile   string `json:"mobile"`
}

type DNClientVersionInfo struct {
	Latest      bool   `json:"latest"`
	ReleaseDate string `json:"releaseDate"`
}

// NetworkCurve represents the network curve specified by the API.
type NetworkCurve string

const (
	NetworkCurve25519 NetworkCurve = "25519"
	NetworkCurveP256  NetworkCurve = "P256"
)

func (nc *NetworkCurve) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case "25519":
		*nc = NetworkCurve25519
	case "P256":
		*nc = NetworkCurveP256
	default:
		return errors.New("invalid network curve")
	}

	return nil
}
