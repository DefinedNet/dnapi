package dnapitest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/DefinedNet/dnapi/message"
	"github.com/slackhq/nebula/cert"
	"gopkg.in/yaml.v2"
)

// m is a helper type for building out generic maps (e.g. for marshalling.)
type m map[string]interface{}

type Server struct {
	*httptest.Server

	errors []error

	expectedRequests []requestResponse

	expectedEdPubkey  ed25519.PublicKey
	expectedUserAgent string
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("User-Agent") != s.expectedUserAgent {
		s.errors = append(
			s.errors,
			fmt.Errorf("unexpected user agent: %s, expected: %s", r.Header.Get("User-Agent"), s.expectedUserAgent),
		)
	}

	// There are no more test cases to return, so write nothing and return
	if s.RequestsRemaining() == 0 {
		s.errors = append(s.errors, fmt.Errorf("unexpected request - no mock responses to return"))
		http.Error(w, "unexpected request", http.StatusInternalServerError)
		return
	}

	switch r.URL.Path {
	case message.EnrollEndpoint:
		w.Header().Set("X-Request-ID", "SupaDoopaRequestIdentifier")
		s.handlerEnroll(w, r)
	case message.EndpointV1:
		s.handlerDNClient(w, r)
	default:
		s.errors = append(s.errors, fmt.Errorf("invalid request path %s", r.URL.Path))
		http.NotFound(w, r)
	}
}

func (s *Server) handlerEnroll(w http.ResponseWriter, r *http.Request) {
	// Get the test case to validate
	expected := s.expectedRequests[0]
	s.expectedRequests = s.expectedRequests[1:]
	if expected.dnclientAPI {
		s.errors = append(s.errors, fmt.Errorf("unexpected enrollment request - expected dnclient API request"))
		http.Error(w, "unexpected enrollment request", http.StatusInternalServerError)
		return
	}
	res := expected.enrollRequestResponse

	// read and unmarshal body
	var req message.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errors = append(s.errors, fmt.Errorf("failed to decode enroll request: %w", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// soft failure, we can continue
	if req.Timestamp.IsZero() {
		s.errors = append(s.errors, fmt.Errorf("missing timestamp"))
	}

	if err := s.SetEdPubkey(req.EdPubkey); err != nil {
		s.errors = append(s.errors, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(res.response(req))
}

func (s *Server) SetEdPubkey(edPubkeyPEM []byte) error {
	// hard failure, return
	edPubkey, rest, err := cert.UnmarshalEd25519PublicKey(edPubkeyPEM)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ed pubkey: %w", err)
	}
	s.expectedEdPubkey = edPubkey

	// soft failure, log it and avoid bailing the request
	if len(rest) > 0 {
		s.errors = append(s.errors, fmt.Errorf("unexpected trailer in ed pubkey: %s", rest))
	}

	return nil
}

func (s *Server) handlerDNClient(w http.ResponseWriter, r *http.Request) {
	// Get the test case to validate
	expected := s.expectedRequests[0]
	s.expectedRequests = s.expectedRequests[1:]
	if !expected.dnclientAPI {
		s.errors = append(s.errors, fmt.Errorf("unexpected dnclient API request - expected enrollment request"))
		http.Error(w, "unexpected dnclient API request", http.StatusInternalServerError)
		return
	}
	res := expected.dncRequestResponse

	req := message.RequestV1{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.errors = append(s.errors, fmt.Errorf("failed to decode request: %w", err))
		http.Error(w, "failed to decode request", http.StatusInternalServerError)
		return
	}

	// Assert that the signature is correct
	if !ed25519.Verify(s.expectedEdPubkey, []byte(req.Message), req.Signature) {
		s.errors = append(s.errors, fmt.Errorf("invalid signature"))
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Decode the signed message
	decodedMsg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		s.errors = append(s.errors, fmt.Errorf("failed to decode request message: %w", err))
		http.Error(w, "failed to decode request message", http.StatusInternalServerError)
		return
	}

	msg := message.RequestWrapper{}
	err = json.Unmarshal(decodedMsg, &msg)
	if err != nil {
		s.errors = append(s.errors, fmt.Errorf("failed to unmarshal request wrapper: %w", err))
		http.Error(w, "failed to unmarshal request request", http.StatusInternalServerError)
		return
	}

	// Require the expected request type, otherwise we have derailed.
	if msg.Type != res.expectedType {
		s.errors = append(s.errors, fmt.Errorf("%s is not expected message type %s", msg.Type, res.expectedType))
		http.Error(w, "unexpected message type", http.StatusInternalServerError)
		return
	}

	switch msg.Type {
	case message.DoUpdate:
		var updateKeys message.DoUpdateRequest
		err = json.Unmarshal(msg.Value, &updateKeys)
		if err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to unmarshal DoUpdateRequest: %w", err))
			http.Error(w, "failed to unmarshal DoUpdateRequest", http.StatusInternalServerError)
			return
		}

		if err := s.SetEdPubkey(updateKeys.EdPubkeyPEM); err != nil {
			s.errors = append(s.errors, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case message.LongPollWait:
		var longPoll message.LongPollWaitRequest
		err = json.Unmarshal(msg.Value, &longPoll)
		if err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to unmarshal LongPollWaitRequest: %w", err))
			http.Error(w, "failed to unmarshal LongPollWaitRequest", http.StatusInternalServerError)
			return
		}

		if len(longPoll.SupportedActions) == 0 {
			s.errors = append(s.errors, fmt.Errorf("no supported actions"))
			http.Error(w, "no supported actions", http.StatusInternalServerError)
			return
		}

		if len(longPoll.Client.Identifier) == 0 {
			s.errors = append(s.errors, fmt.Errorf("no client identifier"))
			http.Error(w, "no supported actions", http.StatusInternalServerError)
			return
		}
		if len(longPoll.Client.Version) == 0 {
			s.errors = append(s.errors, fmt.Errorf("no client version"))
			http.Error(w, "no supported actions", http.StatusInternalServerError)
			return
		}
		if len(longPoll.Client.OS) == 0 {
			s.errors = append(s.errors, fmt.Errorf("no no client os"))
			http.Error(w, "no supported actions", http.StatusInternalServerError)
			return
		}
		if len(longPoll.Client.Architecture) == 0 {
			s.errors = append(s.errors, fmt.Errorf("no client architecture"))
			http.Error(w, "no supported actions", http.StatusInternalServerError)
			return
		}
	}

	// return the associated response
	w.Write(res.response(msg))
}

func (s *Server) ExpectEnrollment(code string, response func(req message.EnrollRequest) []byte) {
	s.expectedRequests = append(s.expectedRequests, requestResponse{
		dnclientAPI: false,
		enrollRequestResponse: enrollRequestResponse{
			expectedCode: code,
			response:     response,
		},
	})
}

func (s *Server) ExpectRequest(msgType string, response func(r message.RequestWrapper) []byte) {
	s.expectedRequests = append(s.expectedRequests, requestResponse{
		dnclientAPI: true,
		dncRequestResponse: dncRequestResponse{
			expectedType: msgType,
			response:     response,
		},
	})
}

func (s *Server) Errors() []error {
	defer func() {
		s.errors = []error{}
	}()

	return s.errors
}

func (s *Server) RequestsRemaining() int {
	return len(s.expectedRequests)
}

func NewServer(expectedUserAgent string) *Server {
	s := &Server{
		errors:            []error{},
		expectedRequests:  []requestResponse{},
		expectedUserAgent: expectedUserAgent,
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handler))
	s.Server = ts

	return s
}

type requestResponse struct {
	dnclientAPI           bool
	dncRequestResponse    dncRequestResponse
	enrollRequestResponse enrollRequestResponse
}

type enrollRequestResponse struct {
	expectedCode string

	response func(r message.EnrollRequest) []byte
}

type dncRequestResponse struct {
	expectedType string

	response func(r message.RequestWrapper) []byte
}

func GetNonce(r message.RequestWrapper) []byte {
	msg := struct{ Nonce []byte }{}
	if err := json.Unmarshal(r.Value, &msg); err != nil {
		panic(err)
	}
	return msg.Nonce
}

// NebulaCfg returns a dummy Nebula config file, returning the marshalled cert in yaml format.
func NebulaCfg(caCert []byte) []byte {
	rawConfig := m{
		"pki": m{
			"ca":   string(caCert), // []byte will convert to a YAML list
			"cert": string(caCert), // []byte will convert to a YAML list
			// key will be filled in on the host
		},
		"static_host_map": map[string][]string{},
		"punchy": m{
			"punch":   true,
			"respond": true,
		},
		"lighthouse": "",
		"listen":     "",
		"tun": m{
			"dev":                  "nebula99", // 99 chosen to try to avoid conflicts
			"mtu":                  1300,
			"drop_local_broadcast": true,
			"drop_multicast":       true,
		},
		"logging": m{
			"level":  "info",
			"format": "text",
		},
		"firewall": m{
			"outbound": "",
			"inbound":  "",
		},
	}
	nebulaCfg, err := yaml.Marshal(rawConfig)
	if err != nil {
		panic(err)
	}
	return nebulaCfg
}

func NebulaCACert() (*cert.NebulaCertificate, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "UnitTesting",
			Groups:    []string{"testa", "testb"},
			Ips:       []*net.IPNet{},
			Subnets:   []*net.IPNet{},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(24 * time.Hour),
			PublicKey: pub,
			IsCA:      true,
		},
	}
	nc.Sign(nc.Details.Curve, priv)

	return nc, priv
}
