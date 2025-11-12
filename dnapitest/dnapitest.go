// Package dnapitest contains utilities for testing the dnapi package. Be aware
// that any function in this package may panic on error.
package dnapitest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/DefinedNet/dnapi/keys"
	"github.com/DefinedNet/dnapi/message"
	"github.com/slackhq/nebula/cert"
	"gopkg.in/yaml.v2"
)

// m is a helper type for building out generic maps (e.g. for marshalling.)
type m map[string]interface{}

type Server struct {
	*httptest.Server

	errors []error

	streamedBody []byte

	expectedRequests []Responder

	expectedEdPubkey   ed25519.PublicKey
	expectedP256Pubkey *ecdsa.PublicKey

	expectedUserAgent string

	// curve is set by the enroll request (which must match expectedEnrollment)
	curve message.NetworkCurve
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
	case message.PreAuthEndpoint:
		expected := s.expectedRequests[0]
		s.expectedRequests = s.expectedRequests[1:]
		w.WriteHeader(expected.StatusCode())
		_, _ = w.Write(expected.Respond(nil))
	case message.AuthPollEndpoint:
		s.handlerDoOidcPoll(w, r)
	case message.DownloadsEndpoint:
		expected := s.expectedRequests[0]
		s.expectedRequests = s.expectedRequests[1:]
		w.WriteHeader(expected.StatusCode())
		_, _ = w.Write(expected.Respond(nil))
	default:
		s.errors = append(s.errors, fmt.Errorf("invalid request path %s", r.URL.Path))
		http.NotFound(w, r)
	}
}

func (s *Server) handlerEnroll(w http.ResponseWriter, r *http.Request) {
	// Get the test case to validate
	expectedRaw := s.expectedRequests[0]
	s.expectedRequests = s.expectedRequests[1:]
	res := expectedRaw.(*enrollRequestResponse)

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

	if res.curve == message.NetworkCurve25519 {
		if err := s.SetEdPubkey(req.HostPubkeyEd25519); err != nil {
			s.errors = append(s.errors, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if res.curve == message.NetworkCurveP256 {
		if err := s.SetP256Pubkey(req.HostPubkeyP256); err != nil {
			s.errors = append(s.errors, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s.curve = res.curve

	w.Write(res.Respond(req))
}

func (s *Server) SetCurve(curve message.NetworkCurve) {
	s.curve = curve
}

func (s *Server) SetEdPubkey(edPubkeyPEM []byte) error {
	// hard failure, return
	edPubkey, rest, err := keys.UnmarshalHostEd25519PublicKey(edPubkeyPEM)
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

func (s *Server) SetP256Pubkey(p256PubkeyPEM []byte) error {
	// hard failure, return
	pubkey, rest, err := keys.UnmarshalHostP256PublicKey(p256PubkeyPEM)
	if err != nil {
		return fmt.Errorf("failed to unmarshal P256 pubkey: %w", err)
	}
	s.expectedP256Pubkey = pubkey

	// soft failure, log it and avoid bailing the request
	if len(rest) > 0 {
		s.errors = append(s.errors, fmt.Errorf("unexpected trailer in ed pubkey: %s", rest))
	}

	return nil
}

func (s *Server) handlerDoOidcPoll(w http.ResponseWriter, r *http.Request) {
	// Get the test case to validate
	res := s.expectedRequests[0]
	s.expectedRequests = s.expectedRequests[1:]

	token := r.URL.Query()["pollToken"]
	if len(token) == 0 {
		s.errors = append(s.errors, fmt.Errorf("missing pollToken"))
		http.Error(w, "missing pollToken", http.StatusBadRequest)
		return
	}

	// return the associated response
	w.WriteHeader(res.StatusCode())
	w.Write(res.Respond(nil))
}

func (s *Server) handlerDNClient(w http.ResponseWriter, r *http.Request) {
	// Get the test case to validate
	expected := s.expectedRequests[0]
	s.expectedRequests = s.expectedRequests[1:]
	res := expected.(*dncRequestResponse)

	jd := json.NewDecoder(r.Body)

	req := message.RequestV1{}
	err := jd.Decode(&req)
	if err != nil {
		s.errors = append(s.errors, fmt.Errorf("failed to decode request: %w", err))
		http.Error(w, "failed to decode request", http.StatusInternalServerError)
		return
	}

	// Assert that the signature is correct
	switch s.curve {
	case message.NetworkCurve25519:
		if !ed25519.Verify(s.expectedEdPubkey, []byte(req.Message), req.Signature) {
			s.errors = append(s.errors, fmt.Errorf("invalid signature"))
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	case message.NetworkCurveP256:
		// Convert the signature to a format Go understands
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(req.Signature, &esig); err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to unmarshal signature: %w", err))
			http.Error(w, "failed to unmarshal signature", http.StatusInternalServerError)
			return
		}

		hashed := sha256.Sum256([]byte(req.Message))
		if !ecdsa.Verify(s.expectedP256Pubkey, hashed[:], esig.R, esig.S) {
			s.errors = append(s.errors, fmt.Errorf("invalid signature"))
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	default:
		s.errors = append(s.errors, fmt.Errorf("invalid curve"))
		http.Error(w, "invalid curve", http.StatusInternalServerError)
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
		http.Error(w, fmt.Sprintf("unexpected message type %s, wanted %s", msg.Type, res.expectedType), http.StatusInternalServerError)
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

		switch s.curve {
		case message.NetworkCurve25519:
			if err := s.SetEdPubkey(updateKeys.HostPubkeyEd25519); err != nil {
				s.errors = append(s.errors, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case message.NetworkCurveP256:
			if err := s.SetP256Pubkey(updateKeys.HostPubkeyP256); err != nil {
				s.errors = append(s.errors, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			s.errors = append(s.errors, fmt.Errorf("invalid curve"))
			http.Error(w, "invalid curve", http.StatusInternalServerError)
			return
		}

	case message.DoConfigUpdate:
		var updateKeys message.DoConfigUpdateRequest
		err = json.Unmarshal(msg.Value, &updateKeys)
		if err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to unmarshal DoUpdateRequest: %w", err))
			http.Error(w, "failed to unmarshal DoUpdateRequest", http.StatusInternalServerError)
			return
		}

		switch s.curve {
		case message.NetworkCurve25519:
			if err := s.SetEdPubkey(updateKeys.HostPubkeyEd25519); err != nil {
				s.errors = append(s.errors, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case message.NetworkCurveP256:
			if err := s.SetP256Pubkey(updateKeys.HostPubkeyP256); err != nil {
				s.errors = append(s.errors, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			s.errors = append(s.errors, fmt.Errorf("invalid curve"))
			http.Error(w, "invalid curve", http.StatusInternalServerError)
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

	case message.CommandResponse:
		var cmdResponse message.CommandResponseRequest
		err = json.Unmarshal(msg.Value, &cmdResponse)
		if err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to unmarshal StreamLogsRequest: %w", err))
			http.Error(w, "failed to unmarshal CommandResponse", http.StatusInternalServerError)
			return
		}

	case message.Reauthenticate:
		var reauth message.ReauthenticateRequest
		err = json.Unmarshal(msg.Value, &reauth)
		if err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to unmarshal ReauthenticateRequest: %w", err))
			http.Error(w, "failed to unmarshal ReauthenticateRequest", http.StatusInternalServerError)
			return
		}

	}

	if res.isStreamingRequest {
		s.streamedBody, err = io.ReadAll(io.MultiReader(jd.Buffered(), r.Body))
		if err != nil {
			s.errors = append(s.errors, fmt.Errorf("failed to read body: %w", err))
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
	}

	// return the associated response
	w.WriteHeader(res.StatusCode())
	w.Write(res.Respond(msg))
}

func (s *Server) ExpectEnrollment(code string, curve message.NetworkCurve, response func(req message.EnrollRequest) []byte) {
	s.expectedRequests = append(s.expectedRequests,
		&enrollRequestResponse{
			expectedCode: code,
			response:     response,
			curve:        curve,
		})
}

func (s *Server) ExpectAPIRequest(statusCode int, cb func(r any) []byte) {
	s.expectedRequests = append(s.expectedRequests, &response{
		statusCode: statusCode,
		cb:         cb,
	})
}

func (s *Server) ExpectDNClientRequest(msgType string, statusCode int, response func(r message.RequestWrapper) []byte) {
	s.expectedRequests = append(s.expectedRequests, &dncRequestResponse{
		statusCode:   statusCode,
		expectedType: msgType,
		response:     response,
	})
}

func (s *Server) ExpectStreamingRequest(msgType string, statusCode int, response func(r message.RequestWrapper) []byte) {
	s.expectedRequests = append(s.expectedRequests, &dncRequestResponse{
		isStreamingRequest: true,
		statusCode:         statusCode,
		expectedType:       msgType,
		response:           response,
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

func (s *Server) ExpectedRequests() []Responder {
	return s.expectedRequests
}

func (s *Server) LastStreamedBody() []byte {
	return s.streamedBody
}

func NewServer(expectedUserAgent string) *Server {
	s := &Server{
		errors:            []error{},
		expectedRequests:  []Responder{},
		expectedUserAgent: expectedUserAgent,
		curve:             message.NetworkCurve25519, // default for legacy tests
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handler))
	s.Server = ts

	return s
}

type Responder interface {
	StatusCode() int
	Respond(r any) []byte
}

type response struct {
	statusCode int
	cb         func(r any) []byte
}

func (r *response) StatusCode() int {
	return r.statusCode
}

func (r *response) Respond(x any) []byte {
	return r.cb(x)
}

type enrollRequestResponse struct {
	expectedCode string
	curve        message.NetworkCurve
	response     func(r message.EnrollRequest) []byte
}

func (r *enrollRequestResponse) StatusCode() int {
	return http.StatusOK //TODO?
}

func (r *enrollRequestResponse) Respond(x any) []byte {
	y := x.(message.EnrollRequest)
	return r.response(y)
}

type dncRequestResponse struct {
	expectedType       string
	isStreamingRequest bool
	statusCode         int
	response           func(r message.RequestWrapper) []byte
}

func (r *dncRequestResponse) StatusCode() int {
	return r.statusCode
}

func (r *dncRequestResponse) Respond(x any) []byte {
	y := x.(message.RequestWrapper)
	return r.response(y)
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
	err = nc.Sign(nc.Details.Curve, priv)
	if err != nil {
		panic(err)
	}

	return nc, priv
}

func NebulaCACertP256() (*cert.NebulaCertificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// ecdh.PrivateKey lets us get at the encoded bytes, even though
	// we aren't using ECDH here.
	eKey, err := key.ECDH()
	if err != nil {
		panic(err)
	}

	rawPriv := eKey.Bytes()
	pub := eKey.PublicKey().Bytes()

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Curve:     cert.Curve_P256,
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
	err = nc.Sign(nc.Details.Curve, rawPriv)
	if err != nil {
		panic(err)
	}

	return nc, key
}
