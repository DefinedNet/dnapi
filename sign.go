package dnapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/DefinedNet/dnapi/message"
)

func SignRequestV1(reqType string, value []byte, hostID string, counter uint, privkey ed25519.PrivateKey) ([]byte, error) {
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

	wrapper := message.RequestV1{
		Version:   1,
		HostID:    hostID,
		Counter:   counter,
		Message:   signedMsg,
		Signature: sig,
	}
	b, err := json.Marshal(wrapper)
	if err != nil {
		return nil, err
	}

	return b, nil
}
