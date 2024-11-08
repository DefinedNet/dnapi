package dnapi

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/DefinedNet/dnapi/message"
)

func SignRequestV1(reqType string, value []byte, hostID string, counter uint, privkey PrivateKey) ([]byte, error) {
	encMsg, err := json.Marshal(message.RequestWrapper{
		Type:      reqType,
		Value:     value,
		Timestamp: time.Now(),
	})
	if err != nil {
		return nil, err
	}

	signedMsg := base64.StdEncoding.EncodeToString(encMsg)
	sig, err := privkey.Sign([]byte(signedMsg))
	if err != nil {
		return nil, err
	}

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
