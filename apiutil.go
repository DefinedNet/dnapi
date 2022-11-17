package dnapi

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// InsertConfigPrivateKey takes a Nebula YAML and a Nebula PEM-formatted private key, and inserts the private key into
// the config, overwriting any previous value stored in the config.
func InsertConfigPrivateKey(config []byte, privkey []byte) ([]byte, error) {
	var y map[interface{}]interface{}
	if err := yaml.Unmarshal(config, &y); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %s", err)
	}

	_, ok := y["pki"]
	if !ok {
		return nil, fmt.Errorf("config is missing expected pki section")
	}

	_, ok = y["pki"].(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("config has unexpected value for pki section")
	}

	y["pki"].(map[interface{}]interface{})["key"] = string(privkey)

	return yaml.Marshal(y)
}
