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

// InsertConfigCert takes a Nebula YAML and a Nebula PEM-formatted host certifiate, and inserts the certificate into
// the config, overwriting any previous value stored.
func InsertConfigCert(config []byte, cert []byte) ([]byte, error) {
	var y map[any]any
	if err := yaml.Unmarshal(config, &y); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %s", err)
	}

	_, ok := y["pki"]
	if !ok {
		return nil, fmt.Errorf("config is missing expected pki section")
	}

	_, ok = y["pki"].(map[any]any)
	if !ok {
		return nil, fmt.Errorf("config has unexpected value for pki section")
	}

	y["pki"].(map[any]any)["cert"] = string(cert)

	return yaml.Marshal(y)
}

// FetchConfigPrivateKey takes a Nebula YAML, finds and returns its contained Nebula PEM-formatted private key,
// the Nebula PEM-formatted host cert, or an error.
func FetchConfigPrivateKeyAndCert(config []byte) ([]byte, []byte, error) {
	var y map[any]any
	if err := yaml.Unmarshal(config, &y); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %s", err)
	}

	_, ok := y["pki"]
	if !ok {
		return nil, nil, fmt.Errorf("config is missing expected pki section")
	}

	pki, ok := y["pki"].(map[any]any)
	if !ok {
		return nil, nil, fmt.Errorf("config has unexpected value for pki section")
	}

	configKey, ok := pki["key"]
	if !ok {
		return nil, nil, fmt.Errorf("(%s) config is missing section 'key'", config)
	}

	existingKey, ok := configKey.(string)
	if !ok {
		return nil, nil, fmt.Errorf("config section 'key' found but has unexpected type: %T", configKey)
	}

	configCert, ok := pki["cert"]
	if !ok {
		return nil, nil, fmt.Errorf("config is missing 'cert' section")
	}

	existingCert, ok := configCert.(string)
	if !ok {
		return nil, nil, fmt.Errorf("config section 'cert' found but has unexpected type: %T", configCert)
	}

	return []byte(existingKey), []byte(existingCert), nil
}
