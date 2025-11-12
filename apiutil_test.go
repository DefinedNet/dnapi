package dnapi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestInsertConfigPrivateKey(t *testing.T) {
	cfg, err := InsertConfigPrivateKey([]byte(`
pki: {}
`), []byte("foobar"))
	require.NoError(t, err)

	var y map[string]any
	err = yaml.Unmarshal(cfg, &y)
	require.NoError(t, err)

	require.Equal(t, "foobar", y["pki"].(map[any]any)["key"])

	_, err = InsertConfigPrivateKey([]byte(``), []byte("foobar"))
	require.Error(t, err)

}

func TestFetchConfigPrivateKey(t *testing.T) {
	keyValue := []byte("foobar")
	certValue := []byte("lolwat")

	configValue := fmt.Sprintf(`pki: { cert: %s }`, certValue)
	cfg, err := InsertConfigPrivateKey([]byte(configValue), keyValue)
	require.NoError(t, err)

	var y map[string]any
	err = yaml.Unmarshal(cfg, &y)
	require.NoError(t, err)
	require.Equal(t, keyValue, []byte(y["pki"].(map[any]any)["key"].(string)))

	fetchedVal, fetchedCert, err := FetchConfigPrivateKeyAndCert(cfg)
	require.NoError(t, err)
	assert.Equal(t, certValue, fetchedCert)
	assert.Equal(t, keyValue, fetchedVal)
}
