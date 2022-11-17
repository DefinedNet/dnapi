package dnapi

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestInsertConfigPrivateKey(t *testing.T) {
	cfg, err := InsertConfigPrivateKey([]byte(`
pki: {}
`), []byte("foobar"))
	require.NoError(t, err)

	var y map[string]interface{}
	err = yaml.Unmarshal(cfg, &y)
	require.NoError(t, err)

	require.Equal(t, "foobar", y["pki"].(map[interface{}]interface{})["key"])

	cfg, err = InsertConfigPrivateKey([]byte(``), []byte("foobar"))
	require.Error(t, err)

}
