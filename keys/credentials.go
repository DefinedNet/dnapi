package keys

// Credentials contains information necessary to make requests against the DNClient API.
type Credentials struct {
	HostID      string
	PrivateKey  PrivateKey
	Counter     uint
	TrustedKeys []TrustedKey
}
