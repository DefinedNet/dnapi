module github.com/DefinedNet/dnapi

// 1.26.3+ required: earlier point releases fail every TLS handshake under
// fips140=only, generating the default X25519MLKEM768 key share (golang/go#78372)
go 1.26.3

require (
	github.com/slackhq/nebula v1.11.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.54.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	filippo.io/bigmod v0.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
