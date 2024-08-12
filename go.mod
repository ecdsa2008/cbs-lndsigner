module github.com/Safulet/cbs-lndsigner

require (
	github.com/Yawning/aez v0.0.0-20211027044916-e49e68abd344
	github.com/btcsuite/btcd v0.24.0
	github.com/btcsuite/btcd/btcec/v2 v2.2.1
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.8
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/kkdai/bstream v0.0.0-20161212061736-f391b8402d23
	github.com/tv42/zbase32 v0.0.0-20160707012821-501572607d02
	go.uber.org/zap v1.23.0
	golang.org/x/crypto v0.22.0
	google.golang.org/grpc v1.60.1
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231002182017-d307bd883b97 // indirect
)

// This replace is for https://github.com/advisories/GHSA-w73w-5m7g-f7qc
replace github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt v3.2.1+incompatible

// This replace is for https://github.com/advisories/GHSA-25xm-hr59-7c27
replace github.com/ulikunitz/xz => github.com/ulikunitz/xz v0.5.8

// This replace is for
// https://deps.dev/advisory/OSV/GO-2021-0053?from=%2Fgo%2Fgithub.com%252Fgogo%252Fprotobuf%2Fv1.3.1
replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

// If you change this please also update .github/pull_request_template.md and
// docs/INSTALL.md.
go 1.21

retract v0.0.2
