module github.com/CYC07/cerberus

go 1.26.5

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/stretchr/testify v1.11.1
	// golang.zx2c4.com/wireguard (device/tun/conn) has no importer yet on
	// this branch (WireGuard mesh control-plane, Plan 2A) — only its
	// wgctrl/wgtypes subpackage below is used so far. It's pinned here
	// ahead of Plan 2B's data-plane agent, which imports it. `go mod tidy`
	// would otherwise prune it as unused; don't run tidy until Plan 2B
	// lands.
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	modernc.org/sqlite v1.54.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
