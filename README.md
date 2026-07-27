# Cerberus

A Zero Trust Network Access (ZTNA) system, built from scratch in Go.

No VPN, no open ports, no implicit trust from network location. Every
connection to a protected resource is authenticated (mutual TLS + a
short-lived, cert-bound JWT) and authorized (explicit allow-list policy,
default-deny) before a single byte is proxied.

Own CA, own token issuance, own policy engine, own enforcement gateway —
no third-party identity provider, no cloud control plane.

## Architecture

Three binaries, split control plane / data plane — three heads, one system:

- **`cerberus-ctrl`** — the control plane. Runs its own mini CA, issues
  X.509 client certificates to enrolled devices, issues short-lived
  Ed25519-signed JWTs bound to the requesting certificate's thumbprint,
  and holds policy (`subject → resource → allow|deny`) in SQLite.
- **`cerberus-gw`** — the data plane gateway. Sits in front of a protected
  resource (SSH, by default). Requires mTLS, verifies the client's JWT
  is valid **and** was issued for the exact certificate presenting it,
  checks policy, then proxies raw TCP to the backend. Every denial —
  bad cert, expired token, mismatched thumbprint, policy deny, unknown
  resource — returns an identical generic rejection to the client; the
  real reason is logged server-side only.
- **`cerberusctl`** — the client CLI. `enroll` (get a cert), `login` (get
  a token), `connect` (open an authorized tunnel — usable as an SSH
  `ProxyCommand`), `mesh up` (bring up the WireGuard mesh interface).

```
cerberusctl  --mTLS-->  cerberus-gw  --mTLS-->  cerberus-ctrl   (policy sync, every 30s)
    |                        |
    `--- mTLS+JWT -----------'
                              |
                              `--> backend (sshd:22)
```

The single property this whole design exists to prove: **a valid JWT
issued for one device's certificate is rejected if presented over a
connection authenticated with a different certificate.** That's what
makes cert+JWT a real two-factor scheme instead of a bearer token with
extra steps — see `TestE2E_JWTFromDifferentCertRejected` in
[`test/integration/e2e_test.go`](test/integration/e2e_test.go).

## WireGuard mesh

Alongside the broker above, enrolled devices can opt into a WireGuard
full L3 mesh — any two mesh devices reaching each other directly,
Tailscale-style, instead of proxying through `cerberus-gw`. This is a
second, independent data plane: the broker keeps working exactly as
described above whether or not the mesh is used.

`cerberus-ctrl` has the server side of this: every enrolled device gets
a WireGuard identity and a mesh IP from `100.64.0.0/10` (CGNAT range) at
enroll time (`cerberusctl enroll` generates and registers the keypair
automatically — no extra step needed). A `/mesh` endpoint serves each
device its authorized peer set, computed from the same default-deny
policy engine the broker uses (`mesh:<device>` resources). None of that
grants reachability by itself — mesh access still requires an explicit
policy grant, same as the broker:

```bash
./bin/cerberus-ctrl admin policy add my-pc mesh:other-pc allow
```

**That single, directional grant makes the mesh path mutual.** WireGuard
requires both ends of a tunnel to configure each other as a peer before
a handshake can complete — that's a property of the WireGuard protocol
itself, not a design choice this project made lightly. So the grant
above makes `other-pc` reachable from `my-pc` *and* makes `my-pc`
reachable from `other-pc`. Fine-grained, one-directional enforcement
still lives entirely in `cerberus-gw`'s broker path — mesh only ever
grants device-level L3 reachability, never per-resource control.

The client side is `cerberusctl mesh up`, which brings up a real kernel
WireGuard interface (`cerberus0`, always listening on UDP `51820`) and
keeps it synced with `/mesh` — polling every 30s, re-applying only when
the peer set actually changed. Like `cerberus-ctrl serve` and
`cerberus-gw` above, it's a long-running process that never returns on
its own, so run it the same way, with `&` (or a supervisor):

```bash
sudo CERBERUS_STATE_DIR=./cerberusctl-state \
  ./bin/cerberusctl mesh up 127.0.0.1:8443 203.0.113.10:51820 &
```

**This requires root.** Unlike every other `cerberusctl` command, `mesh
up` creates a real kernel TUN interface, which needs `CAP_NET_ADMIN`.
Pass `CERBERUS_STATE_DIR` on the `sudo` command line itself (as above),
not via a prior `export` — `sudo` does not forward your shell's
environment by default, and root needs to read the same enrolled
state — device cert, CA, and WireGuard key — that `cerberusctl enroll`
wrote as your normal user.

`advertise_endpoint` is optional, but at least one device in a pair
needs to report one: WireGuard can only learn a peer's address from a
packet it has already received, it can never bootstrap a connection to
an address nobody advertised. There's no NAT traversal, no DERP, no
STUN in this feature — both devices need to be directly reachable at
the `IP:port` (UDP `51820`) they advertise.

## Scope

Working end to end: identity (mTLS + cert-bound JWT), policy engine,
gateway enforcement, raw-TCP (SSH) resource type, PC-to-PC, and the
opt-in WireGuard mesh (`cerberusctl mesh up`) described above.

Deliberately out of scope for now: phone/mobile clients, device posture
checks, audit logging beyond server-side deny logs, HTTP/web resource
proxying, continuous re-verification mid-session, and — specific to the
mesh — NAT traversal, DERP-style relaying, or STUN; both mesh peers must
be directly reachable at the address they advertise.

## Requirements

- Go 1.22+
- A backend service to protect (defaults to local `sshd` on port 22)
- Root / `CAP_NET_ADMIN`, only if using `cerberusctl mesh up` — everything else runs unprivileged

No external services, no cloud dependency — everything here is
self-hosted and runs on one machine.

## Build

```bash
go build -o bin/cerberus-ctrl ./cmd/cerberus-ctrl
go build -o bin/cerberus-gw   ./cmd/cerberus-gw
go build -o bin/cerberusctl   ./cmd/cerberusctl
```

## Setup

All three binaries persist state under `./ctrl-state`, `./gw-state`, and
`$CERBERUS_STATE_DIR` (default `~/.cerberus`) respectively, relative to
wherever you run them. Run `cerberus-ctrl` from one directory and keep it
there.

**1. Start the control plane** (generates its root CA and JWT signing key
on first run):

```bash
./bin/cerberus-ctrl serve &
```

**2. Register a policy** — which device may reach which resource:

```bash
./bin/cerberus-ctrl admin policy add my-pc ssh-homepc allow
```

**3. Register a client device** and note the enrollment token it prints:

```bash
./bin/cerberus-ctrl admin device add my-pc
# device "my-pc" registered. enrollment token: <64 hex chars>
```

**4. Issue the gateway its own certificate.** This bundles everything
`cerberus-gw` needs — its cert, key, the CA cert, and the control plane's
JWT public key — into one self-contained directory:

```bash
./bin/cerberus-ctrl admin gw-cert ./gw-state 127.0.0.1
```

**5. Configure and start the gateway**, pointing at whatever resource
you're protecting:

```bash
cat > gw-config.json <<'EOF'
{
  "listen_addr": "127.0.0.1:9443",
  "ctrl_addr": "127.0.0.1:8443",
  "ca_cert_path": "./gw-state/ca.crt",
  "cert_path": "./gw-state/gw.crt",
  "key_path": "./gw-state/gw.key",
  "jwt_pub_path": "./gw-state/jwt.pub",
  "backends": {"ssh-homepc": "127.0.0.1:22"}
}
EOF

./bin/cerberus-gw ./gw-config.json &
```

**6. Enroll and connect from the client**, using the token from step 3:

```bash
export CERBERUS_STATE_DIR=./cerberusctl-state

./bin/cerberusctl enroll 127.0.0.1:8443 ./ctrl-state/root-ca.crt <token>
./bin/cerberusctl login  127.0.0.1:8443
./bin/cerberusctl connect 127.0.0.1:9443 ssh-homepc
```

That last command speaks raw stdin/stdout over the authorized tunnel —
use it as an SSH `ProxyCommand` for a real session:

```bash
ssh -o ProxyCommand="CERBERUS_STATE_DIR=./cerberusctl-state ./bin/cerberusctl connect 127.0.0.1:9443 ssh-homepc" \
    someuser@ssh-homepc
```

A device with no matching policy, an expired token, or a token that
doesn't match its presenting certificate all get the same generic
rejection — check `cerberus-gw`'s log output for the real reason.

## Testing

```bash
go test ./...            # full suite
go test ./... -cover     # with coverage (all logic packages ≥80%)
go test ./... -race      # concurrency-sensitive packages (gwserver, gwproxy)
```

`test/integration/e2e_test.go` drives the real HTTP+TLS enroll → login →
connect flow end to end, including the critical cert/JWT-binding test.

## Security notes

- Revocation (`cerberus-ctrl admin device revoke <id>`) blocks future
  logins immediately, but a JWT already issued to that device stays valid
  until its TTL expires (15 minutes by default) — this is a known
  limitation of the stateless-token design, not a bug.
- All private key material is written `0600`; public certs `0644`.
- The gateway and control-plane HTTP listeners both enforce read/write
  timeouts to resist slow-connection resource exhaustion.
- WireGuard public keys and mesh IPs are each unique per device (enforced
  at the database level), and a self-reported WireGuard endpoint is
  validated as a strict `IP:port` before it's persisted or handed to
  another device.

## License

MIT
