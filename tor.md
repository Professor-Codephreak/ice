# Tor — the node's onion service, Core's torcontrol, and ICE's diagnostics

**Summary.** Tor gives this node inbound connectivity with **no router, no public IP and no third
party**: Bitcoin Core talks to the local tor daemon's **control port**, asks it to create a v3
**onion service** that points at Core's listener, and advertises the resulting `…onion:8333`
address to the network. Inbound onion peers reach Core through tor's local socket, which is why
they show as `127.0.0.1:<port>` in `getpeerinfo` (tagged 🧅 on the Net Map). Outbound to other
onion peers goes through tor's SOCKS5 proxy. ICE enabled all of this on 2026-10-27 with one pkexec
(`enable_onion`), proved it with the **onion self-test** (dial our own onion through tor), and the
first inbound onion peer arrived at 14:43 the same day. The 🧅 Tor page reads health straight from
tor's control port. Tor also lets the WaaS API itself be published as a **service onion** so
clients reach it with no router change (§6).

---

## 1. How Core uses Tor (the source, by file)

| what | where (Bitcoin Core v31.0) |
|---|---|
| control-port client: `PROTOCOLINFO`, `AUTHENTICATE`, `ADD_ONION NEW:ED25519-V3`, reconnect with backoff | [`src/torcontrol.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/torcontrol.cpp) · [`src/torcontrol.h`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/torcontrol.h) (`TorController`, `TorControlConnection`) |
| options `-torcontrol` (default `127.0.0.1:9051`), `-torpassword`, `-listenonion` (default 1 with `-listen`), `-onion`/`-proxy` (SOCKS5), `-onlynet=onion` | [`src/init.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/init.cpp) |
| the onion listener Core binds for the service target (`-bind=127.0.0.1:8334=onion` by default) | [`src/init.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/init.cpp), [`src/net.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/net.cpp) (`CConnman::Bind`, `BF_DONT_ADVERTISE`) |
| SOCKS5 outbound through tor, `.onion` resolution never leaves the host | [`src/netbase.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/netbase.cpp) (`Socks5`, `ConnectThroughProxy`) |
| v3 onion address encoding (56 chars, ed25519 pubkey + checksum + version) | [`src/netaddress.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/netaddress.cpp) (`SetTor`) |
| how onion addresses travel between nodes | [BIP 155 addrv2](https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki) (network id 4 = TorV3) |
| the user guide that ships with Core | [`doc/tor.md`](https://github.com/bitcoin/bitcoin/blob/v31.0/doc/tor.md) |

Mechanics from `src/torcontrol.cpp`:

- **Authentication order.** Core reads `PROTOCOLINFO`; it uses `NULL` auth if tor allows it,
  `HASHEDPASSWORD` if `-torpassword` is set, else `SAFECOOKIE` (reads the cookie file — which is why
  Debian puts users in the `debian-tor` group). ICE uses a **hashed password** so no group juggling
  and no cookie permissions: `torrc` gets `ControlPort 9051`, `HashedControlPassword`,
  `CookieAuthentication 0`; bitcoin.conf gets the clear password (0600 file).
- **The service key is Core's, not tor's.** `ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8334`
  the first time; the returned private key is stored at `<datadir>/onion_v3_private_key` and
  re-sent as `ADD_ONION ED25519-V3:<key>` on every start, so the address is stable. Delete the file
  for a new address.
- **Reconnect ladder.** If the control port drops, Core retries from 1 s, ×1.5 each time, capped at
  10 min (`RECONNECT_TIMEOUT_START/EXP/MAX`). Toggling Tor OFF/ON in ICE therefore needs no Core restart.
- **Two listeners.** Clearnet inbound on `0.0.0.0:8333`; the onion target on `127.0.0.1:8334`
  marked *don't advertise*. Tor connects to 8334 and Core knows those peers are onion
  (`network: "onion"` in getpeerinfo) even though the TCP source is loopback.
- **Privacy guard.** With `-proxy` set Core will not resolve DNS seeds in the clear and will not
  advertise your clearnet address unless `-discover`/`-externalip` say so (`doc/tor.md` §"Privacy").

## 2. The tor side

```
 Tor network ──rendezvous──▶ tor daemon ──TCP 127.0.0.1:8334──▶ Core (inbound onion)
 Core ──SOCKS5 127.0.0.1:9050──▶ tor daemon ──circuits──▶ other .onion peers (outbound onion)
 Core ──127.0.0.1:9051 (control)──▶ tor daemon            (ADD_ONION, GETINFO)
```

Links: [tor manual](https://2019.www.torproject.org/docs/tor-manual.html.en) · [control-port spec](https://spec.torproject.org/control-spec/index.html)
(`GETINFO status/bootstrap-phase`, `network-liveness`, `circuit-status`, `traffic/read`) ·
[onion services v3 spec](https://spec.torproject.org/rend-spec/index.html) · [tor source](https://gitlab.torproject.org/tpo/core/tor) ·
[Tor Project onion service guide](https://community.torproject.org/onion-services/setup/).

## 3. bitcoin.conf — the exceptional examples

What ICE wrote on this host (block marked `# ── Tor onion service (ICE reachability) ──`):

```
listenonion=1
torcontrol=127.0.0.1:9051
torpassword=<secret, bitcoin.conf is 0600>
onion=127.0.0.1:9050
```

`/etc/tor/torrc` lines ICE added:

```
ControlPort 9051
HashedControlPassword 16:…
CookieAuthentication 0
```

Tor-only node (never a clearnet packet from Core; the recommended privacy configuration in Core's `doc/tor.md`):

```
proxy=127.0.0.1:9050
onlynet=onion
listen=1
listenonion=1
torcontrol=127.0.0.1:9051
torpassword=…
bind=127.0.0.1
```

Tor plus clearnet, but keep clearnet DNS/seed lookups off the ISP (what many "dual-stack" guides recommend):

```
proxy=127.0.0.1:9050
onion=127.0.0.1:9050
listenonion=1
torcontrol=127.0.0.1:9051
```

Outbound through Tor, no onion service of your own (no inbound):

```
onion=127.0.0.1:9050
listenonion=0
```

Pin a known onion peer:

```
addnode=rx6aafds2z3oj3c5npswji6m6uncziym4djywm5i5c3k5t3s6lmp3pid.onion:8333
```

Debug the control-port conversation:

```
debug=tor
```

## 4. What the 🧅 Tor page shows and where each number comes from

| row | source |
|---|---|
| tor service / ports | `systemctl is-active tor`, sockets 9050 (SOCKS) and 9051 (control) |
| bootstrap % | control `GETINFO status/bootstrap-phase` (`PROGRESS=100` = usable) |
| liveness | `GETINFO network-liveness` + `status/circuit-established` |
| circuits / OR connections | `GETINFO circuit-status` (count `BUILT`), `orconn-status` |
| traffic | `GETINFO traffic/read`, `traffic/written` — bytes since tor started (shown with the Σ toggle: actual/scientific) |
| version | `GETINFO version` |
| onion service | `getnetworkinfo.localaddresses` `.onion` + `networks.onion.reachable` |
| service onion | `~/.bankon/ice-service-onion.json` + local ports listening (§6) |
| onion peers | `getpeerinfo` `network == "onion"`, in / out |
| bitcoin.conf | the Tor lines as written |
| tor log | `journalctl -u tor -n 3` |

The control-port reader (`ice_reach._tor_control`) authenticates with the `torpassword` from
bitcoin.conf, sends each `GETINFO`, and parses both single-line (`250-key=value`) and multi-line
(`250+key=` … `.`) replies — circuit lists are multi-line, and mixing the two was a bug ICE fixed.

## 5. Proving it

- **🧪 onion self-test** (`onion_selftest`): a SOCKS5 CONNECT to our own `.onion:8333` through
  tor. Success means the rendezvous works end to end: the descriptor is published, tor reaches our
  service, Core's 8334 listener answered. Nothing outside tor is involved.
- **Inbound seen**: Overview `N in`, Net Log rows with `network onion`, Net Map 🧅 ring, and in
  debug.log `connection from 127.0.0.1:<port> accepted` (with `debug=net`, persisted in bitcoin.conf).
- **Evidence**: every enable/toggle/self-test is a `.history` row (`ice-connections`, `ice-reach`).

## 6. Service onion — the WaaS API reachable with no router

Core's onion serves *peers*. Clients of **BANKONBTCWaaS** talk to the WaaS API on `127.0.0.1:8088`
(Express, loopback only on purpose). ICE can publish that port (and optionally the Console :8090) as
**one more v3 hidden service** in torrc (`HiddenServiceDir /var/lib/tor/bankon-service/`,
`HiddenServicePort 8088 127.0.0.1:8088`), reload tor, and store the generated address 0600 in
`~/.bankon/ice-service-onion.json`. A client then uses `http://<56 chars>.onion:8088` over any Tor
client — no router, no DNS, no certificate authority (the onion address *is* the key).

**Guard:** the WaaS API is open unless `BANKON_API_TOKEN` is set in its unit environment
(`bankon-waas/server.mjs`: `app.use('/api', apiAuth())`). ICE refuses to publish it without that
token unless you explicitly override, because an onion address is unguessable but not secret once
shared. Set the token first:

```
systemctl --user edit bankon-waas      # [Service] Environment=BANKON_API_TOKEN=<long random>
systemctl --user restart bankon-waas
```

Then 🧅 Tor → **publish service onion** → **🧪 service self-test** (dials every published port
through tor). **remove** deletes the torrc block, the keys and the address.

## 7. Costs and limits, honestly

- Latency 1–3 s per connect; block relay over onion is a little slower than clearnet.
- Onion inbound peers all appear from loopback — fine, Core tracks them as `onion` for eviction
  diversity (unlike a reverse tunnel, see `docs/reversetunnel.md`).
- Tor OFF (🧅 switch) drops outbound onion peers too; Core's torcontrol reconnects when it is back.
- The clear `torpassword` lives in bitcoin.conf (0600). The hashed form lives in torrc.
- tor is one more daemon; its control port is loopback-only and password-protected.

## References

- Bitcoin Core: [`doc/tor.md`](https://github.com/bitcoin/bitcoin/blob/v31.0/doc/tor.md),
  [`src/torcontrol.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/torcontrol.cpp),
  [`src/netbase.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/netbase.cpp),
  [`doc/p2p-bad-ports.md`](https://github.com/bitcoin/bitcoin/blob/v31.0/doc/p2p-bad-ports.md)
- Tor: [control-port spec](https://spec.torproject.org/control-spec/index.html) · [rend-spec v3](https://spec.torproject.org/rend-spec/index.html) · [tor manual](https://2019.www.torproject.org/docs/tor-manual.html.en) · [source](https://gitlab.torproject.org/tpo/core/tor)
- [BIP 155](https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki) · [BIP 324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
- This repo: `bankon-qt/services/ice_reach.py` (`enable_onion`, `tor_state`, `tor_diagnostics`, `onion_selftest`, `service_onion_*`), `bankon-qt/ice_connections.py` (🧅 page), `docs/ICE.md` §B3, `docs/I2P.md`, `docs/reversetunnel.md`
