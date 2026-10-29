# I2P — a second anonymous network for the node, with its own inbound

**Summary.** I2P (the Invisible Internet Project) is a garlic-routed overlay network. Bitcoin Core
has spoken it natively since **v22.0** through an I2P router's **SAM v3** bridge: Core creates an
I2P *destination* (its address, `<52 chars>.b32.i2p`), connects out to other `.b32.i2p` peers and
accepts inbound through the same session. No router port, no public IP, no third party — only an
I2P router daemon on the laptop (**i2pd**, C++). ICE enables it with one pkexec
(`enable_i2p`: install i2pd, switch on `[sam]`, write `i2psam=127.0.0.1:7656`, restart Core) and
shows it on 🔌 Connections → 🌐 Reachability. I2P is slower than Tor (seconds per connect, tunnels
rebuilt every 10 minutes) and smaller (a few hundred Bitcoin nodes), so run it **alongside** Tor and
clearnet, never alone, unless privacy is the only goal.

Status on this host (2026-10-28): `i2psam` is in bitcoin.conf and Core was restarted with it; the
Ubuntu-packaged **i2pd 2.39.0 segfaults at start** on this system, so SAM is not up yet. The fix is
the project's own PPA (§6). Core simply reports `i2p reachable: false` until SAM answers — nothing
else is affected.

---

## 1. How Core uses I2P (the source, by file)

| what | where (Bitcoin Core v31.0) |
|---|---|
| SAM 3.1 client: `HELLO`, `SESSION CREATE`, `STREAM CONNECT`, `STREAM ACCEPT`, `DEST GENERATE` | [`src/i2p.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/i2p.cpp) · [`src/i2p.h`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/i2p.h) (`i2p::sam::Session`) |
| the accept loop that turns SAM streams into peers | [`src/net.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/net.cpp) `CConnman::ThreadI2PAcceptIncoming`, `CConnman::ConnectNode` (I2P branch) |
| options `-i2psam=<ip:port>`, `-i2pacceptincoming` (default 1), `-onlynet=i2p` | [`src/init.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/init.cpp) |
| the address type (`NET_I2P`, 32-byte destination hash, port always 0) | [`src/netaddress.h`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/netaddress.h) · [`src/netbase.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/netbase.cpp) (`.b32.i2p` parsing) |
| how I2P addresses travel between nodes | [BIP 155 addrv2](https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki) (network id 5 = I2P) |
| the user guide that ships with Core | [`doc/i2p.md`](https://github.com/bitcoin/bitcoin/blob/v31.0/doc/i2p.md) |
| the PR that added it | [bitcoin/bitcoin#20685](https://github.com/bitcoin/bitcoin/pull/20685) "Add I2P support using I2P SAM" (Vasil Dimov, 2021) |

Mechanics worth knowing, straight from `src/i2p.cpp`:

- **Persistent destination.** On first start Core asks SAM `DEST GENERATE SIGNATURE_TYPE=7`
  (EdDSA-Ed25519) and stores the private key as `<datadir>/i2p_private_key`. Delete it to get a new
  address. The public address is `getnetworkinfo.localaddresses` → `…b32.i2p:0`.
- **One session for inbound + outbound** when `-i2pacceptincoming=1` (default). With
  `-i2pacceptincoming=0` Core opens a **transient** session per outbound connection, so your
  destination is never published — maximum privacy, no inbound.
- **Port is always 0.** I2P has no ports; Core encodes `.b32.i2p` peers with port 0 and ignores any
  port you type after an I2P address in `addnode`.
- **Lease sets** are published with `i2cp.leaseSetEncType=4,0` so modern routers can reach you.
- **Timeouts are generous**: a SAM `STREAM CONNECT` may take tens of seconds; Core treats I2P as a
  slow network in its connection scheduling (`net.cpp`, `m_network` aware outbound selection).

## 2. How i2pd fits

```
 Bitcoin Core ──TCP 127.0.0.1:7656 (SAM v3)──▶ i2pd ──garlic tunnels (UDP/TCP 4567+ random)──▶ I2P network
```

i2pd exposes: **SAM** (:7656, Core's door), a web console (:7070), an HTTP proxy (:4444), and its
transport port picked at install. Only SAM must be on; ICE's `enable_i2p` sets `[sam] enabled = true`
in `/etc/i2pd/i2pd.conf` and restarts the service. i2pd needs a few minutes after first start to
build tunnels and fill its netDb (`/var/lib/i2pd/netDb`) before SAM sessions succeed.

Links: [i2pd](https://github.com/PurpleI2P/i2pd) · [i2pd docs](https://i2pd.readthedocs.io/) ·
[SAM v3 spec](https://geti2p.net/en/docs/api/samv3) · [I2P project](https://geti2p.net/) ·
[I2P technical introduction](https://geti2p.net/en/docs/how/tech-intro) (garlic routing, lease sets, netDb).

## 3. bitcoin.conf — the exceptional examples

The one line ICE writes:

```
i2psam=127.0.0.1:7656
```

Full dual-stack node (what this host runs: clearnet + Tor + I2P, all inbound), from Core's own
`doc/i2p.md` and `doc/tor.md`:

```
listen=1
# Tor
listenonion=1
torcontrol=127.0.0.1:9051
torpassword=…
onion=127.0.0.1:9050
# I2P
i2psam=127.0.0.1:7656
i2pacceptincoming=1
```

Privacy-first (never touch clearnet, still serve both anonymous networks):

```
onlynet=onion
onlynet=i2p
proxy=127.0.0.1:9050        # clearnet DNS seeds etc. never leave through the ISP
i2psam=127.0.0.1:7656
listenonion=1
torcontrol=127.0.0.1:9051
```

Outbound-only on I2P (no destination published):

```
i2psam=127.0.0.1:7656
i2pacceptincoming=0
```

Pin a known I2P peer (port must be 0 or omitted):

```
addnode=zlrbo53wfzudvm6h4rjgkfs4kbrmoj4yfilyfn5jb5bw6hssrgch.b32.i2p
```

Debug what Core and SAM say to each other:

```
debug=i2p
```

## 4. Verifying from ICE and the CLI

- 🌐 Reachability → **I2P (i2psam)** row: `configured` once bitcoin.conf has it, i2pd unit state.
- `bitcoin-cli getnetworkinfo` → `networks[].name == "i2p"` → `reachable: true` once SAM is up;
  `localaddresses` lists your `.b32.i2p`.
- `bitcoin-cli getpeerinfo | grep -c '"network": "i2p"'` — I2P peers (out and in).
- `ss -ltn | grep 7656` — SAM listening; `systemctl status i2pd`; `journalctl -u i2pd -n 30`.
- i2pd's console at `http://127.0.0.1:7070` (the I2P row quotes it): **Network status: Firewalled** is
  normal on a NAT host — i2pd still routes through introducers, only transit is reduced; **Tunnel
  creation success rate** climbs over the first minutes; Core's destination appears once SAM can
  build the session's lease set.
- `bitcoin-cli logging '["i2p"]'` turns on Core's I2P log category at runtime (`debug=i2p` to persist).
- The Net Map tags I2P peers; the Net Log's `network` column says `i2p`.

## 5. What it costs and what it buys

| | I2P | Tor onion |
|---|---|---|
| connect latency | seconds; tunnels rebuilt every 10 min | 1–3 s |
| network size (Bitcoin nodes) | hundreds | thousands |
| bandwidth overhead | moderate (garlic layers, tunnel maintenance) | low |
| design | peer-to-peer, every participant routes a little | directory authorities + relays |
| inbound needs | nothing but i2pd | nothing but tor |
| extra attack surface | i2pd binary + its UDP/TCP transport port | tor binary + control port (local) |

Both are valuable for **partition resistance**: a node reachable on three networks is far harder to
eclipse. Core's outbound logic deliberately keeps at least one connection per reachable network
(`net.cpp`, "network-specific outbound").

## 6. Known problem on this host — i2pd 2.39.0 segfault

Ubuntu jammy's `i2pd 2.39.0-1ubuntu1` crashes on start here (`SIGSEGV`, `journalctl -u i2pd`).
The current release is in the project's PPA. Three ways to take that step, all idempotent:

- **ICE**: 🔌 Connections → Reachability → **enable I2P** — `enable_i2p` now adds
  `ppa:purplei2p/i2pd` on apt systems before installing i2pd (one pkexec prompt).
- **bankonOS installer**: `ONLY=reach ./bankonos/install.sh` (tor + i2pd; PPA on Debian/Ubuntu).
- **ICE installer**: `~/ICE/install.sh --reach`.
- **By hand** (what the above run):

```
sudo add-apt-repository -y ppa:purplei2p/i2pd
sudo apt-get update            # may exit non-zero because of OTHER stale repos — the PPA's lists are still fetched
sudo apt-get install -y i2pd && sudo systemctl restart i2pd && sleep 5 && ss -ltn | grep 7656
```

Then `bitcoin-cli getnetworkinfo` shows `i2p reachable: true` within a few minutes (Core reconnects
to SAM by itself; no Core restart needed). If you prefer not to add a PPA: build from source
(`https://i2pd.readthedocs.io/en/latest/devs/building/unix/`) or run the Java router
(`https://geti2p.net/en/download/debian`) — Core only needs *a* SAM bridge on 7656.

## References

- Bitcoin Core: [`doc/i2p.md`](https://github.com/bitcoin/bitcoin/blob/v31.0/doc/i2p.md),
  [`src/i2p.cpp`](https://github.com/bitcoin/bitcoin/blob/v31.0/src/i2p.cpp),
  [release notes 22.0 — I2P](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-22.0.md)
- [BIP 155 addrv2](https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki) · [BIP 324 v2 transport](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) (works over I2P too)
- i2pd: [repo](https://github.com/PurpleI2P/i2pd) · [docs](https://i2pd.readthedocs.io/) · [PPA](https://launchpad.net/~purplei2p/+archive/ubuntu/i2pd) · [SAM v3](https://geti2p.net/en/docs/api/samv3)
- This repo: `bankon-qt/services/ice_reach.py` (`enable_i2p`, `probe`), `docs/ICE.md` §B3, `docs/tor.md`, `docs/reversetunnel.md`
