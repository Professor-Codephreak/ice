# Reverse tunnel — inbound for a node that holds no router admin

**Summary.** A reverse SSH tunnel rents a public TCP port on a machine you *do* control (a VPS, a
friend's server, a VPN endpoint) and pulls it back to this node's `:8333` over one outbound SSH
session. The laptop never needs a router rule, a static IP, UPnP or NAT-PMP. ICE keeps the session
alive with a systemd **user** unit (`bankon-ice-tunnel.service`), tells Bitcoin Core to advertise
the endpoint (`externalip`), and proves the result **from outside** by dialling the endpoint through
a Tor exit. It costs one shell account with key auth on the endpoint and one line in its `sshd_config`.
It trades a little privacy (the endpoint provider sees that a node is there) and Core's netgroup
diversity (every inbound peer arrives through the same tunnel) for reachability that works anywhere.

Where it lives: `bankon-qt/services/ice_reach.py` (`tunnel_setup`, `tunnel_state`,
`tunnel_selftest`, `tunnel_remove`), the 🔌 Connections → **🚇 Tunnel** page, and the
`extensions/tunnel.py` ICE panel (the same truth, as a panel and a CLI).

---

## 1. The problem it solves

A home node is behind carrier NAT or a gateway whose admin page you cannot change. Outbound works,
so the chain syncs — but nobody can dial *you*. The host can only verify a router forward, never
make one (see `docs/ICE.md` §B3 and the ⇄ clearnet self-test, which proved on 2026-10-27 that both
IPv4 and IPv6 to this node are silently dropped).

The paths that need **no router**:

| path | what it needs | who can dial you | latency | privacy |
|---|---|---|---|---|
| Tor onion service (`docs/tor.md`) | tor on the laptop | onion-capable peers | +1–3 s | high |
| I2P (`docs/I2P.md`) | i2pd on the laptop | I2P-capable peers | +seconds | high |
| **reverse tunnel** (this doc) | an account on any public host | **everyone on clearnet** | +endpoint RTT | endpoint sees you |

The tunnel is the only one that gives clearnet IPv4 peers a way in.

## 2. How it works, hop by hop

```
 peer anywhere ──TCP──▶ ENDPOINT:8333 ──(sshd -R)──▶ ssh session ──▶ laptop 127.0.0.1:8333 (Core)
                                                          ▲
                                       one OUTBOUND ssh connection from the laptop (port 22)
```

1. The laptop opens an ordinary outbound SSH session to the endpoint. NAT allows it like any
   outbound connection.
2. `ssh -R 0.0.0.0:8333:127.0.0.1:8333` asks the endpoint's sshd to **listen** on its public
   `:8333` and forward every connection back down the session to the laptop's `127.0.0.1:8333`.
3. Core accepts the connection on its normal listener. It sees the peer as coming from
   `127.0.0.1:<port>` — the local end of the tunnel — exactly like inbound onion peers, which
   arrive from Tor's local proxy. (This is also why `localhost` shows up in the peer list; it is
   not the gateway. The gateway is the router at `10.0.0.1`.)
4. `externalip=<endpoint ip>:8333` in bitcoin.conf makes Core advertise the endpoint's address in
   its `addr` messages, so other nodes learn where to dial.

The exact command the unit runs:

```
/usr/bin/ssh -NT -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
             -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p 22 [-i KEY] \
             -R 0.0.0.0:8333:127.0.0.1:8333 user@endpoint
```

| flag | why |
|---|---|
| `-N -T` | no remote command, no tty: the session exists only to carry the forward |
| `ExitOnForwardFailure=yes` | if the endpoint refuses the port, ssh exits non-zero so systemd restarts instead of sitting there "connected" with no forward |
| `ServerAliveInterval=30 / CountMax=3` | a dead link is noticed within 90 s (NAT tables time out silently) |
| `BatchMode=yes` | never prompt — a unit has nobody to type a password; key auth is required |
| `StrictHostKeyChecking=accept-new` | first contact pins the host key; a changed key later is refused (MITM defence) |
| `Restart=always · RestartSec=10` (unit) | systemd is the retry: sane, systematic, logged — same philosophy as netkeep |

## 3. Setting it up (one page in ICE)

**On the endpoint** (once):

```
# as root on the VPS
adduser --disabled-password bankon          # a user that can only hold the tunnel
mkdir -p /home/bankon/.ssh && cat laptop_key.pub >> /home/bankon/.ssh/authorized_keys
chown -R bankon:bankon /home/bankon/.ssh && chmod 700 /home/bankon/.ssh && chmod 600 /home/bankon/.ssh/authorized_keys
printf 'Match User bankon\n  GatewayPorts clientspecified\n  AllowTcpForwarding remote\n  PermitTTY no\n  X11Forwarding no\n' >> /etc/ssh/sshd_config
systemctl reload sshd
ufw allow 8333/tcp        # or the provider's firewall panel
```

`GatewayPorts` is the line people miss: without it sshd binds the `-R` port on the endpoint's
loopback only and nobody outside can reach it. `clientspecified` lets our `0.0.0.0:` prefix choose.

**On the laptop** (ICE): 🔌 Connections → 🚇 Tunnel → endpoint `bankon@vps.example`, SSH port,
remote port `8333`, identity file (default `~/.ssh/id_ed25519`), ✓ advertise → **▶ install &
start**. ICE writes `~/.config/systemd/user/bankon-ice-tunnel.service`, enables it, writes
`externalip`, and reports the unit's state and its last log lines. Restart Core once so it advertises.

Generate a key if you have none: `ssh-keygen -t ed25519 -f ~/.ssh/bankon_tunnel -N ''`.

## 4. Proving it — from outside

A green unit only proves the SSH session. **🧪 prove from outside** dials `<endpoint ip>:8333`
through a **Tor exit** (so no third-party "port checker" is involved) and, if that fails, dials one
of our own outbound peers through the same exit as a *control*. Control connects + endpoint times
out ⇒ the endpoint is not forwarding (usually `GatewayPorts`, or its firewall). Control fails ⇒
inconclusive, that exit cannot do IPv4; retry picks another exit. Core logs the successful probe as
`connection from 127.0.0.1:<port> accepted` followed by a short disconnect.

Then watch 🌐 Reachability: the tunnel row shows `inbound via tunnel N` — inbound peers that arrived
from loopback but *not* via Core's onion listener. The Net Log and Net Map show them like any
inbound peer. Each probe and each setup/remove is `.history` evidence (`ice-connections`).

## 5. What you give up, honestly

- **The endpoint sees traffic metadata.** With BIP 324 (v2 transport, Core ≥ 26) peer traffic is
  encrypted, so the endpoint sees *that* you run a node and the byte counts, not the messages.
  With v1 peers it sees everything on the wire (which is public data anyway). It cannot forge
  blocks — your node validates everything.
- **One netgroup.** Core protects inbound slots by network group so one /16 cannot crowd out the
  rest (`net.cpp`, `AttemptToEvictConnection`). Every tunnel peer arrives from `127.0.0.1`, so to
  Core they are one group. Fine for serving; weaker as Sybil defence than genuinely diverse inbound.
- **Reachability is rented.** If the endpoint dies, inbound dies; outbound and the chain are
  untouched. netkeep does not touch the tunnel; systemd restarts it.
- **The endpoint's address is public.** It is in your `addr` announcements by design.

## 6. Failure modes the page reports

| symptom | meaning | fix |
|---|---|---|
| unit `activating` / `failed`, log `Permission denied (publickey)` | key not in `authorized_keys` or wrong `-i` | fix the key; `BatchMode` never prompts |
| log `remote port forwarding failed for listen port 8333` | sshd refused `0.0.0.0:8333` | `GatewayPorts clientspecified`, or the port is taken on the endpoint |
| unit active, self-test ✗ with a good control | endpoint firewall / provider panel blocks 8333 | open it there |
| self-test `inconclusive` | that Tor exit has no IPv4 route to the target | press again |
| `inbound via tunnel 0` for hours after a ✓ self-test | Core not advertising yet | restart Core after `externalip` was written; wait — peers learn addresses slowly |

## 7. Removing it

🚇 Tunnel → **■ remove**: stops and disables the unit, deletes it, comments out `externalip` in
bitcoin.conf (backup kept) and forgets the endpoint. Restart Core to stop advertising.

## 8. Alternatives on the same page

- **WireGuard to a VPS** with a DNAT rule on the VPS — lower overhead than SSH, more setup; the ICE
  unit pattern applies unchanged (replace the ExecStart). Not automated.
- **A friend's reachable node as `addnode`** — not inbound for you, but a guaranteed good peer;
  ⇶ Peers page.
- **Tor / I2P** — no third party, no clearnet reachability; the recommended default. See
  `docs/tor.md` and `docs/I2P.md`.

## References

- OpenSSH `ssh(1)` `-R`, `ssh_config(5)` `ExitOnForwardFailure`, `sshd_config(5)` `GatewayPorts`:
  https://man.openbsd.org/ssh.1 · https://man.openbsd.org/sshd_config.5
- Bitcoin Core `-externalip`, `-discover`, `-listen`: https://github.com/bitcoin/bitcoin/blob/v31.0/src/init.cpp
- Netgroup-based eviction: https://github.com/bitcoin/bitcoin/blob/v31.0/src/net.cpp (`AttemptToEvictConnection`, `src/node/eviction.cpp`)
- BIP 324 (v2 encrypted transport): https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
- systemd user units: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
- This repo: `bankon-qt/services/ice_reach.py`, `bankon-qt/extensions/tunnel.py`, `docs/ICE.md` §B3, `docs/ICE-EXTENSIONS.md`
