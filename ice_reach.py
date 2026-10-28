"""ICE reach — inbound reachability for the node, every path as an option. Qt-free; one job.

Paths a home node has to be reachable from the network, each probed honestly and each with a
single-task action where the host can act by itself:

  ipv4-forward   router forwards TCP 8333 → this host (router UI — the host can only verify)
  ipv6-pinhole   router IPv6 firewall allows TCP 8333 → this host's global address (router UI)
  pcp/natpmp     Core asks the router to map the port itself (-natpmp, default on) — observed in debug.log
  upnp           router IGD — Core dropped UPnP in v29; probed only to say so
  tor-onion      Core creates its own hidden service (listenonion + torcontrol) — no router needed
  i2p            i2psam — an I2P router on the host
  ufw            the host firewall must allow 8333/tcp (the second wall)
  tunnel         a rented public endpoint (VPS / VPN port) — documented, never automated

Truth sources: bitcoin.conf, getnetworkinfo (localaddresses, networks[].reachable, connections_in),
getpeerinfo (inbound per network, addrlocal = our public address as peers see it),
systemd (tor, i2pd), /etc/tor/torrc, ufw, debug.log (pcp lines), the socket layer.
Mutations escalate with pkexec and are evidence (.history kind ice-reach). ICE has precedence.
"""
import json, os, re, shutil, socket, subprocess, time, urllib.request

CONF = os.path.expanduser("~/.bitcoin/bitcoin.conf")
DEBUGLOG = os.path.expanduser("~/.bitcoin/debug.log")
TORRC = "/etc/tor/torrc"
PORT = 8333


def _run(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _has(b):
    return shutil.which(b) is not None


def _port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def conf():
    d = {"listen": "1", "listenonion": None, "torcontrol": None, "torpassword": None, "onion": None, "proxy": None,
         "i2psam": None, "natpmp": None, "bind": [], "externalip": [], "onlynet": [], "discover": None}
    try:
        for ln in open(CONF):
            ln = ln.split("#", 1)[0].strip()
            if "=" not in ln:
                continue
            k, v = (x.strip() for x in ln.split("=", 1))
            if k in ("bind", "externalip", "onlynet"):
                d[k].append(v)
            elif k in d:
                d[k] = v
    except OSError:
        d["missing"] = True
    return d


def rpc(method, params=None, timeout=8):
    """bitcoin-cli (cookie auth), parsed — None when the node is down or choked."""
    r = _run(["bitcoin-cli", method] + [json.dumps(p) if not isinstance(p, str) else p for p in (params or [])], timeout=timeout)
    if not r or r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return r.stdout.strip()


def _unit(name):
    if not _has("systemctl"):
        return None
    r = _run(["systemctl", "is-active", name], timeout=4)
    return (r.stdout.strip() if r else None) or None


def _pcp_log(lines=400):
    """Last PCP/NAT-PMP outcome Core logged (-natpmp): 'mapped' | 'timeout' | 'bind-error' | None."""
    try:
        with open(DEBUGLOG, "rb") as fh:
            fh.seek(0, 2); size = fh.tell(); fh.seek(max(0, size - 4_000_000)); tail = fh.read().decode(errors="ignore")
    except OSError:
        return None, None
    last = None
    for ln in tail.splitlines():
        if "pcp:" in ln or "natpmp" in ln.lower():
            last = ln
    if not last:
        return None, None
    low = last.lower()
    if "giving up" in low or "timeout" in low: return "timeout", last[:160]
    if "could not bind" in low: return "bind-error", last[:160]
    if "mapped" in low or "success" in low: return "mapped", last[:160]
    return "seen", last[:160]


def _upnp_probe(timeout=1.5):
    m = ("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\n"
         "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout); s.sendto(m, ("239.255.255.250", 1900))
        s.recvfrom(2048); return True
    except Exception:
        return False


def _natpmp_probe(gw, timeout=1.5):
    if not gw:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout); s.sendto(bytes([0, 0]), (gw, 5351))
        s.recvfrom(64); return True
    except Exception:
        return False


def _gateway():
    r = _run(["ip", "-4", "route", "show", "default"])
    m = re.search(r"default via (\S+)", r.stdout) if r else None
    return m.group(1) if m else None


def _ipv6_global(iface=None):
    r = _run(["ip", "-6", "addr", "show", "scope", "global"] + (["dev", iface] if iface else []))
    out = []
    for ln in (r.stdout.splitlines() if r else []):
        m = re.search(r"inet6 (\S+)/", ln)
        if m and "temporary" not in ln: out.append(m.group(1))
    return out


def _ufw_8333():
    """True/False/None(unknown — ufw status needs root; we read the rules file when readable)."""
    for path in ("/etc/ufw/user.rules", "/etc/ufw/user6.rules"):
        try:
            txt = open(path).read()
            if re.search(r"--dport 8333 .*-j ACCEPT", txt): return True
        except OSError:
            pass
    r = _run(["ufw", "status"], timeout=4)          # works without root only when ufw is permissive
    if r and r.returncode == 0:
        return bool(re.search(r"^8333(/tcp)?\s+ALLOW", r.stdout, re.M))
    return None


def tor_state():
    cs = conf()
    st = {"installed": _has("tor"), "service": _unit("tor"), "socks": _port_open("127.0.0.1", 9050),
          "control": _port_open("127.0.0.1", 9051), "torrc_control": False,
          "conf_listenonion": cs.get("listenonion") == "1", "conf_torcontrol": cs.get("torcontrol"),
          "conf_onion": cs.get("onion") or cs.get("proxy"), "onion_addr": None, "onion_reachable": None}
    try:
        st["torrc_control"] = bool(re.search(r"^ControlPort\s+9051", open(TORRC).read(), re.M))
    except OSError:
        pass
    ni = rpc("getnetworkinfo")
    if ni:
        for la in ni.get("localaddresses", []):
            if str(la.get("address", "")).endswith(".onion"):
                st["onion_addr"] = f"{la['address']}:{la.get('port', PORT)}"
        st["onion_reachable"] = next((n.get("reachable") for n in ni.get("networks", []) if n.get("name") == "onion"), None)
    return st


def onion_selftest(timeout=25):
    """The one inbound test that needs no outside help: dial our OWN onion through Tor's SOCKS.
    Returns (ok, detail). A connect through the Tor network proves the hidden service answers."""
    st = tor_state()
    if not st["onion_addr"]:
        return None, "no onion address yet (Core creates it after torcontrol connects; wait ~1 min after restart)"
    host, port = st["onion_addr"].rsplit(":", 1)
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=5)
        s.sendall(b"\x05\x01\x00"); 
        if s.recv(2) != b"\x05\x00": return False, "SOCKS5 handshake refused by tor"
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + int(port).to_bytes(2, "big")
        s.settimeout(timeout); s.sendall(req); rep = s.recv(10)
        s.close()
        if len(rep) >= 2 and rep[1] == 0:
            return True, f"connected to {st['onion_addr']} through Tor — inbound onion path works"
        return False, f"tor could not reach {st['onion_addr']} (SOCKS reply {rep[1] if len(rep) > 1 else '?'}) — hidden service not published yet or Core not listening"
    except Exception as e:
        return False, f"self-test failed: {e}"


def inbound_by_net():
    """Inbound peers per network from getpeerinfo — the only way to say WHICH path a peer came in by.
    None when Core is unreachable (never a fabricated 0)."""
    peers = rpc("getpeerinfo")
    if peers is None:
        return None
    out = {}
    for p in peers:
        if p.get("inbound"):
            out[p.get("network", "?")] = out.get(p.get("network", "?"), 0) + 1
    return out


def public_addrs():
    """Our address as the network sees it — `addrlocal` reported by outbound peers (local-first: no
    'what is my IP' service). {'ipv4': (addr, agreeing peers) | None, 'ipv6': ...}."""
    peers = rpc("getpeerinfo") or []
    votes = {"ipv4": {}, "ipv6": {}}
    for p in peers:
        if p.get("inbound") or not p.get("addrlocal"):
            continue
        a = p["addrlocal"].rsplit(":", 1)[0]
        fam = "ipv6" if a.startswith("[") else "ipv4"
        a = a.strip("[]")
        if ":" in a and fam == "ipv4":
            continue
        votes[fam][a] = votes[fam].get(a, 0) + 1
    return {fam: (max(v, key=v.get), v[max(v, key=v.get)]) if v else None for fam, v in votes.items()}


def _socks_connect(atyp, addr_bytes, port, timeout):
    """SOCKS5 CONNECT through tor (127.0.0.1:9050). Returns the reply code (0 = connected) or None."""
    s = socket.create_connection(("127.0.0.1", 9050), timeout=5)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return None
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + int(port).to_bytes(2, "big"))
        rep = s.recv(10)
        return rep[1] if len(rep) >= 2 else None
    finally:
        s.close()


_SOCKS_REP = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable", 4: "host unreachable",
              5: "connection refused", 6: "TTL expired (timed out)", 7: "command not supported", 8: "address type not supported"}


def _control_dial(family, timeout=20):
    """Control for the self-test: dial one of OUR OWN outbound peers (same family) through the same Tor
    exit path. If that works and our address does not, the difference is the router. (peer, seconds | None)."""
    peers = rpc("getpeerinfo") or []
    af = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    cands = []
    for p in peers:
        if p.get("inbound") or p.get("network") != family or p.get("connection_type") in ("addr-fetch", "feeler", "private-broadcast"):
            continue
        m = re.match(r"^\[?([0-9a-fA-F.:]+)\]?:(\d+)$", p.get("addr", ""))
        if not m:
            continue  # DNS-seed names and the like are not dialable by IP
        try:
            socket.inet_pton(af, m.group(1)); cands.append((p["addr"], m.group(1), int(m.group(2))))
        except OSError:
            pass
    if not cands:
        return None, None
    addr, host, port = cands[0]
    try:
        t0 = time.monotonic()
        rep = _socks_connect(0x01 if family == "ipv4" else 0x04, socket.inet_pton(af, host), port, timeout)
        return addr, (time.monotonic() - t0) if rep == 0 else None
    except Exception:
        return addr, None


def clearnet_selftest(family="ipv4", timeout=25):
    """Dial our OWN public address :8333 from OUTSIDE — through a Tor exit, so no third-party service
    sees anything but a TCP connect to a Bitcoin port. A SOCKS success means the router forward (IPv4)
    or pinhole (IPv6) delivered the connection to Core's listener; Core logs it as an inbound
    connection from the exit's IP that closes at once. A control dial to one of our outbound peers
    through the same path makes a failure conclusive. Returns (ok | None, detail)."""
    pa = public_addrs().get(family)
    if not pa:
        return None, f"no {family} address reported by outbound peers (addrlocal) — nothing to dial"
    addr, n = pa
    if not _port_open("127.0.0.1", 9050):
        return None, "tor SOCKS (127.0.0.1:9050) closed — enable Tor on the 🧅 page first"
    seen = f"{addr}:{PORT} (as {n} peer{'s' if n != 1 else ''} see us)"
    t0 = time.monotonic(); timed_out = False
    try:
        rep = _socks_connect(0x01 if family == "ipv4" else 0x04,
                             socket.inet_pton(socket.AF_INET if family == "ipv4" else socket.AF_INET6, addr), PORT, timeout)
    except socket.timeout:
        rep, timed_out = None, True
    except Exception as e:
        return None, f"self-test failed: {e}"
    dt = time.monotonic() - t0
    if rep == 0:
        return True, f"a Tor exit connected to {seen} in {dt:.1f} s — inbound {family} path works (Core logs a short inbound from the exit)"
    if rep is None and not timed_out:
        return None, "SOCKS5 handshake refused by tor"
    # failed — run the control so the verdict is about the router, not about Tor
    cpeer, csec = _control_dial(family)
    ctrl = (f"control: exit reached our peer {cpeer} in {csec:.1f} s" if csec is not None else
            f"control: exit could not reach our peer {cpeer}" if cpeer else f"control: no outbound {family} peer to dial")
    why = "timed out after %.0f s (silently dropped)" % dt if timed_out else _SOCKS_REP.get(rep, f"reply {rep}")
    if csec is None:
        return None, f"inconclusive — {seen}: {why}; {ctrl} (this exit cannot do {family}; retry picks another exit)"
    hint = {"ipv4": "the gateway does not forward TCP 8333 → this host (or ufw/listen off)",
            "ipv6": "the router's IPv6 firewall has no pinhole for TCP 8333 (or ufw/listen off)"}[family]
    return False, f"{seen} NOT reachable from outside: {why} — {hint}; {ctrl}"


def probe():
    cs = conf(); ni = rpc("getnetworkinfo"); gw = _gateway()
    inb = ni.get("connections_in") if ni else None
    outb = ni.get("connections_out") if ni else None
    local = [f"{la.get('address')}:{la.get('port')}" for la in (ni or {}).get("localaddresses", [])]
    pcp, pcp_line = _pcp_log()
    tor = tor_state()
    paths = []
    # ipv4 forward: the host can only observe — and only an inbound peer ON ipv4 proves it (an onion inbound does not)
    bynet = inbound_by_net() or {}
    pub = public_addrs()
    v4_in = bynet.get("ipv4", 0); v6_in = bynet.get("ipv6", 0)
    seen4 = f"seen from outside as {pub['ipv4'][0]} ({pub['ipv4'][1]} peers agree)" if pub.get("ipv4") else "public IPv4 unknown (no addrlocal from peers)"
    paths.append({"key": "ipv4-forward", "name": "IPv4 router forward → :8333", "state": "working" if v4_in else "unknown",
                  "detail": f"gateway {gw or '—'} · {seen4} · inbound ipv4 now {v4_in if inb is not None else '—'}"
                            + (f" · other inbound: {', '.join(f'{k} {v}' for k, v in bynet.items() if k != 'ipv4')}" if any(k != 'ipv4' for k in bynet) else ""),
                  "action": "router UI: forward TCP 8333 → this host · ⇄ clearnet self-test proves it", "can_act": False})
    v6 = _ipv6_global()
    paths.append({"key": "ipv6-pinhole", "name": "IPv6 firewall pinhole → :8333", "state": "working" if v6_in else ("candidate" if v6 else "no-ipv6"),
                  "detail": (f"global {v6[0]}" if v6 else "no global IPv6") + (" · advertised" if any(':' in a and '.onion' not in a for a in local) else "")
                            + (f" · inbound ipv6 now {v6_in}" if inb is not None else ""),
                  "action": "router UI: allow inbound TCP 8333 to this host's IPv6 · ⇄ clearnet self-test proves it", "can_act": False})
    paths.append({"key": "pcp", "name": "PCP / NAT-PMP (Core -natpmp)", "state": {"mapped": "working", "timeout": "unsupported", "bind-error": "error"}.get(pcp, "unknown"),
                  "detail": (pcp_line or "no pcp lines in debug.log") + (" · router answers NAT-PMP" if _natpmp_probe(gw) else " · router silent on 5351"),
                  "action": "nothing to do if the router stays silent", "can_act": False})
    igd = _upnp_probe()
    paths.append({"key": "upnp", "name": "UPnP (IGD)", "state": "unsupported" if not igd else "router-has-igd",
                  "detail": "Core ≥ v29 has no UPnP client; router " + ("answers SSDP" if igd else "does not answer SSDP"),
                  "action": "—", "can_act": False})
    tor_state_s = ("working" if tor["onion_addr"] and tor["onion_reachable"] else
                   "configured" if tor["conf_listenonion"] and tor["conf_torcontrol"] else
                   "installed" if tor["installed"] else "available")
    paths.append({"key": "tor-onion", "name": "Tor onion service (listenonion + torcontrol)", "state": tor_state_s,
                  "detail": f"tor {tor['service'] or 'not installed'} · SOCKS {'open' if tor['socks'] else 'closed'} · control {'open' if tor['control'] else 'closed'} · "
                            f"onion {tor['onion_addr'] or '— (not yet)'}" + (" · reachable" if tor["onion_reachable"] else ""),
                  "action": "enable onion (installs tor, control port, bitcoin.conf, restarts Core)", "can_act": True})
    i2p = {"installed": _has("i2pd") or _has("i2prouter"), "service": _unit("i2pd"), "conf": cs.get("i2psam")}
    paths.append({"key": "i2p", "name": "I2P (i2psam)", "state": "configured" if i2p["conf"] else ("installed" if i2p["installed"] else "available"),
                  "detail": f"i2pd {i2p['service'] or 'not installed'} · i2psam={i2p['conf'] or '—'}",
                  "action": "enable i2p (installs i2pd, SAM bridge, bitcoin.conf, restarts Core)", "can_act": True})
    ufw = _ufw_8333()
    paths.append({"key": "ufw", "name": "Host firewall (ufw) allows 8333/tcp", "state": "working" if ufw else ("unknown" if ufw is None else "blocked"),
                  "detail": "rule present (v4+v6)" if ufw else ("cannot read rules without root" if ufw is None else "no ALLOW rule for 8333"),
                  "action": "ufw allow 8333/tcp", "can_act": True})
    paths.append({"key": "tunnel", "name": "Rented public endpoint (VPS/VPN port)", "state": "manual",
                  "detail": "WireGuard/SSH reverse tunnel to :8333 — a third party in the path; all inbound from one netgroup",
                  "action": "documented only — see docs/ICE.md reachability", "can_act": False})
    return {"inbound": inb, "outbound": outb, "inbound_by_net": bynet if inb is not None else None, "public": pub,
            "local": local, "listen": cs.get("listen", "1") != "0",
            "networks": {n["name"]: n.get("reachable") for n in (ni or {}).get("networks", [])}, "paths": paths, "tor": tor}


# ───────────────────────── actions (single tasks) ─────────────────────────
def _conf_append(lines, marker):
    """Append settings once (idempotent by marker); keep the file 0600; backup first."""
    try:
        txt = open(CONF).read()
    except OSError:
        txt = ""
    if marker in txt:
        return False
    shutil.copy2(CONF, CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")) if os.path.exists(CONF) else None
    with open(CONF, "a") as fh:
        fh.write("\n" + marker + "\n" + "\n".join(lines) + "\n")
    os.chmod(CONF, 0o600)
    return True


def enable_onion():
    """tor + ControlPort (hashed password, no group juggling) + bitcoin.conf + restart Core. One pkexec."""
    import secrets
    cs = conf()
    pw = cs.get("torpassword") or secrets.token_urlsafe(24)
    added = _conf_append([f"listenonion=1", f"torcontrol=127.0.0.1:9051", f"torpassword={pw}", f"onion=127.0.0.1:9050"],
                         "# ── Tor onion service (ICE reachability) ──") if not (cs.get("listenonion") == "1" and cs.get("torcontrol")) else False
    script = (f"export DEBIAN_FRONTEND=noninteractive; command -v tor >/dev/null || apt-get install -y -q tor >/tmp/ice-tor-install.log 2>&1; "
              f"H=$(tor --hash-password '{pw}' | tail -1); "
              f"grep -q '^ControlPort 9051' {TORRC} || printf '\\n# BANKON ICE: Bitcoin Core onion service control\\nControlPort 9051\\nHashedControlPassword %s\\nCookieAuthentication 0\\n' \"$H\" >> {TORRC}; "
              f"systemctl enable tor >/dev/null 2>&1; systemctl restart tor; sleep 2; systemctl is-active tor && echo tor-ok")
    r = _run(["pkexec", "sh", "-c", script], timeout=600)
    out = ((r.stdout or "") + (r.stderr or "")).strip() if r else "pkexec timed out"
    ok = bool(r and r.returncode == 0 and "tor-ok" in out)
    if ok:
        ok2, msg2 = restart_core(); out += " · " + msg2; ok = ok and ok2
    return ok, ("onion enabled: " if ok else "onion setup failed: ") + out[-300:] + (" · bitcoin.conf updated" if added else " · bitcoin.conf already had it")


def restart_core():
    """Core runs as the USER unit bitcoind.service on this host (system unit absent); fall back to
    the system unit, then to bitcoin-cli stop + bitcoind -daemon. Returns (ok, message)."""
    if _unit_user("bitcoind.service") is not None:
        r = _run(["systemctl", "--user", "restart", "bitcoind.service"], timeout=180)
        return bool(r and r.returncode == 0), "core restarted (user unit)" if r and r.returncode == 0 else f"user unit restart failed: {(r.stderr if r else '')[:120]}"
    if _unit("bitcoind.service") is not None:
        r = _run(["pkexec", "systemctl", "restart", "bitcoind.service"], timeout=180)
        return bool(r and r.returncode == 0), "core restarted (system unit)" if r and r.returncode == 0 else "system unit restart failed"
    _run(["bitcoin-cli", "stop"], timeout=30)
    time.sleep(8)
    subprocess.Popen(["bitcoind", "-daemon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, "core restarted (bitcoin-cli stop + bitcoind -daemon)"


def _unit_user(name):
    if not _has("systemctl"):
        return None
    r = _run(["systemctl", "--user", "show", "-p", "LoadState", name], timeout=4)
    if r and "LoadState=loaded" in r.stdout:
        a = _run(["systemctl", "--user", "is-active", name], timeout=4)
        return (a.stdout.strip() if a else None) or "inactive"
    return None


def enable_i2p():
    """i2pd with the SAM bridge + bitcoin.conf i2psam + restart Core. One pkexec."""
    added = _conf_append(["i2psam=127.0.0.1:7656"], "# ── I2P (ICE reachability) ──") if not conf().get("i2psam") else False
    script = ("export DEBIAN_FRONTEND=noninteractive; command -v i2pd >/dev/null || apt-get install -y -q i2pd >/tmp/ice-i2pd-install.log 2>&1; "
              "grep -q '^\\[sam\\]' /etc/i2pd/i2pd.conf && sed -i '/^\\[sam\\]/,/^\\[/{s/^enabled *=.*/enabled = true/}' /etc/i2pd/i2pd.conf || printf '\\n[sam]\\nenabled = true\\naddress = 127.0.0.1\\nport = 7656\\n' >> /etc/i2pd/i2pd.conf; "
              "systemctl enable i2pd >/dev/null 2>&1; systemctl restart i2pd; sleep 2; systemctl is-active i2pd && echo i2pd-ok")
    r = _run(["pkexec", "sh", "-c", script], timeout=600)
    out = ((r.stdout or "") + (r.stderr or "")).strip() if r else "pkexec timed out"
    ok = bool(r and r.returncode == 0 and "i2pd-ok" in out)
    if ok:
        ok2, msg2 = restart_core(); out += " · " + msg2; ok = ok and ok2
    return ok, ("i2p enabled: " if ok else "i2p setup failed: ") + out[-300:] + (" · bitcoin.conf updated" if added else "")


def allow_ufw():
    r = _run(["pkexec", "sh", "-c", "ufw allow 8333/tcp comment 'bitcoin p2p (BANKON)' && ufw status | grep 8333"], timeout=60)
    ok = bool(r and r.returncode == 0)
    return ok, (r.stdout.strip()[-200:] if r else "pkexec timed out")


def addnode(addr, mode="add"):
    """Manual peer management: add | remove | onetry (Core addnode RPC)."""
    res = rpc("addnode", [addr, mode])
    return res is not None or mode == "onetry", f"addnode {addr} {mode}"


def manual_peers():
    r = rpc("getaddednodeinfo") or []
    return [{"addr": n.get("addednode"), "connected": n.get("connected"),
             "via": ", ".join(f"{a.get('address')} ({a.get('connected')})" for a in n.get("addresses", []))} for n in r]


# ───────────────────────── CONSUMER MODE: a node that takes but does not serve ─────────────────────────
def conf_set(key, value):
    """Set key=value in bitcoin.conf (replace the first uncommented line, else append). Backup, 0600."""
    try:
        lines = open(CONF).read().splitlines()
    except OSError:
        lines = []
    shutil.copy2(CONF, CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")) if os.path.exists(CONF) else None
    done = False; out = []
    for ln in lines:
        if not done and re.match(rf"^\s*{re.escape(key)}\s*=", ln):
            out.append(f"{key}={value}"); done = True
        else:
            out.append(ln)
    if not done:
        out.append(f"{key}={value}")
    with open(CONF, "w") as fh:
        fh.write("\n".join(out) + "\n")
    os.chmod(CONF, 0o600)
    return True


def consumer_state():
    """{on, conf_listen, ufw_deny, inbound, applied}. ON = the node does not accept inbound
    (bitcoin.conf listen=0 → fully applied after a Core restart; the firewall deny applies now)."""
    cs = conf(); ni = rpc("getnetworkinfo")
    inb = ni.get("connections_in") if ni else None
    deny = None
    for path in ("/etc/ufw/user.rules", "/etc/ufw/user6.rules"):
        try:
            txt = open(path).read()
            if re.search(r"--dport 8333 .*-j (DROP|REJECT)", txt): deny = True
            elif deny is None and re.search(r"--dport 8333 .*-j ACCEPT", txt): deny = False
        except OSError:
            pass
    on = cs.get("listen") == "0"
    return {"on": on, "conf_listen": cs.get("listen", "1"), "ufw_deny": deny, "inbound": inb,
            "applied": on and (inb == 0) and (deny is not False)}


def set_consumer_mode(on):
    """ON: listen=0 in bitcoin.conf (Core stops listening after restart) + ufw deny 8333/tcp now +
    disconnect current inbound peers now. OFF: listen=1 + ufw allow 8333/tcp. One pkexec. Outbound
    (the chain) is untouched either way. Returns (ok, message)."""
    conf_set("listen", "0" if on else "1")
    if on:
        fw = "ufw --force delete allow 8333/tcp >/dev/null 2>&1; ufw deny 8333/tcp comment 'consumer mode (BANKON ICE)' && echo fw-ok"
    else:
        fw = "ufw --force delete deny 8333/tcp >/dev/null 2>&1; ufw allow 8333/tcp comment 'bitcoin p2p (BANKON)' && echo fw-ok"
    r = _run(["pkexec", "sh", "-c", fw], timeout=60)
    fw_ok = bool(r and "fw-ok" in (r.stdout or ""))
    dropped = 0
    if on:
        for p in rpc("getpeerinfo") or []:
            if p.get("inbound"):
                rpc("disconnectnode", ["", int(p["id"])]); dropped += 1
    msg = (f"consumer mode {'ON' if on else 'OFF'}: bitcoin.conf listen={'0' if on else '1'} · firewall {'deny' if on else 'allow'} 8333 {'✓' if fw_ok else '✗ (pkexec declined?)'}"
           + (f" · {dropped} inbound peer(s) disconnected" if on else "")
           + f" · Core {'stops' if on else 'resumes'} listening after a restart (🔁 restart Core)")
    return fw_ok, msg


# ───────────────────────── TOR: on/off + diagnostics from Tor's own control port ─────────────────────────
def tor_set(on):
    """Start/enable or stop/disable the tor unit (pkexec). Stopping kills outbound onion peers too."""
    cmd = "systemctl enable --now tor && systemctl is-active tor" if on else "systemctl disable --now tor; systemctl is-active tor || echo stopped"
    r = _run(["pkexec", "sh", "-c", cmd], timeout=60)
    out = ((r.stdout or "") + (r.stderr or "")).strip() if r else "pkexec timed out"
    ok = bool(r and r.returncode == 0) if on else bool(r and ("stopped" in out or "inactive" in out))
    return ok, f"tor {'started' if on else 'stopped'}: {out[-120:]}"


def _tor_control(queries, timeout=4):
    """Authenticate on the control port with bitcoin.conf's torpassword and run GETINFO queries.
    Returns {query: value} (multi-line values joined); None if the port or password is unavailable."""
    pw = conf().get("torpassword")
    if not pw:
        return None
    try:
        s = socket.create_connection(("127.0.0.1", 9051), timeout=timeout); f = s.makefile("rwb", buffering=0)
        def send(line):
            f.write((line + "\r\n").encode()); out = []; data = False
            while True:
                ln = f.readline().decode(errors="ignore").rstrip("\r\n")
                if ln == "" and not data: break
                out.append(ln)
                if data:                                   # inside a 250+ multi-line value: raw until a lone '.'
                    if ln == ".": data = False
                    continue
                if ln.startswith("250+"): data = True; continue
                if ln[:3].isdigit() and ln[3:4] == " ": break   # final status line (250 OK / 5xx)
            return out
        auth = send(f'AUTHENTICATE "{pw}"')
        if not auth or not auth[-1].startswith("250"):
            s.close(); return None
        res = {}
        for q in queries:
            lines = send(f"GETINFO {q}")
            vals = []
            for ln in lines:
                if ln.startswith("250-" + q + "="): vals.append(ln[len(q) + 5:])
                elif ln.startswith("250+" + q + "="): continue
                elif ln.startswith("250 OK") or ln == ".": continue
                elif ln.startswith("250 " + q + "="): vals.append(ln[len(q) + 5:])
                elif not ln.startswith(("250", "5")): vals.append(ln)
            res[q] = "\n".join(vals).strip()
        send("QUIT"); s.close(); return res
    except Exception:
        return None


def tor_diagnostics():
    """[(check, ok|None, detail)] — service · bootstrap · liveness · circuits · traffic · onion · peers."""
    rows = []
    installed = _has("tor"); svc = _unit("tor")
    rows.append(("tor service", svc == "active", f"{'installed' if installed else 'not installed'} · {svc or '—'}"))
    socks, ctrl = _port_open("127.0.0.1", 9050), _port_open("127.0.0.1", 9051)
    rows.append(("ports", socks and ctrl, f"SOCKS :9050 {'open' if socks else 'closed'} · control :9051 {'open' if ctrl else 'closed'}"))
    info = _tor_control(["version", "status/bootstrap-phase", "network-liveness", "traffic/read", "traffic/written",
                         "circuit-status", "orconn-status", "status/circuit-established"]) if ctrl else None
    if info is None:
        rows.append(("control auth", None if not ctrl else False, "no torpassword in bitcoin.conf or auth refused" if ctrl else "control port closed"))
    else:
        m = re.search(r"PROGRESS=(\d+)", info.get("status/bootstrap-phase", "")); prog = int(m.group(1)) if m else None
        rows.append(("bootstrap", prog == 100 if prog is not None else None, info.get("status/bootstrap-phase", "")[:120]))
        rows.append(("liveness", info.get("network-liveness") == "up", f"network-liveness {info.get('network-liveness') or '—'} · circuit-established {info.get('status/circuit-established') or '—'}"))
        circ = [ln for ln in info.get("circuit-status", "").splitlines() if ln.strip()]
        built = sum(1 for ln in circ if " BUILT " in (" " + ln + " "))
        rows.append(("circuits", built > 0, f"{built} built / {len(circ)} total · {len([l for l in info.get('orconn-status', '').splitlines() if l.strip()])} OR connections"))
        try:
            rd, wr = int(info.get("traffic/read") or 0), int(info.get("traffic/written") or 0)
        except ValueError:
            rd = wr = 0
        rows.append(("traffic", None, f"read {rd:,} B · written {wr:,} B (since tor started)"))
        rows.append(("version", True, info.get("version") or "—"))
    st = tor_state()
    rows.append(("onion service", bool(st["onion_addr"]) and bool(st["onion_reachable"]),
                 f"{st['onion_addr'] or 'no address yet'} · Core reachable:onion {st['onion_reachable']}"
                 + ("" if st["conf_listenonion"] else " · listenonion not set")))
    peers = rpc("getpeerinfo") or []
    oin = sum(1 for p in peers if p.get("network") == "onion" and p.get("inbound")); oout = sum(1 for p in peers if p.get("network") == "onion" and not p.get("inbound"))
    rows.append(("onion peers", (oin + oout) > 0, f"{oin} in · {oout} out (of {len(peers)} peers)"))
    cs = conf()
    rows.append(("bitcoin.conf", bool(cs.get("torcontrol")), f"listenonion={cs.get('listenonion') or '—'} · torcontrol={cs.get('torcontrol') or '—'} · onion={cs.get('onion') or '—'} · proxy={cs.get('proxy') or '— (clearnet stays direct)'}"))
    r = _run(["journalctl", "-u", "tor", "-n", "3", "--no-pager", "-o", "cat"], timeout=5)
    if r and r.stdout.strip():
        rows.append(("tor log", None, " ⏎ ".join(ln.strip()[:90] for ln in r.stdout.strip().splitlines()[-3:])))
    return rows
