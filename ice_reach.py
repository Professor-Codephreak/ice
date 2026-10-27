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


def probe():
    cs = conf(); ni = rpc("getnetworkinfo"); gw = _gateway()
    inb = ni.get("connections_in") if ni else None
    outb = ni.get("connections_out") if ni else None
    local = [f"{la.get('address')}:{la.get('port')}" for la in (ni or {}).get("localaddresses", [])]
    pcp, pcp_line = _pcp_log()
    tor = tor_state()
    paths = []
    # ipv4 forward: the host can only observe (inbound count on a v4 address) — the router holds the truth
    v4_in = inb is not None and inb > 0
    paths.append({"key": "ipv4-forward", "name": "IPv4 router forward → :8333", "state": "working" if v4_in else "unknown",
                  "detail": f"gateway {gw or '—'} · host listens :8333 · inbound now {inb if inb is not None else '—'}",
                  "action": "router UI: forward TCP 8333 → this host", "can_act": False})
    v6 = _ipv6_global()
    paths.append({"key": "ipv6-pinhole", "name": "IPv6 firewall pinhole → :8333", "state": "candidate" if v6 else "no-ipv6",
                  "detail": (f"global {v6[0]}" if v6 else "no global IPv6") + (" · advertised" if any(':' in a and '.onion' not in a for a in local) else ""),
                  "action": "router UI: allow inbound TCP 8333 to this host's IPv6", "can_act": False})
    paths.append({"key": "pcp", "name": "PCP / NAT-PMP (Core -natpmp)", "state": {"mapped": "working", "timeout": "unsupported", "bind-error": "error"}.get(pcp, "unknown"),
                  "detail": (pcp_line or "no pcp lines in debug.log") + (" · router answers NAT-PMP" if _natpmp_probe(gw) else " · router silent on 5351"),
                  "action": "nothing to do if the router stays silent", "can_act": False})
    paths.append({"key": "upnp", "name": "UPnP (IGD)", "state": "unsupported" if not _upnp_probe() else "router-has-igd",
                  "detail": "Core ≥ v29 has no UPnP client; router " + ("answers SSDP" if _upnp_probe() else "does not answer SSDP"),
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
    return {"inbound": inb, "outbound": outb, "local": local, "listen": cs.get("listen", "1") != "0",
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
