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
  tunnel         a rented public endpoint: reverse SSH tunnel kept by a systemd user unit (no router needed)
  service-onion  the WaaS API (and optionally the Console) as a Tor hidden service — clients reach the
                 SERVICE without any router change

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


def _outside_dial(family, addr, port, seen, hint, timeout=25):
    """Dial addr:port from OUTSIDE through a Tor exit; a control dial to one of our own outbound peers
    through the same path decides whether a failure is about the target or about the exit."""
    if not _port_open("127.0.0.1", 9050):
        return None, "tor SOCKS (127.0.0.1:9050) closed — enable Tor on the 🧅 page first"
    af = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    t0 = time.monotonic(); timed_out = False
    try:
        rep = _socks_connect(0x01 if family == "ipv4" else 0x04, socket.inet_pton(af, addr), port, timeout)
    except socket.timeout:
        rep, timed_out = None, True
    except Exception as e:
        return None, f"self-test failed: {e}"
    dt = time.monotonic() - t0
    if rep == 0:
        return True, f"a Tor exit connected to {seen} in {dt:.1f} s — reachable from outside (Core logs a short inbound from the exit)"
    if rep is None and not timed_out:
        return None, "SOCKS5 handshake refused by tor"
    cpeer, csec = _control_dial(family)
    ctrl = (f"control: exit reached our peer {cpeer} in {csec:.1f} s" if csec is not None else
            f"control: exit could not reach our peer {cpeer}" if cpeer else f"control: no outbound {family} peer to dial")
    why = "timed out after %.0f s (silently dropped)" % dt if timed_out else _SOCKS_REP.get(rep, f"reply {rep}")
    if csec is None:
        return None, f"inconclusive — {seen}: {why}; {ctrl} (this exit cannot do {family}; retry picks another exit)"
    return False, f"{seen} NOT reachable from outside: {why} — {hint}; {ctrl}"


def clearnet_selftest(family="ipv4", timeout=25):
    """Dial our OWN public address :8333 from OUTSIDE — through a Tor exit, so no third-party service
    sees anything but a TCP connect to a Bitcoin port. Success means the router forward (IPv4) or
    pinhole (IPv6) delivered the connection to Core's listener. Returns (ok | None, detail)."""
    pa = public_addrs().get(family)
    if not pa:
        return None, f"no {family} address reported by outbound peers (addrlocal) — nothing to dial"
    addr, n = pa
    seen = f"{addr}:{PORT} (as {n} peer{'s' if n != 1 else ''} see us)"
    hint = {"ipv4": "the gateway does not forward TCP 8333 → this host (or ufw/listen off)",
            "ipv6": "the router's IPv6 firewall has no pinhole for TCP 8333 (or ufw/listen off)"}[family]
    return _outside_dial(family, addr, PORT, seen, hint, timeout)


# ───────────── no-router paths: reverse SSH tunnel to a rented endpoint · service onion ─────────────
UNIT_DIR = os.path.join(os.path.expanduser("~"), ".config", "systemd", "user")
TUNNEL_UNIT = "bankon-ice-tunnel.service"
TUNNEL_CFG = os.path.expanduser("~/.bankon/ice-tunnel.json")
SERVICE_ONION = os.path.expanduser("~/.bankon/ice-service-onion.json")
SERVICE_PORTS = {"waas": 8088, "console": 8090}          # what BANKON serves on loopback
TOR_SVC_DIR = "/var/lib/tor/bankon-service"
_SVC_BEGIN, _SVC_END = "# BANKON ICE: service onion BEGIN", "# BANKON ICE: service onion END"


def _json_read(path):
    try:
        return json.load(open(path))
    except Exception:
        return {}


def _json_write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1)
    os.chmod(path, 0o600)


def conf_unset(key):
    """Comment out every uncommented key= line in bitcoin.conf (backup, 0600). Returns how many."""
    try:
        lines = open(CONF).read().splitlines()
    except OSError:
        return 0
    n = 0; out = []
    for ln in lines:
        if re.match(rf"^\s*{re.escape(key)}\s*=", ln):
            out.append("#" + ln); n += 1
        else:
            out.append(ln)
    if n:
        shutil.copy2(CONF, CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S"))
        with open(CONF, "w") as fh:
            fh.write("\n".join(out) + "\n")
        os.chmod(CONF, 0o600)
    return n


def _resolve4(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return None


def sam_hello(timeout=4):
    """Speak SAM to i2pd ourselves: HELLO → 'HELLO REPLY RESULT=OK VERSION=3.x'. (True, version) | (False, why) | (None, 'closed')."""
    try:
        with socket.create_connection(("127.0.0.1", 7656), timeout=timeout) as sk:
            sk.sendall(b"HELLO VERSION MIN=3.0 MAX=3.1\n")
            rep = sk.recv(256).decode("ascii", "replace").strip()
    except OSError as e:
        return None, f"SAM closed ({e})"
    m = re.search(r"RESULT=(\w+)", rep); v = re.search(r"VERSION=([\d.]+)", rep)
    return (m.group(1) == "OK" if m else False), (f"SAM {v.group(1)}" if v else rep[:60])


def i2pd_console(timeout=3):
    """i2pd's own status from its loopback web console (:7070): network status, tunnel success rate,
    routers known, uptime. None when the console is off. Honest about 'Firewalled' (normal on NAT)."""
    try:
        html = urllib.request.urlopen("http://127.0.0.1:7070/", timeout=timeout).read().decode("utf-8", "replace")
    except Exception:
        return None
    txt = re.sub(r"<[^>]+>", " ", html).replace("&nbsp;", " ")
    def grab(label):
        m = re.search(re.escape(label) + r"\s*:?\s*([^\n]{1,40}?)\s{2,}", txt + "  ")
        return m.group(1).strip() if m else None
    return {"status": grab("Network status"), "tunnel_rate": grab("Tunnel creation success rate"),
            "routers": grab("Routers"), "uptime": grab("Uptime")}


def tunnel_state():
    """The reverse tunnel as it IS: config, unit state, Core's externalip, inbound peers that arrived
    through loopback but not via the onion listener, the unit's last log lines."""
    cfg = _json_read(TUNNEL_CFG)
    st = {"configured": bool(cfg.get("endpoint")), "endpoint": cfg.get("endpoint"), "remote_port": cfg.get("remote_port"),
          "endpoint_ip": cfg.get("endpoint_ip"), "unit": _unit_user(TUNNEL_UNIT), "externalip": conf().get("externalip"),
          "inbound_via": None, "log": None, "ssh": _has("ssh")}
    peers = rpc("getpeerinfo")
    if peers is not None:
        st["inbound_via"] = sum(1 for p in peers if p.get("inbound") and str(p.get("addr", "")).startswith("127.0.0.1:") and p.get("network") != "onion")
    r = _run(["journalctl", "--user", "-u", TUNNEL_UNIT, "-n", "3", "--no-pager", "-o", "cat"], timeout=5)
    if r and r.stdout.strip():
        st["log"] = " ⏎ ".join(ln.strip()[:100] for ln in r.stdout.strip().splitlines()[-3:])
    return st


def tunnel_setup(endpoint, remote_port=8333, ssh_port=22, identity=None, advertise=True):
    """Reverse SSH tunnel kept alive by a systemd USER unit (systemd is the retry: Restart=always).
    Needs: an account on the endpoint with KEY auth (BatchMode — no password prompts in a unit) and
    `GatewayPorts yes|clientspecified` in the endpoint's sshd_config so the port binds on 0.0.0.0.
    advertise=True writes externalip=<endpoint ip>:<port> so Core tells the network (Core restart)."""
    endpoint = (endpoint or "").strip()
    if not re.match(r"^[\w.\-]+@[\w.\-\[\]:]+$", endpoint):
        return False, "endpoint must be user@host"
    if not _has("ssh"):
        return False, "ssh not installed (apt-get install openssh-client)"
    host = endpoint.split("@", 1)[1]
    ip = _resolve4(host.strip("[]"))
    if not ip:
        return False, f"cannot resolve {host}"
    remote_port = int(remote_port); ssh_port = int(ssh_port)
    identity = os.path.expanduser(identity.strip()) if identity and identity.strip() else None
    if identity and not os.path.exists(identity):
        return False, f"identity file not found: {identity}"
    cmd = ["/usr/bin/ssh", "-NT", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
           "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-p", str(ssh_port)]
    if identity:
        cmd += ["-i", identity]
    cmd += ["-R", f"0.0.0.0:{remote_port}:127.0.0.1:{PORT}", endpoint]
    os.makedirs(UNIT_DIR, exist_ok=True)
    unit = f"""[Unit]
Description=BANKON ICE tunnel — reverse SSH :{remote_port} on {host} → this node :{PORT} (docs/ICE.md)
After=network-online.target

[Service]
Type=simple
ExecStart={' '.join(cmd)}
Restart=always
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
"""
    with open(os.path.join(UNIT_DIR, TUNNEL_UNIT), "w") as fh:
        fh.write(unit)
    _json_write(TUNNEL_CFG, {"endpoint": endpoint, "endpoint_ip": ip, "remote_port": remote_port, "ssh_port": ssh_port,
                             "identity": identity, "advertise": bool(advertise), "when": time.strftime("%Y-%m-%dT%H:%M:%S")})
    for c in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", TUNNEL_UNIT]):
        r = _run(c, timeout=20)
        if r is None or r.returncode != 0:
            return False, (r.stderr.strip() if r else "systemctl --user unavailable")
    msg = f"{TUNNEL_UNIT} enabled + started → {host}:{remote_port} (ip {ip})"
    if advertise:
        conf_set("externalip", f"{ip}:{remote_port}"); msg += f" · externalip={ip}:{remote_port} written (restart Core to advertise)"
    time.sleep(3)
    st = _unit_user(TUNNEL_UNIT)
    if st != "active":
        r = _run(["journalctl", "--user", "-u", TUNNEL_UNIT, "-n", "4", "--no-pager", "-o", "cat"], timeout=5)
        return False, msg + f" · unit {st}: " + ((r.stdout.strip().replace(chr(10), ' ⏎ ')[-260:]) if r else "") + " — key auth (BatchMode) and GatewayPorts on the endpoint are required"
    return True, msg + " · ssh session up — press 🧪 prove from outside"


def tunnel_remove():
    """Stop + disable the unit, delete it, comment out externalip. Returns (ok, msg)."""
    _run(["systemctl", "--user", "disable", "--now", TUNNEL_UNIT], timeout=20)
    try:
        os.remove(os.path.join(UNIT_DIR, TUNNEL_UNIT))
    except OSError:
        pass
    _run(["systemctl", "--user", "daemon-reload"], timeout=10)
    n = conf_unset("externalip")
    cfg = _json_read(TUNNEL_CFG)
    try:
        os.remove(TUNNEL_CFG)
    except OSError:
        pass
    return True, f"tunnel removed ({cfg.get('endpoint') or '—'})" + (f" · externalip commented out ({n}) — restart Core to stop advertising" if n else "")


def tunnel_selftest(timeout=25):
    """Prove the tunnel from OUTSIDE: a Tor exit dials <endpoint ip>:<remote port>."""
    cfg = _json_read(TUNNEL_CFG)
    if not cfg.get("endpoint"):
        return None, "no tunnel configured"
    ip = cfg.get("endpoint_ip") or _resolve4(cfg["endpoint"].split("@", 1)[1].strip("[]"))
    if not ip:
        return None, "cannot resolve the endpoint"
    port = int(cfg.get("remote_port") or PORT)
    return _outside_dial("ipv4", ip, port, f"{ip}:{port} (the endpoint)",
                         "the endpoint's sshd has no GatewayPorts yes/clientspecified (the -R port bound to its loopback), its firewall blocks the port, or the unit is down", timeout)


def service_onion_state():
    """The WaaS/Console onion as it IS: published address, which services, tor up, the local ports listening."""
    cfg = _json_read(SERVICE_ONION)
    ports = cfg.get("ports") or {}
    return {"addr": cfg.get("addr"), "ports": ports, "when": cfg.get("when"), "tor": _unit("tor"),
            "listening": {name: _port_open("127.0.0.1", int(port), 0.5) for name, port in ports.items()}}


def waas_token_set():
    """Is the WaaS API gated (BANKON_API_TOKEN in its user unit)? None when the unit is unknown."""
    r = _run(["systemctl", "--user", "show", "bankon-waas.service", "-p", "Environment", "-p", "EnvironmentFiles"], timeout=4)
    if not r or "Environment=" not in r.stdout:
        return None
    if "BANKON_API_TOKEN=" in r.stdout:
        return True
    for ln in r.stdout.splitlines():
        if ln.startswith("EnvironmentFiles=") and ln.split("=", 1)[1].strip():
            path = ln.split("=", 1)[1].split()[0].lstrip("-")
            try:
                if "BANKON_API_TOKEN=" in open(path).read():
                    return True
            except OSError:
                pass
    return False


def service_onion_enable(services=("waas",), force=False):
    """Publish BANKON's loopback services as ONE Tor hidden service (v3). One pkexec: torrc block,
    tor reload, read the hostname tor generates. The address is stored 0600 in ~/.bankon.
    Clients then reach the WaaS API at http://<addr>.onion:8088 with no router involved.
    Refuses to publish an UNGATED WaaS API (no BANKON_API_TOKEN) unless force=True."""
    chosen = {k: SERVICE_PORTS[k] for k in services if k in SERVICE_PORTS}
    if not chosen:
        return False, "no known service chosen (waas, console)"
    if "waas" in chosen and not force and waas_token_set() is not True:
        return False, "refused: the WaaS API has no BANKON_API_TOKEN (open to anyone who learns the address) — set it in the bankon-waas user unit, or publish with force"
    lines = [f"HiddenServiceDir {TOR_SVC_DIR}/", "HiddenServiceVersion 3"] + [f"HiddenServicePort {p} 127.0.0.1:{p}" for p in chosen.values()]
    block = "\n".join([_SVC_BEGIN] + lines + [_SVC_END])
    script = (f"command -v tor >/dev/null || {{ echo no-tor; exit 3; }}; "
              f"sed -i '/{_SVC_BEGIN}/,/{_SVC_END}/d' {TORRC}; printf '%s\n' '{block}' >> {TORRC}; "
              f"systemctl enable tor >/dev/null 2>&1; systemctl reload tor || systemctl restart tor; "
              f"for i in 1 2 3 4 5 6 7 8 9 10; do [ -s {TOR_SVC_DIR}/hostname ] && break; sleep 1; done; "
              f"cat {TOR_SVC_DIR}/hostname")
    r = _run(["pkexec", "sh", "-c", script], timeout=120)
    out = ((r.stdout or "") + (r.stderr or "")).strip() if r else "pkexec timed out"
    m = re.search(r"([a-z2-7]{56})\.onion", out)
    if not (r and r.returncode == 0 and m):
        return False, "service onion failed: " + ("tor not installed — enable Tor first" if "no-tor" in out else out[-260:])
    addr = m.group(0)
    _json_write(SERVICE_ONION, {"addr": addr, "ports": chosen, "when": time.strftime("%Y-%m-%dT%H:%M:%S")})
    return True, f"service onion published: {addr} → " + ", ".join(f"{k} :{p}" for k, p in chosen.items())


def service_onion_remove():
    script = f"sed -i '/{_SVC_BEGIN}/,/{_SVC_END}/d' {TORRC}; systemctl reload tor; rm -rf {TOR_SVC_DIR}; echo removed"
    r = _run(["pkexec", "sh", "-c", script], timeout=60)
    ok = bool(r and r.returncode == 0 and "removed" in (r.stdout or ""))
    if ok:
        try:
            os.remove(SERVICE_ONION)
        except OSError:
            pass
    return ok, "service onion removed (torrc block, keys, address)" if ok else "remove failed: " + ((r.stderr or r.stdout) if r else "pkexec timed out")[-200:]


def service_onion_selftest(timeout=25):
    """Dial the service onion through Tor's SOCKS, each published port."""
    st = service_onion_state()
    if not st["addr"]:
        return None, "no service onion published"
    res = []
    for name, port in st["ports"].items():
        try:
            rep = _socks_connect(0x03, bytes([len(st["addr"])]) + st["addr"].encode(), int(port), timeout)
            res.append((name, rep == 0, f"{name} :{port} " + ("✓ reached through Tor" if rep == 0 else f"✗ {_SOCKS_REP.get(rep, rep)}")))
        except Exception as e:
            res.append((name, None, f"{name} :{port} … {e}"))
    ok = all(ok for _n, ok, _d in res)
    return ok, f"{st['addr']}: " + " · ".join(d for _n, _ok, d in res)


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
    i2p = {"installed": _has("i2pd") or _has("i2prouter"), "service": _unit("i2pd"), "conf": cs.get("i2psam"), "sam": _port_open("127.0.0.1", 7656, 0.5)}
    # Core flags i2p "reachable" as soon as -i2psam is SET — it is config, not a live SAM session. Truth = a .b32.i2p local address.
    i2p_reach = next((n.get("reachable") for n in (ni or {}).get("networks", []) if n.get("name") == "i2p"), None)
    i2p_addr = next((a for a in local if ".b32.i2p" in a), None)
    i2p_state = ("working" if i2p_addr else "error" if (i2p["conf"] and (i2p["service"] in ("failed", "activating", "inactive") or not i2p["sam"])) else
                 "configured" if i2p["conf"] else ("installed" if i2p["installed"] else "available"))
    con = i2pd_console() if i2p["service"] == "active" else None
    hello = sam_hello() if i2p["sam"] else (None, "closed")
    con_s = (f" · router {con['status'] or '?'} (Firewalled is normal on NAT) · tunnels {con['tunnel_rate'] or '?'} · routers {con['routers'] or '?'} · up {con['uptime'] or '?'}" if con else "")
    paths.append({"key": "i2p", "name": "I2P (i2psam)", "state": i2p_state,
                  "detail": f"i2pd {i2p['service'] or 'not installed'} · SAM :7656 {('HELLO ok · ' + hello[1]) if hello[0] else ('open but ' + hello[1]) if i2p['sam'] else 'closed'} · i2psam={i2p['conf'] or '—'} · destination {i2p_addr or '— (none until SAM answers)'}{con_s}"
                            + (" · i2pd crashing — see docs/I2P.md §6 (PPA)" if i2p["service"] in ("failed", "activating") else ""),
                  "action": "enable i2p (installs i2pd, SAM bridge, bitcoin.conf, restarts Core)", "can_act": True})
    ufw = _ufw_8333()
    paths.append({"key": "ufw", "name": "Host firewall (ufw) allows 8333/tcp", "state": "working" if ufw else ("unknown" if ufw is None else "blocked"),
                  "detail": "rule present (v4+v6)" if ufw else ("cannot read rules without root" if ufw is None else "no ALLOW rule for 8333"),
                  "action": "ufw allow 8333/tcp", "can_act": True})
    tn = tunnel_state()
    tn_state = ("working" if tn["unit"] == "active" else "error" if tn["unit"] in ("failed", "inactive", "activating") else "available")
    paths.append({"key": "tunnel", "name": "Rented endpoint — reverse SSH tunnel (no router)", "state": tn_state,
                  "detail": (f"{tn['endpoint']}:{tn['remote_port']} · unit {tn['unit']} · externalip={tn['externalip'] or '—'} · inbound via tunnel {tn['inbound_via'] if tn['inbound_via'] is not None else '—'}"
                             if tn["configured"] else "not configured — any VPS/VPN host you hold an ssh key for; all inbound then shares one netgroup"),
                  "action": "🚇 Tunnel page: endpoint · port · key → systemd user unit keeps it; 🧪 prove from outside", "can_act": True})
    so = service_onion_state()
    paths.append({"key": "service-onion", "name": "WaaS service onion (clients reach the API, no router)", "state": "working" if so["addr"] and so["tor"] == "active" else ("available" if tor["installed"] else "unsupported"),
                  "detail": (f"{so['addr']} → " + ", ".join(f"{k} :{p}{'' if so['listening'].get(k) else ' (not listening!)'}" for k, p in so["ports"].items())) if so["addr"] else "not published — one pkexec publishes the WaaS API (and optionally the Console) as a v3 hidden service",
                  "action": "🧅 Tor page: publish service onion · self-test", "can_act": True})
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
    # Ubuntu/Mint's packaged i2pd 2.39.0 segfaults at start; on apt systems take the project's PPA (ppa:purplei2p/i2pd) first.
    ppa = ("if command -v apt-get >/dev/null; then command -v add-apt-repository >/dev/null || apt-get install -y -q software-properties-common >>/tmp/ice-i2pd-install.log 2>&1; "
           "grep -rqs purplei2p /etc/apt/sources.list.d/ || add-apt-repository -y ppa:purplei2p/i2pd >>/tmp/ice-i2pd-install.log 2>&1; apt-get update -q >>/tmp/ice-i2pd-install.log 2>&1; fi; ")
    script = ("export DEBIAN_FRONTEND=noninteractive; " + ppa + "apt-get install -y -q i2pd >>/tmp/ice-i2pd-install.log 2>&1; "
              "grep -q '^\\[sam\\]' /etc/i2pd/i2pd.conf && sed -i '/^\\[sam\\]/,/^\\[/{s/^enabled *=.*/enabled = true/}' /etc/i2pd/i2pd.conf || printf '\\n[sam]\\nenabled = true\\naddress = 127.0.0.1\\nport = 7656\\n' >> /etc/i2pd/i2pd.conf; "
              "systemctl enable i2pd >/dev/null 2>&1; systemctl restart i2pd; sleep 2; systemctl is-active i2pd && echo i2pd-ok")
    r = _run(["pkexec", "sh", "-c", script], timeout=600)
    out = ((r.stdout or "") + (r.stderr or "")).strip() if r else "pkexec timed out"
    ok = bool(r and r.returncode == 0 and "i2pd-ok" in out)
    if ok:
        ok2, msg2 = restart_core(); out += " · " + msg2; ok = ok and ok2
    if ok:
        time.sleep(6)
        if _unit("i2pd") != "active" or not _port_open("127.0.0.1", 7656, 0.5):
            j = _run(["journalctl", "-u", "i2pd", "-n", "6", "--no-pager", "-o", "cat"], timeout=5)
            crash = "SEGV" in (j.stdout if j else "") or "core-dump" in (j.stdout if j else "")
            return False, ("i2pd crashes at start (SIGSEGV) — the Ubuntu 2.39.0 package is broken here; install the project's PPA yourself: "
                           "sudo add-apt-repository -y ppa:purplei2p/i2pd && sudo apt-get update && sudo apt-get install -y i2pd — see docs/I2P.md §6"
                           if crash else f"i2pd {_unit('i2pd')} · SAM :7656 {'open' if _port_open('127.0.0.1', 7656, 0.5) else 'closed'} — Core will connect when SAM answers") + " · " + out[-160:]
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
    so = service_onion_state()
    rows.append(("service onion", (bool(so["addr"]) and all(so["listening"].values())) if so["addr"] else None,
                 (f"{so['addr']} → " + " · ".join(f"{k} :{p} {'listening' if so['listening'].get(k) else 'NOT listening'}" for k, p in so["ports"].items())) if so["addr"] else "not published (WaaS API reachable only on this host)"))
    cs = conf()
    rows.append(("bitcoin.conf", bool(cs.get("torcontrol")), f"listenonion={cs.get('listenonion') or '—'} · torcontrol={cs.get('torcontrol') or '—'} · onion={cs.get('onion') or '—'} · proxy={cs.get('proxy') or '— (clearnet stays direct)'}"))
    r = _run(["journalctl", "-u", "tor", "-n", "3", "--no-pager", "-o", "cat"], timeout=5)
    if r and r.stdout.strip():
        rows.append(("tor log", None, " ⏎ ".join(ln.strip()[:90] for ln in r.stdout.strip().splitlines()[-3:])))
    return rows
