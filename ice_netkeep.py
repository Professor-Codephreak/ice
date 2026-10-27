"""ICE netkeep — persistent LAN link + Wi-Fi HARD GATE, as a modular ICE extension.

Two halves, both Qt-free (the same file drops into the standalone ~/ICE tool):

  KEEP  — a link watchdog for the laptop's Wi-Fi/LAN uplink: probes NetworkManager + the
          default gateway, detects drops, re-asserts the profile (`nmcli connection up`),
          and fixes the two usual culprits of a flapping iwlwifi link — Wi-Fi power-save
          (NetworkManager default `wifi.powersave=3`) and finite autoconnect retries.
          Every drop / reconnect is an evidence event for the ICE `.history`.

  GATE  — the Wi-Fi hard gate. Stronger than the rfkill soft-block AIRGAP: it takes the
          Wi-Fi down, tells NetworkManager to stop managing it, and UNLOADS THE DRIVER
          (modprobe -r <iwlwifi/ath9k/…> + its consumers) so the interface ceases to exist.
          No driver, no radio, no reconnect — not by a daemon, not by a stray process.
          Restore reloads the remembered modules and hands the device back to NetworkManager.

Precedence (docs/ICE.md): ICE's wall always wins. KEEP pauses itself whenever the radio is
rfkill-blocked (AIRGAP) or the hard gate is down — the watchdog never fights the wall.
Mutations escalate through pkexec (the ICE pattern); probes are unprivileged and never raise.
Nothing here touches wallet keys.
"""
import json, os, re, shutil, subprocess, time

STATE_DIR = os.path.join(os.path.expanduser("~"), ".bankon")
GATE_STATE = os.path.join(STATE_DIR, "ice-hardgate.json")
NM_DROPIN = "/etc/NetworkManager/conf.d/90-bankon-ice-wifi-powersave.conf"

# IEEE 802.11 reason codes seen in wpa_supplicant CTRL-EVENT-DISCONNECTED
REASON = {1: "unspecified (AP dropped us)", 2: "previous auth no longer valid", 3: "deauth: STA leaving",
          4: "inactivity timeout", 5: "AP overloaded", 6: "class-2 frame from non-auth STA",
          7: "class-3 frame from non-assoc STA", 8: "disassoc: STA leaving", 15: "4-way handshake timeout",
          16: "group-key handshake timeout", 23: "802.1X auth failed", 34: "low ACK / poor link",
          36: "STA requested (roam/leave)", 39: "timeout", 52: "AP channel switch"}


def _run(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _has(binary):
    return shutil.which(binary) is not None


def _nm():
    return _has("nmcli")


# ───────────────────────── interfaces & drivers ─────────────────────────
def wifi_ifaces():
    out = []
    try:
        for n in sorted(os.listdir("/sys/class/net")):
            if os.path.exists(f"/sys/class/net/{n}/wireless") or os.path.exists(f"/sys/class/net/{n}/phy80211"):
                out.append(n)
    except OSError:
        pass
    return out


def driver_of(iface):
    """Kernel module name behind an interface (e.g. iwlwifi, ath9k, rtw88_8822be) or None."""
    try:
        return os.path.basename(os.readlink(f"/sys/class/net/{iface}/device/driver/module"))
    except OSError:
        try:
            return os.path.basename(os.readlink(f"/sys/class/net/{iface}/device/driver"))
        except OSError:
            return None


def module_chain(mod):
    """[consumers…, mod] — the order `modprobe -r` needs (consumers before the base driver).
    iwlwifi ← iwldvm/iwlmvm, ath9k ← ath9k_common… computed from lsmod, so it is generic."""
    if not mod:
        return []
    used_by = {}
    r = _run(["lsmod"])
    if not r:
        return [mod]
    for ln in r.stdout.splitlines()[1:]:
        p = ln.split()
        if len(p) >= 4:
            used_by[p[0]] = [x for x in p[3].split(",") if x]
        elif p:
            used_by[p[0]] = []
    order, seen = [], set()
    def walk(m):
        if m in seen:
            return
        seen.add(m)
        for c in used_by.get(m, []):
            walk(c)
        order.append(m)
    walk(mod)
    return order                       # leaves first → base last


# ───────────────────────── link state (unprivileged) ─────────────────────────
def rfkill_blocked(kind="wifi"):
    r = _run(["rfkill", "list", kind])
    if not r or not r.stdout.strip():
        return None
    return "Soft blocked: yes" in r.stdout or "Hard blocked: yes" in r.stdout


def _default_route():
    r = _run(["ip", "-4", "route", "show", "default"])
    if r and r.stdout.strip():
        m = re.search(r"default via (\S+) dev (\S+)", r.stdout)
        if m:
            return m.group(1), m.group(2)
    return None, None


def _ip4(iface):
    if _has("ifconfig"):                              # the classic primitive first
        r = _run(["ifconfig", iface])
        if r:
            m = re.search(r"inet (\S+)\s+netmask (\S+)", r.stdout)
            if m:
                try:
                    import ipaddress as _ipa
                    return str(_ipa.ip_interface((m.group(1), m.group(2))))
                except ValueError:
                    return m.group(1)
    r = _run(["ip", "-4", "-o", "addr", "show", iface])
    if r:
        m = re.search(r"inet (\S+)", r.stdout)
        if m:
            return m.group(1)
    return None


def ifconfig(iface):
    """ifconfig text for the panel (ip -s link as the fallback) — RX/TX errors + drops are the tell."""
    r = _run(["ifconfig", iface]) if _has("ifconfig") else _run(["ip", "-s", "link", "show", iface])
    return (r.stdout.strip() if r else "") or "(no interface)"


def ping_stats(host, count=3, wait=3, interval=0.3):
    """{sent, recv, loss_pct, avg_ms, max_ms} — the primitive every verdict rests on. Tolerant on
    purpose: a slow or lossy gateway is DEGRADED, not down; only silence across all echoes is down."""
    r = _run(["ping", "-c", str(count), "-W", str(wait), "-i", str(interval), "-n", host], timeout=count * (wait + 1) + 3)
    out = {"sent": count, "recv": 0, "loss_pct": 100, "avg_ms": None, "max_ms": None}
    if not r:
        return out
    m = re.search(r"(\d+) packets transmitted, (\d+) received", r.stdout)
    if m:
        out["sent"], out["recv"] = int(m.group(1)), int(m.group(2))
        out["loss_pct"] = round(100 * (1 - out["recv"] / max(1, out["sent"])))
    m = re.search(r"= [\d.]+/([\d.]+)/([\d.]+)/", r.stdout)
    if m:
        out["avg_ms"], out["max_ms"] = round(float(m.group(1)), 3), round(float(m.group(2)), 3)   # ping's own 3-dp resolution
    return out


def powersave(iface):
    """'on' | 'off' | None (iw missing / iface gone)."""
    if not _has("iw"):
        return None
    r = _run(["iw", "dev", iface, "get", "power_save"])
    if not r or not r.stdout.strip():
        return None
    return "on" if "on" in r.stdout else "off"


def link_state():
    """One honest snapshot. Keys: iface, present, driver, state, ssid, bssid, signal, chan,
    ip, gw, gw_ok, conn, powersave, airgap, hardgate, nm_state."""
    st = {"iface": None, "present": False, "driver": None, "state": "no wifi device", "ssid": None,
          "bssid": None, "signal": None, "chan": None, "ip": None, "gw": None, "gw_ok": None,
          "conn": None, "powersave": None, "airgap": None, "hardgate": hardgate_state()["down"],
          "nm_state": None, "ping": None, "degraded": False}
    ifs = wifi_ifaces()
    if not ifs:
        if st["hardgate"]:
            st["state"] = "HARD GATE — driver unloaded"
        return st
    iface = ifs[0]
    st.update(iface=iface, present=True, driver=driver_of(iface), powersave=powersave(iface),
              airgap=rfkill_blocked("wifi"), ip=_ip4(iface))
    if _nm():
        r = _run(["nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device"])
        if r:
            for ln in r.stdout.splitlines():
                p = ln.split(":")
                if p and p[0] == iface and len(p) >= 3:
                    st["nm_state"] = p[1]; st["conn"] = p[2] or None
        r = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,CHAN", "device", "wifi", "list",
                  "ifname", iface, "--rescan", "no"])
        if r:
            for ln in r.stdout.splitlines():
                if ln.startswith("yes:"):
                    # BSSID carries escaped colons → split from the right
                    body = ln[4:]
                    try:
                        chan = body.rsplit(":", 1)[1]; body = body.rsplit(":", 1)[0]
                        sig = body.rsplit(":", 1)[1]; body = body.rsplit(":", 1)[0]
                        ssid, bssid = body.split(":", 1)
                        st.update(ssid=ssid, bssid=bssid.replace("\\:", ":"), signal=int(sig), chan=chan)
                    except (ValueError, IndexError):
                        pass
                    break
    gw, gdev = _default_route()
    if gw and gdev == iface:
        st["gw"] = gw
        pg = ping_stats(gw); st["ping"] = pg
        st["gw_ok"] = pg["recv"] > 0
        st["degraded"] = st["gw_ok"] and (pg["loss_pct"] > 0 or (pg["avg_ms"] or 0) > 500)
    if st["airgap"]:
        st["state"] = "AIRGAP (rfkill)"
    elif st["nm_state"] and st["nm_state"].startswith("connected"):
        pg = st["ping"] or {}
        st["state"] = ("up" if st["gw_ok"] and not st["degraded"] else
                       f"up · DEGRADED (loss {pg.get('loss_pct')}% · avg {pg.get('avg_ms')} ms)" if st["gw_ok"] else
                       "up · gateway silent")
    elif st["nm_state"]:
        st["state"] = st["nm_state"]
    else:
        st["state"] = "up" if st["ip"] else "down"
    return st


# ───────────────────────── KEEP: reconnect + persistent-link fixes ─────────────────────────
def wifi_profiles():
    """[(name, autoconnect, retries, priority)] of saved Wi-Fi profiles (NetworkManager)."""
    if not _nm():
        return []
    r = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    names = [ln.split(":")[0] for ln in (r.stdout.splitlines() if r else []) if ":802-11-wireless" in ln]
    out = []
    for n in names:
        q = _run(["nmcli", "-t", "-f", "connection.autoconnect,connection.autoconnect-retries,connection.autoconnect-priority",
                  "connection", "show", n])
        vals = {}
        for ln in (q.stdout.splitlines() if q else []):
            k, _, v = ln.partition(":")
            vals[k] = v
        out.append((n, vals.get("connection.autoconnect") == "yes",
                    int(vals.get("connection.autoconnect-retries") or -1),
                    int(vals.get("connection.autoconnect-priority") or 0)))
    return out


def reconnect(conn=None, iface=None):
    """Re-assert the uplink. Order: radio on → profile up (or device connect). Non-blocking."""
    if not _nm():
        if iface:
            subprocess.Popen(["pkexec", "ip", "link", "set", iface, "up"])
        return "no NetworkManager — ip link set up"
    subprocess.Popen(["nmcli", "radio", "wifi", "on"])
    if conn:
        subprocess.Popen(["nmcli", "connection", "up", conn] + (["ifname", iface] if iface else []))
        return f"nmcli connection up '{conn}'"
    if iface:
        subprocess.Popen(["nmcli", "device", "connect", iface])
        return f"nmcli device connect {iface}"
    return "nmcli radio wifi on"


def set_autoconnect_forever(conn, priority=10):
    """autoconnect=yes · retries=0 (= forever) · priority — the profile re-dials by itself."""
    if not _nm() or not conn:
        return False
    r = _run(["nmcli", "connection", "modify", conn, "connection.autoconnect", "yes",
              "connection.autoconnect-retries", "0", "connection.autoconnect-priority", str(priority)], timeout=10)
    return bool(r and r.returncode == 0)


def set_powersave(iface, off=True, persist=True, conn=None):
    """Runtime: iw … set power_save off (pkexec). Persist: NM drop-in wifi.powersave=2 (disable)
    + nmcli general reload, and the profile's own 802-11-wireless.powersave=2 so it survives
    distro drop-ins. Returns a status string."""
    if not iface:
        return "no wifi iface"
    parts = []
    if _has("iw"):
        subprocess.Popen(["pkexec", "iw", "dev", iface, "set", "power_save", "off" if off else "on"])
        parts.append(f"iw power_save {'off' if off else 'on'}")
    if persist and _nm():
        val = "2" if off else "3"
        script = (f"printf '[connection]\\nwifi.powersave = {val}\\n' > {NM_DROPIN} && "
                  f"nmcli general reload conf")
        subprocess.Popen(["pkexec", "sh", "-c", script])
        parts.append(f"NM drop-in wifi.powersave={val}")
        if conn:
            _run(["nmcli", "connection", "modify", conn, "802-11-wireless.powersave", val], timeout=10)
            parts.append(f"profile powersave={val}")
    return " · ".join(parts) or "nothing to do"


def recent_drops(hours=24, limit=40):
    """[(iso_time, bssid, code, text)] from wpa_supplicant's journal — the forensic 'why'.
    Bounded (journalctl --since + timeout) so it never stalls the UI thread."""
    if not _has("journalctl"):
        return []
    r = _run(["journalctl", "-q", "--no-pager", "-o", "short-iso", f"--since=-{int(hours)}h",
              "_COMM=wpa_supplicant"], timeout=12)
    out = []
    for ln in (r.stdout.splitlines() if r else []):
        if "CTRL-EVENT-DISCONNECTED" not in ln:
            continue
        m = re.search(r"^(\S+)\s.*bssid=(\S+)\s+reason=(\d+)(.*)$", ln)
        if m:
            code = int(m.group(3))
            txt = REASON.get(code, f"reason {code}") + (" · locally generated" if "locally_generated" in m.group(4) else "")
            out.append((m.group(1), m.group(2), code, txt))
    return out[-limit:]


# ───────────────────────── Bitcoin Core: Tor / P2P compatibility (optional, read-only) ─────────────────────────
def core_settings(conf=None):
    """What Core already says about its network — from bitcoin.conf (datadir symlink-aware).
    Keys: proxy, onion, listenonion, onlynet[], listen, bind[], torcontrol, i2psam, conf."""
    conf = conf or os.path.join(os.path.expanduser("~/.bitcoin"), "bitcoin.conf")
    d = {"proxy": None, "onion": None, "listenonion": None, "onlynet": [], "listen": None, "bind": [],
         "torcontrol": None, "i2psam": None, "conf": conf if os.path.exists(conf) else None}
    try:
        for ln in open(conf):
            ln = ln.split("#", 1)[0].strip()
            if "=" not in ln:
                continue
            k, v = (x.strip() for x in ln.split("=", 1))
            k = k.split(".")[-1]                          # [main] section / main.proxy= forms
            if k in ("onlynet", "bind"):
                d[k].append(v)
            elif k in d:
                d[k] = v
    except OSError:
        pass
    d["tor"] = bool(d["proxy"] or d["onion"] or d["torcontrol"] or "onion" in d["onlynet"])
    d["onion_only"] = bool(d["onlynet"]) and all(n == "onion" for n in d["onlynet"])
    return d


def _port_open(hostport, timeout=1.5):
    import socket
    try:
        host, port = hostport.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def tor_state(cs=None):
    """{configured, socks, service} — Tor as Core would use it (SOCKS reachability + systemd unit)."""
    cs = cs or core_settings()
    socks = cs["onion"] or cs["proxy"] or "127.0.0.1:9050"
    svc = None
    if _has("systemctl"):
        r = _run(["systemctl", "is-active", "tor"], timeout=4)
        svc = (r.stdout.strip() if r else None) or None
    return {"configured": cs["tor"], "socks": socks, "socks_open": _port_open(socks) if cs["tor"] else None, "service": svc}


def verify(cs=None):
    """Connection verification after a (re)connect — [(check, ok|None, detail)]. ok=None = n/a.
    Honest about Tor: an onion-only node is not expected to answer clearnet checks."""
    cs = cs or core_settings(); out = []
    gw, dev = _default_route()
    pg = ping_stats(gw) if gw else {"recv": 0, "loss_pct": 100, "avg_ms": None}
    out.append(("gateway", pg["recv"] > 0, f"{gw or 'no default route'} via {dev or '—'} · loss {pg['loss_pct']}% · avg {pg['avg_ms'] or '—'} ms"))
    if cs["onion_only"]:
        out.append(("internet", None, "n/a — onlynet=onion (clearnet not expected)"))
        out.append(("dns", None, "n/a — onion-only"))
    else:
        pi = ping_stats("9.9.9.9")
        out.append(("internet", pi["recv"] > 0, f"icmp 9.9.9.9 · loss {pi['loss_pct']}% · avg {pi['avg_ms'] or '—'} ms"))
        r = _run(["getent", "hosts", "seed.bitcoin.sipa.be"], timeout=5)
        out.append(("dns", bool(r and r.returncode == 0 and r.stdout.strip()), "seed.bitcoin.sipa.be"))
    if cs["tor"]:
        t = tor_state(cs)
        out.append(("tor", t["socks_open"], f"SOCKS {t['socks']} · service {t['service'] or '?'}"))
    else:
        out.append(("tor", None, "not configured in bitcoin.conf"))
    return out


# ───────────────────────── KEEP: systematic retry (backoff ladder) ─────────────────────────
def reset_device(iface, conn=None):
    """Step 2 — bounce the device under NetworkManager (unprivileged for the active user)."""
    if not _nm() or not iface:
        return reconnect(conn, iface)
    cmd = f"nmcli device disconnect {iface}; sleep 1; nmcli device connect {iface}"
    if conn:
        cmd += f" || nmcli connection up '{conn}'"
    subprocess.Popen(["sh", "-c", cmd]); return f"device bounce {iface}"


def reset_radio(conn=None):
    """Step 3 — bounce the Wi-Fi radio (re-inits the supplicant association)."""
    if not _nm():
        return "no NetworkManager"
    cmd = "nmcli radio wifi off; sleep 2; nmcli radio wifi on" + (f"; sleep 3; nmcli connection up '{conn}'" if conn else "")
    subprocess.Popen(["sh", "-c", cmd]); return "radio bounce"


def reset_driver(iface, conn=None):
    """Step 4 (opt-in, pkexec) — reload the driver chain, then hand back to NetworkManager."""
    mods = module_chain(driver_of(iface)) if iface else []
    if not mods:
        return "no driver to reset"
    cmd = ("modprobe -r " + " ".join(mods) + "; sleep 1; modprobe " + mods[-1] + "; sleep 3; rfkill unblock wifi; nmcli radio wifi on"
           + (f"; sleep 3; nmcli connection up '{conn}'" if conn else ""))
    subprocess.Popen(["pkexec", "sh", "-c", cmd]); return "driver reload " + " ".join(mods)


LADDER = ("profile", "device", "radio", "driver")   # escalation, one rung per failed attempt


# ───────────────────────── MEASURE: time · volume · speed (the kernel's own counters) ─────────────────────────
def iface_counters(iface):
    """Exact byte/packet/error/drop counters from /sys/class/net/<iface>/statistics (since the
    driver loaded). Integers, never floats — the truth every rate is derived from."""
    if not iface:
        return None
    base = f"/sys/class/net/{iface}/statistics/"
    out = {}
    for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
        try:
            out[k] = int(open(base + k).read().strip())
        except (OSError, ValueError):
            return None
    out["ts"] = time.time()
    return out


def link_rate(iface):
    """{signal_dbm, rx_mbps, tx_mbps} from `iw dev <iface> link` (unprivileged) — the PHY rate the
    link negotiated, as opposed to the throughput it is actually carrying."""
    out = {"signal_dbm": None, "rx_mbps": None, "tx_mbps": None}
    if not iface or not _has("iw"):
        return out
    r = _run(["iw", "dev", iface, "link"], timeout=4)
    for ln in (r.stdout.splitlines() if r else []):
        m = re.search(r"signal:\s*(-?\d+)\s*dBm", ln)
        if m: out["signal_dbm"] = int(m.group(1))
        m = re.search(r"(rx|tx) bitrate:\s*([\d.]+)\s*MBit/s", ln)
        if m: out[m.group(1) + "_mbps"] = float(m.group(2))
    if out["signal_dbm"] is None:
        try:
            for ln in open("/proc/net/wireless"):
                if ln.strip().startswith(iface + ":"):
                    out["signal_dbm"] = int(float(ln.split()[3].rstrip(".")))
        except (OSError, ValueError, IndexError):
            pass
    return out


def conn_since(conn):
    """Unix time NetworkManager last ACTIVATED this profile (connection.timestamp) — the honest
    'connected since' for the current session, independent of when the watchdog started."""
    if not _nm() or not conn:
        return None
    r = _run(["nmcli", "-g", "connection.timestamp", "connection", "show", conn], timeout=4)
    try:
        return int(r.stdout.strip()) or None
    except (AttributeError, ValueError):
        return None


class Watchdog:
    """State machine — call tick() every few seconds; returns evidence events
    ({'event': drop|retry|restored|verified|paused|resumed|sample, …}). Pauses under the wall.
    Retry is systematic: exponential backoff (base 5 s, ×2, cap 60 s, ±20 % jitter) and an
    escalation ladder profile → device → radio → driver (driver only if allow_driver).
    MEASURES while up: session time (from NetworkManager's activation timestamp), volume
    (iface byte counters since the session started / since the driver loaded), throughput
    (B/s from counter deltas, with peaks) and the negotiated PHY rate + signal; one `sample`
    event a minute carries them into the .history."""
    SAMPLE_EVERY = 60.0
    def __init__(self, auto=True, grace=2, base=5.0, cap=60.0, allow_driver=False, grace_held=6):
        self.auto = auto; self.grace = grace; self.base = base; self.cap = cap; self.allow_driver = allow_driver
        self.grace_held = grace_held          # probes to tolerate while NetworkManager still says 'connected'
        self.degraded = False
        self.state = None; self.was_up = None; self.fails = 0
        self.drops = 0; self.reconnects = 0; self.last_drop = None; self.up_since = None
        self.paused = False; self.last_action = ""; self.attempt = 0; self.next_at = 0.0
        self.verified = None                  # last verify() result after a restore
        self.sess = None; self._cnt_prev = None; self._sample_ts = 0.0
    # ---- measurement ----
    def _measure(self, st, now):
        iface = st.get("iface"); c = iface_counters(iface); rate = link_rate(iface) if iface else {}
        st["counters"] = c; st["rate"] = rate
        if not c:
            return
        if self.sess is None:
            since = conn_since(st.get("conn")) or now
            self.sess = {"since": since, "rx0": c["rx_bytes"], "tx0": c["tx_bytes"], "rx_bps": 0, "tx_bps": 0,
                         "peak_rx_bps": 0, "peak_tx_bps": 0, "samples": 0}
        s = self.sess
        if self._cnt_prev and c["ts"] > self._cnt_prev["ts"] and c["rx_bytes"] >= self._cnt_prev["rx_bytes"]:
            dt = c["ts"] - self._cnt_prev["ts"]
            s["rx_bps"] = int((c["rx_bytes"] - self._cnt_prev["rx_bytes"]) / dt)
            s["tx_bps"] = int((c["tx_bytes"] - self._cnt_prev["tx_bytes"]) / dt)
            s["peak_rx_bps"] = max(s["peak_rx_bps"], s["rx_bps"]); s["peak_tx_bps"] = max(s["peak_tx_bps"], s["tx_bps"])
        self._cnt_prev = c
        s["rx_B"] = c["rx_bytes"] - s["rx0"]; s["tx_B"] = c["tx_bytes"] - s["tx0"]
        s["uptime_s"] = int(now - s["since"])
        s["rx_mbps"] = rate.get("rx_mbps"); s["tx_mbps"] = rate.get("tx_mbps"); s["signal_dbm"] = rate.get("signal_dbm")
        s["errors"] = c["rx_errors"] + c["tx_errors"]; s["dropped"] = c["rx_dropped"] + c["tx_dropped"]
    def session(self):
        """The measured session, or None before the first up tick. Keys: since, uptime_s, rx_B, tx_B
        (session volume), rx_bps, tx_bps (live), peak_*_bps, rx_mbps/tx_mbps (PHY), signal_dbm,
        errors, dropped, samples."""
        return dict(self.sess) if self.sess else None
    def _sample_event(self, st):
        s = self.sess; pg = st.get("ping") or {}; c = st.get("counters") or {}
        s["samples"] += 1
        return {"event": "sample", "uptime_s": s["uptime_s"], "rx_B": s["rx_B"], "tx_B": s["tx_B"],
                "rx_Bps": s["rx_bps"], "tx_Bps": s["tx_bps"], "rx_mbps": s["rx_mbps"], "tx_mbps": s["tx_mbps"],
                "signal_dbm": s["signal_dbm"], "signal_pct": st.get("signal"), "loss_pct": pg.get("loss_pct"),
                "avg_ms": pg.get("avg_ms"), "errors": s["errors"], "dropped": s["dropped"],
                "iface_rx_total_B": c.get("rx_bytes"), "iface_tx_total_B": c.get("tx_bytes")}
    def _delay(self):
        import random
        d = min(self.cap, self.base * (2 ** self.attempt))
        return d * random.uniform(0.8, 1.2)
    def _rung(self):
        rung = LADDER[min(self.attempt, len(LADDER) - 1)]
        if rung == "driver" and not self.allow_driver:
            rung = "radio"
        return rung
    def _act(self, st):
        rung = self._rung(); iface, conn = st.get("iface"), st.get("conn")
        if rung == "profile": act = reconnect(conn, iface)
        elif rung == "device": act = reset_device(iface, conn)
        elif rung == "radio": act = reset_radio(conn)
        else: act = reset_driver(iface, conn)
        return rung, act
    def tick(self):
        st = link_state(); self.state = st; ev = []; now = time.time()
        walled = bool(st["airgap"]) or bool(st["hardgate"])
        if walled != self.paused:
            self.paused = walled
            ev.append({"event": "paused" if walled else "resumed",
                       "why": "hard gate" if st["hardgate"] else "AIRGAP" if walled else "wall lifted"})
        if walled:
            self.fails = 0; self.attempt = 0; return ev
        up = st["present"] and st["gw_ok"] is True
        if up:
            if self.was_up is not True:
                self.up_since = now; self.sess = None; self._cnt_prev = None   # a new session starts here
            self._measure(st, now)
            if st.get("degraded") != self.degraded:          # quality edge: evidence, never an action
                self.degraded = bool(st.get("degraded")); pg = st.get("ping") or {}
                ev.append({"event": "degraded" if self.degraded else "quality-ok", "loss_pct": pg.get("loss_pct"),
                           "avg_ms": pg.get("avg_ms"), "signal": st.get("signal")})
            if self.was_up is False:
                ev.append({"event": "restored", "ssid": st["ssid"], "ip": st["ip"], "gw": st["gw"],
                           "after_s": round(now - (self.last_drop or now)), "attempts": self.attempt})
                self.verified = verify()
                ev.append({"event": "verified", "checks": {k: v for k, v, _d in self.verified},
                           "detail": "; ".join(f"{k}: {'✓' if v else '✗' if v is False else 'n/a'} {d}" for k, v, d in self.verified)})
            if self.sess and now - self._sample_ts >= self.SAMPLE_EVERY:
                self._sample_ts = now; ev.append(self._sample_event(st))
            self.fails = 0; self.attempt = 0; self.was_up = True; return ev
        self.fails += 1
        held = bool(st.get("nm_state", "") or "").startswith("connected") and bool(st.get("ip"))
        need = self.grace_held if held else self.grace      # NM still holds the link → wait longer, don't re-dial a live link
        if self.was_up is not False and self.fails >= need:
            self.was_up = False; self.drops += 1; self.last_drop = now; self.attempt = 0; self.next_at = now
            s = self.sess or {}
            ev.append({"event": "drop", "iface": st["iface"], "ssid": st["ssid"], "nm": st["nm_state"],
                       "gw": st["gw"], "powersave": st["powersave"],
                       "session_s": s.get("uptime_s"), "session_rx_B": s.get("rx_B"), "session_tx_B": s.get("tx_B"),
                       "peak_rx_Bps": s.get("peak_rx_bps"), "peak_tx_Bps": s.get("peak_tx_bps")})
            self.sess = None; self._cnt_prev = None
        if self.was_up is False and self.auto and now >= self.next_at and self.fails >= need:
            rung, act = self._act(st); self.last_action = f"[{self.attempt + 1}·{rung}] {act}"; self.reconnects += 1
            ev.append({"event": "retry", "rung": rung, "action": act, "attempt": self.attempt + 1})
            self.attempt += 1; self.next_at = now + self._delay()
        return ev


# ───────────────────────── GATE: Wi-Fi hard gate (driver off) ─────────────────────────
def hardgate_state():
    try:
        with open(GATE_STATE) as fh:
            d = json.load(fh)
        d.setdefault("down", False); return d
    except Exception:
        return {"down": False, "modules": [], "iface": None, "since": None}


def _save_gate(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(GATE_STATE, "w") as fh:
            json.dump(d, fh)
    except OSError:
        pass


def hardgate_plan(iface=None):
    """What 'down' would do — shown to the operator before the single pkexec prompt."""
    iface = iface or (wifi_ifaces() or [None])[0]
    mods = module_chain(driver_of(iface)) if iface else []
    steps = []
    if iface:
        if _nm():
            steps.append(f"nmcli radio wifi off && nmcli device set {iface} managed no")
        steps.append(f"ip link set {iface} down")
        steps.append("rfkill block wifi")
    if mods:
        steps.append("modprobe -r " + " ".join(mods))
    return iface, mods, steps


def hardgate_down(iface=None):
    """Driver OFF. One pkexec prompt; the module list is remembered for restore. Returns (ok, msg)."""
    iface, mods, steps = hardgate_plan(iface)
    if not iface and not hardgate_state()["down"]:
        return False, "no wifi interface present"
    if not mods:
        return False, f"could not resolve the driver module for {iface}"
    _save_gate({"down": True, "modules": mods, "iface": iface, "since": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
    script = " ; ".join(steps) + " ; lsmod | grep -q '^" + mods[-1] + " ' && echo STILL_LOADED || echo GONE"
    r = _run(["pkexec", "sh", "-c", script], timeout=40)
    if r is None:
        return False, "pkexec timed out"
    if r.returncode != 0 and "GONE" not in (r.stdout or ""):
        _save_gate({"down": False, "modules": mods, "iface": iface, "since": None})
        return False, (r.stderr or r.stdout or f"rc {r.returncode}").strip()[:300]
    if "STILL_LOADED" in (r.stdout or ""):
        return False, f"{mods[-1]} still loaded (in use?) — radio is rfkill-blocked but the driver remains"
    return True, f"HARD GATE down: {iface} removed, driver {' → '.join(mods)} unloaded"


def hardgate_up():
    """Driver back ON, device handed to NetworkManager, radio unblocked. Returns (ok, msg)."""
    g = hardgate_state()
    mods = list(reversed(g.get("modules") or [])) or ["iwlwifi"]
    iface = g.get("iface")
    steps = ["modprobe " + mods[0]]                   # base first; consumers autoload (or we add them)
    for m in mods[1:]:
        steps.append(f"modprobe {m} 2>/dev/null || true")
    steps.append("rfkill unblock wifi")
    if _nm():
        steps.append("sleep 2")
        if iface:
            steps.append(f"nmcli device set {iface} managed yes 2>/dev/null || true")
        steps.append("nmcli radio wifi on")
    r = _run(["pkexec", "sh", "-c", " ; ".join(steps)], timeout=40)
    if r is None:
        return False, "pkexec timed out"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or f"rc {r.returncode}").strip()[:300]
    _save_gate({"down": False, "modules": g.get("modules") or mods, "iface": iface, "since": None})
    return True, f"HARD GATE lifted: {' ← '.join(mods)} reloaded, {iface or 'wifi'} back under NetworkManager"


# ───────────────────────── PERSIST: the watchdog as a systemd USER unit ─────────────────────────
UNIT = "bankon-ice-netkeep.service"
UNIT_DIR = os.path.join(os.path.expanduser("~"), ".config", "systemd", "user")


def _module_path():
    return os.path.abspath(__file__)


def service_state():
    """'active' | 'inactive' | 'failed' | None (not installed / no systemd --user)."""
    if not _has("systemctl") or not os.path.exists(os.path.join(UNIT_DIR, UNIT)):
        return None
    r = _run(["systemctl", "--user", "is-active", UNIT], timeout=4)
    return (r.stdout.strip() if r else None) or None


def install_service(every=5, allow_driver=False):
    """Write + enable + start the user unit. No root: nmcli acts for the logged-in user; the
    driver rung stays off unless asked (it would prompt pkexec with nobody to answer)."""
    os.makedirs(UNIT_DIR, exist_ok=True)
    py = shutil.which("python3") or "/usr/bin/python3"
    svc_dir = os.path.dirname(_module_path())
    args = f"--watch --every {int(every)}" + (" --allow-driver" if allow_driver else "")
    unit = f"""[Unit]
Description=BANKON ICE netkeep — persistent LAN link watchdog (docs/ICE.md)
After=network.target

[Service]
Type=simple
ExecStart={py} {_module_path()} {args}
WorkingDirectory={svc_dir}
Restart=always
RestartSec=5
Nice=10

[Install]
WantedBy=default.target
"""
    with open(os.path.join(UNIT_DIR, UNIT), "w") as fh:
        fh.write(unit)
    for cmd in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", UNIT]):
        r = _run(cmd, timeout=15)
        if r is None or r.returncode != 0:
            return False, (r.stderr.strip() if r else "systemctl --user unavailable")
    return True, f"{UNIT} enabled + started (every {every} s)"


def remove_service():
    _run(["systemctl", "--user", "disable", "--now", UNIT], timeout=15)
    try:
        os.remove(os.path.join(UNIT_DIR, UNIT))
    except OSError:
        pass
    _run(["systemctl", "--user", "daemon-reload"], timeout=10)
    return True, f"{UNIT} removed"


def _history_append(kind, **fields):
    """Same .history as the Qt tab (services/history_service.py) — imported lazily so the
    module stays usable standalone (falls back to a plain JSONL line)."""
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(_module_path())))
        from services import history_service as H
        H.append(kind, **fields)
    except Exception:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(os.path.join(STATE_DIR, ".history"), "a") as fh:
                fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind, **fields}) + "\n")
        except OSError:
            pass


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="ICE netkeep — persistent LAN link watchdog / Wi-Fi hard gate")
    ap.add_argument("--watch", action="store_true", help="run the watchdog loop (what the systemd unit does)")
    ap.add_argument("--every", type=int, default=5)
    ap.add_argument("--allow-driver", action="store_true", help="enable the driver-reload rung (pkexec)")
    ap.add_argument("--status", action="store_true"); ap.add_argument("--verify", action="store_true")
    ap.add_argument("--drops", type=int, metavar="HOURS")
    ap.add_argument("--gate", choices=["down", "up", "plan"])
    ap.add_argument("--install", action="store_true"); ap.add_argument("--remove", action="store_true")
    a = ap.parse_args(argv)
    if a.status or not any((a.watch, a.verify, a.drops, a.gate, a.install, a.remove)):
        st = link_state(); print(json.dumps(st, indent=1)); print("service:", service_state()); return 0
    if a.verify:
        for k, ok, d in verify():
            print(f"{k:9} {'✓' if ok else '✗' if ok is False else 'n/a'}  {d}")
        return 0
    if a.drops:
        for t, b, c, txt in recent_drops(a.drops):
            print(t, b, c, txt)
        return 0
    if a.gate == "plan":
        iface, mods, steps = hardgate_plan(); print(iface, mods); print("\n".join(steps)); return 0
    if a.gate:
        ok, msg = hardgate_down() if a.gate == "down" else hardgate_up(); print(msg); return 0 if ok else 1
    if a.install:
        ok, msg = install_service(a.every, a.allow_driver); print(msg); return 0 if ok else 1
    if a.remove:
        print(remove_service()[1]); return 0
    wd = Watchdog(auto=True, allow_driver=a.allow_driver)
    _history_append("ice-net", event="service-start", every=a.every)
    while True:
        for e in wd.tick():
            _history_append("ice-net", **e); print(time.strftime("%H:%M:%S"), e, flush=True)
        time.sleep(max(3, a.every))


if __name__ == "__main__":
    raise SystemExit(main())
