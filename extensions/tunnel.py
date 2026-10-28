"""tunnel — reverse SSH tunnel to a rented endpoint, as a service (systemd user unit). One job: say
whether the tunnel is up and proven, and act on it. Setup (endpoint · port · key) lives in the
🔌 Connections → 🚇 Tunnel page; this panel is the same truth as a panel and a CLI. docs/reversetunnel.md"""
import os

KEY = "tunnel"
TITLE = "🚇 tunnel — reverse SSH to a rented endpoint → this node :8333 (no router)"
DOC = "docs/reversetunnel.md"
ORDER = 45
EVERY = 30.0


def _R():
    try:
        from services import ice_reach as R
    except ImportError:
        import ice_reach as R
    return R


def probe():
    return _R().tunnel_state()


def render(st):
    if not st.get("configured"):
        return "not configured — 🔌 Connections → 🚇 Tunnel (any host you hold an ssh key for)"
    return (f"{st['endpoint']}:{st['remote_port']} (ip {st.get('endpoint_ip') or '—'}) · unit {st.get('unit') or 'missing'} · "
            f"externalip {st.get('externalip') or '—'} · inbound via tunnel {st['inbound_via'] if st.get('inbound_via') is not None else '—'}"
            + (f" · {st['log']}" if st.get("log") else ""))


def level(st):
    if not st.get("configured"):
        return "off"
    return {"active": "ok", "activating": "warn"}.get(st.get("unit"), "bad")


def _prove():
    ok, msg = _R().tunnel_selftest(); return msg


def _restart():
    R = _R(); r = R._run(["systemctl", "--user", "restart", R.TUNNEL_UNIT], timeout=20)
    return "unit restarted" if r and r.returncode == 0 else "restart failed: " + ((r.stderr if r else "") or "no systemd --user")[:160]


ACTIONS = [
    ("🧪 prove from outside", _prove, "a Tor exit dials <endpoint ip>:<port>; a control dial to our own peer decides what a failure means", False),
    ("↻ restart unit", _restart, "systemctl --user restart bankon-ice-tunnel.service", False),
    ("■ remove", lambda: _R().tunnel_remove()[1], "stop + disable the unit, comment out externalip (restart Core to stop advertising)", True),
]

TOOLS = [
    ("tunnel-unit", "systemctl", "systemd", "the unit as systemd sees it", "systemctl --user status bankon-ice-tunnel.service --no-pager", False, "cli"),
    ("tunnel-log", "journalctl", "systemd", "ssh's own words — auth, forward refused, keepalive", "journalctl --user -u bankon-ice-tunnel.service -n 30 --no-pager", False, "cli"),
    ("ssh-keygen", "ssh-keygen", "openssh-client", "make the tunnel key once", "ssh-keygen -t ed25519 -f ~/.ssh/bankon_tunnel -N ''", False, "cli"),
]

if __name__ == "__main__":
    import sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    try: from services import ice_ext
    except ImportError: import ice_ext
    raise SystemExit(ice_ext.cli(sys.modules[__name__]))
