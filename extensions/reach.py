"""reach — inbound reachability as an ICE panel (thin over services/ice_reach.py). One job: say which
paths to this node are open, and act on the ones the host can act on. The full UI is the 🔌 Connections dialog."""
import os

KEY = "reach"
TITLE = "🌐 reach — can the network dial this node? (IPv4 · IPv6 · PCP · Tor onion · I2P · ufw)"
DOC = "docs/ICE.md · 🔌 Connections → Reachability"
ORDER = 40
EVERY = 30.0


def _R():
    try:
        from services import ice_reach as R
    except ImportError:
        import ice_reach as R
    return R


def probe():
    st = _R().probe(); st["consumer"] = _R().consumer_state(); return st


def render(st):
    inb = st.get("inbound"); paths = {p["key"]: p for p in st.get("paths", [])}
    tor = paths.get("tor-onion", {}); v4 = paths.get("ipv4-forward", {}); ufw = paths.get("ufw", {})
    onion = st.get("tor", {}).get("onion_addr")
    cm = st.get("consumer") or {}
    mode = "🔇 CONSUMER (not serving)" if cm.get("on") else "serving"
    return (f"{mode} · inbound {inb if inb is not None else '—'} / outbound {st.get('outbound') if st.get('outbound') is not None else '—'} · "
            f"IPv4 forward {v4.get('state', '?')} · Tor onion {tor.get('state', '?')}{(' ' + onion) if onion else ''} · ufw {ufw.get('state', '?')} · "
            f"nets " + " ".join(f"{k}{'✓' if v else '✗'}" for k, v in (st.get('networks') or {}).items()))


def level(st):
    inb = st.get("inbound")
    if inb is None: return "off"
    if inb > 0: return "ok"
    tor = next((p for p in st.get("paths", []) if p["key"] == "tor-onion"), {})
    return "ok" if tor.get("state") == "working" else "warn"


def _selftest():
    ok, msg = _R().onion_selftest(); return msg


def _consumer_on():  return _R().set_consumer_mode(True)[1]
def _consumer_off(): return _R().set_consumer_mode(False)[1]
def _tor_diag():     return " · ".join(f"{k} {'✓' if ok else '✗' if ok is False else '·'} {d[:40]}" for k, ok, d in _R().tor_diagnostics())


ACTIONS = [
    ("🔇 consumer ON", _consumer_on, "listen=0 · ufw deny 8333 · disconnect inbound — take, don't serve", True),
    ("📡 consumer OFF", _consumer_off, "listen=1 · ufw allow 8333", True),
    ("🧅 tor diagnostics", _tor_diag, "bootstrap · liveness · circuits · onion · peers from Tor's control port", False),
    ("🧪 onion self-test", _selftest, "dial our own .onion through Tor's SOCKS — the inbound test that needs no outside help", False),
    ("🛡 ufw allow 8333", lambda: _R().allow_ufw()[1], "ufw allow 8333/tcp", True),
]

TOOLS = [
    ("tor-circuits", "ss", "iproute2", "is Tor holding circuits (connections from the tor daemon)", "ss -tnp | grep -c tor", False, "cli"),
    ("onion-addr", "bitcoin-cli", "bitcoin", "the onion address Core advertises (localaddresses)", "bitcoin-cli getnetworkinfo | grep -A2 onion", False, "cli"),
]

if __name__ == "__main__":
    import sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    try: from services import ice_ext
    except ImportError: import ice_ext
    raise SystemExit(ice_ext.cli(sys.modules[__name__]))
