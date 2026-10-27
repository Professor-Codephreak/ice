"""dnsguard — which resolver answers this host, and does a Core seed resolve. One job.
Built from extensions/_template.py (the contract lives in services/ice_ext.py)."""
import os, re, shutil, subprocess

KEY = "dns"
TITLE = "🧭 dnsguard — who resolves names for the wallet host"
DOC = "docs/ICE.md §B2 (verification) · docs/reference/core-net-activity.md"
ORDER = 60
EVERY = 20.0
SEED = "seed.bitcoin.sipa.be"


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def resolvers():
    """[(server, iface|'global')] from resolvectl (systemd-resolved) or /etc/resolv.conf."""
    out = []
    if shutil.which("resolvectl"):
        r = _run(["resolvectl", "status"])
        link = "global"
        for ln in (r.stdout.splitlines() if r else []):
            m = re.match(r"Link \d+ \((\S+)\)", ln.strip())
            if m: link = m.group(1)
            m = re.search(r"(?:Current )?DNS Server[s]?:\s*(.+)$", ln)
            if m:
                for s in m.group(1).split():
                    out.append((s, link))
    if not out:
        try:
            for ln in open("/etc/resolv.conf"):
                if ln.startswith("nameserver"):
                    out.append((ln.split()[1], "resolv.conf"))
        except OSError:
            pass
    return out


def probe():
    rs = resolvers()
    r = _run(["getent", "hosts", SEED], timeout=6)
    ok = bool(r and r.returncode == 0 and r.stdout.strip())
    n = len(r.stdout.splitlines()) if ok else 0
    stub = any(s.startswith("127.0.0.53") for s, _l in rs)
    lan = any(s.startswith(("10.", "192.168.", "172.")) for s, _l in rs if not s.startswith("127."))
    return {"resolvers": rs, "seed_ok": ok, "seed_answers": n if ok else None, "stub": stub, "lan_resolver": lan,
            "tor_only": _onion_only()}


def _onion_only():
    try:
        conf = os.path.expanduser("~/.bitcoin/bitcoin.conf")
        nets = [ln.split("=", 1)[1].strip() for ln in open(conf) if ln.strip().startswith("onlynet=")]
        return bool(nets) and all(n == "onion" for n in nets)
    except OSError:
        return False


def render(st):
    rs = " ".join(f"{s}@{l}" for s, l in st.get("resolvers", [])[:4]) or "—"
    seed = ("n/a (onlynet=onion)" if st.get("tor_only") else
            f"{SEED} ✓ {st.get('seed_answers')} answers" if st.get("seed_ok") else f"{SEED} ✗")
    return f"resolvers {rs} · stub {'yes' if st.get('stub') else 'no'} · {seed}"


def level(st):
    if st.get("tor_only"): return "ok"
    if not st.get("seed_ok"): return "alert"
    return "warn" if st.get("lan_resolver") else "ok"      # a LAN resolver sees every name the host asks


def _test():
    r = _run(["getent", "hosts", SEED], timeout=8)
    return (r.stdout.strip()[:400] if r and r.stdout.strip() else "no answer")


def _flush():
    if shutil.which("resolvectl"):
        r = _run(["resolvectl", "flush-caches"]); return "caches flushed" if r and r.returncode == 0 else "flush failed"
    return "resolvectl not present"


ACTIONS = [
    ("✔ resolve seed", _test, f"getent hosts {SEED} — the DNS half of ICE verify", False),
    ("🧹 flush caches", _flush, "resolvectl flush-caches", False),
]

TOOLS = [
    ("dig", "dig", "bind9-dnsutils", "ask ONE resolver directly and see who really answered",
     f"dig +short {SEED} @{{gw}}", False, "cli"),
    ("resolvectl", "resolvectl", "systemd", "per-link resolver configuration as systemd-resolved sees it",
     "resolvectl status", False, "cli"),
]

if __name__ == "__main__":
    import sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    try: from services import ice_ext                      # inside bankon-qt
    except ImportError: import ice_ext                      # beside ice.py in the standalone ~/ICE tool
    raise SystemExit(ice_ext.cli(sys.modules[__name__]))
