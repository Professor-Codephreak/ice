"""financialmind — ICE's view of the intelligence layer (FinancialMind.rs, Tauri + Rust + TS).
One job: is it up, what it talks to, and does that square with the wall.

FinancialMind is an EGRESS-heavy app (CoinGecko, DeFiLlama, CoinMarketCap, Polygonscan, LlamaRPC,
GitHub) with three local surfaces: the Vite UI (127.0.0.1:5174), an Anvil EVM (127.0.0.1:8545) and
THOT memory on an IPFS API (localhost:5001, swarm :4001). ICE does not drive it — ICE has precedence
and only reports/starts/stops. Built from extensions/_template.py (contract: services/ice_ext.py)."""
import json, os, re, shutil, socket, subprocess, urllib.request

KEY = "financialmind"
TITLE = "🧠 financialmind — intelligence layer vs the wall (egress · THOT/IPFS · Anvil)"
DOC = "~/financialmind/README.md · docs/ICE-EXTENSIONS.md"
ORDER = 70
EVERY = 10.0
ROOT = os.path.expanduser(os.environ.get("FMIND_ROOT", "~/financialmind"))
PORTS = {"ui": ("127.0.0.1", 5174), "anvil": ("127.0.0.1", 8545), "ipfs_api": ("127.0.0.1", 5001), "ipfs_swarm": ("0.0.0.0", 4001)}
EGRESS = ["api.coingecko.com", "api.llama.fi", "pro-api.coinmarketcap.com", "polygonscan.com", "eth.llamarpc.com", "github.com"]


def _run(cmd, timeout=5, cwd=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    except Exception:
        return None


def _open(host, port, timeout=0.4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def version():
    try:
        m = re.search(r"v(\d+\.\d+\.\d+)", open(os.path.join(ROOT, "README.md")).readline())
        return m.group(1) if m else None
    except OSError:
        return None


def _ipfs(path, timeout=2):
    """Kubo RPC is POST-only; returns parsed JSON or None."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:5001/api/v0/{path}", method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode() or "{}")
    except Exception:
        return None


def _procs():
    """FinancialMind's OWN processes (Tauri binary, its Vite dev server) — never this probe, never a
    shell or editor that merely has the path in its command line."""
    r = _run(["pgrep", "-af", "financialmind/src-tauri|financialmind/target|vite.*--port 5174|vite.*5174"])
    me = str(os.getpid())
    return [ln for ln in (r.stdout.splitlines() if r else [])
            if not ln.startswith(me + " ") and "pgrep" not in ln and "python" not in ln and "extensions/" not in ln]


def _airgap():
    r = _run(["rfkill", "list", "wifi"])
    return bool(r and ("Soft blocked: yes" in r.stdout or "Hard blocked: yes" in r.stdout))


def probe():
    st = {"installed": os.path.isdir(ROOT), "version": version(), "procs": len(_procs()),
          "ui": _open(*PORTS["ui"]), "anvil": _open(*PORTS["anvil"]), "ipfs_api": _open(*PORTS["ipfs_api"]),
          "ipfs_peers": None, "ipfs_pins": None, "swarm_wide_open": False, "airgap": _airgap(), "egress": EGRESS}
    st["running"] = st["ui"] or st["procs"] > 0
    if st["ipfs_api"]:
        sp = _ipfs("swarm/peers"); st["ipfs_peers"] = len((sp or {}).get("Peers") or []) if sp is not None else None
        pl = _ipfs("pin/ls?type=recursive&quiet=true"); st["ipfs_pins"] = len((pl or {}).get("Keys") or {}) if pl is not None else None
        r = _run(["ss", "-ltnH"]); st["swarm_wide_open"] = bool(r and re.search(r"(0\.0\.0\.0|\*|\[::\]):4001\b", r.stdout))
    if st["anvil"]:
        try:
            req = urllib.request.Request("http://127.0.0.1:8545", data=b'{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}',
                                         headers={"content-type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=1.5) as r:
                st["anvil_block"] = int(json.loads(r.read())["result"], 16)
        except Exception:
            st["anvil_block"] = None
    return st


def render(st):
    if not st.get("installed"):
        return f"not installed at {ROOT} (set FMIND_ROOT)"
    up = "RUNNING" if st.get("running") else "stopped"
    bits = [f"v{st.get('version') or '?'} {up}", f"ui :5174 {'✓' if st.get('ui') else '—'}",
            f"anvil :8545 {('✓ block ' + str(st.get('anvil_block'))) if st.get('anvil') else '—'}",
            f"THOT/IPFS :5001 {('✓ peers ' + str(st.get('ipfs_peers') if st.get('ipfs_peers') is not None else '?') + ' · pins ' + str(st.get('ipfs_pins') if st.get('ipfs_pins') is not None else '?')) if st.get('ipfs_api') else '—'}"]
    if st.get("swarm_wide_open"): bits.append("⚠ IPFS swarm :4001 listens on all interfaces")
    if st.get("airgap") and st.get("running"): bits.append("⏸ AIRGAP — its feeds are dark by design")
    bits.append("egress → " + ", ".join(st.get("egress", [])[:3]) + " …")
    return " · ".join(bits)


def level(st):
    if not st.get("installed") or not st.get("running"): return "off"
    if st.get("swarm_wide_open"): return "alert"
    return "warn" if st.get("airgap") else "ok"


def _start():
    if not os.path.isfile(os.path.join(ROOT, "fmind.sh")): return "fmind.sh not found"
    subprocess.Popen(["bash", "fmind.sh"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return "launched fmind.sh (Vite + Tauri) — ~30 s to come up"


def _stop():
    r = _run(["pkill", "-f", "financialmind/src-tauri|vite.*5174"]); return "stop signal sent" if r is not None else "pkill failed"


def _egress():
    """Which of its external hosts resolve right now — the wall's view of its appetite."""
    out = []
    for h in EGRESS:
        try: socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP); out.append(f"{h} ✓")
        except OSError: out.append(f"{h} ✗")
    return " · ".join(out)


def _ipfs_id():
    d = _ipfs("id")
    return (f"{d.get('ID', '?')[:16]}… agent {d.get('AgentVersion', '?')} · {len(d.get('Addresses') or [])} addrs") if d else "IPFS API not answering on :5001"


ACTIONS = [
    ("▶ start", _start, "bash ~/financialmind/fmind.sh — Vite UI + Tauri desktop", False),
    ("■ stop", _stop, "pkill -f financialmind/src-tauri|vite — stop before key operations", False),
    ("🌐 egress check", _egress, "resolve each external host it talks to (DNS only, nothing fetched)", False),
    ("🧠 THOT/IPFS id", _ipfs_id, "POST 127.0.0.1:5001/api/v0/id — the memory node's identity", False),
]

TOOLS = [
    ("ipfs-peers", "ipfs", "kubo", "how many swarm peers the THOT memory node is talking to", "ipfs swarm peers | wc -l", False, "cli"),
    ("cast-block", "cast", "foundry", "Anvil's local EVM height (FinancialMind's sandbox chain)", "cast block-number --rpc-url http://127.0.0.1:8545", False, "cli"),
    ("fmind-conns", "ss", "iproute2", "every live TCP connection FinancialMind holds right now", "ss -tnp | grep -E 'tauri|vite|financialmind'", False, "cli"),
]

if __name__ == "__main__":
    import sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    try: from services import ice_ext                      # inside bankon-qt
    except ImportError: import ice_ext                      # beside ice.py in the standalone ~/ICE tool
    raise SystemExit(ice_ext.cli(sys.modules[__name__]))
