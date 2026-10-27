"""ICE extension discovery — the one-thing-well contract every modular ICE/BANKON module follows.

An extension is ONE Python file in bankon-qt/extensions/ (files starting with '_' are skipped).
It is Qt-free, so the same file also runs as a CLI and inside the standalone ~/ICE tool.
It exposes, by name (all optional except KEY/TITLE/probe):

    KEY      = "netkeep"              # short slug — .history kind becomes "ice-<KEY>"
    TITLE    = "🔗 netkeep — …"        # panel header (one line)
    DOC      = "docs/ICE.md §B2"      # where the operator reads more
    ORDER    = 50                     # panel order in the tab (lower = higher); default 100

    def probe() -> dict               # unprivileged · bounded (<2 s) · never raises · returns facts
    def render(state: dict) -> str    # one monospace line (or a few) from probe()'s dict; default = key:value
    def level(state: dict) -> str     # "ok" | "warn" | "alert" | "off" → colour; default "ok"
    ACTIONS  = [                      # single tasks — one button each; fn() returns a status string
        ("↻ verify", fn, "tooltip", False),   # (label, callable, tooltip, needs_root)
    ]
    TOOLS    = [ ... ]                # rows merged into ice_tools.TOOLS (same 7-tuple)
    EVERY    = 5.0                    # probe period in seconds while the tab is visible (default 5)
    def main(argv) -> int             # optional CLI: python3 extensions/<file>.py --status …

Rules of the house (docs/ICE.md): local-first, nothing leaves the host; mutations escalate with
pkexec; every action is .history evidence; honest unknowns ('—', never a fabricated 0); numbers go
through the shell's fmt_* helpers when rendered by Qt. ICE has precedence — never fight the wall.
"""
import importlib.util, os, sys, time, traceback

EXT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extensions")


def discover(ext_dir=EXT_DIR):
    """[module, …] sorted by ORDER then KEY. A broken extension is reported, never fatal."""
    mods = []
    if not os.path.isdir(ext_dir):
        return mods
    if ext_dir not in sys.path:
        sys.path.insert(0, ext_dir)
    for fn in sorted(os.listdir(ext_dir)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        path = os.path.join(ext_dir, fn)
        try:
            spec = importlib.util.spec_from_file_location("bankon_ext_" + fn[:-3], path)
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            if not getattr(m, "KEY", None) or not callable(getattr(m, "probe", None)):
                continue
            m.__ext_path__ = path; mods.append(m)
        except Exception:
            sys.stderr.write(f"[ice_ext] {fn}: {traceback.format_exc(limit=1)}")
    mods.sort(key=lambda m: (getattr(m, "ORDER", 100), m.KEY))
    return mods


def safe_probe(m):
    """probe() that honours the contract even when the extension does not: bounded, never raises."""
    t0 = time.time()
    try:
        st = m.probe() or {}
    except Exception as e:
        st = {"error": str(e)[:200]}
    st["_ms"] = int((time.time() - t0) * 1000)
    return st


def render(m, st):
    try:
        if callable(getattr(m, "render", None)):
            return m.render(st)
    except Exception as e:
        return f"render failed: {e}"
    return " · ".join(f"{k} {v}" for k, v in st.items() if not k.startswith("_"))


def level(m, st):
    try:
        return m.level(st) if callable(getattr(m, "level", None)) else ("alert" if st.get("error") else "ok")
    except Exception:
        return "warn"


def tools():
    """Every extension's TOOLS rows — ice_tools.TOOLS + these is the whole shelf."""
    out = []
    for m in discover():
        out += list(getattr(m, "TOOLS", []) or [])
    return out


def evidence(m, **fields):
    """Append to the shared ICE .history as kind 'ice-<KEY>' (Qt-free; same store as the tab).
    Standalone (~/ICE, no services package): a plain JSONL line into ~/.bankon/.history."""
    try:
        from services import history_service as H
        H.append(f"ice-{m.KEY}", **fields); return
    except Exception:
        pass
    try:
        import json
        d = os.path.join(os.path.expanduser("~"), ".bankon"); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, ".history"), "a") as fh:
            fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": f"ice-{m.KEY}", **fields}) + "\n")
    except Exception:
        pass


def cli(m, argv=None):
    """Default CLI for an extension that has none: --status (probe → JSON) · --do <action label>."""
    import json
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv or argv[0] == "--status":
        print(json.dumps(safe_probe(m), indent=1)); return 0
    if argv[0] == "--do" and len(argv) > 1:
        for label, fn, _tip, _root in getattr(m, "ACTIONS", []):
            if argv[1] in label:
                print(fn()); evidence(m, action=label, via="cli"); return 0
        print("no such action; have:", [a[0] for a in getattr(m, "ACTIONS", [])]); return 1
    print(f"usage: {os.path.basename(m.__ext_path__)} [--status | --do <action>]"); return 1
