"""TEMPLATE — copy to extensions/<key>.py and fill the blanks. One job. Qt-free. See services/ice_ext.py.

    cp extensions/_template.py extensions/mything.py      # the file name is free; KEY is the identity
    python3 extensions/mything.py --status                 # CLI works before any UI exists
"""
import os, shutil, subprocess

KEY = "template"                         # slug → .history kind "ice-template"
TITLE = "🧩 template — one job, stated in one line"
DOC = "docs/ICE.md · ICE-EXTENSIONS"
ORDER = 100                              # position in the 🧊 ICE tab (lower = higher)
EVERY = 5.0                              # probe cadence while the tab is visible


def _run(cmd, timeout=4):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def probe():
    """Facts only. Unprivileged. Bounded. Unknown = None (never a fabricated 0)."""
    return {"present": shutil.which("true") is not None, "example": None}


def render(st):
    """One honest line. Use st['_fmt'] helpers (fmt_bytes/fmt_rate/fmt_secs/fmt_temp) when the shell provides them."""
    f = st.get("_fmt") or {}
    return f"present {st.get('present')} · example {st.get('example') if st.get('example') is not None else '—'}"


def level(st):
    return "ok" if st.get("present") else "off"


def _do_something():
    """A single task. Escalate with pkexec only when the kernel needs root. Return a status string."""
    r = _run(["true"])
    return "done" if r and r.returncode == 0 else "failed"


ACTIONS = [
    ("▶ do the thing", _do_something, "what it runs, verbatim: true", False),
]

TOOLS = [
    # ("key", "binary", "apt package", "one job", "snippet {iface} {subnet} {gw}", needs_root, "cli|tui|gui"),
]

if __name__ == "__main__":
    import sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    try: from services import ice_ext                      # inside bankon-qt
    except ImportError: import ice_ext                      # beside ice.py in the standalone ~/ICE tool
    raise SystemExit(ice_ext.cli(sys.modules[__name__]))
