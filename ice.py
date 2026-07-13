#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# ICE maintains the github.com/cypherpunk2048 standard (client-controlled, local-first).
"""
ICE — CPU / Temperature Controller  (localhost, single-use, GTK3 + tray)

Scale CPU performance and hold temperature down on a Linux laptop. Uses the
intel_pstate `max_perf_pct` knob (a direct 0-100 % cap), turbo toggle, and
cpufreq governors; falls back to scaling_max_freq when intel_pstate is absent.

- Needs root to write /sys -> self-elevates with `sudo -E` (asks for the
  password in the terminal and waits) if not already root.
- Lives in the system tray (Ayatana AppIndicator), showing live temperature.
- Quitting RESTORES full CPU performance and cleans up — clean gone.
- Optional: persist chosen settings at boot via a systemd unit; and uninstall.

CLI:
  --apply       apply the saved /etc config to hardware and exit (used by boot unit)
  --uninstall   restore defaults, remove unit/config/launcher and this folder, exit
"""

import json
import os
import sys
import glob
import math
import shutil
import time
import signal
import subprocess

# ── Self-elevate: ask for sudo and wait for it ────────────────────────────────
if os.geteuid() != 0:
    print("This controller needs root to change CPU scaling. Requesting sudo…")
    try:
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
    except FileNotFoundError:
        sys.exit("sudo not found — run this script as root.")

# psutil is only needed for the live GUI (temp/cpu readouts), not for --apply.
try:
    import psutil
except ImportError:
    psutil = None

INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))

# ── BANKON_VAULT (frozen storage) — import the isolated bankon-vault module. ICE runs as root via
# sudo -E, so add the invoking user's site-packages (embit lives there) + the module path.
_VAULT_DIR = os.path.join(_REAL_HOME, "bankon-tools", "bankon-vault") if False else None  # set below
def _vault_paths():
    home = os.environ.get("SUDO_USER") and os.path.expanduser("~" + os.environ["SUDO_USER"]) or os.path.expanduser("~")
    mod = os.path.join(home, "bankon-tools", "bankon-vault")
    usersite = glob.glob(os.path.join(home, ".local/lib/python3*/site-packages"))
    return mod, usersite
try:
    _vmod, _usersite = _vault_paths()
    for _p in [_vmod, *_usersite]:
        if _p and os.path.isdir(_p) and _p not in sys.path:
            sys.path.append(_p)
    from bankon_vault import BankonVault, PassphraseOverseer          # noqa: E402
    from bankon_vault.chains.btc import BitcoinAdapter                 # noqa: E402
    from bankon_vault.policy import ApprovalGate, gated_sign_psbt      # noqa: E402
    HAS_VAULT = True
    try:
        from blackice import BlackICE, SOFT, FIRM, HARD, SECURE, DEGRADED, BREACHED   # noqa: E402
        HAS_BLACKICE = True
    except Exception:
        HAS_BLACKICE = False
    _vhome = os.environ.get("SUDO_USER") and os.path.expanduser("~" + os.environ["SUDO_USER"]) or os.path.expanduser("~")
    VAULT_PATH = os.environ.get("BANKON_VAULT_PATH", os.path.join(_vhome, ".bankon-vault"))
except Exception as _e:
    HAS_VAULT = False
    VAULT_PATH = None
    _VAULT_IMPORT_ERR = str(_e)
if "HAS_BLACKICE" not in dir():
    try:
        from blackice import BlackICE, SOFT, FIRM, HARD, SECURE, DEGRADED, BREACHED   # noqa: E402
        HAS_BLACKICE = True
    except Exception:
        HAS_BLACKICE = False

# ── Sysfs paths ───────────────────────────────────────────────────────────────
PSTATE = "/sys/devices/system/cpu/intel_pstate"
MAX_PERF_PCT = f"{PSTATE}/max_perf_pct"
NO_TURBO = f"{PSTATE}/no_turbo"
CPU_GLOB = "/sys/devices/system/cpu/cpu[0-9]*/cpufreq"
GOV_AVAIL = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors"
CPUINFO_MAX = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"
CPUINFO_MIN = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq"
HAS_PSTATE = os.path.isdir(PSTATE) and os.path.exists(MAX_PERF_PCT)


def _read(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _write(path, value):
    try:
        with open(path, "w") as f:
            f.write(str(value))
        return True
    except OSError as e:
        print(f"write {path} = {value} failed: {e}")
        return False


def read_int(path, default=0):
    try:
        return int(_read(path))
    except (TypeError, ValueError):
        return default


# ── Hardware control ──────────────────────────────────────────────────────────
def available_governors():
    g = _read(GOV_AVAIL, "")
    return g.split() if g else []


def current_governor():
    return _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "?")


def set_governor(gov):
    ok = True
    for d in glob.glob(CPU_GLOB):
        ok &= _write(os.path.join(d, "scaling_governor"), gov)
    return ok


def set_max_perf_pct(pct):
    pct = max(10, min(100, int(pct)))
    if HAS_PSTATE:
        return _write(MAX_PERF_PCT, pct)
    fmin = read_int(CPUINFO_MIN, 800000)
    fmax = read_int(CPUINFO_MAX, 3500000)
    target = int(fmin + (fmax - fmin) * pct / 100)
    ok = True
    for d in glob.glob(CPU_GLOB):
        ok &= _write(os.path.join(d, "scaling_max_freq"), target)
    return ok


def get_max_perf_pct():
    if HAS_PSTATE:
        return read_int(MAX_PERF_PCT, 100)
    fmin = read_int(CPUINFO_MIN, 800000)
    fmax = read_int(CPUINFO_MAX, 3500000)
    cur = read_int("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", fmax)
    return 100 if fmax == fmin else max(10, min(100, round((cur - fmin) / (fmax - fmin) * 100)))


def set_turbo(enabled):
    if HAS_PSTATE and os.path.exists(NO_TURBO):
        return _write(NO_TURBO, 0 if enabled else 1)
    return False


def get_turbo():
    if HAS_PSTATE and os.path.exists(NO_TURBO):
        return read_int(NO_TURBO, 0) == 0
    return True


def cpu_temp():
    if not psutil:
        return None
    try:
        temps = psutil.sensors_temperatures()
    except Exception:
        return None
    best = None
    for chip in ("coretemp", "k10temp", "zenpower", "dell_smm", "acpitz"):
        for s in temps.get(chip, []):
            label = (s.label or "").lower()
            if chip == "dell_smm" and label != "cpu":
                continue
            if chip == "acpitz" and best is not None:
                continue
            if s.current and (best is None or s.current > best):
                best = s.current
        if best is not None and chip in ("coretemp", "k10temp", "zenpower"):
            break
    return best


def cur_freq_ghz():
    f = read_int("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", 0)
    return f / 1_000_000 if f else 0.0


def default_governor():
    govs = available_governors()
    for g in ("schedutil", "ondemand", "conservative", "powersave"):
        if g in govs:
            return g
    return current_governor()


def restore_defaults():
    """Return the CPU to unthrottled full performance (used on quit)."""
    set_max_perf_pct(100)
    set_turbo(True)
    set_governor(default_governor())


# ── Network wall: radio control (ICE = the wall between network and wallet) ────
# ICE gates the machine's radios. rfkill soft-blocks a whole class (bluetooth /
# wifi / wwan / nfc). "Airgap" blocks everything — no RF path to the wallet host.
RADIO_TYPES = [
    ("bluetooth", "Bluetooth"),
    ("wifi", "Wi-Fi"),
    ("wwan", "Cellular (WWAN)"),
    ("nfc", "NFC"),
]
HAS_RFKILL = shutil.which("rfkill") is not None


def radio_set(kind, on):
    """on=True → unblock (radio enabled); on=False → block (radio off / walled)."""
    if not HAS_RFKILL:
        return
    subprocess.run(["rfkill", "unblock" if on else "block", kind], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def radio_is_on(kind):
    """True if the radio class is currently enabled (not soft-blocked)."""
    if not HAS_RFKILL:
        return True
    try:
        out = subprocess.run(["rfkill", "list", kind], capture_output=True, text=True).stdout
    except OSError:
        return True
    if not out.strip():
        return True  # no such device present → treat as not-blocking
    return "Soft blocked: yes" not in out


def airgap(on):
    """on=True → cut ALL radios (the wall up); on=False → restore all radios."""
    if not HAS_RFKILL:
        return
    subprocess.run(["rfkill", "block" if on else "unblock", "all"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ── Firewall (ufw) — ICE (Intrusion Countermeasure Electronics) controls the FIREWALL ──────────
HAS_UFW = shutil.which("ufw") is not None


def ufw_status():
    """(active|None, summary) from `ufw status`. None when ufw is absent."""
    if not HAS_UFW:
        return (None, "not installed")
    try:
        out = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=6).stdout
    except Exception:
        return (None, "unavailable")
    active = "Status: active" in out
    rules = sum(1 for ln in out.splitlines() if (" ALLOW " in ln or " DENY " in ln or " REJECT " in ln or " LIMIT " in ln))
    return (active, f"{'active' if active else 'inactive'} · {rules} rules")


def ufw_set(on):
    if HAS_UFW:
        subprocess.run(["ufw", "--force", "enable" if on else "disable"], check=False,
                       capture_output=True, text=True)


def ufw_reload():
    if HAS_UFW:
        subprocess.run(["ufw", "reload"], check=False, capture_output=True, text=True)


# ── Bitcoin datadir — locate, diagnose, and (easily) relocate where .bitcoin lives ─────────────
_SUDO_USER = os.environ.get("SUDO_USER") or ""
_REAL_HOME = os.path.expanduser("~" + _SUDO_USER) if _SUDO_USER and _SUDO_USER != "root" else os.path.expanduser("~")
DATADIR_LINK = os.path.join(_REAL_HOME, ".bitcoin")


def is_datadir(p):
    return bool(p) and (os.path.isdir(os.path.join(p, "blocks")) or os.path.isfile(os.path.join(p, "bitcoin.conf")))


def datadir_target():
    try:
        return os.path.realpath(DATADIR_LINK)
    except Exception:
        return DATADIR_LINK


def datadir_df():
    """(used_bytes, total_bytes, free_bytes) for the filesystem holding the datadir."""
    try:
        st = os.statvfs(datadir_target())
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        return (total - free, total, free)
    except Exception:
        return (0, 0, 0)

# ── rageBTC discovery, shared with the Console: find every .bitcoin, pick the largest, remember
# all locations in ONE .history file (bankon-console/.history) — persists across drive unplugs.
DDH_FILE = os.path.join(_REAL_HOME, "bankon-tools", "bankon-console", ".history")
DD_SKIP = {"node_modules", "__pycache__", "Trash", "lost+found", "snap", "flatpak", "venv",
           "proc", "sys", "dev", "run", "tmp"}


def _dd_probes():
    """Well-known layouts, probed FIRST (instant): ~/.bitcoin, /home/*/.bitcoin, and for every
    mounted volume <vol>/.bitcoin + <vol>/home/*/.bitcoin — finds standard datadirs without traversal."""
    def kids(p):
        try:
            return [os.path.join(p, n) for n in os.listdir(p)]
        except OSError:
            return []
    out = [os.path.join(_REAL_HOME, ".bitcoin")]
    out += [os.path.join(u, ".bitcoin") for u in kids("/home")]
    vols = []
    for base in ("/media", "/run/media"):
        for u in kids(base):
            vols += kids(u)
    vols += kids("/mnt")
    for v in vols:
        out.append(os.path.join(v, ".bitcoin"))
        out += [os.path.join(hu, ".bitcoin") for hu in kids(os.path.join(v, "home"))]
    return out


def find_datadirs(deadline=15.0, maxd=6):
    """Known-location probes first (instant), then a breadth-first sweep for exotic spots.
    Sizes from blk*.dat metadata only. → sorted largest-first."""
    t0 = time.time()
    seen, found = set(), []

    def consider(full):
        real = os.path.realpath(full)
        if real in seen:
            return
        seen.add(real)
        if os.path.isdir(os.path.join(real, "blocks")) or os.path.isfile(os.path.join(real, "bitcoin.conf")):
            found.append(real)
    for pr in _dd_probes():                               # phase 1: standard layouts, instant
        if os.path.isdir(pr):
            consider(pr)
    roots = [r for r in (_REAL_HOME, "/home", "/media", "/mnt", "/run/media") if os.path.isdir(r)]
    q = [(r, 0) for r in roots]                           # phase 2: BFS — shallow first, deadline-safe
    i = 0
    while i < len(q) and time.time() - t0 < deadline:
        p, d = q[i]; i += 1
        try:
            ents = list(os.scandir(p))
        except OSError:
            continue
        for e in ents:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if e.name == ".bitcoin":                      # check BEFORE the dot-dir skip
                consider(e.path)
                continue
            if d >= maxd or e.name.startswith(".") or e.name in DD_SKIP:
                continue
            q.append((e.path, d + 1))
    out = []
    for pth in found:
        blk = bts = 0
        try:
            for f in os.listdir(os.path.join(pth, "blocks")):
                if f.startswith("blk") and f.endswith(".dat"):
                    blk += 1
                    try:
                        bts += os.path.getsize(os.path.join(pth, "blocks", f))
                    except OSError:
                        pass
        except OSError:
            pass
        out.append({"path": pth, "blk": blk, "bytes": bts})
    out.sort(key=lambda x: -x["bytes"])
    return out


def ddh_load():
    try:
        with open(DDH_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def ddh_update(dirs):
    h = ddh_load()
    now = int(time.time())
    for d in dirs:
        e = h.get(d["path"], {"firstSeen": now})
        e.update(lastSeen=now, bytes=d["bytes"], blkFiles=d["blk"])
        h[d["path"]] = e
    cur = datadir_target()
    if cur:
        h["_current"] = {"path": cur, "asOf": now}
    try:
        os.makedirs(os.path.dirname(DDH_FILE), exist_ok=True)
        with open(DDH_FILE, "w") as f:
            json.dump(h, f, indent=2)
        if _SUDO_USER and _SUDO_USER != "root":
            shutil.chown(DDH_FILE, _SUDO_USER, _SUDO_USER)
    except Exception:
        pass
    return h



# ── Fan: read RPM always; allow targeting ONLY when the hardware exposes PWM ────
def _find_fan_input():
    for h in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        fans = sorted(glob.glob(os.path.join(h, "fan*_input")))
        if fans:
            return fans[0]
    return None


def _find_fan_pwm():
    # A pwmN with a pwmN_enable sibling = proper, standard manual control.
    for h in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        for p in sorted(glob.glob(os.path.join(h, "pwm[0-9]"))):
            if os.path.exists(p + "_enable"):
                return p
    return None


FAN_INPUT = _find_fan_input()
FAN_PWM = _find_fan_pwm()


def fan_rpm():
    if not FAN_INPUT:
        return None
    return read_int(FAN_INPUT, 0) or None


def fan_can_control():
    return FAN_PWM is not None


def set_fan_pct(pct):
    """Target fan speed 0–100 % (manual). Only when fan_can_control()."""
    if not FAN_PWM:
        return
    _write(FAN_PWM + "_enable", 1)                       # 1 = manual
    _write(FAN_PWM, int(max(0, min(100, pct)) / 100 * 255))


def fan_auto():
    """Hand the fan back to the firmware/driver (automatic)."""
    if FAN_PWM:
        _write(FAN_PWM + "_enable", 2)


# ── Boot persistence (config + systemd unit) ──────────────────────────────────
CONFIG = "/etc/ice-cpu.conf"
SERVICE_NAME = "ice.service"
SERVICE_DST = f"/etc/systemd/system/{SERVICE_NAME}"


def save_config(pct, turbo_on, governor):
    try:
        with open(CONFIG, "w") as f:
            f.write("# CPU / Temperature Controller — restored at boot\n")
            f.write(f"max_perf_pct={int(pct)}\nturbo={1 if turbo_on else 0}\ngovernor={governor}\n")
        return True
    except OSError as e:
        print(f"save_config failed: {e}")
        return False


def load_config():
    cfg = {}
    try:
        with open(CONFIG) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except OSError:
        pass
    return cfg


def apply_config():
    cfg = load_config()
    if not cfg:
        print("no config to apply")
        return
    if cfg.get("governor"):
        set_governor(cfg["governor"])
    if "max_perf_pct" in cfg:
        set_max_perf_pct(int(cfg["max_perf_pct"]))
    if "turbo" in cfg:
        set_turbo(cfg["turbo"] == "1")
    print("applied:", cfg)


def service_installed():
    return os.path.exists(SERVICE_DST)


def install_service():
    unit = (
        "[Unit]\nDescription=Apply saved CPU scaling / thermal settings\n"
        "After=multi-user.target\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart=/usr/bin/env python3 {os.path.abspath(__file__)} --apply\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    try:
        with open(SERVICE_DST, "w") as f:
            f.write(unit)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError as e:
        print(f"install_service failed: {e}")
        return False


def disable_service():
    subprocess.run(["systemctl", "disable", SERVICE_NAME], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for p in (SERVICE_DST, CONFIG):
        try:
            os.remove(p)
        except OSError:
            pass
    subprocess.run(["systemctl", "daemon-reload"], check=False)


def _user_home():
    u = os.environ.get("SUDO_USER")
    if u:
        try:
            import pwd
            return pwd.getpwnam(u).pw_dir
        except (KeyError, ImportError):
            pass
    return os.path.expanduser("~")


def uninstall(remove_dir=True):
    """Full removal: restore CPU, drop the boot unit/config/launcher and this folder."""
    restore_defaults()
    disable_service()
    desktop = os.path.join(_user_home(), ".local/share/applications", "ice.desktop")
    try:
        os.remove(desktop)
    except OSError:
        pass
    shutil.rmtree(os.path.join(INSTALL_DIR, "__pycache__"), ignore_errors=True)
    if remove_dir:
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    print("Uninstalled: CPU restored, boot unit/config/launcher removed.")


# ── GTK GUI + tray ────────────────────────────────────────────────────────────
import gi  # noqa: E402
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk  # noqa: E402
try:
    import cairo  # noqa: E402   (pycairo — for the 3D knob radial gradients)
    HAS_CAIRO = True
except Exception:
    HAS_CAIRO = False

APPIND = None
for _name in ("AyatanaAppIndicator3", "AppIndicator3"):
    try:
        gi.require_version(_name, "0.1")
        APPIND = getattr(__import__("gi.repository", fromlist=[_name]), _name)
        break
    except (ValueError, ImportError):
        continue


class Knob3D(Gtk.DrawingArea):
    """A 3D-look rotary knob (pure cairo → works software-rendered on the HD 3000).
    NiceGUI-Knob-inspired: a coloured value track around a raised, bevelled knob body with an
    indicator notch and centre value. Drag to turn · scroll to nudge. lo..hi over a 270° sweep."""
    _START, _SPAN = 135.0, 270.0

    def __init__(self, lo=10, hi=100, value=50, unit="%", accent=(0.0, 0.75, 1.0), on_change=None):
        super().__init__()
        self.lo, self.hi, self.unit, self.accent, self.on_change = lo, hi, unit, accent, on_change
        self.value = float(max(lo, min(hi, value)))
        self.set_size_request(130, 130)
        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.BUTTON1_MOTION_MASK | Gdk.EventMask.SCROLL_MASK)
        self.connect("draw", self._draw)
        self.connect("button-press-event", self._pointer)
        self.connect("motion-notify-event", self._pointer)
        self.connect("scroll-event", self._scroll)

    def set_value(self, v, emit=False):
        self.value = float(max(self.lo, min(self.hi, v))); self.queue_draw()
        if emit and self.on_change:
            self.on_change(round(self.value))

    def _val2ang(self, v):
        return math.radians(self._START + (v - self.lo) / (self.hi - self.lo) * self._SPAN)

    def _draw(self, _w, cr):
        a, b = self.get_allocated_width(), self.get_allocated_height()
        cx, cy, R = a / 2, b / 2, min(a, b) / 2 - 12
        s, e = math.radians(self._START), math.radians(self._START + self._SPAN)
        cr.set_line_cap(1)
        cr.set_line_width(9); cr.set_source_rgb(0.13, 0.15, 0.18); cr.arc(cx, cy, R, s, e); cr.stroke()   # track
        cr.set_source_rgb(*self.accent); cr.arc(cx, cy, R, s, self._val2ang(self.value)); cr.stroke()      # value arc
        kr = R - 16
        if HAS_CAIRO:                                                                                       # raised 3D body
            g = cairo.RadialGradient(cx - kr * 0.35, cy - kr * 0.35, kr * 0.1, cx, cy, kr * 1.15)
            g.add_color_stop_rgb(0, 0.32, 0.36, 0.42); g.add_color_stop_rgb(1, 0.08, 0.09, 0.12)
            cr.set_source(g)
        else:
            cr.set_source_rgb(0.16, 0.18, 0.22)
        cr.arc(cx, cy, kr, 0, 2 * math.pi); cr.fill()
        cr.set_line_width(2); cr.set_source_rgba(1, 1, 1, 0.14)                                             # top bevel highlight
        cr.arc(cx, cy, kr - 1, math.radians(200), math.radians(340)); cr.stroke()
        cr.set_source_rgba(0, 0, 0, 0.45); cr.arc(cx, cy, kr - 1, math.radians(20), math.radians(160)); cr.stroke()
        va = self._val2ang(self.value)                                                                     # indicator notch
        cr.set_line_width(4); cr.set_source_rgb(*self.accent)
        cr.move_to(cx + (kr - 18) * math.cos(va), cy + (kr - 18) * math.sin(va))
        cr.line_to(cx + (kr - 4) * math.cos(va), cy + (kr - 4) * math.sin(va)); cr.stroke()
        cr.set_source_rgb(0.93, 0.93, 0.96); cr.select_font_face("Sans", 0, 1); cr.set_font_size(26)        # centre value
        txt = f"{self.value:.0f}{self.unit}"; ext = cr.text_extents(txt)
        cr.move_to(cx - ext.width / 2, cy + ext.height / 2 - 2); cr.show_text(txt)

    def _pointer(self, _w, ev):
        if not (ev.type == Gdk.EventType.BUTTON_PRESS or (ev.state & Gdk.ModifierType.BUTTON1_MASK)):
            return False
        a, b = self.get_allocated_width(), self.get_allocated_height()
        aa = (math.degrees(math.atan2(ev.y - b / 2, ev.x - a / 2)) - self._START) % 360
        if aa > self._SPAN:
            aa = 0 if aa > (self._SPAN + 360) / 2 else self._SPAN
        self.set_value(self.lo + aa / self._SPAN * (self.hi - self.lo), emit=True)
        return True

    def _scroll(self, _w, ev):
        self.set_value(self.value + (2 if ev.direction == Gdk.ScrollDirection.UP else -2), emit=True)
        return True


class ThermostatDial(Gtk.DrawingArea):
    """Thermostat KNOB (cairo, NiceGUI/QKnob-styled): a dark track ring, a bitcoin-orange VALUE
    arc to the draggable target, a thin heat-coloured arc for the CURRENT temperature, and a
    raised bevelled centre disc showing the target big + 'now' small. lo..hi °C over 270°.
    Drag to set the target · scroll to nudge ±1 °C; calls on_change(target)."""
    _START, _SPAN = 135.0, 270.0

    def __init__(self, lo=50, hi=95, on_change=None):
        super().__init__()
        self.lo, self.hi, self.on_change = lo, hi, on_change
        self.target = 80.0
        self.current = None
        self.set_size_request(180, 180)
        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.BUTTON1_MOTION_MASK
                        | Gdk.EventMask.SCROLL_MASK)
        self.connect("draw", self._on_draw)
        self.connect("button-press-event", self._on_pointer)
        self.connect("motion-notify-event", self._on_pointer)
        self.connect("scroll-event", self._on_scroll)

    def _on_scroll(self, _w, ev):
        self.set_target(self.target + (1 if ev.direction == Gdk.ScrollDirection.UP else -1))
        if self.on_change:
            self.on_change(round(self.target))
        return True

    def set_current(self, t):
        self.current = t
        self.queue_draw()

    def set_target(self, t):
        self.target = max(self.lo, min(self.hi, float(t)))
        self.queue_draw()

    def _val2ang(self, v):
        frac = (v - self.lo) / (self.hi - self.lo)
        return math.radians(self._START + frac * self._SPAN)

    def _ang2val(self, ang_deg):
        a = (ang_deg - self._START) % 360         # 0 at start, clockwise
        if a > self._SPAN:                         # inside the bottom gap → snap to nearest end
            a = 0 if a > (self._SPAN + 360) / 2 else self._SPAN
        return self.lo + a / self._SPAN * (self.hi - self.lo)

    @staticmethod
    def _color(t):
        if t is None:
            return (0.5, 0.6, 0.7)
        if t >= 85:
            return (0.96, 0.32, 0.29)
        if t >= 70:
            return (1.0, 0.6, 0.0)
        return (0.30, 0.69, 0.31)

    def _on_draw(self, _w, cr):
        a, b = self.get_allocated_width(), self.get_allocated_height()
        cx, cy, R = a / 2, b / 2, min(a, b) / 2 - 14
        s = math.radians(self._START); e = math.radians(self._START + self._SPAN)
        cr.set_line_cap(1)  # round
        # track ring (QKnob track_color)
        cr.set_line_width(11); cr.set_source_rgb(0.10, 0.13, 0.18)
        cr.arc(cx, cy, R, s, e); cr.stroke()
        # VALUE arc → target, bitcoin orange (QKnob color)
        ta = self._val2ang(self.target)
        cr.set_source_rgb(0.97, 0.58, 0.10)
        cr.arc(cx, cy, R, s, ta); cr.stroke()
        # CURRENT temperature: thin inner arc, heat-coloured (thermostat semantics kept)
        if self.current is not None:
            cr.set_line_width(4); cr.set_source_rgb(*self._color(self.current))
            cr.arc(cx, cy, R - 11, s, self._val2ang(max(self.lo, min(self.hi, self.current)))); cr.stroke()
        # raised centre disc (QKnob center_color + 3D bevel — matches Knob3D)
        kr = R - 22
        if HAS_CAIRO:
            g = cairo.RadialGradient(cx - kr * 0.35, cy - kr * 0.35, kr * 0.1, cx, cy, kr * 1.15)
            g.add_color_stop_rgb(0, 0.30, 0.34, 0.40); g.add_color_stop_rgb(1, 0.07, 0.09, 0.12)
            cr.set_source(g)
        else:
            cr.set_source_rgb(0.15, 0.17, 0.21)
        cr.arc(cx, cy, kr, 0, 2 * math.pi); cr.fill()
        cr.set_line_width(2); cr.set_source_rgba(1, 1, 1, 0.13)     # top bevel highlight
        cr.arc(cx, cy, kr - 1, math.radians(200), math.radians(340)); cr.stroke()
        cr.set_source_rgba(0, 0, 0, 0.45)                           # bottom shadow
        cr.arc(cx, cy, kr - 1, math.radians(20), math.radians(160)); cr.stroke()
        # indicator notch at the target angle (orange, on the disc edge)
        cr.set_line_width(4); cr.set_source_rgb(0.97, 0.58, 0.10)
        cr.move_to(cx + (kr - 14) * math.cos(ta), cy + (kr - 14) * math.sin(ta))
        cr.line_to(cx + (kr - 3) * math.cos(ta), cy + (kr - 3) * math.sin(ta)); cr.stroke()
        # centre value (show_value): target big, 'now' small + heat-coloured
        cr.set_source_rgb(0.93, 0.93, 0.95)
        cr.select_font_face("Sans", 0, 1); cr.set_font_size(30)
        txt = f"{self.target:.0f}°"
        ext = cr.text_extents(txt); cr.move_to(cx - ext.width / 2, cy + ext.height / 2 - 6); cr.show_text(txt)
        cr.set_font_size(11)
        cr.set_source_rgb(*(self._color(self.current) if self.current is not None else (0.55, 0.58, 0.62)))
        sub = "target" if self.current is None else f"now {self.current:.0f}°C"
        ext2 = cr.text_extents(sub); cr.move_to(cx - ext2.width / 2, cy + 26); cr.show_text(sub)

    def _on_pointer(self, _w, ev):
        pressed = ev.type == Gdk.EventType.BUTTON_PRESS
        dragging = bool(ev.state & Gdk.ModifierType.BUTTON1_MASK)
        if not (pressed or dragging):
            return False
        a, b = self.get_allocated_width(), self.get_allocated_height()
        ang = math.degrees(math.atan2(ev.y - b / 2, ev.x - a / 2))
        self.set_target(self._ang2val(ang))
        if self.on_change:
            self.on_change(round(self.target))
        return True


class Controller:
    def __init__(self):
        self.auto = False
        self.target = 80
        self._applying = False
        self._syncing = False
        self._build_window()
        self._build_tray()
        self.tick()

    # ── window ──
    def _build_window(self):
        self.win = Gtk.Window(title="ICE — Intrusion Countermeasure Electronics · firewall · thermal · airgap")
        self.win.set_border_width(12)
        self.win.set_resizable(False)
        self.win.connect("delete-event", self._on_close)  # X = hide to tray

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.win.add(box)

        # readouts
        row = Gtk.Box(spacing=14)
        self.temp_lbl = Gtk.Label()
        self.temp_lbl.set_markup("<span size='xx-large' weight='bold'>-- °C</span>")
        row.pack_start(self.temp_lbl, False, False, 0)
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.cpu_lbl = Gtk.Label(label="CPU: --%", xalign=0)
        self.freq_lbl = Gtk.Label(label="Freq: -- GHz", xalign=0)
        self.fan_lbl = Gtk.Label(label="Fan: --", xalign=0)
        self.drv_lbl = Gtk.Label(label=("intel_pstate" if HAS_PSTATE else "cpufreq") + " driver", xalign=0)
        for w in (self.cpu_lbl, self.freq_lbl, self.fan_lbl, self.drv_lbl):
            info.pack_start(w, False, False, 0)
        row.pack_start(info, False, False, 0)
        box.pack_start(row, False, False, 0)

        # max performance — a 3D rotary KNOB (ICE controller). self.scale is kept as the hidden value
        # store (presets/save read it); the knob drives it. Drag to turn · scroll to nudge.
        box.pack_start(Gtk.Label(label="Max CPU performance", xalign=0), False, False, 0)
        self.scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 10, 100, 1)
        self.scale.set_value(get_max_perf_pct())
        self.scale.connect("value-changed", self._on_scale)     # NOT packed — the knob is the visible control
        krow = Gtk.Box(spacing=18); krow.set_halign(Gtk.Align.CENTER)
        self.cpuknob = Knob3D(10, 100, get_max_perf_pct(), unit="%", accent=(0.0, 0.75, 1.0),
                              on_change=lambda v: self.scale.set_value(v))
        kcol = Gtk.Box(orientation=Gtk.Orientation.VERTICAL); kcol.pack_start(self.cpuknob, False, False, 0)
        klbl = Gtk.Label(); klbl.set_markup("<span size='small' foreground='#8aa0b4'>CPU cap</span>")
        kcol.pack_start(klbl, False, False, 0); krow.pack_start(kcol, False, False, 0)
        box.pack_start(krow, False, False, 0)

        # governor + turbo
        gov_row = Gtk.Box(spacing=10)
        gov_row.pack_start(Gtk.Label(label="Governor"), False, False, 0)
        self.gov_combo = Gtk.ComboBoxText()
        govs = available_governors() or [current_governor()]
        for g in govs:
            self.gov_combo.append_text(g)
        cur = current_governor()
        self.gov_combo.set_active(govs.index(cur) if cur in govs else 0)
        self.gov_combo.connect("changed", self._on_gov)
        gov_row.pack_start(self.gov_combo, False, False, 0)
        self.turbo_chk = Gtk.CheckButton(label="Turbo boost")
        self.turbo_chk.set_active(get_turbo())
        self.turbo_chk.connect("toggled", self._on_turbo)
        gov_row.pack_start(self.turbo_chk, False, False, 0)
        box.pack_start(gov_row, False, False, 0)

        # presets
        pf = Gtk.Box(spacing=6)
        pf.pack_start(Gtk.Label(label="Presets:"), False, False, 0)
        for label, name in (("❄ Cool", "cool"), ("⚖ Balanced", "balanced"), ("🔥 Full", "full")):
            b = Gtk.Button(label=label)
            b.connect("clicked", lambda _b, n=name: self.preset(n))
            pf.pack_start(b, False, False, 0)
        box.pack_start(pf, False, False, 0)

        # ── Thermostat: one target temperature, three synced controls ──
        box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)
        thead = Gtk.Label(); thead.set_markup("<b>🌡 Thermostat</b> — one target temperature, three ways to set it")
        thead.set_xalign(0); box.pack_start(thead, False, False, 0)
        self.auto_chk = Gtk.CheckButton(label="Auto-cool ON — hold the CPU at/under the target")
        self.auto_chk.connect("toggled", self._on_auto)
        box.pack_start(self.auto_chk, False, False, 0)

        trow = Gtk.Box(spacing=14)
        self.dial = ThermostatDial(50, 95, on_change=self._set_target)   # 1) classic dial
        trow.pack_start(self.dial, False, False, 0)

        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        col.set_valign(Gtk.Align.CENTER)
        # 2) slider bar
        sl = Gtk.Box(spacing=6)
        sl.pack_start(Gtk.Label(label="Slider"), False, False, 0)
        self.target_scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 50, 95, 1)
        self.target_scale.set_value(self.target); self.target_scale.set_size_request(210, -1)
        self.target_scale.connect("value-changed", lambda s: self._set_target(int(s.get_value())))
        sl.pack_start(self.target_scale, True, True, 0)
        col.pack_start(sl, False, False, 0)
        # 3) up / down
        ud = Gtk.Box(spacing=6)
        ud.pack_start(Gtk.Label(label="Up / Down"), False, False, 0)
        adj = Gtk.Adjustment(value=self.target, lower=50, upper=95, step_increment=1, page_increment=5)
        self.target_spin = Gtk.SpinButton(); self.target_spin.set_adjustment(adj); self.target_spin.set_digits(0)
        self.target_spin.connect("value-changed", lambda s: self._set_target(int(s.get_value())))
        ud.pack_start(self.target_spin, False, False, 0)
        down = Gtk.Button(label="▼"); down.connect("clicked", lambda _b: self._set_target(self.target - 1))
        up = Gtk.Button(label="▲"); up.connect("clicked", lambda _b: self._set_target(self.target + 1))
        ud.pack_start(down, False, False, 0); ud.pack_start(up, False, False, 0)
        ud.pack_start(Gtk.Label(label="°C"), False, False, 0)
        col.pack_start(ud, False, False, 0)
        trow.pack_start(col, True, True, 0)
        box.pack_start(trow, False, False, 0)
        self.dial.set_target(self.target)

        # ── Fan speed: control only when the hardware exposes PWM (targetable) ──
        if fan_can_control():
            fanrow = Gtk.Box(spacing=6)
            fanrow.pack_start(Gtk.Label(label="Fan target"), False, False, 0)
            self.fan_scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0, 100, 5)
            self.fan_scale.set_size_request(200, -1)
            self.fan_scale.connect("value-changed", lambda s: set_fan_pct(int(s.get_value())))
            fanrow.pack_start(self.fan_scale, True, True, 0)
            fauto = Gtk.Button(label="Auto")
            fauto.connect("clicked", lambda _b: (fan_auto(), self.status.set_text("Fan → automatic")))
            fanrow.pack_start(fauto, False, False, 0)
            box.pack_start(fanrow, False, False, 0)

        # persistence + uninstall
        persist = Gtk.Box(spacing=6)
        b1 = Gtk.Button(label="💾 Persist at boot")
        b1.connect("clicked", self._on_persist)
        persist.pack_start(b1, False, False, 0)
        b2 = Gtk.Button(label="✖ Remove persistence")
        b2.connect("clicked", self._on_unpersist)
        persist.pack_start(b2, False, False, 0)
        b3 = Gtk.Button(label="🗑 Uninstall")
        b3.connect("clicked", self._on_uninstall)
        persist.pack_start(b3, False, False, 0)
        box.pack_start(persist, False, False, 0)

        # ── Network wall / radios: ICE gates the RF path to the wallet ──
        box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)
        wall = Gtk.Label()
        wall.set_markup("<b>🧊 Network wall</b> — the wall between the network and the wallet")
        wall.set_xalign(0)
        box.pack_start(wall, False, False, 0)
        rf = Gtk.Box(spacing=6)
        ag = Gtk.Button(label="🛑 AIRGAP (cut all radios)")
        ag.connect("clicked", lambda _b: (airgap(True), self._refresh_radios(),
                                          self.status.set_text("AIRGAP up — all radios cut. Wallet is walled off.")))
        rf.pack_start(ag, False, False, 0)
        rs = Gtk.Button(label="📡 Restore radios")
        rs.connect("clicked", lambda _b: (airgap(False), self._refresh_radios(),
                                          self.status.set_text("Radios restored.")))
        rf.pack_start(rs, False, False, 0)
        box.pack_start(rf, False, False, 0)
        rr = Gtk.Box(spacing=10)
        self.radio_chks = {}
        for kind, label in RADIO_TYPES:
            c = Gtk.CheckButton(label=label)
            c.set_active(radio_is_on(kind))
            c.connect("toggled", self._on_radio, kind)
            self.radio_chks[kind] = c
            rr.pack_start(c, False, False, 0)
        box.pack_start(rr, False, False, 0)
        if not HAS_RFKILL:
            wall.set_sensitive(False)
            rf.set_sensitive(False)
            rr.set_sensitive(False)

        # ── Firewall (ufw) — the software wall; ICE controls it ──
        fwrow = Gtk.Box(spacing=6)
        self.fw_lbl = Gtk.Label(xalign=0); self.fw_lbl.set_markup("🛡 firewall: …")
        fwrow.pack_start(self.fw_lbl, True, True, 0)
        for label, fn in (("Enable", lambda: ufw_set(True)), ("Disable", lambda: ufw_set(False)),
                          ("Reload", ufw_reload), ("Status ▸", self._show_ufw)):
            b = Gtk.Button(label=label)
            b.connect("clicked", lambda _b, f=fn: (f(), self._refresh_fw()))
            fwrow.pack_start(b, False, False, 0)
        box.pack_start(fwrow, False, False, 0)
        if not HAS_UFW:
            fwrow.set_sensitive(False)

        # ── Bitcoin datadir — see/change where .bitcoin lives, with disk diagnostics ──
        box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)
        dh = Gtk.Label(); dh.set_markup("<b>📁 Bitcoin datadir</b> — where .bitcoin lives (attach point)"); dh.set_xalign(0)
        box.pack_start(dh, False, False, 0)
        self.dd_path = Gtk.Label(xalign=0); self.dd_path.set_line_wrap(True); self.dd_path.set_selectable(True)
        box.pack_start(self.dd_path, False, False, 0)
        self.dd_diag = Gtk.Label(xalign=0); self.dd_diag.set_line_wrap(True)
        box.pack_start(self.dd_diag, False, False, 0)
        ddr = Gtk.Box(spacing=6)
        chb = Gtk.Button(label="📂 Change location…"); chb.connect("clicked", self._choose_datadir)
        opb = Gtk.Button(label="Open folder"); opb.connect("clicked", self._open_datadir)
        rfb = Gtk.Button(label="↻ Rescan"); rfb.connect("clicked", lambda _b: self._refresh_datadir(deep=True))
        for b in (chb, opb, rfb):
            ddr.pack_start(b, False, False, 0)
        box.pack_start(ddr, False, False, 0)
        # rageBTC tools: find every .bitcoin (largest first) + the persistent .history w/ delete·shred
        ddr2 = Gtk.Box(spacing=6)
        fb = Gtk.Button(label="🔎 Find all .bitcoin")
        fb.set_tooltip_text("Search local + external devices; largest first; recorded in .history")
        fb.connect("clicked", self._find_datadirs)
        ddr2.pack_start(fb, False, False, 0)
        hb = Gtk.Button(label="🕘 .history")
        hb.set_tooltip_text("Every .bitcoin location ever seen (persists across drive unplugs)")
        hb.connect("clicked", self._show_history)
        ddr2.pack_start(hb, False, False, 0)
        db = Gtk.Button(label="🗑 delete")
        db.set_tooltip_text("Delete .history (plain remove)")
        db.connect("clicked", lambda _b: self._clear_history(False))
        ddr2.pack_start(db, False, False, 0)
        ddr2.pack_start(Gtk.Label(label="passes"), False, False, 0)
        self.shred_spin = Gtk.SpinButton.new_with_range(1, 35, 1)
        self.shred_spin.set_value(7)
        self.shred_spin.set_tooltip_text("Shred overwrite passes (default 7)")
        ddr2.pack_start(self.shred_spin, False, False, 0)
        sb = Gtk.Button(label="🔥 shred")
        sb.set_tooltip_text("TRUE shred .history — N overwrite passes + a final zero pass, then unlink")
        sb.connect("clicked", lambda _b: self._clear_history(True))
        ddr2.pack_start(sb, False, False, 0)
        box.pack_start(ddr2, False, False, 0)

        # ── BANKON_VAULT — frozen (very-cold) storage: signs ONLY while AIRGAP is up ──
        box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)
        vh = Gtk.Label(); vh.set_markup("<b>❄ BANKON_VAULT</b> — frozen storage (signs only under AIRGAP)")
        vh.set_xalign(0); box.pack_start(vh, False, False, 0)
        self.vault_lbl = Gtk.Label(xalign=0); self.vault_lbl.set_line_wrap(True)
        box.pack_start(self.vault_lbl, False, False, 0)
        vrow = Gtk.Box(spacing=6)
        self.freeze_btn = Gtk.Button(label="❄ Freeze")
        self.freeze_btn.set_tooltip_text("Cut all radios (AIRGAP) and lock the vault — very cold")
        self.freeze_btn.connect("clicked", self._vault_freeze)
        self.thaw_btn = Gtk.Button(label="🔓 Thaw-to-sign")
        self.thaw_btn.set_tooltip_text("Only works when AIRGAP is up: unlock, sign a PSBT file, re-lock")
        self.thaw_btn.connect("clicked", self._vault_thaw_sign)
        vrow.pack_start(self.freeze_btn, False, False, 0); vrow.pack_start(self.thaw_btn, False, False, 0)
        box.pack_start(vrow, False, False, 0)
        if not HAS_VAULT:
            vh.set_sensitive(False); vrow.set_sensitive(False)
        self._vault = None

        # ── 🖤 blackICE — active countermeasures: guard the signing moment, respond to a breach ──
        box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)
        bh = Gtk.Label(); bh.set_markup("<b>🖤 blackICE</b> — perimeter watch + active countermeasures")
        bh.set_xalign(0); box.pack_start(bh, False, False, 0)
        self.bi_lbl = Gtk.Label(xalign=0); self.bi_lbl.set_markup("perimeter: <b>—</b> (disarmed)")
        box.pack_start(self.bi_lbl, False, False, 0)
        brow = Gtk.Box(spacing=6)
        self.bi_arm_btn = Gtk.Button(label="🛡 Arm session"); self.bi_arm_btn.connect("clicked", self._bi_arm)
        self.bi_disarm_btn = Gtk.Button(label="Disarm"); self.bi_disarm_btn.connect("clicked", self._bi_disarm)
        brow.pack_start(self.bi_arm_btn, False, False, 0); brow.pack_start(self.bi_disarm_btn, False, False, 0)
        brow.pack_start(Gtk.Label(label="response"), False, False, 0)
        self.bi_resp = Gtk.ComboBoxText()
        for t in ("soft (warn)", "firm (re-airgap)", "hard (abort+lock+wipe)"):
            self.bi_resp.append_text(t)
        self.bi_resp.set_active(2); brow.pack_start(self.bi_resp, False, False, 0)
        brow.pack_start(Gtk.Label(label="dead-man s"), False, False, 0)
        self.bi_deadman = Gtk.SpinButton.new_with_range(0, 3600, 5); self.bi_deadman.set_value(15)
        self.bi_deadman.set_tooltip_text("Dead-man's switch: lose the heartbeat for N seconds → tear down (0 = off)")
        brow.pack_start(self.bi_deadman, False, False, 0)
        box.pack_start(brow, False, False, 0)
        if not HAS_BLACKICE:
            bh.set_sensitive(False); brow.set_sensitive(False)
        self._bi = None

        self.status = Gtk.Label(label="Running as root — changes apply live. Close = tray; Quit = restore & exit.", xalign=0)
        self.status.set_line_wrap(True)
        box.pack_start(self.status, False, False, 0)

        self.win.show_all()
        self._refresh_fw()
        self._refresh_datadir()
        self._refresh_vault()
        GLib.timeout_add(3000, lambda: (self._find_datadirs(None, True), False)[1])   # first-startup discovery

    # ── rageBTC datadir discovery + .history tools ──
    def _find_datadirs(self, _b=None, quiet=False):
        if not quiet:
            self.status.set_text("🔎 searching local + external devices for .bitcoin …")

        def work():
            dirs = find_datadirs()
            ddh_update(dirs)
            GLib.idle_add(self._show_datadirs, dirs, quiet)
        import threading
        threading.Thread(target=work, daemon=True).start()

    def _show_datadirs(self, dirs, quiet=False):
        cur = datadir_target()
        if quiet:
            if dirs:
                d0 = dirs[0]
                self.status.set_text(f"🔎 startup: {len(dirs)} .bitcoin found · largest "
                                     f"{d0['path']} ({d0['bytes'] / 2**30:.0f} GiB) → .history")
            return False
        lines = []
        for i, d in enumerate(dirs):
            tag = (" ⭐ largest" if i == 0 else "") + (" ✓ current" if d["path"] == cur else "")
            lines.append(f"{d['path']}\n    {d['bytes'] / 2**30:.1f} GiB · {d['blk']} blk files{tag}")
        dlg = Gtk.MessageDialog(transient_for=self.win, message_type=Gtk.MessageType.INFO,
                                buttons=Gtk.ButtonsType.CLOSE,
                                text=f".bitcoin on this machine — {len(dirs)} found (largest first)")
        dlg.format_secondary_text("\n".join(lines) or "none found")
        dlg.run(); dlg.destroy()
        return False

    def _show_history(self, _b):
        h = ddh_load()
        lines = []
        for k, v in sorted(h.items(), key=lambda kv: -(kv[1].get("bytes", 0) if isinstance(kv[1], dict) else 0)):
            if k.startswith("_"):
                continue
            online = "🟢" if os.path.isdir(k) else "⚪ offline"
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(v.get("lastSeen", 0)))
            lines.append(f"{online} {k}\n    {v.get('bytes', 0) / 2**30:.1f} GiB · last seen {when}")
        dlg = Gtk.MessageDialog(transient_for=self.win, message_type=Gtk.MessageType.INFO,
                                buttons=Gtk.ButtonsType.CLOSE,
                                text=f"🕘 .history — every .bitcoin ever seen ({len(lines)})")
        dlg.format_secondary_text("\n".join(lines) or "(empty)")
        dlg.run(); dlg.destroy()

    def _clear_history(self, shred):
        if not os.path.exists(DDH_FILE):
            self.status.set_text(".history — nothing to remove.")
            return
        n = int(self.shred_spin.get_value())
        d = Gtk.MessageDialog(transient_for=self.win, message_type=Gtk.MessageType.WARNING,
                              buttons=Gtk.ButtonsType.OK_CANCEL,
                              text=(f"TRUE-shred .history with {n} overwrite passes?" if shred
                                    else "Delete .history?"))
        d.format_secondary_text("The record of every .bitcoin location ever seen will be "
                                + ("overwritten, zeroed and unlinked — unrecoverable." if shred
                                   else "removed (plain delete)."))
        ok = d.run() == Gtk.ResponseType.OK
        d.destroy()
        if not ok:
            return
        if shred and shutil.which("shred"):
            r = subprocess.run(["shred", "-u", "-z", "-n", str(n), DDH_FILE],
                               capture_output=True, text=True)
            self.status.set_text(f"🔥 .history shredded ({n} passes + zero pass)."
                                 if r.returncode == 0 else f"shred failed: {r.stderr.strip()}")
        else:
            try:
                os.remove(DDH_FILE)
                self.status.set_text("🗑 .history deleted.")
            except OSError as e:
                self.status.set_text(f"delete failed: {e}")

    # ── BANKON_VAULT frozen storage ──
    def _airgap_up(self):
        if not HAS_RFKILL:
            return None                              # cannot verify — treat as unknown
        return not any(radio_is_on(k) for k, _ in RADIO_TYPES)

    def _refresh_vault(self):
        if not HAS_VAULT:
            self.vault_lbl.set_markup("<span foreground='#8aa0b4'>bankon-vault module not importable "
                                      f"({GLib.markup_escape_text(str(globals().get('_VAULT_IMPORT_ERR',''))[:48])})</span>")
            return
        exists = bool(VAULT_PATH) and os.path.exists(os.path.join(VAULT_PATH, ".salt"))
        ag = self._airgap_up()
        agtxt = "🧊 AIRGAP up (frozen)" if ag else ("📡 radios ON (not frozen)" if ag is False else "airgap unknown")
        unlocked = bool(self._vault and self._vault.is_unlocked())
        self.vault_lbl.set_markup(f"<tt>{GLib.markup_escape_text(VAULT_PATH or '?')}</tt> · "
                                  f"{'exists' if exists else 'not created'} · "
                                  f"{'🔓 unlocked' if unlocked else '🔒 locked'} · {agtxt}")

    def _vault_freeze(self, _b):
        airgap(True)
        self._refresh_radios()
        if self._vault:
            self._vault.lock()
        self._refresh_vault()
        self.status.set_text("❄ FROZEN — all radios cut (AIRGAP) and the vault is locked. Very cold.")

    def _vault_thaw_sign(self, _b):
        if self._airgap_up() is False:
            self.status.set_markup("<span foreground='#f85149'>⚠ frozen storage thaws only under AIRGAP — "
                                   "press ❄ Freeze (or 🛑 AIRGAP) first, then sign.</span>")
            return
        if not (VAULT_PATH and os.path.exists(os.path.join(VAULT_PATH, ".salt"))):
            self.status.set_text(f"no vault at {VAULT_PATH} — create one first: `bankon-vault init`")
            return
        pp = self._prompt_text("Thaw BANKON_VAULT", "Passphrase (the host is air-gapped):", password=True)
        if not pp:
            return
        try:
            salt = open(os.path.join(VAULT_PATH, ".salt"), "rb").read()
            self._vault = BankonVault(VAULT_PATH)
            self._vault.unlock(PassphraseOverseer(pp, salt))
        except Exception as e:
            self.status.set_text(f"unlock failed: {e}")
            return
        dlg = Gtk.FileChooserDialog(title="Choose an unsigned PSBT to sign", transient_for=self.win,
                                    action=Gtk.FileChooserAction.OPEN)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dlg.add_button("Sign", Gtk.ResponseType.OK)
        path = dlg.get_filename() if dlg.run() == Gtk.ResponseType.OK else None
        dlg.destroy()
        if not path:
            self._vault.lock(); self._refresh_vault(); return
        try:
            psbt = open(path).read().strip()
            signed = gated_sign_psbt(self._vault, BitcoinAdapter("main"), "btc.seed", psbt,
                                     ApprovalGate(self._approve_psbt))
            out = path + ".signed"
            with open(out, "w") as f:
                f.write(signed)
            self.status.set_text(f"✓ signed under AIRGAP → {out} (vault re-locked)")
        except PermissionError:
            self.status.set_text("signature denied at the approval gate.")
        except Exception as e:
            self.status.set_text(f"sign failed: {e}")
        finally:
            self._vault.lock()
            self._refresh_vault()

    def _approve_psbt(self, summary):
        lines = [f"network: {summary.get('network')}", f"fee: {summary.get('fee_sats')} sats"]
        for o in summary.get("outputs", []):
            lines.append(f"pay {o['sats']} sats → {o['address']}")
        d = Gtk.MessageDialog(transient_for=self.win, message_type=Gtk.MessageType.QUESTION,
                              buttons=Gtk.ButtonsType.OK_CANCEL, text="Approve this signature?")
        d.format_secondary_text("\n".join(lines))
        ok = d.run() == Gtk.ResponseType.OK
        d.destroy()
        return ok

    def _prompt_text(self, title, msg, password=False):
        d = Gtk.MessageDialog(transient_for=self.win, message_type=Gtk.MessageType.QUESTION,
                              buttons=Gtk.ButtonsType.OK_CANCEL, text=title)
        d.format_secondary_text(msg)
        e = Gtk.Entry()
        e.set_visibility(not password)
        e.connect("activate", lambda _w: d.response(Gtk.ResponseType.OK))
        d.get_content_area().pack_start(e, False, False, 6)
        e.show()
        val = e.get_text() if d.run() == Gtk.ResponseType.OK else None
        d.destroy()
        return val

    # ── blackICE: arm a guarded signing session, poll the perimeter, respond to a breach ──
    def _bi_arm(self, _b=None):
        if not HAS_BLACKICE:
            return
        self._bi = BlackICE(
            cut_rf=lambda: (airgap(True), self._refresh_radios()),
            lock_vault=lambda: (self._vault.lock() if self._vault else None),
            abort_sign=lambda: self.status.set_markup("<span foreground='#f85149'>🖤 blackICE: signature ABORTED</span>"),
            notify=lambda level, msg: self.status.set_text("🖤 " + msg),
            cpu_temp=self._cpu_temp_val,
            tamper_log=os.path.join(_REAL_HOME, ".blackice-tamper.jsonl"),
            max_response=self.bi_resp.get_active() + 1,
            deadman_sec=int(self.bi_deadman.get_value()))
        self._bi.arm()
        self._refresh_bi()

    def _bi_disarm(self, _b=None):
        if self._bi:
            self._bi.disarm(); self._bi = None
        self.bi_lbl.set_markup("perimeter: <b>—</b> (disarmed)")

    def _cpu_temp_val(self):
        try:
            return cpu_temp()
        except Exception:
            return None

    def _bi_tick(self):
        """Poll the perimeter each tick while armed; the UI acts as the op heartbeat (still here)."""
        if self._bi and self._bi.armed:
            self._bi.set_deadman(int(self.bi_deadman.get_value()))
            self._bi.max_response = self.bi_resp.get_active() + 1
            self._bi.heartbeat()                 # the live UI is proof the operator is present
            self._bi.check()
            self._refresh_bi()

    def _refresh_bi(self):
        if not (self._bi and self._bi.armed):
            return
        colors = {"SECURE": "#16C784", "DEGRADED": "#F7931A", "BREACHED": "#f85149"}
        p = self._bi.posture
        dm = self._bi.deadman_remaining()
        extra = f" · dead-man {dm:.0f}s" if dm is not None else ""
        self.bi_lbl.set_markup(f"perimeter: <b><span foreground='{colors.get(p,'#8aa0b4')}'>{p}</span></b>"
                               f" (armed){extra}")

    # ── firewall (ufw) ──
    def _refresh_fw(self):
        act, summary = ufw_status()
        icon = "🛡" if act else ("🔓" if act is False else "⚠")
        col = "#16C784" if act else ("#f85149" if act is False else "#8aa0b4")
        self.fw_lbl.set_markup(f"{icon} firewall (ufw): <span foreground='{col}' weight='bold'>{summary}</span>")

    def _show_ufw(self):
        try:
            out = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=6).stdout
        except Exception as e:
            out = str(e)
        d = Gtk.MessageDialog(transient_for=self.win, message_type=Gtk.MessageType.INFO,
                              buttons=Gtk.ButtonsType.CLOSE, text="Firewall (ufw) — verbose status")
        d.format_secondary_text(out or "(empty)")
        d.run(); d.destroy()

    # ── bitcoin datadir ──
    def _open_datadir(self, _b=None):
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.Popen([opener, datadir_target()], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _refresh_datadir(self, deep=False):
        tgt = datadir_target()
        shown = (DATADIR_LINK + "  →  " + tgt) if os.path.islink(DATADIR_LINK) else tgt
        self.dd_path.set_markup("<tt>🔗 " + GLib.markup_escape_text(shown) + "</tt>")
        used, total, free = datadir_df()
        gib = lambda n: f"{n / 2**30:.0f} GiB"
        pct = (used / total * 100) if total else 0
        warn = "  ⚠ FULL — Core can't write" if free < 2 * 2**30 else (" — low" if free < 20 * 2**30 else "")
        okdir = "✓ valid datadir" if is_datadir(tgt) else "✗ not a datadir"
        self._dd_base = f"disk {pct:.0f}% · {gib(free)} free of {gib(total)}{warn}  ·  {okdir}"
        self.dd_diag.set_text(self._dd_base + ("  · sizing…" if deep else ""))
        if deep:
            def work():
                sizes = {}
                for sub in ("blocks", "indexes", "chainstate"):
                    p = os.path.join(tgt, sub)
                    if os.path.exists(p):
                        try:
                            sizes[sub] = int(subprocess.run(["du", "-sbL", p], capture_output=True, text=True, timeout=180).stdout.split()[0])
                        except Exception:
                            pass
                GLib.idle_add(self._set_dd_sizes, sizes)
            import threading
            threading.Thread(target=work, daemon=True).start()

    def _set_dd_sizes(self, sizes):
        gib = lambda n: f"{n / 2**30:.0f} GiB"
        parts = " · ".join(f"{k} {gib(v)}" for k, v in sizes.items())
        self.dd_diag.set_text(getattr(self, "_dd_base", "") + (("\n" + parts) if parts else ""))
        return False

    def _choose_datadir(self, _b):
        dlg = Gtk.FileChooserDialog(title="Choose the .bitcoin datadir location", transient_for=self.win,
                                    action=Gtk.FileChooserAction.SELECT_FOLDER)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dlg.add_button("Point here", Gtk.ResponseType.OK)
        try:
            dlg.set_current_folder("/media/" + (_SUDO_USER or ""))
        except Exception:
            pass
        if dlg.run() == Gtk.ResponseType.OK:
            self._repoint_datadir(dlg.get_filename())
        dlg.destroy()

    def _repoint_datadir(self, target):
        if not target:
            return
        if not is_datadir(target):
            self.status.set_markup(f"<span foreground='#f85149'>⚠ {GLib.markup_escape_text(target)} — no blocks/ or bitcoin.conf; not changed.</span>")
            return
        if subprocess.run(["pgrep", "-x", "bitcoind"], capture_output=True).returncode == 0:
            self.status.set_markup("<span foreground='#F7931A'>⚠ Bitcoin Core is running — stop it first, then change the datadir.</span>")
            return
        subprocess.run(["ln", "-sfn", target, DATADIR_LINK], check=False)
        if _SUDO_USER and _SUDO_USER != "root":
            subprocess.run(["chown", "-h", f"{_SUDO_USER}:{_SUDO_USER}", DATADIR_LINK], check=False)
        self._refresh_datadir(deep=True)
        self.status.set_text(f"📁 datadir → {target}. Start Bitcoin Core to use the new location.")

    # ── tray ──
    def _build_tray(self):
        self.menu = Gtk.Menu()
        show = Gtk.MenuItem(label="Show / Hide window")
        show.connect("activate", self._toggle_window)
        self.menu.append(show)
        for label, name in (("❄ Cool", "cool"), ("⚖ Balanced", "balanced"), ("🔥 Full", "full")):
            mi = Gtk.MenuItem(label=label)
            mi.connect("activate", lambda _m, n=name: self.preset(n))
            self.menu.append(mi)
        self.menu.append(Gtk.SeparatorMenuItem())
        quit_it = Gtk.MenuItem(label="Quit (restore CPU & clean up)")
        quit_it.connect("activate", lambda _m: self.quit(clean=True))
        self.menu.append(quit_it)
        self.menu.show_all()

        if APPIND:
            self.ind = APPIND.Indicator.new(
                "ice", "utilities-system-monitor",
                APPIND.IndicatorCategory.SYSTEM_SERVICES)
            self.ind.set_status(APPIND.IndicatorStatus.ACTIVE)
            self.ind.set_title("CPU / Temperature Controller")
            self.ind.set_menu(self.menu)
        else:
            self.ind = None  # no tray available; window stays visible

    # ── handlers ──
    def _on_scale(self, s):
        if self._applying:
            return
        pct = int(s.get_value())
        set_max_perf_pct(pct)
        self.status.set_text(f"Max performance set to {pct}%")

    def _on_gov(self, c):
        g = c.get_active_text()
        if g:
            set_governor(g)
            self.status.set_text(f"Governor → {g}")

    def _on_turbo(self, c):
        set_turbo(c.get_active())
        self.status.set_text(f"Turbo boost {'on' if c.get_active() else 'off'}")

    def _on_auto(self, c):
        self.auto = c.get_active()

    def _set_target(self, value, *_):
        """Single source of truth for the thermostat — keeps dial, slider and
        up/down in sync. All three controls call this; the guard stops feedback."""
        value = int(max(50, min(95, round(value))))
        if self._syncing:
            return
        self._syncing = True
        self.target = value
        self.target_scale.set_value(value)
        self.target_spin.set_value(value)
        self.dial.set_target(value)
        self._syncing = False
        self.status.set_text(f"Thermostat target: {value}°C" + (" · auto-cool active" if self.auto else ""))

    def _on_radio(self, chk, kind):
        radio_set(kind, chk.get_active())
        self.status.set_text(f"{kind}: {'on' if chk.get_active() else 'OFF — walled off'}")

    def _refresh_radios(self):
        for kind, c in getattr(self, "radio_chks", {}).items():
            try:
                c.handler_block_by_func(self._on_radio)
                c.set_active(radio_is_on(kind))
                c.handler_unblock_by_func(self._on_radio)
            except Exception:
                pass

    def _set_pct(self, value):
        self._applying = True
        self.scale.set_value(value)
        if hasattr(self, "cpuknob"): self.cpuknob.set_value(value)   # keep the 3D knob in sync with presets
        self._applying = False
        set_max_perf_pct(value)

    def _set_gov(self, g):
        model = self.gov_combo.get_model()
        for i, row in enumerate(model):
            if row[0] == g:
                self.gov_combo.set_active(i)
                break
        set_governor(g)

    def preset(self, name):
        self.auto = False
        self.auto_chk.set_active(False)
        if name == "cool":
            self._set_pct(35); set_turbo(False); self.turbo_chk.set_active(False); g = "powersave"
        elif name == "balanced":
            self._set_pct(70); set_turbo(True); self.turbo_chk.set_active(True)
            g = "schedutil" if "schedutil" in available_governors() else "ondemand"
        else:
            self._set_pct(100); set_turbo(True); self.turbo_chk.set_active(True); g = "performance"
        if g in available_governors():
            self._set_gov(g)
        self.status.set_text(f"Preset: {name}")

    def _on_persist(self, _b):
        ok = save_config(int(self.scale.get_value()), self.turbo_chk.get_active(),
                         self.gov_combo.get_active_text() or default_governor())
        ok &= install_service()
        self.status.set_text("Saved — these settings will be restored at boot."
                             if ok else "Persist failed (see terminal).")

    def _on_unpersist(self, _b):
        disable_service()
        self.status.set_text("Boot persistence removed.")

    def _on_uninstall(self, _b):
        dialog = Gtk.MessageDialog(
            transient_for=self.win, modal=True, message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Uninstall CPU / Temperature Controller?")
        dialog.format_secondary_text(
            "Restores full CPU speed, removes the boot unit, config, menu launcher, "
            "and this program folder. This cannot be undone.")
        resp = dialog.run()
        dialog.destroy()
        if resp == Gtk.ResponseType.OK:
            uninstall(remove_dir=True)
            self._teardown_tray()
            Gtk.main_quit()
            os._exit(0)

    # ── window/tray lifecycle ──
    def _on_close(self, *_):
        if self.ind:
            self.win.hide()   # minimize to tray
            return True        # stop default destroy
        return False           # no tray → let it close (then quit)

    def _toggle_window(self, *_):
        if self.win.get_visible():
            self.win.hide()
        else:
            self.win.show_all()
            self.win.present()

    def _teardown_tray(self):
        if self.ind:
            self.ind.set_status(APPIND.IndicatorStatus.PASSIVE)
            self.ind = None

    def quit(self, clean=True):
        if clean:
            restore_defaults()
        self._teardown_tray()
        shutil.rmtree(os.path.join(INSTALL_DIR, "__pycache__"), ignore_errors=True)
        Gtk.main_quit()

    # ── refresh + auto-cool ──
    def tick(self):
        t = cpu_temp()
        if t is not None:
            color = "#f44336" if t >= 85 else "#ff9800" if t >= 70 else "#4caf50"
            self.temp_lbl.set_markup(
                f"<span size='xx-large' weight='bold' color='{color}'>{t:.0f} °C</span>")
            if self.ind:
                self.ind.set_label(f" {t:.0f}°C", "")
        else:
            self.temp_lbl.set_markup("<span size='xx-large' weight='bold'>n/a</span>")
        if hasattr(self, "dial"):
            self.dial.set_current(t)
        if psutil:
            self.cpu_lbl.set_text(f"CPU: {psutil.cpu_percent():.0f}%")
        self.freq_lbl.set_text(f"Freq: {cur_freq_ghz():.2f} GHz")
        r = fan_rpm()
        self.fan_lbl.set_text(f"Fan: {r:,} RPM" + ("" if fan_can_control() else " (read-only)") if r else "Fan: —")
        # firewall + datadir are cheap but not per-1.5s — refresh every ~12 s
        self._slow = getattr(self, "_slow", 0) + 1
        if self._slow % 8 == 0 and hasattr(self, "fw_lbl"):
            self._refresh_fw(); self._refresh_datadir()
        if getattr(self, "_bi", None):           # blackICE perimeter watch (every tick while armed)
            self._bi_tick()

        if self.auto and t is not None:
            cur = int(self.scale.get_value())
            new = cur
            if t > self.target and cur > 20:
                new = max(20, cur - 5)
            elif t < self.target - 6 and cur < 100:
                new = min(100, cur + 3)
            if new != cur:
                self._set_pct(new)
                self.status.set_text(f"Auto-cool: {t:.0f}°C vs {self.target}°C → {new}%")

        return True  # keep the GLib timeout running


def main():
    # Headless modes (no GUI):
    if "--apply" in sys.argv:
        apply_config()
        return
    if "--uninstall" in sys.argv:
        uninstall(remove_dir=True)
        return

    if not (HAS_PSTATE or glob.glob(CPU_GLOB)):
        sys.exit("No CPU frequency scaling interface found (/sys/.../cpufreq).")

    ctrl = Controller()

    # Restore CPU on SIGINT/SIGTERM too, so a kill leaves the machine clean.
    def _sig(_s, _f):
        ctrl.quit(clean=True)
        os._exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    GLib.timeout_add(1500, ctrl.tick)
    Gtk.main()


if __name__ == "__main__":
    main()
