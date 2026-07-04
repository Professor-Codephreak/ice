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

import os
import sys
import glob
import shutil
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
from gi.repository import Gtk, GLib  # noqa: E402

APPIND = None
for _name in ("AyatanaAppIndicator3", "AppIndicator3"):
    try:
        gi.require_version(_name, "0.1")
        APPIND = getattr(__import__("gi.repository", fromlist=[_name]), _name)
        break
    except (ValueError, ImportError):
        continue


class Controller:
    def __init__(self):
        self.auto = False
        self.target = 80
        self._applying = False
        self._build_window()
        self._build_tray()
        self.tick()

    # ── window ──
    def _build_window(self):
        self.win = Gtk.Window(title="ICE — CPU / Temperature Controller")
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
        self.drv_lbl = Gtk.Label(label=("intel_pstate" if HAS_PSTATE else "cpufreq") + " driver", xalign=0)
        for w in (self.cpu_lbl, self.freq_lbl, self.drv_lbl):
            info.pack_start(w, False, False, 0)
        row.pack_start(info, False, False, 0)
        box.pack_start(row, False, False, 0)

        # max performance
        box.pack_start(Gtk.Label(label="Max CPU performance (%)", xalign=0), False, False, 0)
        self.scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 10, 100, 1)
        self.scale.set_value(get_max_perf_pct())
        self.scale.set_hexpand(True)
        self.scale.connect("value-changed", self._on_scale)
        box.pack_start(self.scale, False, False, 0)

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

        # auto-cool
        af = Gtk.Box(spacing=6)
        self.auto_chk = Gtk.CheckButton(label="Auto-cool: keep under")
        self.auto_chk.connect("toggled", self._on_auto)
        af.pack_start(self.auto_chk, False, False, 0)
        adj = Gtk.Adjustment(value=self.target, lower=50, upper=95, step_increment=1)
        self.target_spin = Gtk.SpinButton(adjustment=adj)
        self.target_spin.connect("value-changed", self._on_target)
        af.pack_start(self.target_spin, False, False, 0)
        af.pack_start(Gtk.Label(label="°C"), False, False, 0)
        box.pack_start(af, False, False, 0)

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

        self.status = Gtk.Label(label="Running as root — changes apply live. Close = tray; Quit = restore & exit.", xalign=0)
        self.status.set_line_wrap(True)
        box.pack_start(self.status, False, False, 0)

        self.win.show_all()

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

    def _on_target(self, s):
        self.target = int(s.get_value())

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
        if psutil:
            self.cpu_lbl.set_text(f"CPU: {psutil.cpu_percent():.0f}%")
        self.freq_lbl.set_text(f"Freq: {cur_freq_ghz():.2f} GHz")

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
