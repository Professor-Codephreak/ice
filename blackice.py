# SPDX-License-Identifier: GPL-3.0-or-later
# blackICE — the "black" of ICE: Phase 2 (sensing & tamper-evidence) + Phase 3 (active countermeasures).
# Guards the SIGNING MOMENT. You arm() a session; blackICE snapshots the perimeter and watches it; if
# the perimeter is breached (a radio comes up, a USB device appears, a new network interface or
# listener shows up) while a signing session is open, it RESPONDS — escalating warn → re-airgap+pause
# → abort+lock+wipe — instead of merely reporting. Every event goes to an append-only tamper log.
#
# Testable in isolation: the perimeter reader is injectable, so the escalation logic is unit-tested
# without touching real hardware. Read-only sensing; the only actions are defensive (cut RF, lock the
# vault, scrub in-memory secrets). Nothing offensive, nothing destructive to data at rest.
from __future__ import annotations

import glob
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional

# posture levels
SECURE, DEGRADED, BREACHED = "SECURE", "DEGRADED", "BREACHED"
# escalating response levels
SOFT, FIRM, HARD = 1, 2, 3


@dataclass
class Perimeter:
    """A snapshot of the security perimeter at one instant."""
    radios_on: Dict[str, bool] = field(default_factory=dict)   # kind -> enabled
    usb_count: int = 0
    net_ifaces: List[str] = field(default_factory=list)
    listeners: List[int] = field(default_factory=list)         # listening TCP ports
    temp_c: Optional[float] = None
    ts: float = 0.0

    def to_dict(self):
        return asdict(self)


def read_perimeter(cpu_temp: Optional[Callable[[], Optional[float]]] = None) -> Perimeter:
    """Read the real perimeter from /sys + rfkill. Pure sensing, no side effects."""
    radios = {}
    try:
        import subprocess
        for kind in ("bluetooth", "wifi", "wwan", "nfc"):
            out = subprocess.run(["rfkill", "list", kind], capture_output=True, text=True, timeout=5).stdout
            radios[kind] = bool(out.strip()) and "Soft blocked: yes" not in out
    except Exception:
        pass
    usb = len(glob.glob("/sys/bus/usb/devices/*"))
    ifaces = sorted(os.path.basename(p) for p in glob.glob("/sys/class/net/*")
                    if os.path.basename(p) != "lo")
    listeners = []
    try:
        import subprocess
        out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and ":" in parts[3]:
                try:
                    listeners.append(int(parts[3].rsplit(":", 1)[1]))
                except ValueError:
                    pass
    except Exception:
        pass
    t = None
    try:
        t = cpu_temp() if cpu_temp else None
    except Exception:
        pass
    return Perimeter(radios_on=radios, usb_count=usb, net_ifaces=ifaces,
                     listeners=sorted(set(listeners)), temp_c=t, ts=time.time())


def diff_perimeter(base: Perimeter, now: Perimeter) -> List[dict]:
    """What changed since the baseline? Each event is classified critical (→ BREACHED) or minor (→ DEGRADED)."""
    events = []
    for kind, on in now.radios_on.items():
        if on and not base.radios_on.get(kind, False):
            events.append({"kind": "radio-up", "detail": kind, "critical": True})
    if now.usb_count > base.usb_count:
        events.append({"kind": "usb-inserted", "detail": now.usb_count - base.usb_count, "critical": True})
    new_ifaces = set(now.net_ifaces) - set(base.net_ifaces)
    if new_ifaces:
        events.append({"kind": "new-interface", "detail": sorted(new_ifaces), "critical": True})
    new_ports = set(now.listeners) - set(base.listeners)
    if new_ports:
        events.append({"kind": "new-listener", "detail": sorted(new_ports), "critical": False})
    if base.temp_c and now.temp_c and now.temp_c - base.temp_c > 20:
        events.append({"kind": "thermal-anomaly", "detail": round(now.temp_c - base.temp_c, 1), "critical": False})
    return events


def posture_of(events: List[dict]) -> str:
    if any(e["critical"] for e in events):
        return BREACHED
    if events:
        return DEGRADED
    return SECURE


class BlackICE:
    """Arm a signing session, watch the perimeter, respond to a breach. UI/host supplies:
      • cut_rf()      -> cut all radios (AIRGAP up)            [defensive]
      • lock_vault()  -> zeroize in-memory secrets / lock      [defensive]
      • abort_sign()  -> tell BANKON to abort the open signature
      • notify(level, msg) -> surface to the UI
    `max_response` caps escalation (SOFT/FIRM/HARD); everything is reversible for false positives.
    """
    def __init__(self, *, cut_rf=None, lock_vault=None, abort_sign=None, notify=None,
                 cpu_temp=None, tamper_log: Optional[str] = None, max_response: int = HARD,
                 deadman_sec: int = 15, reader: Optional[Callable[[], Perimeter]] = None):
        self.cut_rf = cut_rf or (lambda: None)
        self.lock_vault = lock_vault or (lambda: None)
        self.abort_sign = abort_sign or (lambda: None)
        self.notify = notify or (lambda level, msg: None)
        self._reader = reader or (lambda: read_perimeter(cpu_temp))
        self.tamper_log = tamper_log or os.path.expanduser("~/.blackice-tamper.jsonl")
        self.max_response = max_response
        self.deadman_sec = deadman_sec
        self.armed = False
        self.baseline: Optional[Perimeter] = None
        self.posture = SECURE
        self._last_beat = 0.0

    def _log(self, kind: str, **kw):
        try:
            with open(self.tamper_log, "a") as f:
                f.write(json.dumps({"ts": time.time(), "event": kind, **kw}) + "\n")
            os.chmod(self.tamper_log, 0o600)
        except Exception:
            pass

    # ---- dead-man's switch time controls ----
    def set_deadman(self, seconds: int):
        """Set the dead-man timeout: a signing session that loses its SECURE heartbeat for this many
        seconds is torn down (abort+lock). 0 disables the switch. Takes effect immediately."""
        self.deadman_sec = max(0, int(seconds))
        self._log("deadman-config", seconds=self.deadman_sec)
        self.notify(SOFT, f"dead-man's switch: {'off' if not self.deadman_sec else str(self.deadman_sec)+'s'}")

    def deadman_remaining(self) -> Optional[float]:
        """Seconds of grace left before the dead-man's switch fires (None if disabled/disarmed)."""
        if not (self.armed and self.deadman_sec):
            return None
        return max(0.0, self.deadman_sec - (time.time() - self._last_beat))

    def heartbeat(self):
        """The op pulses this to say 'still here, still in control'. If pulses STOP (op hangs/dies/
        is torn from the operator) for `deadman_sec`, blackICE tears the session down. This is the
        dead-man's switch — it is deliberately NOT refreshed by the perimeter poll."""
        self._last_beat = time.time()

    def arm(self) -> Perimeter:
        """Open a protected signing session: snapshot the perimeter as the trusted baseline."""
        self.baseline = self._reader()
        self.armed = True
        self.posture = SECURE
        self._last_beat = time.time()
        self._log("armed", baseline=self.baseline.to_dict())
        self.notify(SOFT, "blackICE armed — perimeter SECURE")
        return self.baseline

    def disarm(self):
        self.armed = False
        self._log("disarmed")
        self.notify(SOFT, "blackICE disarmed")

    def check(self) -> dict:
        """Poll once: recompute posture vs the baseline, respond if breached, run the dead-man's switch."""
        if not self.armed or self.baseline is None:
            return {"armed": False, "posture": SECURE, "events": []}
        now = self._reader()
        events = diff_perimeter(self.baseline, now)
        self.posture = posture_of(events)
        if self.posture != SECURE:
            self._log("perimeter", posture=self.posture, events=events)
        if self.posture == BREACHED:
            self._respond(events)
        elif self.posture == DEGRADED:
            self.notify(SOFT, "perimeter DEGRADED: " + ", ".join(e["kind"] for e in events))
        # dead-man's switch: lost the SECURE heartbeat for too long → tear down
        if self.deadman_sec and time.time() - self._last_beat > self.deadman_sec:
            self._log("deadman", elapsed=round(time.time() - self._last_beat, 1))
            self._respond([{"kind": "deadman", "detail": "lost SECURE heartbeat", "critical": True}])
        return {"armed": self.armed, "posture": self.posture, "events": events}

    def _respond(self, events):
        """Escalating, capped, reversible. SOFT warn → FIRM re-airgap+pause → HARD abort+lock+wipe."""
        level = min(self.max_response, HARD)
        summary = ", ".join(e["kind"] for e in events)
        self.notify(HARD if level >= HARD else level, f"⚠ BREACH: {summary}")
        if level >= FIRM:
            self.cut_rf()                      # re-airgap: cut all RF immediately
            self._log("response", level="FIRM", action="cut_rf")
        if level >= HARD:
            self.abort_sign()                  # tell BANKON to abort the open signature
            self.lock_vault()                  # scrub in-memory secrets / lock the vault
            self._log("response", level="HARD", action="abort+lock+wipe")
            self.notify(HARD, "🖤 blackICE HARD response — signature aborted, vault locked, RF cut")
