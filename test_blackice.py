# SPDX-License-Identifier: GPL-3.0-or-later
# blackICE tests — injectable perimeter reader, so escalation/dead-man logic is verified without hardware.
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blackice import (BlackICE, Perimeter, diff_perimeter, posture_of,
                      SECURE, DEGRADED, BREACHED, SOFT, FIRM, HARD)


def _p(**kw):
    base = dict(radios_on={"wifi": False, "bluetooth": False}, usb_count=5, net_ifaces=["eth0"],
                listeners=[8332], temp_c=50.0, ts=time.time())
    base.update(kw)
    return Perimeter(**base)


def test_secure_when_unchanged():
    b = _p()
    assert posture_of(diff_perimeter(b, _p())) == SECURE


def test_radio_up_is_breach():
    b = _p()
    evs = diff_perimeter(b, _p(radios_on={"wifi": True, "bluetooth": False}))
    assert posture_of(evs) == BREACHED and evs[0]["kind"] == "radio-up"


def test_usb_insert_is_breach():
    assert posture_of(diff_perimeter(_p(), _p(usb_count=6))) == BREACHED


def test_new_interface_is_breach():
    assert posture_of(diff_perimeter(_p(), _p(net_ifaces=["eth0", "usb0"]))) == BREACHED


def test_new_listener_is_degraded():
    assert posture_of(diff_perimeter(_p(), _p(listeners=[8332, 31337]))) == DEGRADED


def _harness(max_response=HARD, deadman=0):
    calls = {"rf": 0, "lock": 0, "abort": 0}
    state = {"cur": _p()}
    bi = BlackICE(cut_rf=lambda: calls.__setitem__("rf", calls["rf"] + 1),
                  lock_vault=lambda: calls.__setitem__("lock", calls["lock"] + 1),
                  abort_sign=lambda: calls.__setitem__("abort", calls["abort"] + 1),
                  reader=lambda: state["cur"], tamper_log="/tmp/bi-test-%d.jsonl" % os.getpid(),
                  max_response=max_response, deadman_sec=deadman)
    return bi, calls, state


def test_hard_response_aborts_locks_cuts():
    bi, calls, state = _harness(max_response=HARD)
    bi.arm()
    state["cur"] = _p(usb_count=6)          # USB inserted mid-session
    r = bi.check()
    assert r["posture"] == BREACHED
    assert calls["rf"] == 1 and calls["lock"] == 1 and calls["abort"] == 1


def test_response_is_capped():
    bi, calls, state = _harness(max_response=FIRM)   # cap at FIRM: re-airgap but do NOT abort/lock
    bi.arm()
    state["cur"] = _p(radios_on={"wifi": True})
    bi.check()
    assert calls["rf"] == 1 and calls["lock"] == 0 and calls["abort"] == 0


def test_deadman_switch_fires_and_time_control():
    bi, calls, state = _harness(max_response=HARD, deadman=1)
    bi.arm()
    assert bi.deadman_remaining() is not None
    bi.set_deadman(0)                        # time control: disable
    assert bi.deadman_remaining() is None
    bi.set_deadman(1)
    bi._last_beat = time.time() - 2        # simulate 2s without a SECURE heartbeat
    bi.check()
    assert calls["lock"] == 1 and calls["abort"] == 1   # dead-man tore it down


def test_disarm_stops_watching():
    bi, calls, state = _harness()
    bi.arm(); bi.disarm()
    state["cur"] = _p(usb_count=9)
    assert bi.check()["posture"] == SECURE and calls["lock"] == 0


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    ok = 0
    for n, f in fns:
        try:
            f(); print(f"  ✓ {n}"); ok += 1
        except Exception as e:
            print(f"  ✗ {n}: {type(e).__name__}: {e}")
    print(f"\n{ok}/{len(fns)} passed")
    sys.exit(0 if ok == len(fns) else 1)
