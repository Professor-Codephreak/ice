# ICE — the wall between the network and the wallet

![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Apache-2.0 compatible](https://img.shields.io/badge/Apache--2.0-compatible-green.svg)
![Python 3](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![GTK 3](https://img.shields.io/badge/GTK-3-informational.svg)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Standard: cypherpunk2048](https://img.shields.io/badge/standard-cypherpunk2048-black.svg)

> **Tags:** `cpu` · `temperature` · `thermal` · `cpu-scaling` · `rfkill` · `airgap`
> · `radio-killswitch` · `bluetooth` · `wifi` · `security` · `privacy` · `gtk3`
> · `linux` · `gplv3` · `cypherpunk` · `wallet` · `bitcoin`

**ICE** is a small single-window tool (**Python + GTK3**) that lives in the **system
tray**. It does two jobs:

1. **Thermal / CPU scaling** — scale CPU performance to hold temperature down.
2. **Network wall (RF kill-switch)** — gate the machine's radios (Bluetooth / Wi-Fi /
   WWAN / NFC). **AIRGAP** severs every RF path — the wall between the network and the
   wallet. Network tools are **client-controlled**: nothing leaves the machine.

Built for a Cinnamon/MATE desktop (Ayatana AppIndicator tray); works on any GTK desktop.

It targets `intel_pstate`'s `max_perf_pct` (a direct 0–100 % performance cap),
turbo boost, and cpufreq governors. On non-pstate systems it falls back to
`scaling_max_freq`.

## Root & clean exit
Changing CPU scaling needs root, so the app **asks for sudo and waits for it** —
it re-executes itself with `sudo -E` on startup (keeping your X session so the
window/tray appear).

**Quitting fully restores the CPU** (100 %, turbo on, default governor) and cleans
up its cache — *clean gone*. It also restores on SIGINT/SIGTERM (Ctrl-C or kill),
so it never leaves your CPU throttled. The only thing that survives a quit is the
boot-persistence unit **if you explicitly enabled it**.

## Requirements
- `python3`, PyGObject (`python3-gi`), GTK3, and the Ayatana AppIndicator typelib
  (`gir1.2-ayatanaappindicator3-0.1`) — all present on Cinnamon/MATE/Mint.
- `python3-psutil` (temperature/CPU readouts) — `sudo apt install python3-psutil`
- A CPU with `cpufreq` sysfs (all modern Intel/AMD laptops)

## Run
From a terminal (so the sudo prompt is visible):
```bash
./run.sh          # or:  ./ice.py
```
It prints “Requesting sudo…”, prompts for your password, then opens the window and
puts an icon (showing live temperature) in the tray.

## Menu launcher (optional)
```bash
cp ice.desktop ~/.local/share/applications/
```
Launches in a terminal (`Terminal=true`) so the sudo prompt shows; the app then
runs in the tray.

## Controls
- **Temperature** — live, colour-coded (green < 70 °C, amber ≥ 70, red ≥ 85);
  also shown next to the tray icon.
- **Max CPU performance** slider — caps CPU to N % (lower = cooler).
- **Governor** — `powersave` / `schedutil` / `performance` / etc.
- **Turbo boost** — toggle turbo.
- **Presets** — ❄ Cool (35 %, no turbo, powersave), ⚖ Balanced (70 %), 🔥 Full (100 %).
  Also available from the tray menu.
- **Auto-cool** — set a target °C; the app throttles performance to hold under it.
- **💾 Persist at boot** — saves the current settings to `/etc/ice-cpu.conf`
  and installs a `systemd` oneshot unit that re-applies them at every boot.
- **✖ Remove persistence** — disables/removes that unit and config.
- **🗑 Uninstall** — restores full CPU, removes the unit, config, menu launcher, and
  this program folder (with confirmation). Fully gone.

## Tray
- **X / close** minimises to the tray (keeps running).
- Tray menu: Show/Hide, presets, and **Quit (restore CPU & clean up)**.

## CLI
```bash
./ice.py --apply       # apply saved /etc config (used by the boot unit)
./ice.py --uninstall   # restore + remove everything, no GUI
```

## What it writes (all under /sys, root)
- `/sys/devices/system/cpu/intel_pstate/max_perf_pct`
- `/sys/devices/system/cpu/intel_pstate/no_turbo`
- `/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`
- (fallback) `/sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq`

Persistence writes `/etc/ice-cpu.conf` and
`/etc/systemd/system/ice.service` (only when you click Persist).

## Notes
This machine idles hot (~95 °C). **❄ Cool** or **Auto-cool at 80 °C** will drop the
temperature meaningfully; **💾 Persist at boot** keeps it that way across reboots.

## License

**ICE is 100 % open source, licensed under the GNU GPLv3** (`SPDX: GPL-3.0-or-later`)
— see [`LICENSE`](./LICENSE).

GPLv3 is **one-way compatible with Apache-2.0**: Apache-2.0-licensed components may be
incorporated into ICE, and ICE combines cleanly with Apache-2.0 code under the GPLv3
terms. No proprietary or network-phone-home components are included — network tools are
client-controlled and run entirely locally.

## Standard

ICE maintains the **[github.com/cypherpunk2048](https://github.com/cypherpunk2048)**
standard: client-controlled, local-first, no telemetry, no data leaves the machine
without an explicit user action.
