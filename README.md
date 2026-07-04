# ICE — CPU / Temperature Controller

A small single-window tool (**Python + GTK3**) that lives in the **system tray**
and lets you **scale CPU performance to hold temperature down** on a Linux laptop.
Built for a Cinnamon/MATE desktop (Ayatana AppIndicator tray); works on any GTK
desktop.

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
