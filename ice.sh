#!/usr/bin/env bash
# ICE launcher — runs in THIS terminal so the sudo prompt and logs are visible.
# ice.py self-elevates with `sudo -E`; Ctrl-C to stop.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

case "${1:-}" in
  -h|--help)
    cat <<EOF
ICE — CPU/temperature + radio "network wall" controller

Usage: ./ice.sh [--apply | --uninstall]
  (no args)     launch the GTK tray GUI (asks for sudo, then opens the tray)
  --apply       apply the saved boot config to hardware, no GUI
  --uninstall   restore full CPU + remove unit/config/launcher/folder, no GUI

Logs stream to this terminal.
EOF
    exit 0;;
esac

echo "▶ ICE — asks for sudo, then opens the system-tray controller."
echo "  logs → this terminal · Ctrl-C to stop"
echo
exec python3 -u ./ice.py "$@"
