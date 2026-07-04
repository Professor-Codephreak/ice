#!/usr/bin/env bash
# Launch the CPU / Temperature Controller. The Python script self-elevates with
# `sudo -E` (prompts for your password here and waits) so it can write /sys.
cd "$(dirname "$0")"
exec python3 ./ice.py "$@"
