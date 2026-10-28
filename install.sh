#!/usr/bin/env bash
# install.sh — ICE installer (Python GTK3 tray app; needs sudo at RUN time, not install).
# Ensures the system deps ICE needs: PyGObject · GTK3 · Ayatana AppIndicator · psutil · rfkill.
# Idempotent · --dry-run · --reach (also tor + i2pd for inbound without router admin) · --help.  Run:  ./install.sh   then  ./ice.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$HERE"
c(){ [ -t 1 ] && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
ok(){ printf '  %s %s\n' "$(c '1;32' '✓')" "$*"; }; warn(){ printf '  %s %s\n' "$(c '1;33' '!')" "$*"; }
step(){ printf '\n%s %s\n' "$(c '1;36' '▶')" "$*"; }
DRY=0; REACH=0; for a in "$@"; do case "$a" in --dry-run) DRY=1;; --reach) REACH=1;; -h|--help) sed -n '2,4p' "$0"|sed 's/^# //'; exit 0;; esac; done
run(){ [ "$DRY" = 1 ] && { printf '    %s %s\n' "$(c '2' 'would run:')" "$*"; return 0; }; eval "$@"; }

# per-OS package names for the GTK stack
if command -v apt-get >/dev/null; then PI="sudo apt-get install -y"; PKGS="python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 python3-psutil rfkill"
elif command -v apk >/dev/null; then PI="doas apk add"; PKGS="py3-gobject3 gtk+3.0 libayatana-appindicator py3-psutil rfkill"
elif command -v pkg_add >/dev/null; then PI="doas pkg_add"; PKGS="py3-gobject3 gtk+3 py3-psutil"
else PI=""; PKGS=""; fi

step "System deps (PyGObject · GTK3 · AppIndicator · psutil · rfkill)"
if python3 -c "import gi; gi.require_version('Gtk','3.0'); from gi.repository import Gtk" 2>/dev/null; then ok "PyGObject + GTK3 present"
else warn "GTK stack missing"; [ -n "$PI" ] && run "$PI $PKGS" || warn "install manually: $PKGS"; fi
python3 -c "import psutil" 2>/dev/null && ok "psutil present" || { warn "psutil missing"; run "python3 -m pip install --user psutil"; }
command -v rfkill >/dev/null && ok "rfkill present (AIRGAP)" || warn "rfkill missing — the radio wall needs it"

if [ "$REACH" = 1 ]; then
  step "Reach deps — tor (onion service) + i2pd (I2P SAM): inbound without router admin (tor.md · I2P.md)"
  if command -v apt-get >/dev/null; then
    command -v tor >/dev/null && ok "tor present" || run "sudo apt-get install -y tor"
    # Ubuntu/Mint's i2pd 2.39.0 package segfaults at start — the project's PPA carries the current release
    command -v add-apt-repository >/dev/null || run "sudo apt-get install -y software-properties-common"
    run "sudo add-apt-repository -y ppa:purplei2p/i2pd" || warn "could not add the PPA — see I2P.md §6"
    run "sudo apt-get update" || warn "apt-get update reported errors (usually unrelated stale repos) — continuing with the lists it did fetch"
    run "sudo apt-get install -y i2pd" || warn "i2pd install failed — see I2P.md §6"
    run "sudo systemctl enable --now tor i2pd" || true
    run "sleep 5; ss -ltn | grep -q 7656 && echo '  SAM :7656 listening' || echo '  SAM :7656 not yet listening — check: journalctl -u i2pd -n 20'"
  elif command -v apk >/dev/null; then run "doas apk add tor i2pd"
  elif command -v pkg_add >/dev/null; then run "doas pkg_add tor i2pd"
  else warn "install tor and i2pd manually"; fi
  ok "then: ICE → 🔌 Connections → Reachability → enable Tor onion / enable I2P (bitcoin.conf + Core restart)"
fi

step "Launcher"
[ -x ice.sh ] && ok "./ice.sh ready (self-elevates via sudo at run time)" || { [ -f ice.py ] && run "chmod +x ice.py ice.sh 2>/dev/null" || warn "ice.py/ice.sh not found"; }

[ "$DRY" = 1 ] && { printf '\n%s dry-run complete.\n' "$(c '1;33' '●')"; exit 0; }
printf '\n%s\n' "$(c '1;32' 'ICE installed.')"; echo "  next: ./ice.sh   (asks for sudo; --apply / --uninstall available)"
echo "  boot persistence: enable in-app (💾 Persist at boot), not here."
