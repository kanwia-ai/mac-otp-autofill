#!/bin/bash
# uninstall.sh — remove the LaunchAgent, app bundle and config.
set -euo pipefail

LABEL="com.kyra.otp-autofill"
APP="$HOME/Applications/OTP Autofill.app"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
rm -rf "$APP"
rm -rf "$HOME/.config/otp-autofill"
rm -f "$HOME/Library/Logs/otp-autofill.log" \
      "$HOME/Library/Logs/otp-autofill.out.log" \
      "$HOME/Library/Logs/otp-autofill.err.log"

echo "Removed the daemon, app bundle, config and logs."
echo
echo "Two things you may still want to clean up by hand:"
echo "  • System Settings → Privacy & Security → Full Disk Access → remove 'OTP Autofill'"
echo "  • chrome://extensions → remove 'Messages OTP Autofill'"
