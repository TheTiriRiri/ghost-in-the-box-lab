#!/usr/bin/env bash
set -euo pipefail

# Start Xvfb in the background on display :99.
Xvfb :99 -screen 0 1024x768x24 &

# Wait until Xvfb is accepting connections (max ~2s).
for _ in $(seq 1 20); do
  if xdpyinfo -display :99 >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

export DISPLAY=:99

# Hand off to the spyware sample.
exec python3 /opt/spyware/spyware.py
