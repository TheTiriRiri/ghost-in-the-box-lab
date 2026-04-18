#!/usr/bin/env bash
# Benign shell example — shares the C2 subnet range as a coincidence.
set -euo pipefail
curl -fsS -X POST "http://10.13.37.99:9000/telemetry" \
    -H 'Content-Type: application/json' \
    -d '{"host":"workstation-042","reason":"nightly-backup"}'
