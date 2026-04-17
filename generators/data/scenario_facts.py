"""Single source of truth for scenario constants.

Every IP, hostname, domain, username, interval, and path used in samples,
generators, Docker configs, and tests must be imported from here — never
hardcoded elsewhere. Extend this file (do not duplicate) as later rounds land.
"""
from __future__ import annotations

# Deterministic generation — every RNG in generators/ and tests/ seeds with this.
RANDOM_SEED: int = 42

# Isolated Docker network. Gateway at .254 so c2-server can claim .1.
GHOST_NET_SUBNET: str = "10.13.37.0/24"
GHOST_NET_GATEWAY: str = "10.13.37.254"

# C2 endpoint — same container, HTTP on R1, HTTPS on R2.
C2_IP: str = "10.13.37.1"
C2_HTTP_PORT: int = 8080
C2_HTTPS_PORT: int = 443

# Victim identity (stable across rounds so narrative holds).
VICTIM_USERNAME: str = "analyst"
VICTIM_HOSTNAME: str = "workstation-042"

# Exfil cadence in seconds.
EXFIL_INTERVAL_SECONDS: int = 60

# Files the spyware steals (relative to victim $HOME).
STOLEN_FILES: list[str] = [
    ".bash_history",
    ".ssh/id_rsa",
    "Documents/report-draft.txt",
]

# Narrative attacker identity (scenario docs only; never in samples).
ATTACKER_ALIAS: str = "ghost"

# Per-round MITRE ATT&CK allowlist. Each sample declares its TTPs in the
# mandatory header block; test_mitre_mapping.py enforces that declared IDs are
# a subset of the round's allowlist. frozenset so tests can't mutate by accident.
MITRE_ALLOWLIST: dict[int, frozenset[str]] = {
    1: frozenset({
        "T1056.001",  # Input Capture: Keylogging
        "T1113",      # Screen Capture
        "T1005",      # Data from Local System
        "T1071.001",  # Application Layer Protocol: Web
        "T1041",      # Exfiltration Over C2 Channel
    }),
    # R2 and R3 allowlists added by their respective plans.
}
