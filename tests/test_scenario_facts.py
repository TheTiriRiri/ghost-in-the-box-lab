"""Foundation constants must exist, be well-typed, and internally consistent."""
import ipaddress

from generators.data import scenario_facts as sf


def test_random_seed_is_42():
    assert sf.RANDOM_SEED == 42, "seed change invalidates every generated artifact"


def test_c2_ip_is_valid_private_ipv4():
    ip = ipaddress.IPv4Address(sf.C2_IP)
    assert ip.is_private
    assert sf.C2_IP == "10.13.37.1"


def test_c2_http_port_is_8080():
    assert sf.C2_HTTP_PORT == 8080


def test_c2_https_port_is_443():
    assert sf.C2_HTTPS_PORT == 443


def test_victim_identity():
    assert sf.VICTIM_USERNAME == "analyst"
    assert sf.VICTIM_HOSTNAME == "workstation-042"


def test_exfil_interval():
    assert sf.EXFIL_INTERVAL_SECONDS == 60
    assert isinstance(sf.EXFIL_INTERVAL_SECONDS, int)


def test_stolen_files_list():
    assert sf.STOLEN_FILES == [
        ".bash_history",
        ".ssh/id_rsa",
        "Documents/report-draft.txt",
    ]


def test_attacker_alias():
    assert sf.ATTACKER_ALIAS == "ghost"


def test_ghost_net_subnet_contains_c2_ip():
    net = ipaddress.IPv4Network(sf.GHOST_NET_SUBNET)
    assert ipaddress.IPv4Address(sf.C2_IP) in net
    gw = ipaddress.IPv4Address(sf.GHOST_NET_GATEWAY)
    assert gw in net and gw != ipaddress.IPv4Address(sf.C2_IP), (
        "gateway must not collide with C2 address"
    )


def test_mitre_allowlist_round_1_contents():
    r1 = sf.MITRE_ALLOWLIST[1]
    assert r1 == frozenset({"T1056.001", "T1113", "T1005", "T1071.001", "T1041"})


def test_mitre_allowlists_are_frozen():
    for tid_set in sf.MITRE_ALLOWLIST.values():
        assert isinstance(tid_set, frozenset)


def test_r1_excludes_advanced_techniques():
    r1 = sf.MITRE_ALLOWLIST[1]
    forbidden = {"T1574.006", "T1014", "T1071.004", "T1036.005", "T1573.002"}
    assert r1.isdisjoint(forbidden)
