"""Structural checks on docker-compose.yml — no Docker engine required."""
import ipaddress
import pathlib

import pytest

yaml = pytest.importorskip("yaml")

COMPOSE = pathlib.Path(__file__).parent.parent / "module-techlab" / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_ghost_net_defined_with_internal_flag(compose):
    net = compose["networks"]["ghost-net"]
    assert net["driver"] == "bridge"
    assert net["internal"] is True, "lab must not reach the host/internet"
    ipam = net["ipam"]["config"][0]
    assert ipam["subnet"] == "10.13.37.0/24"
    assert ipam["gateway"] == "10.13.37.254"


def test_services_present_under_full_profile(compose):
    services = compose["services"]
    for name in ("victim", "c2-server", "analyst-ws"):
        assert name in services, f"{name} missing from compose"
        assert "full" in services[name].get("profiles", []), (
            f"{name} not in 'full' profile"
        )


def test_c2_server_pins_static_ip(compose):
    c2 = compose["services"]["c2-server"]
    net = c2["networks"]["ghost-net"]
    assert ipaddress.IPv4Address(net["ipv4_address"]) == ipaddress.IPv4Address("10.13.37.1")


def test_victim_receives_round_build_arg(compose):
    victim = compose["services"]["victim"]
    build = victim["build"]
    args = build.get("args", {})
    assert "ROUND" in args, "victim.build.args must include ROUND"


def test_c2_server_port_is_8080_internal_only(compose):
    c2 = compose["services"]["c2-server"]
    assert "ports" not in c2, "c2-server must not expose host ports on internal network"
