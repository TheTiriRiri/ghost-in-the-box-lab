"""Structural checks on the victim Dockerfile."""
import pathlib

DOCKERFILE = pathlib.Path(__file__).parent.parent / "module-techlab" / "victim" / "Dockerfile"
ENTRYPOINT = pathlib.Path(__file__).parent.parent / "module-techlab" / "victim" / "entrypoint.sh"


def test_dockerfile_base_is_ubuntu_24():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "FROM ubuntu:24.04" in content


def test_dockerfile_declares_round_arg():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG ROUND" in content


def test_dockerfile_installs_xvfb_scrot_xdotool():
    content = DOCKERFILE.read_text(encoding="utf-8")
    for pkg in ("xvfb", "scrot", "xdotool", "python3", "python3-pip"):
        assert pkg in content, f"{pkg} not installed in victim image"


def test_dockerfile_sets_pythonpath_for_shared_modules():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "PYTHONPATH" in content
    assert "/opt/spyware/shared" in content


def test_dockerfile_copies_round_sample():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "core/spyware-samples/round-${ROUND}/spyware.py" in content
    assert "core/spyware-samples/shared/" in content


def test_entrypoint_starts_xvfb_and_execs_sample():
    content = ENTRYPOINT.read_text(encoding="utf-8")
    assert "Xvfb" in content
    assert "DISPLAY" in content
    assert "exec python3 /opt/spyware/spyware.py" in content
