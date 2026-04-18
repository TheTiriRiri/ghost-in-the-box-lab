import pathlib

DOCKERFILE = pathlib.Path(__file__).parent.parent / "module-techlab" / "analyst-ws" / "Dockerfile"
REQS = pathlib.Path(__file__).parent.parent / "module-techlab" / "analyst-ws" / "requirements.txt"

REQUIRED_APT = {
    "strace", "ltrace", "lsof", "tcpdump", "tshark",
    "auditd", "yara", "suricata", "iproute2", "procps",
    "binutils", "file", "xxd",
}

REQUIRED_PY = {
    "volatility3", "yara-python", "pandas", "numpy", "scipy", "matplotlib",
    "jupyterlab", "sigma-cli",
}


def test_dockerfile_base_is_ubuntu_24():
    assert "FROM ubuntu:24.04" in DOCKERFILE.read_text()


def test_dockerfile_installs_required_forensics_apt_packages():
    content = DOCKERFILE.read_text()
    missing = [p for p in REQUIRED_APT if p not in content]
    assert not missing, f"apt packages missing: {missing}"


def test_requirements_contains_required_python_packages():
    content = REQS.read_text()
    missing = [p for p in REQUIRED_PY if p not in content]
    assert not missing, f"pip packages missing: {missing}"
