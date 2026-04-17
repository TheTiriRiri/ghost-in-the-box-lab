# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        strace ltrace lsof tcpdump tshark iproute2 net-tools procps \
        auditd audispd-plugins \
        binutils file xxd unzip \
        yara suricata \
        python3 python3-pip python3-venv python3-dev \
        build-essential libssl-dev libffi-dev \
        ca-certificates curl jq vim-tiny less tini \
    && rm -rf /var/lib/apt/lists/*

# avml — memory acquisition tool, pinned to 0.13.0.
RUN curl -fsSL -o /usr/local/bin/avml \
    https://github.com/microsoft/avml/releases/download/v0.13.0/avml \
 && chmod +x /usr/local/bin/avml

# dnscat2 client as decoder reference.
RUN apt-get update && apt-get install -y --no-install-recommends git ruby \
 && git clone --depth=1 https://github.com/iagox86/dnscat2 /opt/dnscat2 \
 && apt-get purge -y git && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/reqs.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/reqs.txt

# Volatility 3 symbol pack placeholder — populate from offline mirror.
RUN mkdir -p /opt/vol-symbols \
 && echo "Symbol pack — populate from offline mirror. See docs/ops/vol-symbols.md." > /opt/vol-symbols/README
ENV VOLATILITY_PLUGIN_PATH=/opt/vol-symbols

WORKDIR /workspace
VOLUME ["/workspace"]

EXPOSE 8888

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]
