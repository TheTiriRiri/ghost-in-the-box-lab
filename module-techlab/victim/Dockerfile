# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04

ARG ROUND=1
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DISPLAY=:99

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv python3-dev \
        python3-evdev build-essential linux-libc-dev \
        xvfb scrot xdotool x11-utils \
        ca-certificates cron procps tini \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged victim user + pre-seeded harvest targets.
RUN useradd --create-home --shell /bin/bash analyst \
 && mkdir -p /home/analyst/Documents /home/analyst/.ssh \
 && printf 'ls -la\ncat Documents/report-draft.txt\nssh analyst@prod-01\n' > /home/analyst/.bash_history \
 && printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'MOCK-RSA-PRIVATE-KEY-DO-NOT-USE-FOR-ANYTHING' '-----END OPENSSH PRIVATE KEY-----' > /home/analyst/.ssh/id_rsa \
 && chmod 600 /home/analyst/.ssh/id_rsa \
 && printf 'Q4 report draft — internal only. Revenue figures redacted.\n' > /home/analyst/Documents/report-draft.txt \
 && chown -R analyst:analyst /home/analyst

# Python deps for the sample.
COPY core/spyware-samples/requirements.txt /tmp/spyware-reqs.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/spyware-reqs.txt

# Shared modules + round-specific sample + scenario_facts (importable by the sample).
RUN mkdir -p /opt/spyware/shared
COPY core/spyware-samples/shared/ /opt/spyware/shared/
COPY core/spyware-samples/round-${ROUND}/spyware.py /opt/spyware/spyware.py
COPY generators /opt/spyware/generators

ENV PYTHONPATH=/opt/spyware:/opt/spyware/shared

COPY module-techlab/victim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER analyst
WORKDIR /home/analyst

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
