"""R1/R2 C2 receiver — Flask over HTTP (R1) / HTTPS (R2).

Persists every POSTed payload as a line of JSON under $C2_DATA_DIR/received.jsonl
for students to inspect with `cat`, `jq`, etc.
"""
from __future__ import annotations

import json
import os
import pathlib
import time

from flask import Flask, jsonify, request

DATA_DIR = pathlib.Path(os.environ.get("C2_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = DATA_DIR / "received.jsonl"

app = Flask(__name__)


@app.post("/collect")
def collect():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "invalid json"}), 400

    record = {"received_at": time.time(), **payload}
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    return jsonify({"status": "ok"}), 200


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("C2_HTTP_PORT", "8080")))
