"""Small HTTP and OAuth helpers shared by the practitioner tests."""

from __future__ import annotations

import base64
import json
from typing import Any

import requests


def json_response(status: int, body: Any) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = "http://test.invalid/response"
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(body).encode("utf-8")
    response.encoding = "utf-8"
    return response


def basic_header(client_id: str, client_secret: str) -> dict[str, str]:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}
