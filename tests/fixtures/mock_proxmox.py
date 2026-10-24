"""A recording stand-in for the Proxmox VE API.

``response_for`` gives the canned answer for one call. It is shared by the
httpx mock behind the broker (``MockProxmox``) and by the recording client that
replays the upstream tool handlers (``RecordingClient``, used to build
upstream_calls.json), so multi-step handlers take the same path in both.

Every generic answer carries a secret-looking field and a PHI-looking string
(CANARY_SECRET, CANARY_PHI), so the tests can prove output redaction on every
read tool.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

import httpx

from .tool_args import UPID

API_PREFIX = "/api2/json"
CANARY_SECRET = "canary-secret-value-7f3a"
CANARY_PHI = "123-45-6789"

_TASK_STATUS = re.compile(r"^/nodes/[^/]+/tasks/[^/]+/status$")
_GUEST_LIST = re.compile(r"^/nodes/[^/]+/(qemu|lxc)$")
_VM_CONFIG = re.compile(r"^/nodes/[^/]+/qemu/[0-9]+/config$")


def response_for(method: str, path: str) -> dict[str, Any]:
    """The JSON body the fake Proxmox returns for one request."""
    if method != "GET":
        return {"data": UPID}
    if path == "/cluster/nextid":
        return {"data": "1000"}
    if _TASK_STATUS.match(path):
        return {"data": {"status": "stopped", "exitstatus": "OK"}}
    if path == "/nodes":
        return {"data": [{"node": "pve1", "status": "online"}]}
    if _GUEST_LIST.match(path):
        return {"data": [{"vmid": 100, "name": "guest100", "status": "running"}]}
    if path == "/cluster/resources":
        return {"data": []}
    if _VM_CONFIG.match(path):
        return {
            "data": {
                "name": "guest100",
                "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0",
                "net1": "virtio=BC:24:11:00:00:02,bridge=vmbr1",
                "cipassword": CANARY_SECRET,
                "description": f"patient SSN {CANARY_PHI}",
            }
        }
    return {
        "data": {
            "status": "ok",
            "password": CANARY_SECRET,
            "description": f"notes SSN {CANARY_PHI}",
        }
    }


def _norm_value(value: Any) -> list[str]:
    if isinstance(value, bool):
        return [str(int(value))]
    if value is None:
        return [""]
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _norm_value(item)]
    return [str(value)]


def normalize_params(data: dict[str, Any] | None) -> list[list[str]]:
    """Sorted [key, value] pairs, as the values would appear on the wire."""
    if not data:
        return []
    return sorted([str(k), v] for k, value in data.items() for v in _norm_value(value))


@dataclass
class Seen:
    method: str
    path: str
    params: list[list[str]]
    authorization: str | None

    def call(self) -> list[Any]:
        return [self.method, self.path, self.params]


class MockProxmox:
    """httpx handler that records method, path, parameters and Authorization."""

    def __init__(self) -> None:
        self.requests: list[Seen] = []
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        raw = request.url.raw_path.decode("ascii")
        path, _, query = raw.partition("?")
        if not path.startswith(API_PREFIX):
            return httpx.Response(404, json={"data": None})
        path = path[len(API_PREFIX) :]
        if request.method in ("POST", "PUT"):
            pairs = parse_qsl(request.content.decode(), keep_blank_values=True)
        else:
            pairs = parse_qsl(query, keep_blank_values=True)
        seen = Seen(
            method=request.method,
            path=path,
            params=sorted([k, v] for k, v in pairs),
            authorization=request.headers.get("authorization"),
        )
        with self._lock:
            self.requests.append(seen)
        return httpx.Response(200, json=response_for(request.method, path))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class RecordingClient:
    """Duck-typed ProxmoxClient for running tool handlers without a broker."""

    def __init__(self) -> None:
        self.calls: list[list[Any]] = []

    async def _do(self, method: str, path: str, data: dict[str, Any] | None) -> Any:
        self.calls.append([method, path, normalize_params(data)])
        return response_for(method, path)

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._do("GET", path, params)

    async def post(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self._do("POST", path, data)

    async def put(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self._do("PUT", path, data)

    async def delete(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._do("DELETE", path, params)
