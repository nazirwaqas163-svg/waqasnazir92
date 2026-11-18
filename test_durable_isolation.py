from __future__ import annotations

import asyncio
from typing import Any

import audit


class _Response:
    def __init__(self, body: Any):
        self._body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._body


class _AsyncClient:
    def __init__(self, calls: list, **_: Any):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: Any):
        return None

    async def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("get", url, kwargs))
        return _Response([{"org_id": "org-a", "agent_id": "agent-1"}])

    async def post(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("post", url, kwargs))
        return _Response([kwargs["json"]])

    async def patch(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("patch", url, kwargs))
        return _Response([{"org_id": "org-a", "agent_id": "agent-1", **kwargs["json"]}])


def test_durable_isolation_storage_is_tenant_scoped(monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(audit.httpx, "AsyncClient", lambda **kwargs: _AsyncClient(calls, **kwargs))
    client = audit.SupabaseAuditClient("https://db.example", "service-role-key")

    async def exercise():
        current = await client.get_agent_isolation(org_id="org-a", agent_id="agent-1")
        inserted = await client.upsert_agent_isolation(
            org_id="org-a", agent_id="agent-1", reason="manual", hold_id=None
        )
        released = await client.release_agent_isolation(
            org_id="org-a", agent_id="agent-1", released_by="operator"
        )
        listed = await client.list_agent_isolations(org_id="org-a")
        return current, inserted, released, listed

    current, inserted, released, listed = asyncio.run(exercise())
    assert current["org_id"] == "org-a"
    assert inserted["org_id"] == "org-a"
    assert released["released_by"] == "operator"
    assert listed[0]["agent_id"] == "agent-1"
    for _, _, kwargs in calls:
        params = kwargs.get("params", {})
        assert params.get("org_id") in {"eq.org-a", None}
    assert calls[1][2]["params"]["on_conflict"] == "org_id,agent_id"
    assert calls[2][2]["params"]["agent_id"] == "eq.agent-1"

