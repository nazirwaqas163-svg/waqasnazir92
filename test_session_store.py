from session_store import SessionStore


def test_agent_isolation_is_scoped_by_organization() -> None:
    store = SessionStore()
    record = store.isolate_agent(
        "shared-agent-id", "policy violation", org_id="org-one"
    )

    assert record.to_dict()["org_id"] == "org-one"
    assert store.is_isolated("shared-agent-id", org_id="org-one")
    assert not store.is_isolated("shared-agent-id", org_id="org-two")
    assert store.list_isolated(org_id="org-two") == []


def test_releasing_isolation_only_changes_target_organization() -> None:
    store = SessionStore()
    store.isolate_agent("shared-agent-id", "reason", org_id="org-one")
    store.isolate_agent("shared-agent-id", "reason", org_id="org-two")

    released = store.release_agent(
        "shared-agent-id", released_by="admin", org_id="org-one"
    )

    assert released is not None and released.released_by == "admin"
    assert not store.is_isolated("shared-agent-id", org_id="org-one")
    assert store.is_isolated("shared-agent-id", org_id="org-two")

