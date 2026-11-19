from datetime import datetime, timedelta, timezone

from qa.synthetic_event_soak import main


def test_dry_run_needs_no_api_key_and_sends_nothing(monkeypatch, capsys):
    start_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    monkeypatch.setattr(
        "sys.argv",
        ["synthetic_event_soak.py", "--start-at", start_at, "--count", "2", "--dry-run"],
    )
    monkeypatch.delenv("PULSE_ORG_API_KEY", raising=False)

    assert main() == 0

    output = capsys.readouterr().out
    assert "DRY_RUN event=1" in output
    assert "DRY_RUN event=2" in output
    assert "DRY_RUN_COMPLETE count=2; no requests sent" in output


def test_expired_window_stops_without_api_key(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["synthetic_event_soak.py", "--start-at", "2000-01-01T00:00:00+00:00"],
    )
    monkeypatch.delenv("PULSE_ORG_API_KEY", raising=False)

    assert main() == 0

    output = capsys.readouterr().out
    assert "SOAK_COMPLETE" in output
    assert "events_sent=0" in output

