"""
Phase 2 — Synthesis Engine: forensic pattern analysis over the audit hash chain.

Run standalone (separate process):
  python synthesis_engine.py

When imported by main.py, a daemon background thread runs periodic analysis
without blocking the FastAPI request path.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from audit import Logger, audit_logger

logger = logging.getLogger(__name__)

DEFAULT_WINDOW = 50
DEFAULT_FAILURE_SHARE_THRESHOLD = 0.40
DEFAULT_INTERVAL_SECONDS = float(os.getenv("PULSE_SYNTHESIS_INTERVAL_SECONDS", "60"))


def _classify_outcome(entry: Dict[str, Any]) -> str:
    """Classify a chain entry as allowed, blocked, or unknown."""
    data = entry.get("data")
    if not isinstance(data, dict):
        return "unknown"

    response = data.get("response_payload")
    if not isinstance(response, dict):
        return "unknown"

    if response.get("dropped"):
        return "blocked"

    status_code = response.get("status_code")
    if status_code is None:
        if response.get("choices") or response.get("pulse"):
            return "allowed"
        if response.get("error"):
            return "blocked"
        return "unknown"

    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return "unknown"

    if code == 200:
        return "allowed"
    if code >= 400 or code == 503:
        return "blocked"
    return "unknown"


def _agent_id_from_entry(entry: Dict[str, Any]) -> str:
    data = entry.get("data")
    if isinstance(data, dict):
        agent_id = data.get("agent_id")
        if agent_id is not None and str(agent_id).strip():
            return str(agent_id).strip()
    return "__anonymous__"


class ForensicAuditor:
    """Analyzes recent immutable audit chain entries for governance patterns."""

    def __init__(
        self,
        chain_logger: Logger,
        *,
        window: int = DEFAULT_WINDOW,
        failure_share_threshold: float = DEFAULT_FAILURE_SHARE_THRESHOLD,
    ) -> None:
        self._logger = chain_logger
        self._window = max(1, window)
        self._failure_share_threshold = failure_share_threshold

    def recent_entries(self) -> List[Dict[str, Any]]:
        return self._logger.recent_entries(self._window)

    def generate_pattern_report(self) -> Dict[str, Any]:
        """
        Build a pattern report from the last N audit entries.

        - Counts blocked vs allowed frequencies
        - Flags agent IDs responsible for >40% of failures (configurable)
        """
        entries = self.recent_entries()
        outcomes: List[str] = []
        failure_agents: List[str] = []

        for entry in entries:
            outcome = _classify_outcome(entry)
            outcomes.append(outcome)
            if outcome == "blocked":
                failure_agents.append(_agent_id_from_entry(entry))

        counts = Counter(outcomes)
        allowed = counts.get("allowed", 0)
        blocked = counts.get("blocked", 0)
        unknown = counts.get("unknown", 0)
        classified = allowed + blocked
        total = len(entries)

        failure_counter = Counter(failure_agents)
        failure_total = len(failure_agents)

        flagged_agents: List[Dict[str, Any]] = []
        if failure_total > 0:
            for agent_id, count in failure_counter.most_common():
                share = count / failure_total
                if share > self._failure_share_threshold:
                    flagged_agents.append(
                        {
                            "agent_id": agent_id,
                            "failure_count": count,
                            "share_of_failures": round(share, 4),
                            "threshold": self._failure_share_threshold,
                        }
                    )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_size": self._window,
            "entries_analyzed": total,
            "chain_verified": self._logger.verify_chain(),
            "frequencies": {
                "allowed": allowed,
                "blocked": blocked,
                "unknown": unknown,
                "allowed_pct": round((allowed / classified) * 100, 2) if classified else 0.0,
                "blocked_pct": round((blocked / classified) * 100, 2) if classified else 0.0,
            },
            "failure_attribution": {
                "total_failures": failure_total,
                "by_agent": dict(failure_counter),
                "flagged_agents": flagged_agents,
            },
        }


class SynthesisEngineRunner:
    """
    Runs forensic analysis on a daemon thread so the proxy event loop stays free.
    """

    def __init__(
        self,
        auditor: ForensicAuditor,
        *,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        self._auditor = auditor
        self._interval_seconds = max(5.0, interval_seconds)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._report_lock = threading.Lock()
        self._last_report: Optional[Dict[str, Any]] = None

    @property
    def last_report(self) -> Optional[Dict[str, Any]]:
        with self._report_lock:
            return dict(self._last_report) if self._last_report is not None else None

    def run_once(self) -> Dict[str, Any]:
        report = self._auditor.generate_pattern_report()
        with self._report_lock:
            self._last_report = report
        logger.info(
            "Synthesis report: %s allowed, %s blocked, %s flagged agent(s)",
            report["frequencies"]["allowed"],
            report["frequencies"]["blocked"],
            len(report["failure_attribution"]["flagged_agents"]),
        )
        return report

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                logger.exception("Synthesis engine iteration failed")
            if self._stop.wait(self._interval_seconds):
                break

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="pulse-synthesis-engine",
            daemon=True,
        )
        self._thread.start()
        logger.info("Synthesis engine background thread started (interval=%ss)", self._interval_seconds)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("Synthesis engine background thread stopped")


forensic_auditor = ForensicAuditor(audit_logger)
synthesis_runner = SynthesisEngineRunner(forensic_auditor)


def main() -> None:
    """Standalone process entrypoint — runs synthesis loop in the foreground."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print("Pulse Synthesis Engine — standalone process")
    print(f"Interval: {DEFAULT_INTERVAL_SECONDS}s | Window: {DEFAULT_WINDOW} entries")
    synthesis_runner.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down synthesis engine.")
        synthesis_runner.stop()


if __name__ == "__main__":
    main()
