import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from baseline import extract_text

INTENT_PATTERNS = {
    "build": re.compile(r"\b(build|create|implement|make|write|generate)\b", re.I),
    "debug": re.compile(r"\b(debug|fix|error|traceback|failing|broken)\b", re.I),
    "explain": re.compile(r"\b(explain|why|how|what does|summari[sz]e)\b", re.I),
    "operate": re.compile(r"\b(run|install|start|deploy|execute|serve)\b", re.I),
}


@dataclass
class BDIState:
    beliefs: Dict[str, Any] = field(default_factory=dict)
    desires: List[str] = field(default_factory=list)
    intentions: List[str] = field(default_factory=list)
    turns: int = 0

    def observe(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.turns += 1
        user_texts = [
            extract_text(m.get("content", ""))
            for m in messages
            if m.get("role") == "user"
        ]
        latest = user_texts[-1] if user_texts else ""
        all_text = " ".join(user_texts)
        intents = [name for name, pattern in INTENT_PATTERNS.items() if pattern.search(latest)]

        self.beliefs["last_user_chars"] = len(latest)
        self.beliefs["message_count"] = len(messages)
        self.beliefs["has_system_prompt"] = any(m.get("role") == "system" for m in messages)
        self.beliefs["tool_calls_detected"] = sum(
            1 for m in messages if m.get("role") == "tool" or m.get("tool_calls")
        )
        self.beliefs["escalation_keywords"] = sum(
            1 for kw in ("admin", "root", "sudo", "override", "bypass", "ignore", "disable")
            if kw in all_text.lower()
        )
        self.beliefs["unique_intents_seen"] = len(
            set(self.beliefs.get("_intent_history", "").split(",") + intents)
        )
        self.beliefs["_intent_history"] = ",".join(
            (self.beliefs.get("_intent_history", "") + "," + ",".join(intents)).strip(",").split(",")[-20:]
        )

        if latest:
            desire = latest[:180]
            if desire not in self.desires:
                self.desires.append(desire)
                self.desires = self.desires[-10:]
        if intents:
            self.intentions = intents[-5:]

        return self.snapshot()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "beliefs": dict(self.beliefs),
            "desires": list(self.desires),
            "intentions": list(self.intentions),
            "turns": self.turns,
        }

    def reset(self) -> None:
        self.beliefs.clear()
        self.desires.clear()
        self.intentions.clear()
        self.turns = 0
