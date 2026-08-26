import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


def _iter_candidate_sandbox_files(sample_path: str) -> list[Path]:
    candidates: list[Path] = []
    path = Path(sample_path)
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()

    base_dir = path.parent
    stem = path.stem
    names = [
        path.name + ".sandbox.json",
        stem + ".sandbox.json",
        path.name + ".report.json",
        stem + ".report.json",
        path.name + ".json",
        stem + ".json",
    ]
    for name in names:
        candidate = base_dir / name
        if candidate.exists():
            candidates.append(candidate)

    for sibling in [base_dir / "launcher", base_dir / "sandbox", base_dir.parent / "sandbox" / "launcher"]:
        if sibling.exists():
            for name in names:
                candidate = sibling / name
                if candidate.exists() and candidate not in candidates:
                    candidates.append(candidate)
    return candidates


def merge_sandbox_features(data: Dict[str, Any], sample_path: Optional[str] = None) -> Dict[str, Any]:
    merged = dict(data)
    if not sample_path:
        return merged

    candidates = _iter_candidate_sandbox_files(sample_path)
    for candidate in candidates:
        try:
            with candidate.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            continue

        if not isinstance(payload, dict):
            continue

        for key, value in payload.items():
            if key in {"alerts", "events"}:
                continue
            if key == "mitre_techniques" and isinstance(value, list):
                merged["sandbox_mitre_techniques"] = value
                merged["sandbox_mitre_count"] = len(value)
                continue
            if isinstance(value, (dict, list)):
                continue
            merged[f"sandbox_{key}"] = value

        alerts = payload.get("alerts") or []
        if isinstance(alerts, list):
            merged["sandbox_alert_count"] = len(alerts)

        events = payload.get("events") or []
        if isinstance(events, list):
            merged["sandbox_event_count"] = len(events)
            merged["sandbox_successful_event_count"] = sum(1 for event in events if isinstance(event, dict) and event.get("success") is True)
            merged["sandbox_failed_event_count"] = sum(1 for event in events if isinstance(event, dict) and event.get("success") is not True)

        break

    return merged
