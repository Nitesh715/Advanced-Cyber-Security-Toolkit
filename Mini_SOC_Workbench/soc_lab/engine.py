"""Rule evaluation and alert-to-incident correlation."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .adapters import load_events
from .models import Event

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"low": 25, "medium": 45, "high": 70, "critical": 90}


def load_rules(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as source:
        data = json.load(source)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("rules file must contain a top-level 'rules' array")
    rules = data["rules"]
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"rule #{index} must be an object")
        required = ("id", "name", "type", "severity")
        missing = [key for key in required if key not in rule]
        if missing:
            raise ValueError(f"rule #{index} is missing: {', '.join(missing)}")
        if rule["type"] not in {"single", "threshold", "sequence"}:
            raise ValueError(f"rule {rule['id']}: unsupported type {rule['type']!r}")
        if rule["severity"] not in SEVERITY_RANK:
            raise ValueError(f"rule {rule['id']}: unsupported severity {rule['severity']!r}")
    return rules


def _matches(event: Event, criteria: dict[str, Any]) -> bool:
    return all(event.field(field) == expected for field, expected in criteria.items())


def _group_key(event: Event, fields: list[str]) -> tuple[str, ...]:
    return tuple(str(event.field(field) or "<missing>") for field in fields)


def _alert(
    rule: dict[str, Any],
    matched_events: list[Event],
    entities: dict[str, str],
    alert_number: int,
) -> dict[str, Any]:
    return {
        "alert_id": f"AL-{rule['id']}-{alert_number:04d}",
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "timestamp": matched_events[-1].timestamp.isoformat(),
        "entities": entities,
        "summary": rule.get("summary", rule["name"]),
        "event_ids": [event.event_id for event in matched_events],
        "attack_technique": rule.get("attack_technique"),
        "recommended_actions": rule.get("recommended_actions", []),
    }


def run_detections(events: list[Event], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    ordered_events = sorted(events, key=lambda event: event.timestamp)

    for rule in rules:
        rule_alert_number = 0
        rule_type = rule["type"]

        if rule_type == "single":
            criteria = rule.get("match", {})
            for event in ordered_events:
                if _matches(event, criteria):
                    rule_alert_number += 1
                    alerts.append(_alert(rule, [event], event.entities(), rule_alert_number))

        elif rule_type == "threshold":
            criteria = rule.get("match", {})
            group_by = rule.get("group_by", ["host"])
            threshold = int(rule.get("threshold", 0))
            window_minutes = float(rule.get("window_minutes", 0))
            if threshold < 1 or window_minutes <= 0:
                raise ValueError(f"rule {rule['id']}: threshold and window must be positive")
            window = timedelta(minutes=window_minutes)
            groups: dict[tuple[str, ...], deque[Event]] = defaultdict(deque)
            last_alert_at: dict[tuple[str, ...], datetime] = {}
            for event in ordered_events:
                if not _matches(event, criteria):
                    continue
                key = _group_key(event, group_by)
                bucket = groups[key]
                bucket.append(event)
                while bucket and event.timestamp - bucket[0].timestamp > window:
                    bucket.popleft()
                alert_time = last_alert_at.get(key)
                outside_cooldown = alert_time is None or event.timestamp - alert_time > window
                if len(bucket) >= threshold and outside_cooldown:
                    matched = list(bucket)[-threshold:]
                    entities = {field: value for field, value in zip(group_by, key) if value != "<missing>"}
                    rule_alert_number += 1
                    alerts.append(_alert(rule, matched, entities, rule_alert_number))
                    last_alert_at[key] = event.timestamp

        elif rule_type == "sequence":
            start_match = rule.get("start_match", {})
            end_match = rule.get("end_match", {})
            group_by = rule.get("group_by", ["host"])
            window_minutes = float(rule.get("window_minutes", 0))
            if window_minutes <= 0:
                raise ValueError(f"rule {rule['id']}: sequence window must be positive")
            window = timedelta(minutes=window_minutes)
            starts: dict[tuple[str, ...], deque[Event]] = defaultdict(deque)
            for event in ordered_events:
                if _matches(event, end_match):
                    key = _group_key(event, group_by)
                    bucket = starts[key]
                    while bucket and event.timestamp - bucket[0].timestamp > window:
                        bucket.popleft()
                    if bucket:
                        start_event = bucket[-1]
                        matched = [start_event, event]
                        entities = {field: value for field, value in zip(group_by, key) if value != "<missing>"}
                        rule_alert_number += 1
                        alerts.append(_alert(rule, matched, entities, rule_alert_number))
                if _matches(event, start_match):
                    starts[_group_key(event, group_by)].append(event)

    return sorted(alerts, key=lambda alert: datetime.fromisoformat(alert["timestamp"]))


def correlate_alerts(
    alerts: list[dict[str, Any]], correlation_minutes: float = 30.0
) -> list[dict[str, Any]]:
    """Join alerts sharing a host or source IP inside the correlation window."""
    if not alerts:
        return []
    if correlation_minutes <= 0:
        raise ValueError("correlation window must be positive")
    alerts = sorted(alerts, key=lambda alert: datetime.fromisoformat(alert["timestamp"]))
    window = timedelta(minutes=correlation_minutes)
    parents = list(range(len(alerts)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(alerts)):
        left_time = datetime.fromisoformat(alerts[left]["timestamp"])
        left_entities = alerts[left].get("entities", {})
        for right in range(left + 1, len(alerts)):
            right_time = datetime.fromisoformat(alerts[right]["timestamp"])
            if right_time - left_time > window:
                break
            right_entities = alerts[right].get("entities", {})
            shared_host = left_entities.get("host") and left_entities.get("host") == right_entities.get("host")
            shared_ip = (
                left_entities.get("source_ip")
                and left_entities.get("source_ip") == right_entities.get("source_ip")
            )
            if shared_host or shared_ip:
                union(left, right)

    components: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, alert in enumerate(alerts):
        components[find(index)].append(alert)

    cases: list[dict[str, Any]] = []
    ordered_components = sorted(components.values(), key=lambda group: min(a["timestamp"] for a in group))
    for case_number, case_alerts in enumerate(ordered_components, start=1):
        case_alerts.sort(key=lambda alert: datetime.fromisoformat(alert["timestamp"]))
        severest = max(case_alerts, key=lambda alert: SEVERITY_RANK[alert["severity"]])
        unique_rules = {alert["rule_id"] for alert in case_alerts}
        score = min(100, SEVERITY_SCORE[severest["severity"]] + 10 * (len(unique_rules) - 1))
        entities: dict[str, set[str]] = defaultdict(set)
        event_ids: set[str] = set()
        recommended_actions: list[str] = []
        for alert in case_alerts:
            for entity_type, value in alert.get("entities", {}).items():
                entities[entity_type].add(value)
            event_ids.update(alert.get("event_ids", []))
            for action in alert.get("recommended_actions", []):
                if action not in recommended_actions:
                    recommended_actions.append(action)

        cases.append(
            {
                "case_id": f"INC-{case_number:04d}",
                "title": f"{len(case_alerts)} correlated alert(s): {severest['rule_name']}",
                "status": "open",
                "severity": severest["severity"],
                "risk_score": score,
                "first_seen": case_alerts[0]["timestamp"],
                "last_seen": case_alerts[-1]["timestamp"],
                "entities": {kind: sorted(values) for kind, values in sorted(entities.items())},
                "alert_ids": [alert["alert_id"] for alert in case_alerts],
                "rule_ids": sorted(unique_rules),
                "event_ids": sorted(event_ids),
                "recommended_actions": recommended_actions,
            }
        )
    return cases
