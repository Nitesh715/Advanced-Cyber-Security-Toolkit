# Detection catalog

The bundled rules demonstrate three useful patterns. They operate on normalized events and synthetic labels; they do not execute or create malicious activity.

| Rule | Detection | Pattern | ATT&CK reference | Severity |
|---|---|---|---|---|
| `AUTH-001` | Repeated authentication failures | Five failures per host, user, and source IP within 10 minutes | T1110 | High |
| `AUTH-002` | Failures followed by success | Failure then success for the same host, user, and source IP within 15 minutes | T1110 | Critical |
| `EXEC-001` | Suspicious process behavior flagged by lab telemetry | Single normalized event label | T1059 | High |
| `IDENTITY-001` | Privileged group membership changed | Single normalized event label | T1098 | High |

## Sample scenario

The synthetic event set includes five failed authentications for one test identity, a later success, and two additional lab event labels on the same test host. The engine should produce a threshold alert, a failure-to-success sequence alert, and two single-event alerts; the shared host/source entities should correlate those alerts into one case. A separate benign success on a different lab host remains unalerted.

## Rule authoring guidance

- Keep `id` stable and unique so analysts can track rule changes.
- State exactly what the event pattern detects in `summary`.
- Group by enough context to reduce accidental aggregation (usually host, identity, and source).
- Describe observable event fields and data prerequisites in project documentation.
- Map ATT&CK only when the behavior supports the mapping; the tag is context, not proof of a technique.
- Add benign and simulated examples and measure precision/recall before deploying a rule.

Supported shapes:

```json
{"id":"EXAMPLE-001","name":"Example event","type":"single","severity":"medium","match":{"event_type":"example_event"}}
```

```json
{"id":"EXAMPLE-002","name":"Repeated event","type":"threshold","severity":"high","match":{"event_type":"example_event"},"group_by":["host","user"],"threshold":5,"window_minutes":10}
```

```json
{"id":"EXAMPLE-003","name":"Event sequence","type":"sequence","severity":"high","start_match":{"event_type":"first_event"},"end_match":{"event_type":"second_event"},"group_by":["host","user"],"window_minutes":15}
```
