import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from Forensics_Timeline_Builder.app import main


@pytest.fixture(autouse=True)
def clear_events():
    main.events.clear()
    yield
    main.events.clear()


def event(timestamp, *, host="host-a", source="syslog", summary="event"):
    return main.EventIn.model_validate(
        {
            "timestamp": timestamp,
            "source": source,
            "host": host,
            "event_type": "test",
            "summary": summary,
        }
    )


def test_health_and_event_lifecycle():
    assert main.health() == {"status": "ok", "events": 0}

    record = main.add_event(event("2025-01-01T00:00:00Z", summary="login"))

    assert record["id"]
    assert record["summary"] == "login"
    assert main.health() == {"status": "ok", "events": 1}
    assert main.clear_events() == {"deleted": 1}
    assert main.health() == {"status": "ok", "events": 0}


def test_rejects_timezone_free_timestamp_and_invalid_sha256():
    with pytest.raises(ValidationError):
        event("2025-01-01T00:00:00")

    invalid = {
        "timestamp": "2025-01-01T00:00:00Z",
        "source": "syslog",
        "host": "host-a",
        "event_type": "test",
        "summary": "event",
        "sha256": "not-a-hash",
    }
    with pytest.raises(ValidationError):
        main.EventIn.model_validate(invalid)


def test_timeline_filters_limits_and_sorts_fractional_timestamps():
    main.add_event(event("2025-01-01T00:00:00.100Z", summary="later"))
    main.add_event(event("2025-01-01T00:00:00Z", summary="earlier"))
    main.add_event(event("2025-01-01T00:00:01Z", host="host-b", source="audit"))

    result = main.timeline(host="host-a", source="syslog", limit=1)

    assert result["count"] == 1
    assert result["events"][0]["summary"] == "earlier"
    assert main.timeline(host="missing") == {"count": 0, "events": []}

    with pytest.raises(HTTPException) as exc_info:
        main.timeline(limit=0)
    assert exc_info.value.status_code == 400
