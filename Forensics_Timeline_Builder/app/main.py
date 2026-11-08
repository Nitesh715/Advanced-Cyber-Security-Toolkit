from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="Forensics Timeline Builder", version="0.1.0")
events: list[dict[str, Any]] = []


class EventIn(BaseModel):
    timestamp: datetime
    source: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=1, max_length=1000)
    actor: str | None = None
    artifact: str | None = None
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone, e.g. Z or +00:00")
        return value.astimezone(timezone.utc)


@app.get("/health")
def health():
    return {"status": "ok", "events": len(events)}


@app.post("/events", status_code=201)
def add_event(event: EventIn):
    record = {"id": str(uuid4()), **event.model_dump(mode="json")}
    events.append(record)
    return record


@app.get("/timeline")
def timeline(host: str | None = None, source: str | None = None, limit: int = 500):
    if not 1 <= limit <= 5000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")
    selected = [e for e in events if (host is None or e["host"] == host) and
                (source is None or e["source"] == source)]
    selected.sort(
        key=lambda event: datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    )
    return {"count": min(len(selected), limit), "events": selected[:limit]}


@app.delete("/events")
def clear_events():
    count = len(events)
    events.clear()
    return {"deleted": count}
