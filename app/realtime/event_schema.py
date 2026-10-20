"""Normalized real-time event model (implementation_plan.md §16)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    protocol: str = ""
    event_type: str = ""
    source: str = ""
    destination: str = ""
    subscriber_id: str = ""
    session_id: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    severity: str = "INFO"
    raw_reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
