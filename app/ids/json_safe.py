"""JSON sanitizers — FastAPI rejects NaN/Inf (dashboard /api/ids/traffic 500)."""

from __future__ import annotations

import math
from typing import Any


def json_safe(value: Any) -> Any:
    """Replace NaN/Inf with None so responses are RFC-compliant JSON."""
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value
