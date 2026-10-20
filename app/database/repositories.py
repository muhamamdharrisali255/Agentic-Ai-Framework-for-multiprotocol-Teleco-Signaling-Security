"""Safe repository methods — no arbitrary SQL from the LLM."""

from __future__ import annotations

from typing import Any, Optional

from app.database import postgres


def find_subscriber(
    *,
    subscriber_id: Optional[str] = None,
    imsi: Optional[str] = None,
    msisdn: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    if not postgres.is_available():
        return None
    if subscriber_id:
        return postgres.fetch_one(
            "SELECT * FROM subscribers WHERE subscriber_code = %s OR id::text = %s LIMIT 1",
            (subscriber_id, subscriber_id),
        )
    if imsi:
        return postgres.fetch_one("SELECT * FROM subscribers WHERE imsi = %s LIMIT 1", (imsi,))
    if msisdn:
        return postgres.fetch_one("SELECT * FROM subscribers WHERE msisdn = %s LIMIT 1", (msisdn,))
    return None


def find_sessions(
    *,
    subscriber_id: Optional[str] = None,
    session_id: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return []
    if session_id:
        row = postgres.fetch_one(
            "SELECT s.* FROM sessions s WHERE s.session_code = %s OR s.id::text = %s LIMIT 1",
            (session_id, session_id),
        )
        return [row] if row else []
    if not subscriber_id:
        return []
    sub = find_subscriber(subscriber_id=subscriber_id)
    if not sub:
        return []
    params: list[Any] = [sub["id"]]
    sql = "SELECT * FROM sessions WHERE subscriber_id = %s"
    if protocol:
        sql += " AND LOWER(protocol) = LOWER(%s)"
        params.append(protocol)
    sql += " ORDER BY started_at DESC LIMIT %s"
    params.append(limit)
    return postgres.fetch_all(sql, tuple(params))


def find_alerts(
    *,
    subscriber_id: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return []
    sql = "SELECT * FROM ids_alerts WHERE 1=1"
    params: list[Any] = []
    if subscriber_id:
        sub = find_subscriber(subscriber_id=subscriber_id)
        if sub:
            sql += " AND subscriber_id = %s"
            params.append(sub["id"])
    if severity:
        sql += " AND UPPER(severity) = UPPER(%s)"
        params.append(severity)
    if protocol:
        sql += " AND LOWER(protocol) = LOWER(%s)"
        params.append(protocol)
    sql += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)
    return postgres.fetch_all(sql, tuple(params))


def find_attack_pattern(
    *,
    attack_id: Optional[str] = None,
    protocol: Optional[str] = None,
    name_contains: Optional[str] = None,
) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return []
    if attack_id:
        row = postgres.fetch_one("SELECT * FROM attack_patterns WHERE attack_id = %s", (attack_id,))
        return [row] if row else []
    sql = "SELECT * FROM attack_patterns WHERE 1=1"
    params: list[Any] = []
    if protocol:
        sql += " AND LOWER(protocol) = LOWER(%s)"
        params.append(protocol)
    if name_contains:
        sql += " AND LOWER(name) LIKE LOWER(%s)"
        params.append(f"%{name_contains}%")
    sql += " ORDER BY attack_id LIMIT 20"
    return postgres.fetch_all(sql, tuple(params))


def find_dictionary_term(term: str) -> Optional[dict[str, Any]]:
    if not postgres.is_available() or not term:
        return None
    t = term.strip()
    row = postgres.fetch_one(
        "SELECT * FROM domain_dictionary WHERE LOWER(term) = LOWER(%s) LIMIT 1",
        (t,),
    )
    if row:
        return row
    return postgres.fetch_one(
        "SELECT * FROM domain_dictionary WHERE aliases @> %s::jsonb LIMIT 1",
        (f'["{t}"]',),
    )


def list_dictionary_terms(limit: int = 200) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return []
    return postgres.fetch_all(
        "SELECT term, definition, domain, aliases FROM domain_dictionary ORDER BY term LIMIT %s",
        (limit,),
    )


def find_operator(*, tadig: Optional[str] = None, name: Optional[str] = None) -> list[dict[str, Any]]:
    if not postgres.is_available():
        return []
    if tadig:
        row = postgres.fetch_one("SELECT * FROM operators WHERE UPPER(tadig) = UPPER(%s)", (tadig,))
        return [row] if row else []
    if name:
        return postgres.fetch_all(
            "SELECT * FROM operators WHERE LOWER(name) LIKE LOWER(%s) LIMIT 10",
            (f"%{name}%",),
        )
    return []
