"""Conversation CRUD for multi-turn chat."""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from pathlib import Path

from app.database import postgres

_MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "database" / "migrations"


def _available() -> bool:
    return postgres.is_available()


def ensure_schema() -> None:
    if not _available():
        return
    path = _MIGRATIONS_DIR / "002_conversations.sql"
    if path.exists():
        with postgres.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(path.read_text())


def create_conversation(
    *,
    title: str = "New chat",
    document_filter: str | None = None,
    top_k: int = 5,
) -> dict[str, Any]:
    ensure_schema()
    cid = str(uuid.uuid4())
    if not _available():
        return {"id": cid, "title": title, "document_filter": document_filter, "top_k": top_k}
    postgres.execute(
        """
        INSERT INTO conversations (id, title, document_filter, top_k)
        VALUES (%s::uuid, %s, %s, %s)
        """,
        (cid, title, document_filter, top_k),
    )
    row = postgres.fetch_one("SELECT * FROM conversations WHERE id = %s::uuid", (cid,))
    return row or {"id": cid, "title": title}


def list_conversations(*, limit: int = 40) -> list[dict[str, Any]]:
    ensure_schema()
    if not _available():
        return []
    return postgres.fetch_all(
        """
        SELECT c.*,
               (SELECT content FROM conversation_messages m
                WHERE m.conversation_id = c.id AND m.role = 'user'
                ORDER BY m.created_at ASC LIMIT 1) AS first_message
        FROM conversations c
        ORDER BY c.updated_at DESC
        LIMIT %s
        """,
        (limit,),
    )


def get_conversation(conversation_id: str) -> Optional[dict[str, Any]]:
    ensure_schema()
    if not _available():
        return None
    return postgres.fetch_one("SELECT * FROM conversations WHERE id = %s::uuid", (conversation_id,))


def touch_conversation(conversation_id: str, *, title: str | None = None) -> None:
    if not _available():
        return
    if title:
        postgres.execute(
            "UPDATE conversations SET updated_at = NOW(), title = %s WHERE id = %s::uuid",
            (title, conversation_id),
        )
    else:
        postgres.execute(
            "UPDATE conversations SET updated_at = NOW() WHERE id = %s::uuid",
            (conversation_id,),
        )


def delete_conversation(conversation_id: str) -> bool:
    if not _available():
        return False
    n = postgres.execute("DELETE FROM conversations WHERE id = %s::uuid", (conversation_id,))
    return n > 0


def add_message(
    conversation_id: str,
    role: str,
    content: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_schema()
    mid = str(uuid.uuid4())
    meta = json.dumps(metadata or {})
    if not _available():
        return {"id": mid, "conversation_id": conversation_id, "role": role, "content": content}
    postgres.execute(
        """
        INSERT INTO conversation_messages (id, conversation_id, role, content, metadata)
        VALUES (%s::uuid, %s::uuid, %s, %s, %s::jsonb)
        """,
        (mid, conversation_id, role, content, meta),
    )
    touch_conversation(conversation_id)
    row = postgres.fetch_one("SELECT * FROM conversation_messages WHERE id = %s::uuid", (mid,))
    return row or {"id": mid, "role": role, "content": content}


def get_messages(conversation_id: str, *, limit: int = 40) -> list[dict[str, Any]]:
    ensure_schema()
    if not _available():
        return []
    rows = postgres.fetch_all(
        """
        SELECT * FROM conversation_messages
        WHERE conversation_id = %s::uuid
        ORDER BY created_at ASC
        LIMIT %s
        """,
        (conversation_id, limit),
    )
    return rows


def history_for_agent(conversation_id: str | None, *, limit: int = 10) -> list[dict[str, str]]:
    """Last N turns as {role, content} for LLM context."""
    if not conversation_id:
        return []
    rows = get_messages(conversation_id, limit=limit * 2)
    out: list[dict[str, str]] = []
    for row in rows:
        role = row.get("role", "")
        if role not in ("user", "assistant"):
            continue
        content = (row.get("content") or "").strip()
        if not content:
            meta = row.get("metadata") or {}
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            agent = meta.get("agent") if isinstance(meta, dict) else None
            if agent and isinstance(agent, dict):
                content = (agent.get("answer") or "").strip()
        if content:
            out.append({"role": role, "content": content})
    return out[-limit:]
