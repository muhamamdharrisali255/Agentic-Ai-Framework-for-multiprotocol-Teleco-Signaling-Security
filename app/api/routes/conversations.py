"""Conversation history API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.chat import conversations as conv

router = APIRouter()


class NewConversationRequest(BaseModel):
    title: str = "New chat"
    document: str | None = None
    top_k: int = Field(default=5, ge=1, le=20)


@router.get("/conversations")
def list_conversations(limit: int = 40):
    return {"conversations": conv.list_conversations(limit=limit)}


@router.post("/conversations")
def create_conversation(req: NewConversationRequest):
    row = conv.create_conversation(
        title=req.title,
        document_filter=req.document,
        top_k=req.top_k,
    )
    return row


@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str):
    row = conv.get_conversation(conversation_id)
    if not row:
        raise HTTPException(404, "Conversation not found")
    messages = conv.get_messages(conversation_id)
    return {"conversation": row, "messages": messages}


@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: str):
    if not conv.delete_conversation(conversation_id):
        raise HTTPException(404, "Conversation not found")
    return {"ok": True}
