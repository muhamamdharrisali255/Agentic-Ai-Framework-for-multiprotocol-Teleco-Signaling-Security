"""Common data schema for both ORIGINAL and DOCLING pipelines."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ContentType(str, Enum):
    PARAGRAPH = "paragraph"
    HEADING = "heading"
    TABLE = "table"
    TABLE_ROW = "table_row"
    LIST_ITEM = "list_item"
    CAPTION = "caption"
    TEXT = "text"
    TOC = "toc"


class EntityRecord(BaseModel):
    entity: str
    type: str
    document_id: str
    section_id: Optional[str] = None
    table_id: Optional[str] = None
    row_id: Optional[str] = None
    page: Optional[int] = None
    source_text: str = ""


class TableStructured(BaseModel):
    table_id: str
    headers: list[str] = Field(default_factory=list)
    rows: list[dict[str, str]] = Field(default_factory=list)
    caption: str = ""
    page_number: Optional[int] = None
    section_id: Optional[str] = None
    document_id: str = ""


class SectionRecord(BaseModel):
    section_id: str
    title: str
    page_start: Optional[int] = None
    page_end: Optional[int] = None
    content: list[str] = Field(default_factory=list)
    tables: list[TableStructured] = Field(default_factory=list)
    subsections: list["SectionRecord"] = Field(default_factory=list)
    level: int = 1
    parent_section_id: Optional[str] = None
    toc_path: list[str] = Field(default_factory=list)


class CanonicalDocument(BaseModel):
    document_id: str
    title: str
    file_name: str
    pipeline: str
    sections: list[SectionRecord] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChunkRecord(BaseModel):
    chunk_id: str
    document_id: str
    pipeline: str
    content: str
    content_type: ContentType = ContentType.PARAGRAPH
    page: Optional[int] = None
    section: str = ""
    subsection: str = ""
    table_id: Optional[str] = None
    row_id: Optional[str] = None
    entities: list[EntityRecord] = Field(default_factory=list)
    parent_id: Optional[str] = None
    prev_chunk_id: Optional[str] = None
    next_chunk_id: Optional[str] = None
    toc_path: str = ""
    file_name: str = ""
    source_location: str = ""
    structured_table: Optional[TableStructured] = None

    def to_metadata(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "pipeline": self.pipeline,
            "content_type": self.content_type.value,
            "page": self.page,
            "section": self.section,
            "subsection": self.subsection,
            "table_id": self.table_id,
            "row_id": self.row_id,
            "parent_id": self.parent_id,
            "prev_chunk_id": self.prev_chunk_id,
            "next_chunk_id": self.next_chunk_id,
            "toc_path": self.toc_path,
            "file_name": self.file_name,
            "source_location": self.source_location,
            "entities": [e.model_dump() for e in self.entities],
        }


class RetrievalResult(BaseModel):
    chunk: ChunkRecord
    score: float
    rank: int


SectionRecord.model_rebuild()
