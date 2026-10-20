"""Route RAEX IR.21 documents into the structured store instead of embeddings.

IR.21 is a filled-in form, not prose: every value belongs to a typed field, so
similarity search over its text is the wrong retrieval mechanism. These
documents are parsed into PostgreSQL relations and answered with SQL, while
prose specifications continue through the vector pipeline.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ir21 import postgres as pg
from ir21.parser import looks_like_ir21, parse_ir21
from ir21.records import Dataset

# Enough of the RAEX template to identify it from the opening pages alone.
_PDF_MARKERS = (
    re.compile(r"raex\s*ir\.?\s*21", re.I),
    re.compile(r"tadig\s*code\s*:", re.I),
    re.compile(r"section\s*id\s*:\s*\d", re.I),
)


def _head_text(path: Path, pages: int = 4) -> str:
    try:
        import pdfplumber

        with pdfplumber.open(str(path)) as pdf:
            return "\n".join((p.extract_text() or "") for p in pdf.pages[:pages])
    except Exception:
        return ""


def is_ir21_pdf(path: Path) -> bool:
    """Cheap pre-check so IR.21 files never enter the embedding pipeline."""
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md"}:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:8000]
        except Exception:
            return False
        from ir21.text_parser import looks_like_ir21_text

        return looks_like_ir21_text(text)
    text = _head_text(path)
    if not text:
        return False
    return sum(bool(rx.search(text)) for rx in _PDF_MARKERS) >= 2


def ingest_text(text: str, file_name: str) -> list[dict[str, Any]]:
    """Load one or more RAEX filings from plain text into PostgreSQL."""
    from ir21.text_parser import parse_all

    results: list[dict[str, Any]] = []
    for dataset in parse_all(text, file_name=file_name):
        counts = pg.load_dataset(dataset)
        results.append(
            {
                "route": "structured",
                "backend": "postgresql",
                "document_id": dataset.document.document_id,
                "tadig": dataset.document.tadig,
                "organisation": dataset.document.organisation_name,
                "file_name": dataset.document.file_name,
                "counts": counts,
                "records": sum(counts.values()),
            }
        )
    from ir21.retrieval import refresh_vocabulary

    refresh_vocabulary()
    return results


def document_id_for(path: Path, dataset: Optional[Dataset] = None) -> str:
    if dataset and dataset.document.tadig:
        return f"IR21-{dataset.document.tadig.upper()}"
    return f"IR21-{path.stem[:40]}"


def ingest(path: Path, export: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Parse an IR.21 filing and replace its rows in PostgreSQL.

    Plain-text dumps are parsed directly. PDFs prefer full-document text
    (the RAEX template is regular) and fall back to Docling tables.
    """
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md"}:
        loaded = ingest_text(path.read_text(encoding="utf-8", errors="ignore"), path.name)
        if not loaded:
            raise ValueError(f"{path.name} does not follow the RAEX IR.21 template")
        return loaded[0] if len(loaded) == 1 else {"documents": loaded, "records": sum(d["records"] for d in loaded)}

    text = ""
    try:
        import pdfplumber

        with pdfplumber.open(str(path)) as pdf:
            text = "\n".join((p.extract_text() or "") for p in pdf.pages)
    except Exception:
        text = ""

    if text:
        from ir21.text_parser import looks_like_ir21_text, parse_ir21_text

        if looks_like_ir21_text(text):
            dataset = parse_ir21_text(text, file_name=path.name)
            dataset.document.document_id = document_id_for(path, dataset)
            if dataset.document.tadig and (
                dataset.camel_support or dataset.network_elements
            ):
                counts = pg.load_dataset(dataset)
                from ir21.retrieval import refresh_vocabulary

                refresh_vocabulary()
                result = {
                    "route": "structured",
                    "backend": "postgresql",
                    "document_id": dataset.document.document_id,
                    "tadig": dataset.document.tadig,
                    "organisation": dataset.document.organisation_name,
                    "counts": counts,
                    "records": sum(counts.values()),
                    "parser": "text",
                }
                try:
                    from app.ontology.ir21_etl import feed_from_ir21

                    result["ontology_feed"] = feed_from_ir21(mirror_graph=True)
                except Exception as exc:
                    result["ontology_feed"] = {"ok": False, "error": str(exc)}
                return result

    from docling_pipeline.extractor import extract_with_docling

    export = export or extract_with_docling(path)
    if not looks_like_ir21(export):
        raise ValueError(f"{path.name} does not follow the RAEX IR.21 template")

    dataset = parse_ir21(export, document_id="pending", file_name=path.name)
    dataset.document.document_id = document_id_for(path, dataset)
    counts = pg.load_dataset(dataset)

    from ir21.retrieval import refresh_vocabulary

    refresh_vocabulary()
    result = {
        "route": "structured",
        "backend": "postgresql",
        "document_id": dataset.document.document_id,
        "tadig": dataset.document.tadig,
        "organisation": dataset.document.organisation_name,
        "counts": counts,
        "records": sum(counts.values()),
        "parser": "docling",
    }
    try:
        from app.ontology.ir21_etl import feed_from_ir21

        result["ontology_feed"] = feed_from_ir21(mirror_graph=True)
    except Exception as exc:
        result["ontology_feed"] = {"ok": False, "error": str(exc)}
    return result


def remove(file_name: str) -> None:
    pg.delete_document(file_name)
    from ir21.retrieval import refresh_vocabulary

    refresh_vocabulary()
