"""Original pipeline — PDF/text extraction with structure-aware chunking.

Fixed-size, page-local slicing used to cut numbered procedures in half and
carried no heading metadata, so multi-step answers could never be retrieved
whole. Chunks are now built per section across page boundaries: headings become
section/subsection metadata, every chunk carries its breadcrumb so it is
self-describing once embedded, enumerated lists stay with the sentence that
introduces them, and continuation chunks stay linked to their section parent.

Headings are validated against the document's own table of contents where one
exists. Extracted PDF text frequently drops auto-numbered chapter numbers and
promotes ordinary numbered table rows, so the TOC is the only reliable
authority; documents without one fall back to numbering-sequence heuristics.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pdfplumber

import config
from shared.ids import chunk_id, doc_id
from shared.schema import ChunkRecord, ContentType

# "3.3.6.2 Title", "B.3.4.1 Title", "Annex A Title"
_HEADING_RE = re.compile(
    r"^(?:(?:annex\s+)?[A-Z]?\d+(?:\.\d+)*|annex\s+[A-Z])[.)]?\s+\S.{0,110}$",
    re.I,
)
_NUMBER_RE = re.compile(r"^((?:annex\s+)?[A-Z]?\d+(?:\.\d+)*|annex\s+[A-Z])[.)]?\s+(.*)$", re.I)
_LIST_ITEM_RE = re.compile(r"^\s*(?:\d+[.)]|[a-z][.)]|[-•*])\s+\S")
_TOC_ENTRY_RE = re.compile(r"^(.*?)\s+(\d{1,4})$")
_SENTENCE_END = (".", ":", "?", "!")

_TARGET_CHARS = max(config.ORIGINAL_CHUNK_SIZE, 1400)
_MAX_CHARS = _TARGET_CHARS + 700
# Hard ceiling so unbroken material (tables of contents, dense lists) cannot
# grow into a single chunk too large to embed meaningfully.
_HARD_MAX_CHARS = _TARGET_CHARS * 2
_MIN_CHARS = 200
_TOC_SCAN_PAGES = 12


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


@dataclass
class _Heading:
    """A document heading and its position in the numbering hierarchy."""

    number: str
    title: str
    ancestors: List[str] = field(default_factory=list)

    @property
    def full(self) -> str:
        return f"{self.number} {self.title}".strip() if self.number else self.title

    @property
    def depth(self) -> int:
        return len(_number_parts(self.number)) if self.number else 1

    def breadcrumb(self) -> str:
        return " > ".join([*self.ancestors, self.full])


def extract_text_from_pdf(path: Path) -> List[Tuple[str, int]]:
    pages: List[Tuple[str, int]] = []
    with pdfplumber.open(path) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            if text.strip():
                pages.append((text.strip(), i))
    return pages


def extract_text_from_file(path: Path) -> List[Tuple[str, int]]:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract_text_from_pdf(path)
    if suffix in (".txt", ".md"):
        return [(path.read_text(encoding="utf-8"), 1)]
    raise ValueError(f"Unsupported file type: {suffix}")


def _repeated_lines(pages: List[Tuple[str, int]]) -> set[str]:
    """Running headers/footers, detected by how often a line repeats."""
    if len(pages) < 4:
        return set()
    counts: Counter[str] = Counter()
    for text, _ in pages:
        for line in {l.strip() for l in text.split("\n") if l.strip()}:
            counts[line] += 1
    threshold = max(3, int(len(pages) * 0.4))
    return {line for line, n in counts.items() if n >= threshold and len(line) < 120}


def _is_page_furniture(line: str, repeated: set[str], edge: bool) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if stripped in repeated:
        return True
    # "Page 38 of 147", "V10.0 Page 38 of 147"
    if re.fullmatch(r"(?:[\w.]+\s+)?page\s+\d+\s+of\s+\d+", stripped, re.I):
        return True
    # A bare number is a page number at the page edge, but may be a heading
    # number or table value anywhere else.
    return edge and bool(re.fullmatch(r"\d{1,4}", stripped))


def _iter_lines(pages: List[Tuple[str, int]], repeated: set[str]) -> Iterable[Tuple[str, int]]:
    for text, page in pages:
        raw_lines = text.split("\n")
        last = len(raw_lines) - 1
        for i, raw in enumerate(raw_lines):
            if not _is_page_furniture(raw, repeated, edge=i in (0, 1, last)):
                yield raw.rstrip(), page


def _number_parts(number: str) -> List[str]:
    """"3.3.6" -> [3,3,6]; "Annex B" -> [B]; "B.3.4" -> [B,3,4]."""
    cleaned = re.sub(r"^annex\s+", "", (number or "").strip(), flags=re.I)
    return [p for p in cleaned.split(".") if p]


def _plausible_number(number: str) -> bool:
    """Reject body text that merely starts with a figure, e.g. "5012 or 5005."."""
    parts = _number_parts(number)
    if not parts:
        return False
    digits = [p for p in parts if p.isdigit()]
    # A top-level chapter is rarely above 99; deeper levels stay small too.
    if len(parts) == 1 and digits and len(digits[0]) > 2:
        return False
    return all(len(d) <= 3 for d in digits)


def _heading_shape(line: str) -> Optional[Tuple[str, str]]:
    """(number, title) when the line looks like a numbered heading."""
    stripped = line.strip()
    if not _HEADING_RE.match(stripped) or _LIST_ITEM_RE.match(stripped):
        return None
    m = _NUMBER_RE.match(stripped)
    if not m:
        return None
    number, title = m.group(1), m.group(2).strip()
    if not _plausible_number(number) or not title or len(title) > 110:
        return None
    return number, title


class _TocIndex:
    """Heading catalogue parsed from the document's table of contents."""

    def __init__(self) -> None:
        self.title_by_number: Dict[str, str] = {}
        self.number_by_title: Dict[str, str] = {}

    def __bool__(self) -> bool:
        return bool(self.title_by_number)

    def add(self, number: str, title: str) -> None:
        key = ".".join(_number_parts(number))
        if key and key not in self.title_by_number:
            self.title_by_number[key] = title
        norm = _norm(title)
        if norm and norm not in self.number_by_title:
            self.number_by_title[norm] = key

    def _known_parent(self, parts: List[str]) -> bool:
        return len(parts) > 1 and ".".join(parts[:-1]) in self.title_by_number

    def resolve(self, number: str, title: str) -> Optional[_Heading]:
        """Match a body line against the catalogue and build its hierarchy."""
        key = ".".join(_number_parts(number)) if number else self.number_by_title.get(_norm(title), "")
        if not key:
            return None
        parts = _number_parts(key)
        if key not in self.title_by_number:
            # Tables of contents are usually depth-limited; a deeper heading is
            # genuine when its parent is catalogued and it reads like a title.
            if not (self._known_parent(parts) and title[:1].isupper()):
                return None
            self.add(key, title)
        known = self.title_by_number[key]
        if number and _norm(title) and not _titles_match(title, known):
            return None
        ancestors = []
        for i in range(1, len(parts)):
            prefix = ".".join(parts[:i])
            if prefix in self.title_by_number:
                ancestors.append(f"{prefix} {self.title_by_number[prefix]}".strip())
        return _Heading(number=key, title=known, ancestors=ancestors)


def _titles_match(found: str, known: str) -> bool:
    """Body headings wrap or truncate; accept a prefix match either way."""
    a, b = _norm(found), _norm(known)
    return a == b or a.startswith(b[:40]) or b.startswith(a[:40])


def _wraps_into_next(line: str) -> bool:
    """A TOC line with no page number that clearly continues onto the next."""
    stripped = line.strip()
    if stripped.endswith(_SENTENCE_END):
        return False
    return bool(_heading_shape(stripped)) or len(stripped) > 60


def _parse_toc(pages: List[Tuple[str, int]], repeated: set[str]) -> _TocIndex:
    """Read "N.N Title <page>" entries, joining titles that wrap across lines."""
    toc = _TocIndex()
    pending: List[str] = []
    unnumbered: List[str] = []

    for text, _ in pages[:_TOC_SCAN_PAGES]:
        for raw in text.split("\n"):
            line = raw.strip()
            if not line or line in repeated:
                continue
            # Join only with a line that was left hanging mid-title, so a
            # complete entry never absorbs the unrelated line above it.
            if pending and _wraps_into_next(pending[-1]):
                pending.append(line)
                m = _TOC_ENTRY_RE.match(" ".join(pending))
            else:
                pending = [line]
                m = _TOC_ENTRY_RE.match(line)
            if not m:
                if len(pending) > 2:
                    pending = []
                continue
            entry = m.group(1).strip()
            pending = []
            shape = _heading_shape(entry)
            if shape:
                number, title = shape
                toc.add(number, title)
                # An unnumbered entry above "N.x" is chapter N, whose own
                # number the PDF text does not carry.
                parts = _number_parts(number)
                if len(parts) > 1 and unnumbered:
                    toc.add(parts[0], unnumbered[-1])
                    unnumbered = []
            elif 3 < len(entry) <= 120 and entry[0].isupper():
                unnumbered.append(entry)
    return toc


class _HeadingStack:
    """Fallback hierarchy for documents without a usable table of contents."""

    def __init__(self) -> None:
        self._stack: List[_Heading] = []
        self._last_child: Dict[str, str] = {}

    @staticmethod
    def _follows(previous: Optional[str], candidate: str) -> bool:
        if candidate.isdigit():
            return int(candidate) == (int(previous) + 1 if previous and previous.isdigit() else 1)
        if len(candidate) == 1 and candidate.isalpha():
            expected = chr(ord(previous) + 1) if previous and len(previous) == 1 else "A"
            return candidate.upper() == expected.upper()
        return False

    def push(self, number: str, title: str) -> Optional[_Heading]:
        parts = _number_parts(number)
        if not parts:
            return None
        parent_key = ".".join(parts[:-1])
        if parent_key and parent_key not in self._last_child:
            return None
        if not self._follows(self._last_child.get(parent_key), parts[-1]):
            return None

        self._last_child[parent_key] = parts[-1]
        self._last_child.setdefault(".".join(parts), "")
        while self._stack and self._stack[-1].depth >= len(parts):
            self._stack.pop()
        heading = _Heading(number=number, title=title, ancestors=[h.full for h in self._stack])
        self._stack.append(heading)
        return heading


def _section_fields(heading: Optional[_Heading]) -> Tuple[str, str, str]:
    """(section, subsection, toc_path) for the current heading."""
    if heading is None:
        return "", "", ""
    section = heading.ancestors[0] if heading.ancestors else heading.full
    subsection = heading.full if heading.ancestors else ""
    return section, subsection, heading.breadcrumb()


class _ChunkBuilder:
    """Accumulates lines and emits linked chunks for one section."""

    def __init__(self, document_id: str, file_name: str) -> None:
        self.document_id = document_id
        self.file_name = file_name
        self.chunks: List[ChunkRecord] = []
        self._section_parent: Optional[str] = None

    def start_section(self) -> None:
        self._section_parent = None

    def emit(self, buffer: List[str], page: int, heading: Optional[_Heading]) -> None:
        body = "\n".join(buffer).strip()
        if not body:
            return
        section, subsection, breadcrumb = _section_fields(heading)
        # Every chunk repeats its breadcrumb so an isolated retrieval hit still
        # says which section it came from.
        content = f"{breadcrumb}\n{body}" if breadcrumb and breadcrumb not in body else body
        record = ChunkRecord(
            chunk_id=chunk_id(),
            document_id=self.document_id,
            pipeline="original",
            content=content,
            content_type=ContentType.TEXT,
            page=page,
            section=section,
            subsection=subsection,
            toc_path=breadcrumb,
            parent_id=self._section_parent,
            file_name=self.file_name,
            source_location=f"page:{page}",
        )
        if self._section_parent is None:
            self._section_parent = record.chunk_id
        self.chunks.append(record)


def _split_point(buffer: List[str]) -> int:
    """Index to cut at: after the last completed sentence, else at the end."""
    for i in range(len(buffer) - 1, 0, -1):
        if buffer[i - 1].rstrip().endswith(_SENTENCE_END):
            return i
    return len(buffer)


def _merge_small_chunks(chunks: List[ChunkRecord]) -> List[ChunkRecord]:
    """Fold stub chunks into their neighbour so no fragment stands alone."""
    merged: List[ChunkRecord] = []
    for chunk in chunks:
        if (
            merged
            and len(chunk.content) < _MIN_CHARS
            and merged[-1].toc_path == chunk.toc_path
            and len(merged[-1].content) + len(chunk.content) < _HARD_MAX_CHARS
        ):
            merged[-1].content = f"{merged[-1].content}\n{chunk.content}"
            continue
        merged.append(chunk)
    return merged


def _link_sequence(chunks: List[ChunkRecord]) -> None:
    for i, chunk in enumerate(chunks):
        chunk.prev_chunk_id = chunks[i - 1].chunk_id if i else None
        chunk.next_chunk_id = chunks[i + 1].chunk_id if i + 1 < len(chunks) else None


def _detect_heading(
    line: str, toc: _TocIndex, stack: _HeadingStack
) -> Optional[_Heading]:
    """Resolve a body line to a catalogued heading, or None if it is prose."""
    stripped = line.strip()
    shape = _heading_shape(stripped)
    if toc:
        if shape:
            return toc.resolve(*shape)
        # Chapter headings often lose their number in extracted text.
        if 3 < len(stripped) <= 90 and stripped[0].isupper() and not _LIST_ITEM_RE.match(stripped):
            return toc.resolve("", stripped)
        return None
    return stack.push(*shape) if shape else None


def structure_aware_chunks(
    pages: List[Tuple[str, int]], document_id: str, file_name: str
) -> List[ChunkRecord]:
    """Chunk on section boundaries, keeping lists and their lead-in together."""
    repeated = _repeated_lines(pages)
    toc = _parse_toc(pages, repeated)
    lines = list(_iter_lines(pages, repeated))
    builder = _ChunkBuilder(document_id, file_name)
    stack = _HeadingStack()

    buffer: List[str] = []
    size = 0
    heading: Optional[_Heading] = None
    start_page = pages[0][1] if pages else 1
    in_list = False

    skip_next = False
    for idx, (line, page) in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        candidate = line.strip()
        joined = False
        if idx + 1 < len(lines) and _wraps_into_next(candidate) and _heading_shape(candidate):
            tail = lines[idx + 1][0].strip()
            if tail and not _heading_shape(tail) and not _LIST_ITEM_RE.match(tail) and len(tail) <= 60:
                candidate, joined = f"{candidate} {tail}", True

        promoted = _detect_heading(candidate, toc, stack)
        if promoted:
            builder.emit(buffer, start_page, heading)
            buffer, size, in_list = [], 0, False
            heading = promoted
            builder.start_section()
            start_page = page
            skip_next = joined
            continue

        is_item = bool(_LIST_ITEM_RE.match(line))
        soft_break = size >= _TARGET_CHARS and not in_list and not is_item and not line.strip()
        firm_break = size >= _MAX_CHARS and not in_list and not is_item
        if soft_break or firm_break or size >= _HARD_MAX_CHARS:
            cut = _split_point(buffer)
            builder.emit(buffer[:cut], start_page, heading)
            buffer = buffer[cut:]
            size = sum(len(l) + 1 for l in buffer)
            in_list = False
            start_page = page

        if not buffer:
            start_page = page
        buffer.append(line)
        size += len(line) + 1
        in_list = is_item or (in_list and bool(line.strip()))

    builder.emit(buffer, start_page, heading)
    chunks = _merge_small_chunks(builder.chunks)
    _link_sequence(chunks)
    return chunks


def process_document(path: Path) -> List[ChunkRecord]:
    file_name = path.name
    document_id = doc_id(file_name)
    pages = extract_text_from_file(path)
    if not pages:
        return []
    return structure_aware_chunks(pages, document_id, file_name)
