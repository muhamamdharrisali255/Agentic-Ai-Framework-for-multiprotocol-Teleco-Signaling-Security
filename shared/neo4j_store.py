"""Neo4j entity-relationship graph store (JSON file fallback)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import config
from shared.ir21_schema import RelationRecord
from shared.schema import EntityRecord


class GraphStore:
    """Entity graph: Neo4j when available, otherwise local JSON."""

    def __init__(self) -> None:
        self._driver = None
        self._backend = "json"
        self._json_path = Path(config.GRAPH_JSON_PATH)
        self._json_path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = {"entities": [], "relations": []}
        if self._json_path.exists():
            try:
                self._data = json.loads(self._json_path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {"entities": [], "relations": []}

        if config.NEO4J_URI:
            try:
                from neo4j import GraphDatabase
                self._driver = GraphDatabase.driver(
                    config.NEO4J_URI,
                    auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
                    connection_timeout=5.0,
                )
                self._driver.verify_connectivity()
                self._backend = "neo4j"
                self._init_neo4j()
            except Exception as exc:
                print(f"[graph_store] Neo4j unavailable ({exc}); using JSON fallback")
                if self._driver is not None:
                    try:
                        self._driver.close()
                    except Exception:
                        pass
                self._driver = None
                self._backend = "json"

    @property
    def backend(self) -> str:
        return self._backend

    def _init_neo4j(self) -> None:
        assert self._driver is not None
        with self._driver.session() as session:
            session.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE (e.key) IS UNIQUE")

    def clear_all(self) -> None:
        if self._backend == "neo4j" and self._driver is not None:
            with self._driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
            return
        self._data = {"entities": [], "relations": []}
        self._save_json()

    def delete_by_file_name(self, file_name: str) -> None:
        if self._backend == "neo4j" and self._driver is not None:
            with self._driver.session() as session:
                # Prefer file_name so shared legacy DOC_001 ids cannot wipe other docs
                session.run(
                    "MATCH (e:Entity {file_name: $f}) DETACH DELETE e",
                    f=file_name,
                )
            return
        self._data["entities"] = [e for e in self._data["entities"] if e.get("file_name") != file_name]
        self._data["relations"] = [r for r in self._data["relations"] if r.get("file_name") != file_name]
        self._save_json()

    def replace_document_graph(
        self,
        document_id: str,
        file_name: str,
        entities: list[EntityRecord],
        relations: list[RelationRecord],
    ) -> None:
        # Delete by file_name only (never wipe other documents via shared document_id)
        self.delete_by_file_name(file_name)
        if self._backend == "neo4j":
            self._write_neo4j(document_id, file_name, entities, relations)
        else:
            for e in entities:
                self._data["entities"].append(
                    {
                        **e.model_dump(),
                        "file_name": file_name,
                        "key": f"{e.type}:{e.entity}".lower(),
                    }
                )
            for r in relations:
                self._data["relations"].append(r.model_dump())
            self._save_json()

    def delete_document(self, document_id: str) -> None:
        if self._backend == "neo4j" and self._driver is not None:
            with self._driver.session() as session:
                session.run(
                    "MATCH (e:Entity {document_id: $d}) DETACH DELETE e",
                    d=document_id,
                )
                session.run(
                    "MATCH ()-[r:REL {document_id: $d}]->() DELETE r",
                    d=document_id,
                )
            return
        self._data["entities"] = [e for e in self._data["entities"] if e.get("document_id") != document_id]
        self._data["relations"] = [r for r in self._data["relations"] if r.get("document_id") != document_id]
        self._save_json()

    def query_neighborhood(
        self,
        query: str,
        file_name: Optional[str] = None,
        limit: int = 30,
    ) -> dict[str, Any]:
        tokens = [t for t in re_split_tokens(query) if len(t) >= 2]
        if self._backend == "neo4j" and self._driver is not None:
            return self._query_neo4j(tokens, file_name, limit)
        return self._query_json(tokens, file_name, limit)

    def graph_markdown(self, query: str, file_name: Optional[str] = None, limit: int = 30) -> str:
        data = self.query_neighborhood(query, file_name=file_name, limit=limit)
        if not data.get("relations") and not data.get("entities"):
            return ""
        lines = [f"### Entity relationship graph ({data.get('backend', self._backend)})"]
        for e in data.get("entities", [])[:15]:
            lines.append(f"- Entity **{e.get('entity')}** ({e.get('type')})")
        if data.get("relations"):
            lines.append("\n#### Relations")
            for r in data["relations"][:limit]:
                lines.append(
                    f"- ({r.get('subject_type')}) **{r.get('subject')}** "
                    f"-[{r.get('predicate')}]-> "
                    f"**{r.get('object')}** ({r.get('object_type')})"
                    + (f" [Sec {r['section_id']}]" if r.get("section_id") else "")
                )
        return "\n".join(lines)

    def _write_neo4j(
        self,
        document_id: str,
        file_name: str,
        entities: list[EntityRecord],
        relations: list[RelationRecord],
    ) -> None:
        assert self._driver is not None
        ent_rows = []
        seen_e: set[str] = set()
        for e in entities:
            key = f"{document_id}:{e.type}:{e.entity}".lower()
            if key in seen_e:
                continue
            seen_e.add(key)
            ent_rows.append(
                {
                    "key": key,
                    "entity": e.entity,
                    "type": e.type,
                    "document_id": document_id,
                    "file_name": file_name,
                    "section_id": e.section_id,
                    "page": e.page,
                    "source_text": (e.source_text or "")[:300],
                }
            )
        rel_rows = []
        seen_r: set[tuple[str, str, str]] = set()
        for r in relations:
            skey = f"{document_id}:{r.subject_type}:{r.subject}".lower()
            okey = f"{document_id}:{r.object_type}:{r.object}".lower()
            rk = (skey, r.predicate, okey)
            if rk in seen_r:
                continue
            seen_r.add(rk)
            rel_rows.append(
                {
                    "skey": skey,
                    "okey": okey,
                    "subject": r.subject,
                    "stype": r.subject_type,
                    "object": r.object,
                    "otype": r.object_type,
                    "predicate": r.predicate,
                    "document_id": document_id,
                    "file_name": file_name,
                    "section_id": r.section_id,
                    "page": r.page,
                    "confidence": r.confidence,
                }
            )

        with self._driver.session() as session:
            # Batch entities
            for i in range(0, len(ent_rows), 200):
                batch = ent_rows[i : i + 200]
                session.run(
                    """
                    UNWIND $rows AS row
                    MERGE (n:Entity {key: row.key})
                    SET n.entity=row.entity, n.type=row.type, n.document_id=row.document_id,
                        n.file_name=row.file_name, n.section_id=row.section_id, n.page=row.page,
                        n.source_text=row.source_text
                    """,
                    rows=batch,
                )
            for i in range(0, len(rel_rows), 200):
                batch = rel_rows[i : i + 200]
                session.run(
                    """
                    UNWIND $rows AS row
                    MERGE (s:Entity {key: row.skey})
                    ON CREATE SET s.entity=row.subject, s.type=row.stype,
                                  s.document_id=row.document_id, s.file_name=row.file_name
                    MERGE (o:Entity {key: row.okey})
                    ON CREATE SET o.entity=row.object, o.type=row.otype,
                                  o.document_id=row.document_id, o.file_name=row.file_name
                    MERGE (s)-[rel:REL {predicate: row.predicate, document_id: row.document_id}]->(o)
                    SET rel.section_id=row.section_id, rel.page=row.page, rel.confidence=row.confidence,
                        rel.file_name=row.file_name
                    """,
                    rows=batch,
                )

    def _query_neo4j(self, tokens: list[str], file_name: Optional[str], limit: int) -> dict[str, Any]:
        assert self._driver is not None
        entities: list[dict] = []
        relations: list[dict] = []
        with self._driver.session() as session:
            # Find seed entities
            cypher = """
            MATCH (e:Entity)
            WHERE ($file_name IS NULL OR e.file_name = $file_name)
              AND any(t IN $tokens WHERE toLower(e.entity) CONTAINS t OR toLower(e.type) CONTAINS t)
            RETURN e.entity AS entity, e.type AS type, e.file_name AS file_name,
                   e.section_id AS section_id, e.page AS page
            LIMIT $limit
            """
            result = session.run(cypher, tokens=tokens or [""], file_name=file_name, limit=limit)
            entities = [dict(r) for r in result]
            cypher_rel = """
            MATCH (s:Entity)-[r:REL]->(o:Entity)
            WHERE ($file_name IS NULL OR s.file_name = $file_name)
              AND (
                size($tokens)=0 OR
                any(t IN $tokens WHERE
                    toLower(s.entity) CONTAINS t OR toLower(o.entity) CONTAINS t
                    OR toLower(r.predicate) CONTAINS t OR toLower(s.type) CONTAINS t
                    OR toLower(o.type) CONTAINS t)
              )
            RETURN s.entity AS subject, s.type AS subject_type, r.predicate AS predicate,
                   o.entity AS object, o.type AS object_type, r.section_id AS section_id,
                   r.page AS page, s.file_name AS file_name
            LIMIT $limit
            """
            result = session.run(cypher_rel, tokens=tokens or [""], file_name=file_name, limit=limit)
            relations = [dict(r) for r in result]
        return {"entities": entities, "relations": relations, "backend": "neo4j"}

    def _query_json(self, tokens: list[str], file_name: Optional[str], limit: int) -> dict[str, Any]:
        ents = []
        for e in self._data.get("entities", []):
            if file_name and e.get("file_name") != file_name:
                continue
            blob = f"{e.get('entity','')} {e.get('type','')}".lower()
            if not tokens or any(t in blob for t in tokens):
                ents.append(e)
        rels = []
        for r in self._data.get("relations", []):
            if file_name and r.get("file_name") != file_name:
                continue
            blob = f"{r.get('subject','')} {r.get('object','')} {r.get('predicate','')} {r.get('subject_type','')} {r.get('object_type','')}".lower()
            if not tokens or any(t in blob for t in tokens):
                rels.append(r)
        return {"entities": ents[:limit], "relations": rels[:limit], "backend": "json"}

    def _save_json(self) -> None:
        self._json_path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")


def re_split_tokens(query: str) -> list[str]:
    import re
    return [t for t in re.split(r"\W+", (query or "").lower()) if t]


_graph: Optional[GraphStore] = None


def get_graph_store() -> GraphStore:
    global _graph
    if _graph is None:
        _graph = GraphStore()
    return _graph
