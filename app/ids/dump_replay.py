"""Load a rules + live-traffic dump and replay it through IPS/IDS (Case 1)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.ids.rules_3g4g import (
    get_all_cat1_rules,
    get_all_cat2_rules,
    get_all_cat3_rules,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DUMP = ROOT / "data" / "dumps" / "signaling_live_dump.json"


def enrolled_rules() -> list[dict[str, Any]]:
    """Compact CAT1/2/3 rule dump used as the live signature pack."""
    out: list[dict[str, Any]] = []
    for rule in get_all_cat1_rules():
        out.append(_rule_row(rule, "CAT1"))
    for rule in get_all_cat2_rules():
        out.append(_rule_row(rule, "CAT2"))
    for rule in get_all_cat3_rules():
        out.append(_rule_row(rule, getattr(rule, "category", "CAT3") or "CAT3"))
    return out


def _rule_row(rule: Any, category: str) -> dict[str, Any]:
    return {
        "rule_id": getattr(rule, "rule_id", ""),
        "sid": int(getattr(rule, "sid", 0) or 0),
        "name": getattr(rule, "name", ""),
        "category": category,
        "protocol": getattr(rule, "protocol", ""),
        "action": getattr(rule, "action", "BLOCK" if category == "CAT1" else "VALIDATE"),
        "severity": getattr(rule, "severity", ""),
        "attack_pattern": getattr(rule, "attack_pattern", ""),
        "rule_text": getattr(rule, "rule_text", ""),
        "opcode": getattr(rule, "opcode", None),
        "command_code": getattr(rule, "command_code", None),
        "procedure": getattr(rule, "procedure", ""),
    }


def live_traffic() -> list[dict[str, Any]]:
    """Live signalling + Suricata EVE samples that exercise the enrolled rules."""
    return [
        {
            "id": "cat1-ati",
            "kind": "inspect",
            "expect": {"decision": "BLOCK", "category": "CAT1"},
            "inspect": {
                "protocol": "MAP",
                "procedure": "AnyTimeInterrogation",
                "opcode": 71,
                "direction": "INBOUND",
                "calling_gt": "882990012345678",
                "source": "10.0.0.1",
                "destination": "10.0.0.2",
                "imsi": "419050123456789",
            },
            "eve": {
                "event_type": "alert",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "protocol": "MAP",
                "opcode": 71,
                "calling_gt": "882990012345678",
                "imsi": "419050123456789",
                "alert": {
                    "signature": "Unauthorized AnyTimeInterrogation",
                    "signature_id": 1000002,
                    "category": "CAT1",
                    "severity": 1,
                },
            },
        },
        {
            "id": "cat2-unknown-realm",
            "kind": "inspect",
            "expect": {"decision": "BLOCK", "category": "CAT2"},
            "inspect": {
                "protocol": "Diameter",
                "procedure": "Update-Location-Request",
                "opcode": 316,
                "direction": "INBOUND",
                "origin_realm": "unknown.operator.com",
                "origin_host": "mme.unknown.operator.com",
                "imsi": "419050123456789",
                "serving_network": "999-99",
            },
        },
        {
            "id": "cat2-ss7-known-gt",
            "kind": "inspect",
            "expect": {"category_in": ["CAT2", "CAT3.1", "CAT3.2"]},
            "inspect": {
                "protocol": "MAP",
                "procedure": "UpdateLocation",
                "opcode": 2,
                "direction": "INBOUND",
                "calling_gt": "965961234567",
                "imsi": "419021234567890",
                "map_version": "MAPv3",
            },
        },
        {
            "id": "cat3-auth",
            "kind": "inspect",
            "expect": {"decision": "ALLOW"},
            "inspect": {
                "protocol": "Diameter",
                "procedure": "Authentication-Information-Request",
                "opcode": 318,
                "direction": "INBOUND",
                "origin_realm": "zain.com.kw",
                "origin_host": "mme1.zain.com.kw",
                "imsi": "419029998887776",
                "event_type": "auth",
                "timestamp": "2026-09-18T12:00:00",
            },
        },
        {
            "id": "cat3-kuwait",
            "kind": "inspect",
            "expect": {"decision_in": ["ALLOW", "ESCALATE"]},
            "inspect": {
                "protocol": "Diameter",
                "procedure": "Update-Location-Request",
                "opcode": 316,
                "direction": "INBOUND",
                "origin_realm": "zain.com.kw",
                "origin_host": "mme1.zain.com.kw",
                "imsi": "419029998887776",
                "latitude": 29.3759,
                "longitude": 47.9774,
                "event_type": "location",
                "timestamp": "2026-09-18T12:01:00",
            },
        },
        {
            "id": "cat3-london",
            "kind": "inspect",
            "expect": {"decision": "ESCALATE", "category": "CAT3.2"},
            "inspect": {
                "protocol": "Diameter",
                "procedure": "Update-Location-Request",
                "opcode": 316,
                "direction": "INBOUND",
                "origin_realm": "zain.com.kw",
                "origin_host": "mme1.zain.com.kw",
                "imsi": "419029998887776",
                "latitude": 51.5074,
                "longitude": -0.1278,
                "event_type": "location",
                "timestamp": "2026-09-18T12:04:00",
            },
        },
        {
            "id": "eve-ulr-sid-900002",
            "kind": "eve",
            "expect": {"blocked": True},
            "eve": {
                "timestamp": "2026-09-18T12:10:00.123456+0000",
                "event_type": "alert",
                "src_ip": "192.0.2.11",
                "src_port": 3868,
                "dest_ip": "10.0.0.5",
                "dest_port": 3868,
                "proto": "TCP",
                "app_proto": "diameter",
                "flow_id": 987654321,
                "imsi": "001010000000001",
                "alert": {
                    "action": "blocked",
                    "gid": 1,
                    "signature_id": 900002,
                    "rev": 1,
                    "signature": "TEL-DIA-CAT3.2-ULR-UNAUTHORIZED-CONTEXT",
                    "category": "policy-violation",
                    "severity": 1,
                },
            },
        },
        {
            "id": "eve-gtp-sid-900009",
            "kind": "eve",
            "expect": {},
            "eve": {
                "timestamp": "2026-09-18T12:11:00.000000+0000",
                "event_type": "alert",
                "src_ip": "10.20.30.40",
                "dest_ip": "10.0.0.12",
                "proto": "UDP",
                "app_proto": "gtp",
                "flow_id": 112233445,
                "imsi": "001010000000042",
                "teid": "0x00a1b2c3",
                "alert": {
                    "signature_id": 900009,
                    "signature": "TEL-GTP-CAT2-SESSION-NO-CONTEXT",
                    "category": "policy-violation",
                    "severity": 1,
                },
            },
        },
    ]


def build_dump() -> dict[str, Any]:
    return {
        "version": 1,
        "source": "signaling_firewall",
        "description": "Enrolled 3G/4G detection rules plus live interconnect traffic for Case 1 replay.",
        "rules": enrolled_rules(),
        "traffic": live_traffic(),
    }


def write_default_dump(path: Path | None = None) -> Path:
    dest = Path(path or DEFAULT_DUMP)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_dump(), indent=2) + "\n", encoding="utf-8")
    return dest


def load_dump(path: str | Path | None = None) -> dict[str, Any]:
    """Load a combined dump, Suricata EVE NDJSON, Suricata rules text, or PCAP."""
    dest = Path(path or DEFAULT_DUMP)
    if not dest.exists():
        if path is None:
            write_default_dump(dest)
        else:
            raise FileNotFoundError(str(dest))
    raw = dest.read_bytes()
    if raw[:2] == b"MZ":
        raise ValueError(
            f"{dest.name} is a Windows executable, not a rules/traffic dump. "
            "Use data/dumps/signaling_live_dump.json or a .pcap/.pcapng capture."
        )

    # Binary packet captures → structured inspect traffic for Case 1 replay
    suffix = dest.suffix.lower()
    if suffix in {".pcap", ".pcapng", ".cap"} or raw[:4] in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x0a\x0d\x0d\x0a",
    ):
        from app.ids.pcap_ingest import extract_pcap_traffic

        max_packets = 8000 if dest.stat().st_size > 5_000_000 else None
        max_events = 250 if max_packets else 400
        return extract_pcap_traffic(dest, max_events=max_events, max_packets=max_packets)

    text = raw.decode("utf-8", errors="replace").lstrip("\ufeff")
    if dest.suffix.lower() in {".rules", ".txt"} and "sid:" in text.lower():
        return {"version": 1, "rules": _parse_suricata_rules(text), "traffic": []}
    if dest.suffix.lower() in {".ndjson", ".eve"} or (
        "\n{" in text and '"event_type"' in text and not text.lstrip().startswith("{")
    ):
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            events.append({"id": f"eve-{len(events)+1}", "kind": "eve", "eve": json.loads(line), "expect": {}})
        return {"version": 1, "rules": [], "traffic": events}
    data = json.loads(text)
    if isinstance(data, list):
        return {"version": 1, "rules": [], "traffic": _normalize_traffic_list(data)}
    data.setdefault("rules", [])
    data.setdefault("traffic", [])
    return data


def build_captures_dump(
    dumps_dir: str | Path | None = None,
    *,
    include_live_json: bool = True,
) -> dict[str, Any]:
    """Merge PCAP extracts + optional Suricata rules + live JSON into one dump."""
    root = Path(dumps_dir or (ROOT / "data" / "dumps"))
    rules: list[dict[str, Any]] = list(enrolled_rules())
    traffic: list[dict[str, Any]] = []
    sources: list[str] = []

    rules_txt = root / "Full-updated-SS7.rules.txt"
    if rules_txt.exists():
        suri = _parse_suricata_rules(rules_txt.read_text(encoding="utf-8", errors="replace"))
        rules.extend(suri)
        sources.append(rules_txt.name)

    if include_live_json and DEFAULT_DUMP.exists():
        live = json.loads(DEFAULT_DUMP.read_text(encoding="utf-8"))
        traffic.extend(live.get("traffic") or [])
        sources.append(DEFAULT_DUMP.name)

    for pattern in ("*.pcap", "*.pcapng", "*.cap"):
        for pcap in sorted(root.glob(pattern)):
            extracted = load_dump(pcap)
            traffic.extend(extracted.get("traffic") or [])
            sources.append(pcap.name)

    return {
        "version": 1,
        "source": "signaling_firewall_captures",
        "description": "Merged live dump + PCAP extracts + SS7 Suricata rule pack for Case 1 block testing.",
        "sources": sources,
        "rules": rules,
        "traffic": traffic,
    }


def write_captures_dump(path: Path | None = None) -> Path:
    dest = Path(path or (ROOT / "data" / "dumps" / "captures_merged_dump.json"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_captures_dump(), indent=2) + "\n", encoding="utf-8")
    return dest


def _parse_suricata_rules(text: str) -> list[dict[str, Any]]:
    import re

    rules = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if not re.match(r"^(alert|drop|reject|pass)\s+", s, re.I):
            continue
        sid = ""
        m = re.search(r"sid\s*:\s*(\d+)", s, re.I)
        if m:
            sid = m.group(1)
        msg = ""
        mm = re.search(r'msg\s*:\s*"([^"]+)"', s, re.I)
        if mm:
            msg = mm.group(1)
        rules.append(
            {
                "rule_id": f"SID-{sid}" if sid else f"LINE-{len(rules)+1}",
                "sid": int(sid) if sid else 0,
                "name": msg or s[:80],
                "category": "tool",
                "rule_text": s,
            }
        )
    return rules


def _normalize_traffic_list(rows: list[Any]) -> list[dict[str, Any]]:
    out = []
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            continue
        if row.get("inspect") or row.get("eve"):
            row.setdefault("id", f"evt-{i}")
            out.append(row)
        elif row.get("event_type") == "alert" or row.get("alert"):
            out.append({"id": f"eve-{i}", "kind": "eve", "eve": row, "expect": {}})
        else:
            out.append({"id": f"inspect-{i}", "kind": "inspect", "inspect": row, "expect": {}})
    return out


def _expect_ok(got: dict[str, Any], expect: dict[str, Any]) -> tuple[bool, str]:
    if not expect:
        return True, "no expectation"
    if "decision" in expect and str(got.get("decision") or "").upper() != str(expect["decision"]).upper():
        return False, f"decision {got.get('decision')} != {expect['decision']}"
    if "decision_in" in expect:
        allowed = {str(x).upper() for x in expect["decision_in"]}
        if str(got.get("decision") or "").upper() not in allowed:
            return False, f"decision {got.get('decision')} not in {sorted(allowed)}"
    if "category" in expect and str(got.get("category") or "") != str(expect["category"]):
        return False, f"category {got.get('category')} != {expect['category']}"
    if "category_in" in expect:
        allowed = {str(x) for x in expect["category_in"]}
        if str(got.get("category") or "") not in allowed:
            return False, f"category {got.get('category')} not in {sorted(allowed)}"
    if "blocked" in expect and bool(got.get("blocked")) != bool(expect["blocked"]):
        return False, f"blocked {got.get('blocked')} != {expect['blocked']}"
    return True, "ok"


def replay_dump(
    dump: dict[str, Any] | None = None,
    *,
    path: str | Path | None = None,
    router: Any | None = None,
    publish: bool = True,
) -> dict[str, Any]:
    """Replay dump traffic through operator IDS + IPS parser.

    When publish=True (default), each event is pushed onto the IDS event bus so
    Live Traffic / Alerts / KPIs update — same path as /api/ids/inspect demos.
    """
    from datetime import datetime

    from app.agent.ips_agent import capture
    from app.agent.ips_ids_parser import parse_ips_ids_incident
    from app.ids.category_router import get_router
    from app.ids.decision import DecisionType
    from app.ids.event_bus import EventType, IDSEvent, get_event_bus

    payload = dump if dump is not None else load_dump(path)
    r = router or get_router()
    if hasattr(r, "start"):
        r.start()

    bus = get_event_bus() if publish else None
    results: list[dict[str, Any]] = []
    failed = 0
    published = 0

    for evt in payload.get("traffic") or []:
        expect = evt.get("expect") or {}
        got: dict[str, Any] = {"id": evt.get("id"), "kind": evt.get("kind")}
        inspect_payload = evt.get("inspect")
        eve = evt.get("eve")

        # IPS capture for Suricata EVE / raw wire samples
        if eve:
            try:
                cap = capture(dict(eve), protocol=str(eve.get("protocol") or eve.get("app_proto") or ""))
                got["ips_capture"] = {
                    "protocol": cap.get("protocol"),
                    "event_id": (cap.get("event") or {}).get("event_id")
                    or (cap.get("event") or {}).get("id"),
                }
            except Exception as exc:
                got["ips_capture_error"] = str(exc)
            bundle = parse_ips_ids_incident(
                dict(eve),
                protocol=str(eve.get("protocol") or eve.get("app_proto") or ""),
            )
            got["ips"] = {
                "blocked": bool(bundle.get("blocked")),
                "action": bundle.get("ids_action") or bundle.get("action"),
                "category": bundle.get("category"),
                "protocol": (bundle.get("capture") or {}).get("protocol"),
                "rules": len(bundle.get("detection_rules") or []),
            }
            if "blocked" in expect and "decision" not in got:
                got["blocked"] = bool(bundle.get("blocked"))

        # Operator IDS inspect (CAT1→CAT2→CAT3)
        if inspect_payload:
            inspection = r.inspect(dict(inspect_payload))
            final = inspection.final_decision
            decision = final.decision.value if hasattr(final.decision, "value") else str(final.decision)
            category = final.category.value if hasattr(final.category, "value") else str(final.category)
            got.update(
                {
                    "decision": decision,
                    "category": category,
                    "reason": final.reason,
                    "rule": (final.detection_rule or ""),
                    "sid": final.rule_sid,
                    "event_id": inspection.event_id,
                    "latency_ms": inspection.processing_time_ms,
                }
            )

            if bus is not None:
                msg = dict(inspect_payload)
                packet_event = bus.create_packet_event(
                    {
                        "event_id": inspection.event_id,
                        "protocol": msg.get("protocol") or "",
                        "procedure": msg.get("procedure") or "",
                        "source": msg.get("source") or msg.get("calling_gt") or msg.get("origin_realm") or "",
                        "destination": msg.get("destination") or "",
                        "global_title": msg.get("calling_gt") or "",
                        "origin_realm": msg.get("origin_realm") or "",
                        "subscriber_id_masked": final.subscriber_id_masked,
                        "category": category,
                        "decision": decision,
                        "rule_id": final.detection_rule or "",
                        "processing_latency_ms": inspection.processing_time_ms,
                        "confidence": getattr(final, "confidence", 1),
                        "dump_id": evt.get("id"),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
                bus.publish_sync(packet_event)
                decision_data = final.to_dict()
                bus.publish_sync(bus.create_decision_event(decision_data))
                if final.decision in (DecisionType.BLOCK, DecisionType.ESCALATE):
                    alert = bus.create_alert(decision_data)
                    bus.publish_sync(
                        IDSEvent(
                            event_id=alert.alert_id,
                            event_type=EventType.ALERT,
                            timestamp=datetime.utcnow(),
                            data=alert.to_dict(),
                            category=alert.category,
                            severity=alert.severity,
                        )
                    )
                published += 1

        elif eve and bus is not None:
            # EVE-only: still surface on Live Traffic from IPS capture + IDS parse
            alert_meta = eve.get("alert") if isinstance(eve.get("alert"), dict) else {}
            decision = "BLOCK" if got.get("ips", {}).get("blocked") or str(alert_meta.get("action") or "").lower() in (
                "blocked",
                "drop",
            ) else str(got.get("ips", {}).get("action") or "ALERT").upper()
            if decision in ("DROP", "BLOCKED"):
                decision = "BLOCK"
            category = str(got.get("ips", {}).get("category") or alert_meta.get("category") or "CAT2")
            if category.lower() in ("policy-violation", "attempted-admin"):
                category = "CAT2"
            eid = str(
                got.get("ips_capture", {}).get("event_id")
                or eve.get("flow_id")
                or evt.get("id")
                or ""
            )
            packet_event = bus.create_packet_event(
                {
                    "event_id": eid,
                    "protocol": str(eve.get("protocol") or eve.get("app_proto") or "").upper(),
                    "procedure": str(alert_meta.get("signature") or "Suricata alert"),
                    "source": eve.get("src_ip") or "",
                    "destination": eve.get("dest_ip") or "",
                    "subscriber_id_masked": eve.get("imsi") or "",
                    "category": category,
                    "decision": decision,
                    "rule_id": str(alert_meta.get("signature_id") or ""),
                    "dump_id": evt.get("id"),
                    "timestamp": eve.get("timestamp") or datetime.utcnow().isoformat(),
                }
            )
            bus.publish_sync(packet_event)
            if decision in ("BLOCK", "ESCALATE"):
                alert = bus.create_alert(
                    {
                        "event_id": eid,
                        "decision": decision,
                        "category": category,
                        "reason": alert_meta.get("signature") or "Dump EVE alert",
                        "detection_rule": str(alert_meta.get("signature_id") or ""),
                        "attack_pattern": "",
                        "subscriber_id_masked": eve.get("imsi") or "",
                        "severity": "high" if decision == "BLOCK" else "medium",
                    }
                )
                bus.publish_sync(
                    IDSEvent(
                        event_id=alert.alert_id,
                        event_type=EventType.ALERT,
                        timestamp=datetime.utcnow(),
                        data=alert.to_dict(),
                        category=alert.category,
                        severity=alert.severity,
                    )
                )
            got.setdefault("decision", decision)
            got.setdefault("category", category)
            published += 1

        ok, detail = _expect_ok(got, expect)
        got["ok"] = ok
        got["detail"] = detail
        if not ok:
            failed += 1
        results.append(got)

    if bus is not None and hasattr(r, "get_metrics"):
        try:
            bus.publish_sync(bus.create_metric_event(r.get_metrics()))
        except Exception:
            pass

    return {
        "dump": str(path or DEFAULT_DUMP),
        "rules": len(payload.get("rules") or []),
        "traffic": len(payload.get("traffic") or []),
        "passed": len(results) - failed,
        "failed": failed,
        "published": published,
        "results": results,
        "ok": failed == 0 and bool(results),
    }
