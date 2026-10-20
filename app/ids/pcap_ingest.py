"""Extract inspect-ready signaling events from PCAP / PCAPNG dumps.

Supports:
- SIGTRAN / SCTP / M3UA / TCAP / MAP opcode heuristics
- Diameter over SCTP (command code + Origin-Realm AVP)
- GTPv2-C message types over UDP/2123
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

MAP_OPCODE_NAMES: dict[int, str] = {
    2: "UpdateLocation",
    3: "CancelLocation",
    4: "ProvideRoamingNumber",
    5: "NoteSubscriberDataModified",
    6: "ResumeCallHandling",
    7: "InsertSubscriberData",
    8: "DeleteSubscriberData",
    9: "SendParameters",
    10: "RegisterSS",
    11: "EraseSS",
    12: "ActivateSS",
    13: "DeactivateSS",
    14: "InterrogateSS",
    22: "SendRoutingInfo",
    23: "UpdateGPRSLocation",
    44: "SendRoutingInfoForSM",
    45: "SendRoutingInfoForSM",
    46: "MO-ForwardSM",
    56: "SendAuthenticationInfo",
    58: "SendIMSI",
    67: "AnyTimeSubscriptionInterrogation",
    70: "ProvideSubscriberInfo",
    71: "AnyTimeInterrogation",
}

DIAMETER_CMD_NAMES: dict[int, str] = {
    257: "Capabilities-Exchange-Request",
    258: "Re-Auth-Request",
    271: "Accounting-Request",
    272: "Credit-Control-Request",
    280: "Device-Watchdog-Request",
    282: "Disconnect-Peer-Request",
    316: "Update-Location-Request",
    317: "Update-Location-Answer",
    318: "Authentication-Information-Request",
    319: "Authentication-Information-Answer",
    320: "Cancel-Location-Request",
    321: "Cancel-Location-Answer",
    322: "Insert-Subscriber-Data-Request",
    323: "Insert-Subscriber-Data-Answer",
    324: "Delete-Subscriber-Data-Request",
    325: "Delete-Subscriber-Data-Answer",
    329: "Purge-UE-Request",
    330: "Purge-UE-Answer",
}

GTP_MSG_NAMES: dict[int, str] = {
    1: "Echo-Request",
    2: "Echo-Response",
    32: "Create-Session-Request",
    33: "Create-Session-Response",
    34: "Modify-Bearer-Request",
    35: "Modify-Bearer-Response",
    36: "Delete-Session-Request",
    37: "Delete-Session-Response",
    64: "Downlink-Data-Notification",
    95: "Create-Bearer-Request",
    96: "Create-Bearer-Response",
    97: "Update-Bearer-Request",
    98: "Update-Bearer-Response",
    166: "Change-Notification-Request",
    170: "Release-Access-Bearers-Request",
    176: "Create-Indirect-Data-Forwarding-Tunnel-Request",
    177: "Create-Indirect-Data-Forwarding-Tunnel-Response",
}


def _sctp_payloads(pkt) -> list[bytes]:
    from scapy.layers.inet import IP  # noqa: F401
    from scapy.layers.sctp import SCTP, SCTPChunkData
    from scapy.packet import Raw

    out: list[bytes] = []
    if SCTP not in pkt:
        return out
    layer = pkt[SCTP]
    seen = 0
    while layer is not None and seen < 32:
        seen += 1
        if isinstance(layer, SCTPChunkData) or layer.__class__.__name__ == "SCTPChunkData":
            data = bytes(getattr(layer, "data", b"") or b"")
            if not data:
                try:
                    data = bytes(layer.payload)
                except Exception:
                    data = b""
            if data:
                out.append(data)
        nxt = getattr(layer, "payload", None)
        if nxt is None or nxt is layer:
            break
        layer = nxt
    if not out and Raw in pkt:
        out.append(bytes(pkt[Raw]))
    return out


def _find_map_opcodes(payload: bytes) -> list[int]:
    """Match Suricata-style TCAP invoke: a1 .. 02 01 <id> 02 01 <opcode>."""
    found: list[int] = []
    i = 0
    while i < len(payload) - 7:
        if payload[i] == 0xA1:
            window = payload[i : i + 24]
            for j in range(1, min(12, len(window) - 5)):
                if (
                    window[j] == 0x02
                    and window[j + 1] == 0x01
                    and j + 5 < len(window)
                    and window[j + 3] == 0x02
                    and window[j + 4] == 0x01
                ):
                    found.append(window[j + 5])
                    break
        i += 1
    return found


def _decode_sccp_gt(payload: bytes) -> str:
    """Best-effort GT digits from SCCP Called/Calling party address blobs."""
    # Look for SCCP address indicator near GT tags; fall back to BCD-ish runs.
    digits: list[str] = []
    for i in range(len(payload) - 4):
        # common pattern: 0x12 08 00 11 ... or 0x0b 12 08 ...
        if payload[i] in (0x12, 0x0B) and i + 3 < len(payload) and payload[i + 1] in (0x06, 0x07, 0x08, 0x09, 0x93):
            chunk = payload[i + 2 : i + 2 + 12]
            for b in chunk:
                lo = b & 0x0F
                hi = (b >> 4) & 0x0F
                if lo <= 9:
                    digits.append(str(lo))
                if hi <= 9:
                    digits.append(str(hi))
                elif hi == 0x0F:
                    break
            if len(digits) >= 6:
                return "".join(digits)[:18]
            digits = []
    return ""


def _find_diameter_msgs(payload: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    i = 0
    while i + 20 <= len(payload):
        if payload[i] != 0x01:
            i += 1
            continue
        length = int.from_bytes(payload[i + 1 : i + 4], "big")
        if not (20 <= length <= len(payload) - i) or length >= 8192:
            i += 1
            continue
        flags = payload[i + 4]
        cmd = int.from_bytes(payload[i + 5 : i + 8], "big")
        app = int.from_bytes(payload[i + 8 : i + 12], "big")
        if not (0 < cmd < 2000):
            i += 1
            continue
        body = payload[i : i + length]
        realm = _diameter_avp_string(body, 296)  # Origin-Realm
        host = _diameter_avp_string(body, 264)  # Origin-Host
        out.append(
            {
                "cmd": cmd,
                "app_id": app,
                "request": bool(flags & 0x80),
                "origin_realm": realm,
                "origin_host": host,
                "length": length,
            }
        )
        i += length
    return out


def _diameter_avp_string(msg: bytes, code: int) -> str:
    """Parse Diameter AVPs after the 20-byte header for a UTF-8/octet string."""
    pos = 20
    while pos + 8 <= len(msg):
        avp_code = int.from_bytes(msg[pos : pos + 4], "big")
        flags = msg[pos + 4]
        avp_len = int.from_bytes(msg[pos + 5 : pos + 8], "big")
        if avp_len < 8 or pos + avp_len > len(msg):
            break
        header = 8
        if flags & 0x80:  # Vendor-Specific
            if avp_len < 12:
                break
            header = 12
        if avp_code == code:
            raw = msg[pos + header : pos + avp_len]
            try:
                return raw.rstrip(b"\x00").decode("utf-8", errors="ignore")
            except Exception:
                return ""
        # AVPs padded to 4 bytes
        padded = (avp_len + 3) & ~3
        pos += padded
    return ""


def _find_gtpv2(payload: bytes) -> list[int]:
    if len(payload) < 8:
        return []
    # GTPv2 version sits in bits 8-6 of first octet
    version = (payload[0] >> 5) & 0x07
    if version != 2:
        return []
    return [payload[1]]


def extract_pcap_traffic(
    path: str | Path,
    *,
    max_events: int = 400,
    max_packets: int | None = None,
) -> dict[str, Any]:
    """Read a pcap/pcapng and return dump-shaped {rules:[], traffic:[...]}."""
    from scapy.all import UDP, conf, rdpcap
    from scapy.layers.inet import IP

    conf.verb = 0
    dest = Path(path)
    pkts = rdpcap(str(dest))
    if max_packets is not None:
        pkts = pkts[:max_packets]

    traffic: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    seen_keys: set[str] = set()

    for idx, pkt in enumerate(pkts):
        if len(traffic) >= max_events:
            break
        src = dst = ""
        if IP in pkt:
            src = str(pkt[IP].src)
            dst = str(pkt[IP].dst)

        # Diameter / MAP over SCTP
        for pl in _sctp_payloads(pkt):
            for opc in _find_map_opcodes(pl):
                name = MAP_OPCODE_NAMES.get(opc, f"MAP-opcode-{opc}")
                gt = _decode_sccp_gt(pl)
                key = f"map:{opc}:{gt}:{src}"
                stats["map"] += 1
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                expect: dict[str, Any] = {}
                # Known CAT1 prohibited ops — expect BLOCK when external
                if opc in (58, 71, 70, 45, 7, 8, 67):
                    expect = {"decision_in": ["BLOCK", "ESCALATE"]}
                traffic.append(
                    {
                        "id": f"{dest.stem}-map-{opc}-{len(traffic)+1}",
                        "kind": "inspect",
                        "source_file": dest.name,
                        "expect": expect,
                        "inspect": {
                            "protocol": "MAP",
                            "procedure": name,
                            "opcode": opc,
                            "direction": "INBOUND",
                            "calling_gt": gt or "999000000000",
                            "source": src,
                            "destination": dst,
                            "imsi": "410010000000001",
                        },
                    }
                )

            for dia in _find_diameter_msgs(pl):
                cmd = int(dia["cmd"])
                # Prefer requests; still keep a few answers for coverage
                if not dia["request"] and cmd not in (317, 319, 321, 323):
                    continue
                name = DIAMETER_CMD_NAMES.get(cmd, f"Diameter-cmd-{cmd}")
                realm = dia.get("origin_realm") or "unknown.operator.local"
                key = f"dia:{cmd}:{realm}:{src}"
                stats["diameter"] += 1
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                expect = {}
                if cmd in (316, 318, 320, 322, 324, 329) and realm:
                    expect = {"decision_in": ["BLOCK", "ESCALATE", "ALLOW"]}
                traffic.append(
                    {
                        "id": f"{dest.stem}-dia-{cmd}-{len(traffic)+1}",
                        "kind": "inspect",
                        "source_file": dest.name,
                        "expect": expect,
                        "inspect": {
                            "protocol": "Diameter",
                            "procedure": name,
                            "opcode": cmd,
                            "direction": "INBOUND",
                            "origin_realm": realm,
                            "origin_host": dia.get("origin_host") or "",
                            "source": src,
                            "destination": dst,
                            "imsi": "410040000000001",
                        },
                    }
                )

        # GTPv2-C
        if UDP in pkt and (pkt[UDP].sport == 2123 or pkt[UDP].dport == 2123):
            pl = bytes(pkt[UDP].payload)
            for msg in _find_gtpv2(pl):
                name = GTP_MSG_NAMES.get(msg, f"GTPv2-{msg}")
                key = f"gtp:{msg}:{src}"
                stats["gtp"] += 1
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                traffic.append(
                    {
                        "id": f"{dest.stem}-gtp-{msg}-{len(traffic)+1}",
                        "kind": "inspect",
                        "source_file": dest.name,
                        "expect": {},
                        "inspect": {
                            "protocol": "GTP-C",
                            "procedure": name,
                            "opcode": msg,
                            "direction": "INBOUND",
                            "source": src,
                            "destination": dst,
                            "source_gateway": src,
                            "imsi": "410010000000042",
                        },
                    }
                )

        if len(traffic) >= max_events:
            break

    return {
        "version": 1,
        "source": "pcap_ingest",
        "description": f"Extracted signaling events from {dest.name}",
        "pcap": str(dest),
        "packets": len(pkts),
        "stats": dict(stats),
        "rules": [],
        "traffic": traffic,
    }


def is_pcap_path(path: str | Path) -> bool:
    return Path(path).suffix.lower() in {".pcap", ".pcapng", ".cap"}
