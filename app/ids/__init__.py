"""
Signaling Firewall IDS/IPS Module - Phase 1

Live packet inspection with CAT1/CAT2/CAT3 detection:
- CAT1: Immediate rule-based blocking (no contextual lookup)
- CAT2: Rule + IR.21 contextual validation  
- CAT3: Stateful subscriber/mobility analysis
"""

from app.ids.category_router import CategoryRouter
from app.ids.cat1_engine import CAT1Engine
from app.ids.cat2_engine import CAT2Engine
from app.ids.cat3_engine import CAT3Engine
from app.ids.decision import Decision, DecisionType
from app.ids.event_bus import EventBus, IDSEvent

__all__ = [
    "CategoryRouter",
    "CAT1Engine", 
    "CAT2Engine",
    "CAT3Engine",
    "Decision",
    "DecisionType",
    "EventBus",
    "IDSEvent",
]
