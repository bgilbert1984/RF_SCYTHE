# writebus.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Union
import hashlib
import json
import time
from datetime import datetime


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _safe_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))


def _stable_hash(obj: Any) -> str:
    return hashlib.sha256(_safe_json(obj).encode("utf-8")).hexdigest()


def _coalesce(*vals):
    for v in vals:
        if v is not None and v != "":
            return v
    return None


@dataclass
class Provenance:
    source: str = "manual_ui"        # e.g. "manual_ui", "lpi_detector_v1", "pcap_ingest"
    operator_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    model_version: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)  # hashes/paths/pcap ids
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WriteContext:
    """
    Context derived from request/session. Registries should accept ctx, not raw globals.
    """
    room_name: str = "Global"
    mission_id: Optional[str] = None
    team_id: Optional[str] = None
    operator: Any = None                  # optional operator object
    operator_id: Optional[str] = None     # string if no operator object
    session_token: Optional[str] = None
    request_id: Optional[str] = None
    source: str = "manual_ui"
    origin_host: Optional[str] = None
    model_version: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)

    def provenance(self) -> Provenance:
        op_id = _coalesce(self.operator_id, getattr(self.operator, "operator_id", None), getattr(self.operator, "callsign", None))
        ses_id = None
        if self.session_token:
            # do NOT store raw token; hash it
            ses_id = hashlib.sha256(self.session_token.encode("utf-8")).hexdigest()[:16]
        return Provenance(
            source=self.source,
            operator_id=op_id,
            session_id=ses_id,
            request_id=self.request_id,
            model_version=self.model_version,
            evidence_refs=list(self.evidence_refs),
        )


@dataclass
class GraphOp:
    """
    A canonical graph operation expressed as a GraphEvent-like dict.
    We favor apply_graph_event() because it centralizes behavior and sequence IDs.
    """
    event_type: str                      # NODE_UPDATE / NODE_CREATE / EDGE_CREATE / EDGE_UPDATE / NODE_DELETE / EDGE_DELETE
    entity_id: str
    entity_data: Dict[str, Any]


@dataclass
class WriteResult:
    ok: bool
    entity_id: str
    entity_type: str
    room_name: str
    persisted: bool
    graph_applied: bool
    errors: List[str] = field(default_factory=list)
    debug: Dict[str, Any] = field(default_factory=dict)


class WriteBus:
    """
    The only sanctioned writer that touches both persistence/broadcast AND the hypergraph.
    Everything else must call this.
    """

    def __init__(
        self,
        operator_manager: Any,
        hypergraph_engine: Any,
        *,
        default_room: str = "Global",
        graph_event_bus: Optional[Any] = None,   # optional pubsub bus
        strict_no_bypass: bool = False,
    ):
        self.operator_manager = operator_manager
        self.hypergraph = hypergraph_engine
        self.default_room = default_room
        self.graph_event_bus = graph_event_bus
        self.strict_no_bypass = strict_no_bypass

    # --- room helpers ---

    def _ensure_room_id(self, room_name: str, operator: Any = None) -> Optional[str]:
        if not self.operator_manager:
            return None
        try:
            room = self.operator_manager.get_room_by_name(room_name)
            if room:
                return getattr(room, "room_id", None) or room.get("room_id") or room.get("id")
        except Exception:
            pass

        # best-effort create
        try:
            created = self.operator_manager.create_room(room_name, description=f"Auto-created room: {room_name}", operator=operator)
            if created:
                return getattr(created, "room_id", None) or created.get("room_id") or created.get("id")
        except Exception:
            return None
        return None

    # --- provenance injection ---

    def _inject_provenance(self, payload: Dict[str, Any], prov: Provenance) -> Dict[str, Any]:
        payload = dict(payload or {})
        meta = dict(payload.get("meta") or payload.get("metadata") or {})
        meta["provenance"] = prov.to_dict()
        # keep both keys if your UI uses either
        payload["metadata"] = meta
        payload["meta"] = meta
        return payload

    # --- idempotency key ---

    def _idempotency_key(self, entity_id: str, entity_type: str, payload: Dict[str, Any], prov: Provenance) -> str:
        # stable across retries of the same write
        core = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "payload_hash": _stable_hash(payload),
            "request_id": prov.request_id,
            "source": prov.source,
        }
        return _stable_hash(core)[:24]

    # --- core commit ---

    def commit(
        self,
        *,
        entity_id: str,
        entity_type: str,
        entity_data: Dict[str, Any],
        graph_ops: List[GraphOp],
        ctx: WriteContext,
        persist: bool = True,
        audit: bool = True,
        idempotency_key: Optional[str] = None,
    ) -> WriteResult:
        """
        Commit a write atomically-ish across:
          (1) hypergraph apply_graph_event
          (2) operator_manager publish_to_room (SQLite + broadcast)
          (3) optional graph_event_bus publish for streaming clients
          (4) optional audit log (if your operator_manager provides it)

        The order is: graph -> room persistence -> bus publish.
        Rationale: hypergraph becomes canonical, room mirrors for collaboration/persistence.
        """
        errors: List[str] = []
        room_name = ctx.room_name or self.default_room
        prov = ctx.provenance()

        # inject provenance into durable entity payload
        entity_data = self._inject_provenance(entity_data, prov)

        # compute idempotency key (helpful for logs / future de-dupe)
        idem = idempotency_key or self._idempotency_key(entity_id, entity_type, entity_data, prov)

        # ---- (1) apply graph ops ----
        graph_applied = True
        for op in graph_ops:
            ge = {
                "event_type": op.event_type,
                "entity_id": op.entity_id,
                "entity_data": self._inject_provenance(op.entity_data, prov),
            }
            try:
                # Prefer apply_graph_event if present
                if hasattr(self.hypergraph, "apply_graph_event") and callable(getattr(self.hypergraph, "apply_graph_event")):
                    ok = self.hypergraph.apply_graph_event(ge)
                    if not ok:
                        graph_applied = False
                        errors.append(f"graph_op_failed:{op.event_type}:{op.entity_id}")
                else:
                    # fallback: minimal direct upsert (avoid here if possible)
                    graph_applied = False
                    errors.append("hypergraph_missing_apply_graph_event")
            except Exception as e:
                graph_applied = False
                errors.append(f"hypergraph_exception:{type(e).__name__}:{e}")

        # ---- (2) persist/broadcast to room ----
        persisted = False
        if persist and self.operator_manager:
            try:
                room_id = self._ensure_room_id(room_name, operator=ctx.operator)
                if room_id:
                    # publish_to_room signature varies; keep it conservative
                    self.operator_manager.publish_to_room(
                        room_id,
                        entity_id=entity_id,
                        entity_type=entity_type,
                        entity_data=entity_data,
                        operator=ctx.operator if ctx.operator is not None else ctx.operator_id,
                    )
                    persisted = True
                else:
                    errors.append(f"room_missing:{room_name}")
            except Exception as e:
                errors.append(f"publish_exception:{type(e).__name__}:{e}")

        # ---- (3) optional graph event bus publish ----
        # This is useful for real-time clients that subscribe to the bus
        if self.graph_event_bus:
            try:
                # publish the durable entity event (not each graph op)
                self.graph_event_bus.publish({
                    "event_type": "ENTITY_UPSERT",
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "entity_data": entity_data,
                    "room": room_name,
                    "idempotency_key": idem,
                    "timestamp": time.time(),
                })
            except Exception as e:
                errors.append(f"bus_publish_exception:{type(e).__name__}:{e}")

        # ---- (4) optional audit log ----
        if audit and self.operator_manager:
            try:
                # If you have an explicit API, use it. Otherwise this is a no-op skeleton.
                if hasattr(self.operator_manager, "audit_entity_event"):
                    self.operator_manager.audit_entity_event(
                        entity_id=entity_id,
                        entity_type=entity_type,
                        event_type="UPSERT",
                        operator_id=prov.operator_id,
                        timestamp=prov.timestamp,
                        new_data=entity_data,
                        idempotency_key=idem,
                    )
            except Exception:
                # audit must never break primary flow
                pass

        ok = (len(errors) == 0)
        return WriteResult(
            ok=ok,
            entity_id=entity_id,
            entity_type=entity_type,
            room_name=room_name,
            persisted=persisted,
            graph_applied=graph_applied,
            errors=errors,
            debug={"idempotency_key": idem, "provenance": prov.to_dict()},
        )


# ---------------------------
# Singleton convenience
# ---------------------------

_DEFAULT_BUS: Optional[WriteBus] = None


def init_writebus(
    operator_manager: Any,
    hypergraph_engine: Any,
    *,
    default_room: str = "Global",
    graph_event_bus: Optional[Any] = None,
    strict_no_bypass: bool = False,
) -> WriteBus:
    global _DEFAULT_BUS
    _DEFAULT_BUS = WriteBus(
        operator_manager=operator_manager,
        hypergraph_engine=hypergraph_engine,
        default_room=default_room,
        graph_event_bus=graph_event_bus,
        strict_no_bypass=strict_no_bypass,
    )
    return _DEFAULT_BUS


def bus() -> WriteBus:
    if _DEFAULT_BUS is None:
        raise RuntimeError("WriteBus not initialized. Call init_writebus(...) during server startup.")
    return _DEFAULT_BUS
