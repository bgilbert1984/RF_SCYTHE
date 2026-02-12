from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, Any, Set, List, Optional, Iterable, Tuple, Callable
import time
import threading
import math
import json
import os
from types import SimpleNamespace
from contextlib import contextmanager


@dataclass
class HGNode:
    id: str
    kind: str
    position: Optional[List[float]] = None
    frequency: Optional[float] = None
    labels: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    created_at: float = None
    updated_at: float = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HGEdge:
    id: str
    kind: str
    nodes: List[str]
    weight: float = 1.0
    labels: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    timestamp: float = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HypergraphEngine:
    """Clarktech HypergraphEngine with simple GraphEvent emission."""

    def __init__(self, freq_step_mhz: float = 10.0):
        # core stores
        self.nodes: Dict[str, HGNode] = {}
        self.edges: Dict[str, HGEdge] = {}

        # indices
        self.node_to_edges: Dict[str, Set[str]] = defaultdict(set)
        self.kind_index: Dict[str, Set[str]] = defaultdict(set)
        self.edge_kind_index: Dict[str, Set[str]] = defaultdict(set)
        self.label_index: Dict[str, Dict[Any, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self.freq_buckets: Dict[str, Set[str]] = defaultdict(set)
        self.degree: Dict[str, int] = defaultdict(int)

        # spatial helpers
        self._positions: Dict[str, Tuple[float, float, float]] = {}
        self._spatial_dirty = False
        self._spatial_index = None

        # concurrency
        self._lock = threading.RLock()

        # eventing
        self.subscribers: List[Callable] = []
        self.sequence: int = 0
        self.event_bus = None  # optional external GraphEventBus
        self._emitting = False  # re-entrancy guard for _emit

        # config
        self.freq_step_mhz = float(freq_step_mhz)

    @contextmanager
    def _suppress_emit(self):
        prev = self._emitting
        self._emitting = True
        try:
            yield
        finally:
            self._emitting = prev

    def _normalize_node_data(self, d: dict, fallback_id: Optional[str] = None) -> dict:
        src = dict(d or {})
        # extract core fields
        nid = src.get('id') or src.get('node_id') or fallback_id
        kind = src.get('kind') or src.get('type') or 'entity'
        pos = src.get('position')
        freq = src.get('frequency')
        labels = src.get('labels') or {}
        meta = src.get('metadata') or {}
        
        # move everything else into metadata (avoid HGNode strict init errors)
        known_keys = {'id', 'node_id', 'kind', 'type', 'position', 'frequency', 'labels', 'metadata', 'created_at', 'updated_at'}
        for k, v in src.items():
            if k not in known_keys:
                meta[k] = v

        return {
            'id': nid,
            'kind': kind,
            'position': pos,
            'frequency': freq,
            'labels': labels,
            'metadata': meta,
            'created_at': src.get('created_at'),
            'updated_at': src.get('updated_at')
        }

    def _normalize_edge_data(self, d: dict, fallback_id: Optional[str] = None) -> dict:
        src = dict(d or {})
        # defaults
        eid_val = src.get('id') or fallback_id
        kind = src.get('kind') or src.get('type') or 'edge'
        nodes = src.get('nodes') or []
        weight = src.get('weight', 1.0)
        labels = src.get('labels') or {}
        meta = src.get('metadata') or {}
        timestamp = src.get('timestamp') or time.time()
        
        # move extra keys to metadata
        known_keys = {'id', 'kind', 'type', 'nodes', 'weight', 'labels', 'metadata', 'timestamp'}
        for k, v in src.items():
            if k not in known_keys:
                meta[k] = v

        return {
            'id': eid_val,
            'kind': kind,
            'nodes': nodes,
            'weight': weight,
            'labels': labels,
            'metadata': meta,
            'timestamp': timestamp
        }

    # ---------- Node ops ----------
    def add_node(self, node: Any) -> str:
        with self._lock:
            now = time.time()
            if not isinstance(node, HGNode):
                # use consistent normalization
                data = self._normalize_node_data(node)
                node = HGNode(**data)
            node.created_at = node.created_at or now
            node.updated_at = now
            self.nodes[node.id] = node

            self.kind_index[node.kind].add(node.id)

            if node.labels:
                for k, v in node.labels.items():
                    if isinstance(v, (list, tuple, set)):
                        for it in v:
                            self.label_index[k][it].add(node.id)
                    else:
                        self.label_index[k][v].add(node.id)

            if node.frequency is not None:
                band = self._freq_band(node.frequency, step=self.freq_step_mhz)
                self.freq_buckets[band].add(node.id)

            if node.position:
                self._positions[node.id] = tuple(node.position[:3]) if len(node.position) >= 2 else tuple(node.position)
                self._spatial_dirty = True

            self.degree.setdefault(node.id, 0)

            # emit event
            try:
                self.sequence += 1
                ge = {
                    'event_type': 'NODE_CREATE',
                    'entity_id': node.id,
                    'entity_kind': node.kind,
                    'entity_data': node.to_dict(),
                    'timestamp': time.time(),
                    'sequence_id': self.sequence
                }
                self._emit(ge)
            except Exception:
                pass

            return node.id

    def update_node(self, node_id: str, **updates) -> Optional[HGNode]:
        with self._lock:
            node = self.nodes.get(node_id)
            if not node:
                return None

            # remove old indices
            old_labels = node.labels or {}
            old_freq = node.frequency
            for k, v in old_labels.items():
                if isinstance(v, (list, tuple, set)):
                    for it in v:
                        self.label_index[k][it].discard(node_id)
                else:
                    self.label_index[k][v].discard(node_id)
            if old_freq is not None:
                self.freq_buckets[self._freq_band(old_freq, step=self.freq_step_mhz)].discard(node_id)

            # apply updates
            for k, v in updates.items():
                setattr(node, k, v)
            node.updated_at = time.time()

            # reindex
            if node.labels:
                for k, v in node.labels.items():
                    if isinstance(v, (list, tuple, set)):
                        for it in v:
                            self.label_index[k][it].add(node_id)
                    else:
                        self.label_index[k][v].add(node_id)
            if node.frequency is not None:
                self.freq_buckets[self._freq_band(node.frequency, step=self.freq_step_mhz)].add(node_id)
            if node.position:
                self._positions[node.id] = tuple(node.position[:3]) if len(node.position) >= 2 else tuple(node.position)
                self._spatial_dirty = True

            try:
                self.sequence += 1
                ge = {
                    'event_type': 'NODE_UPDATE',
                    'entity_id': node_id,
                    'entity_kind': node.kind,
                    'entity_data': node.to_dict(),
                    'timestamp': time.time(),
                    'sequence_id': self.sequence
                }
                self._emit(ge)
            except Exception:
                pass

            return node

    def get_node(self, node_id: str) -> Optional[HGNode]:
        return self.nodes.get(node_id)

    def remove_node(self, node_id: str) -> None:
        with self._lock:
            node = self.nodes.pop(node_id, None)
            if not node:
                return
            self.kind_index[node.kind].discard(node_id)
            if node.labels:
                for k, v in node.labels.items():
                    if isinstance(v, (list, tuple, set)):
                        for it in v:
                            self.label_index[k][it].discard(node_id)
                    else:
                        self.label_index[k][v].discard(node_id)
            if node.frequency is not None:
                self.freq_buckets[self._freq_band(node.frequency, step=self.freq_step_mhz)].discard(node_id)
            self._positions.pop(node_id, None)
            self._spatial_dirty = True
            # remove edges touching this node
            for eid in list(self.node_to_edges.get(node_id, [])):
                self.remove_edge(eid)
            self.node_to_edges.pop(node_id, None)
            self.degree.pop(node_id, None)

            try:
                self.sequence += 1
                ge = {
                    'event_type': 'NODE_DELETE',
                    'entity_id': node_id,
                    'entity_kind': node.kind,
                    'entity_data': {'id': node_id},
                    'timestamp': time.time(),
                    'sequence_id': self.sequence
                }
                self._emit(ge)
            except Exception:
                pass

    # ---------- Edge ops ----------
    def add_edge(self, edge: Any) -> str:
        with self._lock:
            if not isinstance(edge, HGEdge):
                # use consistent normalization
                data = self._normalize_edge_data(edge)
                edge = HGEdge(**data)
            edge.timestamp = edge.timestamp or time.time()
            self.edges[edge.id] = edge
            self.edge_kind_index[edge.kind].add(edge.id)
            for nid in edge.nodes:
                self.node_to_edges[nid].add(edge.id)
                self.degree[nid] = self.degree.get(nid, 0) + 1

            try:
                self.sequence += 1
                ge = {
                    'event_type': 'EDGE_CREATE',
                    'entity_id': edge.id,
                    'entity_kind': edge.kind,
                    'entity_data': edge.to_dict(),
                    'timestamp': time.time(),
                    'sequence_id': self.sequence
                }
                self._emit(ge)
            except Exception:
                pass

            return edge.id

    def remove_edge(self, edge_id: str) -> None:
        with self._lock:
            edge = self.edges.pop(edge_id, None)
            if not edge:
                return
            self.edge_kind_index[edge.kind].discard(edge_id)
            for nid in edge.nodes:
                self.node_to_edges[nid].discard(edge_id)
                self.degree[nid] = max(0, self.degree.get(nid, 1) - 1)

            try:
                self.sequence += 1
                ge = {
                    'event_type': 'EDGE_DELETE',
                    'entity_id': edge_id,
                    'entity_kind': edge.kind,
                    'entity_data': {'id': edge_id},
                    'timestamp': time.time(),
                    'sequence_id': self.sequence
                }
                self._emit(ge)
            except Exception:
                pass

    def get_edge(self, edge_id: str) -> Optional[HGEdge]:
        return self.edges.get(edge_id)

    # ---------- Queries ----------
    def nodes_by_kind(self, kind: str) -> Iterable[HGNode]:
        for nid in self.kind_index.get(kind, []):
            n = self.nodes.get(nid)
            if n:
                yield n

    def nodes_with_label(self, key: str, value: Any) -> Iterable[HGNode]:
        for nid in self.label_index.get(key, {}).get(value, []):
            n = self.nodes.get(nid)
            if n:
                yield n

    def nodes_in_freq_band(self, fmin: float, fmax: float) -> Iterable[HGNode]:
        bands = self._bands_between(fmin, fmax, step=self.freq_step_mhz)
        seen: Set[str] = set()
        for b in bands:
            for nid in self.freq_buckets.get(b, []):
                if nid in seen:
                    continue
                node = self.nodes.get(nid)
                if node and node.frequency is not None and fmin <= node.frequency <= fmax:
                    seen.add(nid)
                    yield node

    def edges_for_node(self, node_id: str) -> Iterable[HGEdge]:
        for eid in self.node_to_edges.get(node_id, []):
            e = self.edges.get(eid)
            if e:
                yield e

    def top_central_nodes(self, k: int = 5):
        with self._lock:
            return sorted(self.degree.items(), key=lambda x: x[1], reverse=True)[:k]

    # ---------- Spatial (simple) ----------
    def rebuild_spatial_index(self):
        with self._lock:
            self._spatial_index = None
            self._spatial_dirty = False

    def nodes_in_bbox(self, min_lat: float, max_lat: float, min_lon: float, max_lon: float) -> Iterable[HGNode]:
        for nid, pos in self._positions.items():
            lat, lon, *_ = pos
            if min_lat <= lat <= max_lat and min_lon <= lon <= max_lon:
                n = self.nodes.get(nid)
                if n:
                    yield n

    # ---------- Snapshot / persistence ----------
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'nodes': [n.to_dict() for n in self.nodes.values()],
                'edges': [e.to_dict() for e in self.edges.values()],
                'ts': time.time()
            }

    def save_snapshot(self, path: str) -> None:
        try:
            dump = self.snapshot()
            tmp = f"{path}.tmp"
            ddir = os.path.dirname(path) or '.'
            if not os.path.exists(ddir):
                try:
                    os.makedirs(ddir, exist_ok=True)
                except Exception:
                    pass
            with open(tmp, 'w') as f:
                json.dump(dump, f)
            os.replace(tmp, path)
        except Exception:
            return

    def load_snapshot(self, path: str) -> bool:
        try:
            if not os.path.exists(path):
                return False
            with open(path, 'r') as f:
                dump = json.load(f)
            nodes = dump.get('nodes', [])
            edges = dump.get('edges', [])
            with self._lock:
                # clear current
                self.nodes.clear()
                self.edges.clear()
                self.node_to_edges.clear()
                self.kind_index.clear()
                self.edge_kind_index.clear()
                self.label_index.clear()
                self.freq_buckets.clear()
                self.degree.clear()
                self._positions.clear()

                for n in nodes:
                    try:
                        self.add_node(n)
                    except Exception:
                        continue
                for e in edges:
                    try:
                        self.add_edge(e)
                    except Exception:
                        continue
            return True
        except Exception:
            return False

    # ---------- Eventing ----------
    def subscribe(self, callback: Callable) -> None:
        with self._lock:
            self.subscribers.append(callback)

    def _emit(self, ge: Dict[str, Any]) -> None:
        # Re-entrancy guard: prevent infinite loops when apply_graph_event
        # triggers further add_node/update_node calls that would re-emit.
        if self._emitting:
            return
        self._emitting = True
        try:
            # local subscribers
            for cb in list(self.subscribers):
                try:
                    cb(ge)
                except Exception:
                    continue

            # external event bus (if attached)
            eb = getattr(self, 'event_bus', None)
            if eb and hasattr(eb, 'publish'):
                try:
                    eb.publish(SimpleNamespace(**ge))
                except Exception:
                    try:
                        eb.publish(ge)
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            self._emitting = False

    def apply_graph_event(self, ge) -> bool:
        """Apply a GraphEvent (dict or object) to this HypergraphEngine (best-effort)."""
        # (3) Event replay suppression to prevent "echo"
        with self._suppress_emit():
            try:
                if ge is None:
                    return False
                if isinstance(ge, dict):
                    et = ge.get('event_type')
                    eid = ge.get('entity_id')
                    data = ge.get('entity_data') or {}
                else:
                    et = getattr(ge, 'event_type', None)
                    eid = getattr(ge, 'entity_id', None)
                    data = getattr(ge, 'entity_data', None) or {}

                if not et:
                    return False

                if et == 'NODE_CREATE':
                    nd = self._normalize_node_data(data, fallback_id=eid)
                    nid = nd.get('id')
                    if not nid:
                        return False
                    
                    if self.get_node(nid):
                        # (1) Partial update safety: only patch keys present in source
                        src = data if isinstance(data, dict) else {}
                        patch = {}
                        if 'position' in src: patch['position'] = nd['position']
                        if 'frequency' in src: patch['frequency'] = nd['frequency']
                        if 'labels' in src: patch['labels'] = nd['labels']
                        
                        # Handle metadata + implicit extra fields
                        known_keys = {'id', 'node_id', 'kind', 'type', 'position', 'frequency', 'labels', 'metadata', 'created_at', 'updated_at'}
                        has_implicit = any(k not in known_keys for k in src)
                        if 'metadata' in src or has_implicit:
                            patch['metadata'] = nd['metadata']
                            
                        self.update_node(nid, **patch)
                    else:
                        nd.setdefault('id', nid)
                        nd.setdefault('kind', 'entity')
                        self.add_node(nd)
                    return True

                if et == 'NODE_UPDATE':
                    nd = self._normalize_node_data(data, fallback_id=eid)
                    nid = nd.get('id')
                    if not nid:
                        return False
                    
                    # Use upsert logic (create if missing, update if present)
                    if self.get_node(nid):
                        # (1) Partial update safety: only patch keys present in source
                        src = data if isinstance(data, dict) else {}
                        patch = {}
                        if 'position' in src: patch['position'] = nd['position']
                        if 'frequency' in src: patch['frequency'] = nd['frequency']
                        if 'labels' in src: patch['labels'] = nd['labels']
                        
                        # Handle metadata + implicit extra fields
                        known_keys = {'id', 'node_id', 'kind', 'type', 'position', 'frequency', 'labels', 'metadata', 'created_at', 'updated_at'}
                        has_implicit = any(k not in known_keys for k in src)
                        if 'metadata' in src or has_implicit:
                            patch['metadata'] = nd['metadata']
                            
                        self.update_node(nid, **patch)
                    else:
                        nd.setdefault('id', nid)
                        nd.setdefault('kind', 'entity')
                        self.add_node(nd)
                    return True

                if et == 'NODE_DELETE':
                    if eid:
                        self.remove_node(eid)
                        return True
                    return False

                if et in ('EDGE_CREATE', 'HYPEREDGE_CREATE', 'EDGE_UPDATE'):
                    ed = self._normalize_edge_data(data, fallback_id=eid)
                    edge_id = ed.get('id') or eid
                    if not edge_id:
                        return False
                    try:
                        if self.get_edge(edge_id):
                            self.remove_edge(edge_id)
                    except Exception:
                        pass
                    self.add_edge(ed)
                    return True

                if et in ('EDGE_DELETE', 'HYPEREDGE_DELETE'):
                    if eid:
                        self.remove_edge(eid)
                        return True
                    return False

                return False
            except Exception:
                return False

class RFHypergraphAdapter:
    """Adapter mapping RF-style dicts into HGNode/HGEdge calls."""
    def __init__(self, engine: HypergraphEngine):
        self.engine = engine

    def add_node_from_rf(self, node_data: Dict[str, Any]) -> str:
        nid = node_data.get('node_id') or f"rf_{int(time.time()*1000)}"
        node = {
            'id': nid,
            'kind': 'rf',
            'position': node_data.get('position'),
            'frequency': node_data.get('frequency'),
            'labels': node_data.get('labels', {}),
            'metadata': node_data.get('metadata', {})
        }
        return self.engine.add_node(node)

    def add_edge_from_rf(self, edge_data: Dict[str, Any]) -> str:
        eid = edge_data.get('id') or f"edge_{int(time.time()*1000)}"
        edge = {
            'id': eid,
            'kind': edge_data.get('type', 'rf_coherence'),
            'nodes': edge_data.get('nodes', []),
            'weight': float(edge_data.get('signal_strength', 0.0)),
            'labels': edge_data.get('labels', {}),
            'metadata': edge_data.get('metadata', {}),
            'timestamp': edge_data.get('timestamp', time.time())
        }
        return self.engine.add_edge(edge)


__all__ = ['HypergraphEngine', 'HGNode', 'HGEdge', 'RFHypergraphAdapter']
