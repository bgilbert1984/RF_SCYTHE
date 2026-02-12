# RF SCYTHE — Command Ops Visualization

**Version:** 1.3.0  
**Date:** 2026-02-11  
**Platform:** Linux (tested on Alma Linux 9 / WSL2)

## Overview

RF SCYTHE is a full-stack RF signal intelligence and network reconnaissance platform with a Cesium 3D globe interface. It combines real-time PCAP analysis, GeoIP enrichment, hypergraph-based entity tracking, and multi-operator collaboration into a single deployment.

### Key Capabilities

- **PCAP Ingestion** — Real parsing via Scapy/dpkt with GeoIP resolution (MaxMind GeoLite2)
- **Cesium 3D Globe** — Entity markers, flow arcs, satellite tracks, AIS vessel overlays
- **Hypergraph Engine** — In-memory graph with nodes, edges, spatial indexing, and event bus
- **Auto-Reconnaissance** — Automated entity discovery with disposition tracking
- **Multi-Operator Rooms** — SSE/WebSocket collaboration with SQLite-backed persistence
- **WriteBus Architecture** — Single chokepoint for all graph mutations ensuring consistency
- **Detection Registry** — Two-tier detection policy (Live Edge + Durable Summary)

## Quick Start

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**Core dependencies** (minimum for server startup):
```
Flask>=2.0.0
numpy>=1.21.0
scipy>=1.7.0
scapy>=2.5.0
dpkt>=1.9.0
maxminddb>=2.0.0
```

### 2. Start the Server

```bash
cd NerfEngine
python3 rf_scythe_api_server.py --host 0.0.0.0 --port 8080
```

### 3. Open the Console

Navigate to: `http://localhost:8080/command-ops-visualization.html`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  command-ops-visualization.html (Cesium 3D Globe UI)    │
│  ├── AutoReconVisualization   (entity markers/tracks)   │
│  ├── CesiumEntityManager     (safe position resolver)   │
│  ├── PcapGlobeOverlay        (PCAP hub rendering)       │
│  └── HypergraphModal         (graph visualization)      │
├─────────────────────────────────────────────────────────┤
│  rf_scythe_api_server.py (Flask API — port 8080)        │
│  ├── /api/recon/*        Recon entity CRUD + spatial    │
│  ├── /api/pcap/*         PCAP upload/ingest/subgraph    │
│  ├── /api/rf-hypergraph/*  Hypergraph query/diff        │
│  ├── /api/rooms/*        Room management + SSE          │
│  ├── /api/sensors/*      Sensor registry                │
│  ├── /api/nmap/*         Nmap scanning                  │
│  ├── /api/ndpi/*         Deep packet inspection         │
│  └── /api/ais/*          AIS vessel tracking            │
├─────────────────────────────────────────────────────────┤
│  WriteBus (writebus.py)                                 │
│  └── Single chokepoint: graph → room persist → publish  │
├─────────────────────────────────────────────────────────┤
│  HypergraphEngine (hypergraph_engine.py)                │
│  └── In-memory graph + spatial index + event bus        │
├─────────────────────────────────────────────────────────┤
│  Registries                                             │
│  ├── pcap_registry.py   (Scapy→dpkt→sim + GeoIP)       │
│  ├── detection_registry.py (two-tier policy)            │
│  └── recon_registry.py  (entity upsert helper)          │
├─────────────────────────────────────────────────────────┤
│  OperatorSessionManager (operator_session_manager.py)   │
│  └── SQLite-backed rooms, entities, SSE/WS streaming    │
└─────────────────────────────────────────────────────────┘
```

## File Manifest

### Core Server
| File | Description |
|------|-------------|
| `rf_scythe_api_server.py` | Main Flask server (all API routes) |
| `writebus.py` | WriteBus — canonical graph mutation chokepoint |
| `hypergraph_engine.py` | HypergraphEngine + RFHypergraphAdapter |
| `graph_event_bus.py` | Redis-backed graph event bus |
| `graph_query_dsl.py` | DSL parser for hypergraph queries |
| `subgraph_diff.py` | Subgraph diff generator |
| `operator_session_manager.py` | Multi-user session/room management |
| `poi_manager.py` | Point-of-interest CRUD |
| `sensor_registry.py` | Sensor upsert/assign/activity |
| `pcap_to_geo_hypergraph.py` | PCAP → GeoIP → Hypergraph pipeline |

### Registries (`registries/`)
| File | Description |
|------|-------------|
| `pcap_registry.py` | PCAP artifact/session management + GeoIP |
| `detection_registry.py` | Two-tier detection policy |
| `recon_registry.py` | Recon entity upsert helper |

### Frontend
| File | Description |
|------|-------------|
| `command-ops-visualization.html` | Main UI (Cesium globe + all panels) |
| `cesium-visualization.js` | Cesium globe initialization |
| `cesium-helpers.js` | Cesium utility functions |
| `cesium-patches.js` | Cesium monkey-patches |
| `cesium-error-handler.js` | Cesium error recovery |
| `cesium-ellipse-fix.js` | Ellipse rendering fix |
| `cesium-error-debugger.js` | Debug overlay for Cesium errors |
| `notification-system.js` | Toast notification system |
| `coordinate-validation.js` | Coordinate validation utilities |
| `coordinate-error-handler.js` | Coordinate error recovery |
| `ionosphere-visualization.js` | Ionosphere layer rendering |
| `ionosphere-data-enhancer.js` | Ionosphere data processing |
| `mock-api.js` | Mock API for offline/demo mode |
| `network-infrastructure.js` | Network topology visualization |
| `urh-integration.js` | Universal Radio Hacker integration |

### Stylesheets
| File | Description |
|------|-------------|
| `styles.css` | Main application styles |
| `network-visualization.css` | Network graph styles |
| `missile-operations.css` | Missile ops panel styles |
| `urh-integration.css` | URH panel styles |
| `assets/css/*.css` | Additional theme styles |

### Assets
| Directory | Description |
|-----------|-------------|
| `assets/GeoLite2-*.mmdb` | MaxMind GeoIP databases (City, ASN, Country) |
| `assets/artifacts/pcap/` | Stored PCAP capture files |
| `assets/cesium_models/` | 3D models (missiles, ships, aircraft) |
| `assets/stars/` | Skybox star map textures |
| `assets/missions/` | Mission templates and schemas |
| `assets/images/` | Logo and UI images |
| `fonts/` | Typeface files for 3D text |
| `models/` | ML models (signal LSTM, spectral CNN) |
| `config/` | API configuration |

## Database Files (Auto-Created)

These SQLite databases are created automatically on first run:

- `operator_sessions.db` — Operator accounts, sessions, rooms, entities
- `poi_database.db` — Points of interest

## External Dependencies (CDN)

The frontend loads these from CDN (no local install needed):

- **Cesium 1.108** — 3D globe rendering
- **Plotly 2.12.1** — Chart visualization
- **Socket.IO 4.5.4** — Real-time communication
- **Three.js 0.158.0** — 3D rendering helpers

## Environment Variables (Optional)

| Variable | Description |
|----------|-------------|
| `OP_SESSION_DB_PATH` | Custom path for operator_sessions.db |
| `OP_SESSION_REDIS_URL` | Redis URL for cross-process event fan-out |
| `CESIUM_ION_TOKEN` | Cesium Ion access token (for terrain/imagery) |

## API Quick Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/recon/entities` | GET | All tracked entities (RECON + PCAP_HOST + NMAP) |
| `/api/recon/entity` | POST | Create/update entity |
| `/api/pcap/sessions` | GET | List PCAP sessions |
| `/api/pcap/<id>/ingest` | POST | Ingest/re-ingest PCAP session |
| `/api/pcap/<id>/subgraph` | GET | Hypergraph subgraph for session |
| `/api/pcap/<id>/globe` | GET | Globe overlay data |
| `/api/rf-hypergraph/query` | POST | Hypergraph DSL query |
| `/api/rooms` | GET | List collaboration rooms |
| `/api/status` | GET | System health check |

## License

Proprietary — All rights reserved.
