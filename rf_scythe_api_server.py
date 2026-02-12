#!/usr/bin/env python3
"""
RF SCYTHE Integrated API Server

A comprehensive Flask-based server providing:
- RF Hypergraph visualization and metrics APIs
- Nmap network scanning integration
- NDPI deep packet inspection integration
- Static file serving for the command-ops-visualization.html

For Alma Linux 9 / RHEL-based systems
"""

import os
import sys
import json
import time
import random
import subprocess
import threading
import logging
import math
import numpy as np
from functools import wraps
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timezone
from collections import defaultdict, deque
from types import SimpleNamespace
import urllib.request
import urllib.error
import ssl

# Try to import scipy for spatial indexing
try:
    from scipy.spatial import cKDTree
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logger_temp = logging.getLogger(__name__)
    logger_temp.warning("scipy not available - spatial indexing disabled. Install with: pip install scipy")

# Try to import sklearn for advanced spatial queries
try:
    from sklearn.neighbors import BallTree
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Check for Flask availability
try:
    from flask import Flask, request, jsonify, send_from_directory, Response
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Flask not installed. Install with: pip install flask flask-cors")

# Check for Flask-SocketIO availability
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    print("Flask-SocketIO not installed. WebSocket support disabled. Install with: pip install flask-socketio")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('rf_scythe_server')

# ============================================================================
# RF SCYTHE REGISTRIES (Globals)
# ============================================================================
detection_registry = None  # Populated at startup
pcap_registry_instance = None 
sensor_registry_instance = None
writebus_instance = None

# ============================================================================
# RF HYPERGRAPH DATA STORAGE
# ============================================================================

class RFHypergraphStore:
    """In-memory storage for RF hypergraph data"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset all data"""
        self.session_id = f"session_{int(time.time())}"
        self.nodes = {}
        self.hyperedges = []
        self.start_time = time.time()
        logger.info(f"Hypergraph session reset: {self.session_id}")
    
    def add_node(self, node_data: Dict[str, Any]) -> str:
        """Add an RF node"""
        node_id = node_data.get('node_id') or f"rf_node_{len(self.nodes)}_{int(time.time()*1000)}"
        self.nodes[node_id] = {
            'node_id': node_id,
            'position': node_data.get('position', [0, 0, 0]),
            'frequency': node_data.get('frequency', 0),
            'power': node_data.get('power', -80),
            'modulation': node_data.get('modulation', 'Unknown'),
            'timestamp': time.time(),
            'metadata': node_data.get('metadata', {})
        }
        # publish node create event
        try:
            self._maybe_publish_node_create(node_id, self.nodes[node_id])
        except Exception:
            pass
        # mirror into attached HypergraphEngine (unified node model)
        try:
            engine = getattr(self, 'hypergraph_engine', None)
            if engine:
                eng_node = {
                    'id': node_id,
                    'kind': 'rf',
                    'position': self.nodes[node_id].get('position'),
                    'frequency': self.nodes[node_id].get('frequency'),
                    'labels': {},
                    'metadata': self.nodes[node_id].get('metadata', {})
                }
                engine.add_node(eng_node)
        except Exception:
            pass
        # Mirror into unified HypergraphEngine via adapter if available
        try:
            adapter = getattr(self, 'rf_adapter', None)
            if adapter:
                adapter.add_node_from_rf(self.nodes[node_id])
            else:
                engine = getattr(self, 'hypergraph_engine', None)
                if engine:
                    eng_node = {
                        'id': node_id,
                        'kind': 'rf',
                        'position': self.nodes[node_id].get('position'),
                        'frequency': self.nodes[node_id].get('frequency'),
                        'labels': {},
                        'metadata': self.nodes[node_id].get('metadata', {})
                    }
                    try:
                        engine.add_node(eng_node)
                    except Exception:
                        pass
        except Exception:
            pass

        return node_id

    def _maybe_publish_node_create(self, node_id: str, node_record: Dict[str, Any]):
        if getattr(self, 'event_bus', None):
            try:
                ev = SimpleNamespace(
                    event_type='NODE_CREATE',
                    entity_id=node_id,
                    entity_kind='rf_node',
                    entity_data=node_record
                )
                self.event_bus.publish(ev)
            except Exception:
                pass
    
    def add_hyperedge(self, edge_data: Dict[str, Any]) -> int:
        """Add a hyperedge"""
        edge = {
            'nodes': edge_data.get('nodes', []),
            'cardinality': len(edge_data.get('nodes', [])),
            'signal_strength': edge_data.get('signal_strength', -70),
            'timestamp': time.time(),
            'metadata': edge_data.get('metadata', {})
        }
        self.hyperedges.append(edge)
        # publish hyperedge create
        try:
            if getattr(self, 'event_bus', None):
                ev = SimpleNamespace(
                    event_type='HYPEREDGE_CREATE',
                    entity_id=str(len(self.hyperedges)-1),
                    entity_kind='hyperedge',
                    entity_data=edge
                )
                self.event_bus.publish(ev)
        except Exception:
            pass
        # mirror into unified HypergraphEngine via adapter if available
        try:
            adapter = getattr(self, 'rf_adapter', None)
            if adapter:
                adapter.add_edge_from_rf(edge)
            else:
                engine = getattr(self, 'hypergraph_engine', None)
                if engine:
                    eng_edge = {
                        'id': str(len(self.hyperedges)-1),
                        'kind': edge.get('type') or 'rf_coherence',
                        'nodes': edge.get('nodes', []),
                        'weight': float(edge.get('signal_strength', 0.0)),
                        'labels': {},
                        'metadata': edge.get('metadata', {}),
                        'timestamp': edge.get('timestamp', time.time())
                    }
                    try:
                        engine.add_edge(eng_edge)
                    except Exception:
                        pass
        except Exception:
            pass
        return len(self.hyperedges) - 1
    
    def get_visualization_data(self) -> Dict[str, Any]:
        """Get data formatted for visualization"""
        nodes_list = list(self.nodes.values())
        
        # Calculate centrality (simple degree-based)
        centrality = defaultdict(int)
        for edge in self.hyperedges:
            for node_id in edge.get('nodes', []):
                centrality[node_id] += 1
        
        # Get top central nodes
        central_nodes = sorted(
            [(nid, centrality[nid]) for nid in self.nodes.keys()],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            'nodes': nodes_list,
            'hyperedges': self.hyperedges,
            'central_nodes': [
                {
                    'node_id': nid,
                    'centrality': cent / max(len(self.hyperedges), 1),
                    'frequency': self.nodes.get(nid, {}).get('frequency', 0)
                }
                for nid, cent in central_nodes
            ],
            'session_id': self.session_id,
            'timestamp': time.time()
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get hypergraph metrics"""
        # Calculate frequency distribution
        freq_dist = defaultdict(int)
        for node in self.nodes.values():
            freq = node.get('frequency', 0)
            band = f"{int(freq // 10) * 10}-{int(freq // 10) * 10 + 10}"
            freq_dist[band] += 1
        
        # Calculate centrality for high centrality nodes
        centrality = defaultdict(int)
        for edge in self.hyperedges:
            for node_id in edge.get('nodes', []):
                centrality[node_id] += 1
        
        high_cent_nodes = sorted(
            [(nid, centrality[nid]) for nid in self.nodes.keys()],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            'total_nodes': len(self.nodes),
            'total_hyperedges': len(self.hyperedges),
            'session_id': self.session_id,
            'collection_duration': time.time() - self.start_time,
            'frequency_distribution': dict(freq_dist),
            'high_centrality_nodes': [
                {
                    'node_id': nid,
                    'centrality': cent / max(len(self.hyperedges), 1),
                    'frequency': self.nodes.get(nid, {}).get('frequency', 0)
                }
                for nid, cent in high_cent_nodes
            ]
        }
    
    def generate_test_data(self, num_nodes: int = 20, freq_min: float = 88.0, 
                          freq_max: float = 108.0, area_size: float = 1000.0) -> Dict[str, Any]:
        """Generate synthetic test data"""
        # Clear existing data but keep session
        self.nodes = {}
        self.hyperedges = []
        
        # Base location (San Francisco)
        base_lat, base_lon = 37.7749, -122.4194
        
        # Generate nodes
        modulations = ['FM', 'AM', 'PSK', 'FSK', 'QAM', 'OFDM']
        
        for i in range(num_nodes):
            lat_offset = (random.random() - 0.5) * (area_size / 111000)  # Convert meters to degrees
            lon_offset = (random.random() - 0.5) * (area_size / 111000)
            
            node_data = {
                'node_id': f"rf_node_{i}_{int(time.time()*1000)}",
                'position': [
                    base_lat + lat_offset,
                    base_lon + lon_offset,
                    random.random() * 500  # altitude 0-500m
                ],
                'frequency': freq_min + random.random() * (freq_max - freq_min),
                'power': -80 + random.random() * 50,  # -80 to -30 dBm
                'modulation': random.choice(modulations),
                'metadata': {
                    'source': 'test_generator',
                    'generated_at': time.time()
                }
            }
            self.add_node(node_data)
        
        # Generate hyperedges
        node_ids = list(self.nodes.keys())
        num_edges = min(num_nodes * 2, 30)
        
        for _ in range(num_edges):
            cardinality = random.randint(2, min(5, len(node_ids)))
            edge_nodes = random.sample(node_ids, cardinality)
            
            edge_data = {
                'nodes': edge_nodes,
                'signal_strength': -80 + random.random() * 50,
                'metadata': {
                    'coherence': random.random(),
                    'generated': True
                }
            }
            self.add_hyperedge(edge_data)
        
        logger.info(f"Generated {num_nodes} nodes and {num_edges} hyperedges")
        return self.get_visualization_data()
    
    def add_network_host(self, host_data: Dict[str, Any]) -> str:
        """Add a network host as a hypergraph node"""
        ip = host_data.get('ip', '0.0.0.0')
        node_id = f"net_{ip.replace('.', '_')}"
        
        # Convert IP to pseudo-position (for visualization)
        ip_parts = [int(x) for x in ip.split('.')]
        lat = 37.0 + (ip_parts[2] - 128) * 0.01  # Spread around SF
        lon = -122.0 + (ip_parts[3] - 128) * 0.01
        
        self.nodes[node_id] = {
            'node_id': node_id,
            'type': 'network_host',
            'ip': ip,
            'hostname': host_data.get('hostname', ip),
            'position': [lat, lon, 0],
            'ports': host_data.get('ports', []),
            'services': [p.get('service', 'unknown') for p in host_data.get('ports', [])],
            'frequency': len(host_data.get('ports', [])) * 100,  # Pseudo-frequency based on ports
            'power': -50 + len(host_data.get('ports', [])) * 5,  # Signal strength based on activity
            'modulation': 'TCP/IP',
            'timestamp': time.time(),
            'metadata': {
                'source': 'nmap',
                'status': host_data.get('status', 'up'),
                'mac': host_data.get('mac'),
                'os': host_data.get('os')
            }
        }
        # publish network host create
        try:
            self._maybe_publish_network_host(node_id, self.nodes[node_id])
        except Exception:
            pass
        # mirror into unified HypergraphEngine via adapter if available
        try:
            adapter = getattr(self, 'rf_adapter', None)
            if adapter:
                adapter.add_node_from_rf(self.nodes[node_id])
            else:
                engine = getattr(self, 'hypergraph_engine', None)
                if engine:
                    services = [p.get('service') for p in self.nodes[node_id].get('ports', []) if p.get('service')]
                    subnet = None
                    try:
                        subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                    except Exception:
                        subnet = None
                    labels = {}
                    if services:
                        labels['service'] = services
                    if subnet:
                        labels['subnet'] = subnet
                    eng_node = {
                        'id': node_id,
                        'kind': 'network_host',
                        'position': self.nodes[node_id].get('position'),
                        'frequency': self.nodes[node_id].get('frequency'),
                        'labels': labels,
                        'metadata': self.nodes[node_id].get('metadata', {})
                    }
                    try:
                        engine.add_node(eng_node)
                    except Exception:
                        pass
        except Exception:
            pass

        return node_id

    def _maybe_publish_network_host(self, node_id: str, host_record: Dict[str, Any]):
        if getattr(self, 'event_bus', None):
            try:
                ev = SimpleNamespace(
                    event_type='NODE_CREATE',
                    entity_id=node_id,
                    entity_kind='network_host',
                    entity_data=host_record
                )
                self.event_bus.publish(ev)
            except Exception:
                pass
    
    def create_service_hyperedges(self):
        """Create hyperedges connecting hosts with same services"""
        # Group nodes by service
        service_groups = defaultdict(list)
        for node_id, node in self.nodes.items():
            if node.get('type') == 'network_host':
                for service in node.get('services', []):
                    if service and service != 'unknown':
                        service_groups[service].append(node_id)
        
        # Create hyperedges for each service group
        for service, node_ids in service_groups.items():
            if len(node_ids) >= 2:
                edge = {
                    'nodes': node_ids,
                    'cardinality': len(node_ids),
                    'type': 'service_group',
                    'service': service,
                    'signal_strength': -60 + len(node_ids) * 2,
                    'timestamp': time.time(),
                    'metadata': {
                        'relationship': f'shared_{service}_service',
                        'description': f'Hosts running {service}'
                    }
                }
                self.hyperedges.append(edge)
                try:
                    if getattr(self, 'event_bus', None):
                        ev = SimpleNamespace(
                            event_type='HYPEREDGE_CREATE',
                            entity_id=str(len(self.hyperedges)-1),
                            entity_kind='hyperedge',
                            entity_data=edge
                        )
                        self.event_bus.publish(ev)
                except Exception:
                    pass
                # mirror into HypergraphEngine
                try:
                    adapter = getattr(self, 'rf_adapter', None)
                    if adapter:
                        adapter.add_edge_from_rf(edge)
                    else:
                        engine = getattr(self, 'hypergraph_engine', None)
                        if engine:
                            eng_edge = {
                                'id': str(len(self.hyperedges)-1),
                                'kind': 'service_group',
                                'nodes': node_ids,
                                'weight': float(edge.get('signal_strength', 0.0)),
                                'labels': {'service': service},
                                'metadata': edge.get('metadata', {}),
                                'timestamp': edge.get('timestamp')
                            }
                            try:
                                engine.add_edge(eng_edge)
                            except Exception:
                                pass
                except Exception:
                    pass
        
        return len(service_groups)
    
    def create_subnet_hyperedges(self):
        """Create hyperedges connecting hosts in same subnet"""
        # Group nodes by /24 subnet
        subnet_groups = defaultdict(list)
        for node_id, node in self.nodes.items():
            if node.get('type') == 'network_host':
                ip = node.get('ip', '')
                if ip:
                    subnet = '.'.join(ip.split('.')[:3])
                    subnet_groups[subnet].append(node_id)
        
        # Create hyperedges for each subnet
        for subnet, node_ids in subnet_groups.items():
            if len(node_ids) >= 2:
                edge = {
                    'nodes': node_ids,
                    'cardinality': len(node_ids),
                    'type': 'subnet_group',
                    'subnet': f'{subnet}.0/24',
                    'signal_strength': -50 + len(node_ids) * 3,
                    'timestamp': time.time(),
                    'metadata': {
                        'relationship': 'same_subnet',
                        'description': f'Hosts in subnet {subnet}.0/24'
                    }
                }
                self.hyperedges.append(edge)
                try:
                    if getattr(self, 'event_bus', None):
                        ev = SimpleNamespace(
                            event_type='HYPEREDGE_CREATE',
                            entity_id=str(len(self.hyperedges)-1),
                            entity_kind='hyperedge',
                            entity_data=edge
                        )
                        self.event_bus.publish(ev)
                except Exception:
                    pass
                # mirror into HypergraphEngine
                try:
                    adapter = getattr(self, 'rf_adapter', None)
                    if adapter:
                        adapter.add_edge_from_rf(edge)
                    else:
                        engine = getattr(self, 'hypergraph_engine', None)
                        if engine:
                            eng_edge = {
                                'id': str(len(self.hyperedges)-1),
                                'kind': 'subnet_group',
                                'nodes': node_ids,
                                'weight': float(edge.get('signal_strength', 0.0)),
                                'labels': {'subnet': edge.get('subnet')},
                                'metadata': edge.get('metadata', {}),
                                'timestamp': edge.get('timestamp')
                            }
                            try:
                                engine.add_edge(eng_edge)
                            except Exception:
                                pass
                except Exception:
                    pass
        
        return len(subnet_groups)


# ============================================================================
# NMAP INTEGRATION
# ============================================================================

class NmapScanner:
    """Nmap network scanner integration"""
    
    def __init__(self):
        self.scan_results = {}
        self.scanning = False
        self.last_scan_time = None
    
    def check_nmap_available(self) -> bool:
        """Check if nmap is installed"""
        try:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def scan(self, target: str, options: str = '-sn') -> Dict[str, Any]:
        """Run an nmap scan"""
        if not self.check_nmap_available():
            return {
                'status': 'simulated',
                'message': 'nmap not installed. Install with: sudo dnf install nmap',
                'simulated': True,
                'results': self._generate_simulated_results(target)
            }
        
        self.scanning = True
        try:
            # Build command - restrict to safe options
            safe_options = options.replace(';', '').replace('|', '').replace('&', '')
            cmd = ['nmap'] + safe_options.split() + [target]
            
            logger.info(f"Running nmap: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            self.scan_results = {
                'status': 'success',
                'target': target,
                'options': safe_options,
                'output': result.stdout,
                'timestamp': time.time(),
                'hosts': self._parse_nmap_output(result.stdout)
            }
            self.last_scan_time = time.time()
            
        except subprocess.TimeoutExpired:
            self.scan_results = {
                'status': 'error',
                'message': 'Scan timed out after 120 seconds'
            }
        except Exception as e:
            self.scan_results = {
                'status': 'error',
                'message': str(e)
            }
        finally:
            self.scanning = False
        
        return self.scan_results
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output into structured data"""
        hosts = []
        current_host = None
        
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                if current_host:
                    hosts.append(current_host)
                parts = line.split()
                ip = parts[-1].strip('()')
                hostname = parts[-2] if len(parts) > 4 else ip
                current_host = {
                    'ip': ip,
                    'hostname': hostname,
                    'ports': [],
                    'status': 'up'
                }
            elif current_host and '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    current_host['ports'].append({
                        'port': parts[0],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    })
        
        if current_host:
            hosts.append(current_host)
        
        return hosts
    
    def _generate_simulated_results(self, target: str) -> List[Dict[str, Any]]:
        """Generate simulated scan results when nmap is not available"""
        # Parse target for simulation
        if '/' in target:
            base_ip = target.split('/')[0]
        else:
            base_ip = target
        
        base_parts = base_ip.split('.')[:3]
        
        hosts = []
        for i in range(random.randint(3, 10)):
            host_ip = f"{'.'.join(base_parts)}.{random.randint(1, 254)}"
            hosts.append({
                'ip': host_ip,
                'hostname': f"host-{host_ip.replace('.', '-')}",
                'status': 'up',
                'ports': [
                    {'port': '22/tcp', 'state': 'open', 'service': 'ssh'},
                    {'port': '80/tcp', 'state': 'open', 'service': 'http'},
                ] if random.random() > 0.5 else []
            })
        
        return hosts


# ============================================================================
# NDPI INTEGRATION
# ============================================================================

class NDPIAnalyzer:
    """nDPI deep packet inspection integration"""
    
    def __init__(self):
        self.analysis_results = {}
        self.analyzing = False
    
    def check_ndpi_available(self) -> bool:
        """Check if ndpiReader is installed"""
        try:
            result = subprocess.run(['which', 'ndpiReader'], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def analyze_interface(self, interface: str = 'eth0', duration: int = 10) -> Dict[str, Any]:
        """Analyze network traffic on an interface"""
        if not self.check_ndpi_available():
            return {
                'status': 'simulated',
                'message': 'ndpiReader not installed. Install nDPI for real analysis.',
                'results': self._generate_simulated_results()
            }
        
        self.analyzing = True
        try:
            cmd = ['ndpiReader', '-i', interface, '-s', str(duration)]
            
            logger.info(f"Running nDPI: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
            
            self.analysis_results = {
                'status': 'success',
                'interface': interface,
                'duration': duration,
                'output': result.stdout,
                'protocols': self._parse_ndpi_output(result.stdout),
                'timestamp': time.time()
            }
            
        except subprocess.TimeoutExpired:
            self.analysis_results = {
                'status': 'error',
                'message': 'Analysis timed out'
            }
        except Exception as e:
            self.analysis_results = {
                'status': 'error',
                'message': str(e)
            }
        finally:
            self.analyzing = False
        
        return self.analysis_results
    
    def _parse_ndpi_output(self, output: str) -> Dict[str, Any]:
        """Parse nDPI output into structured data"""
        result = {
            'protocols': [],
            'categories': [],
            'statistics': {},
            'risks': []
        }
        
        # Find the "Detected protocols:" section
        in_protocols = False
        in_categories = False
        in_risks = False
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Section markers
            if 'Detected protocols:' in line:
                in_protocols = True
                in_categories = False
                in_risks = False
                continue
            elif 'Category statistics:' in line:
                in_protocols = False
                in_categories = True
                in_risks = False
                continue
            elif 'Risk stats' in line:
                in_protocols = False
                in_categories = False
                in_risks = True
                continue
            elif line.startswith('Protocol statistics:') or line.startswith('NOTE:'):
                in_protocols = False
                in_categories = False
                continue
            
            # Parse detected protocols (format: "TLS packets: 79 bytes: 17278 flows: 4")
            if in_protocols and line and not line.startswith('*'):
                # Try to parse: PROTOCOL packets: N bytes: N flows: N
                import re
                match = re.match(r'(\S+)\s+packets:\s*(\d+)\s+bytes:\s*(\d+)\s+flows:\s*(\d+)', line)
                if match:
                    result['protocols'].append({
                        'protocol': match.group(1),
                        'packets': int(match.group(2)),
                        'bytes': int(match.group(3)),
                        'flows': int(match.group(4))
                    })
            
            # Parse categories (format: "Web packets: 80 bytes: 20357 flows: 8")
            elif in_categories and line and not line.startswith('*'):
                import re
                match = re.match(r'(\S+)\s+packets:\s*(\d+)\s+bytes:\s*(\d+)\s+flows:\s*(\d+)', line)
                if match:
                    result['categories'].append({
                        'category': match.group(1),
                        'packets': int(match.group(2)),
                        'bytes': int(match.group(3)),
                        'flows': int(match.group(4))
                    })
            
            # Parse key statistics
            if 'IP packets:' in line:
                import re
                match = re.search(r'IP packets:\s*(\d+)', line)
                if match:
                    result['statistics']['ip_packets'] = int(match.group(1))
            elif 'Unique flows:' in line:
                import re
                match = re.search(r'Unique flows:\s*(\d+)', line)
                if match:
                    result['statistics']['unique_flows'] = int(match.group(1))
            elif 'TCP Packets:' in line:
                import re
                match = re.search(r'TCP Packets:\s*(\d+)', line)
                if match:
                    result['statistics']['tcp_packets'] = int(match.group(1))
            elif 'UDP Packets:' in line:
                import re
                match = re.search(r'UDP Packets:\s*(\d+)', line)
                if match:
                    result['statistics']['udp_packets'] = int(match.group(1))
            elif 'nDPI throughput:' in line:
                import re
                match = re.search(r'nDPI throughput:\s*([\d.]+)\s*pps\s*/\s*([\d.]+)\s*(\S+)/sec', line)
                if match:
                    result['statistics']['throughput_pps'] = float(match.group(1))
                    result['statistics']['throughput_rate'] = f"{match.group(2)} {match.group(3)}/sec"
        
        return result
    
    def _generate_simulated_results(self) -> Dict[str, Any]:
        """Generate simulated NDPI results"""
        protocols = [
            {'protocol': 'TLS', 'count': random.randint(100, 500), 'bytes': random.randint(50000, 200000), 'category': 'Encrypted'},
            {'protocol': 'HTTP', 'count': random.randint(50, 200), 'bytes': random.randint(20000, 100000), 'category': 'Web'},
            {'protocol': 'DNS', 'count': random.randint(200, 800), 'bytes': random.randint(10000, 50000), 'category': 'Network'},
            {'protocol': 'QUIC', 'count': random.randint(20, 100), 'bytes': random.randint(10000, 80000), 'category': 'Encrypted'},
            {'protocol': 'SSH', 'count': random.randint(5, 30), 'bytes': random.randint(5000, 30000), 'category': 'Remote Access'},
            {'protocol': 'NTP', 'count': random.randint(10, 50), 'bytes': random.randint(1000, 5000), 'category': 'Network'},
            {'protocol': 'Unknown', 'count': random.randint(10, 100), 'bytes': random.randint(5000, 50000), 'category': 'Unknown'},
        ]
        
        return {
            'protocols': protocols,
            'total_flows': sum(p['count'] for p in protocols),
            'total_bytes': sum(p['bytes'] for p in protocols),
            'duration': 10,
            'categories': {
                'Encrypted': sum(p['count'] for p in protocols if p['category'] == 'Encrypted'),
                'Web': sum(p['count'] for p in protocols if p['category'] == 'Web'),
                'Network': sum(p['count'] for p in protocols if p['category'] == 'Network'),
                'Unknown': sum(p['count'] for p in protocols if p['category'] == 'Unknown'),
            }
        }


# ============================================================================
# AIS VESSEL TRACKING
# ============================================================================

class AISTracker:
    """AIS Vessel Tracking from CSV data"""
    
    # Path to AIS CSV file
    AIS_CSV_PATH = 'assets/sample-app-ais-integration-rest-master/var/ais_vessels.csv'
    
    def __init__(self):
        self.vessels = {}  # MMSI -> vessel data
        self.vessel_history = {}  # MMSI -> list of positions
        self.csv_loaded = False
        self.playback_index = {}  # MMSI -> current index in history
        self.all_records = []  # All CSV records
        self.load_csv()
    
    def load_csv(self):
        """Load AIS data from CSV file"""
        try:
            csv_path = os.path.join(os.path.dirname(__file__), self.AIS_CSV_PATH)
            if not os.path.exists(csv_path):
                # Try alternate path
                csv_path = self.AIS_CSV_PATH
            
            if not os.path.exists(csv_path):
                logger.warning(f"AIS CSV not found at {csv_path}")
                self._generate_mock_data()
                return
            
            with open(csv_path, 'r') as f:
                import csv
                reader = csv.DictReader(f)
                
                for row in reader:
                    self.all_records.append(row)
                    mmsi = row.get('MMSI', '')
                    
                    if mmsi not in self.vessel_history:
                        self.vessel_history[mmsi] = []
                        self.playback_index[mmsi] = 0
                    
                    self.vessel_history[mmsi].append({
                        'mmsi': mmsi,
                        'lat': float(row.get('LAT', 0)),
                        'lon': float(row.get('LON', 0)),
                        'sog': float(row.get('SOG', 0)),  # Speed over ground
                        'cog': float(row.get('COG', 0)),  # Course over ground
                        'heading': float(row.get('Heading', 0)),
                        'name': row.get('VesselName', 'Unknown'),
                        'vessel_type': row.get('VesselType', '0'),
                        'length': float(row.get('Length', 0) or 0),
                        'width': float(row.get('Width', 0) or 0),
                        'draft': float(row.get('Draft', 0) or 0),
                        'timestamp': row.get('BaseDateTime', '')
                    })
                
                # Initialize current vessel positions with first record
                for mmsi, history in self.vessel_history.items():
                    if history:
                        self.vessels[mmsi] = history[0].copy()
                        self.vessels[mmsi]['history_length'] = len(history)
                
                self.csv_loaded = True
                logger.info(f"Loaded {len(self.all_records)} AIS records for {len(self.vessels)} vessels")
                
        except Exception as e:
            logger.error(f"Error loading AIS CSV: {e}")
            self._generate_mock_data()
    
    def _generate_mock_data(self):
        """Generate mock AIS data if CSV not available"""
        logger.info("Generating mock AIS data")
        
        mock_vessels = [
            {'mmsi': '730156067', 'name': 'RM SEA TROUT', 'lat': 40.42, 'lon': -124.94, 'type': 'Fishing'},
            {'mmsi': '368179250', 'name': 'SEAHAWK', 'lat': 25.77, 'lon': -80.15, 'type': 'Patrol'},
            {'mmsi': '368138010', 'name': 'NEW YORK', 'lat': 40.46, 'lon': -73.83, 'type': 'Ferry'},
            {'mmsi': '367241000', 'name': 'ATLANTIS', 'lat': 41.88, 'lon': -125.07, 'type': 'Research'},
            {'mmsi': '367796610', 'name': 'HOUSTON', 'lat': 29.30, 'lon': -94.59, 'type': 'Cargo'},
            {'mmsi': '368024740', 'name': 'PILOT BOAT ORION', 'lat': 33.74, 'lon': -118.17, 'type': 'Pilot'},
            {'mmsi': '368126190', 'name': 'GERONIMO', 'lat': 34.23, 'lon': -121.24, 'type': 'Yacht'},
            {'mmsi': '367458840', 'name': 'OSPREY', 'lat': 25.76, 'lon': -80.14, 'type': 'Patrol'},
        ]
        
        for vessel in mock_vessels:
            mmsi = vessel['mmsi']
            self.vessels[mmsi] = {
                'mmsi': mmsi,
                'lat': vessel['lat'],
                'lon': vessel['lon'],
                'sog': random.uniform(0, 15),
                'cog': random.uniform(0, 360),
                'heading': random.uniform(0, 360),
                'name': vessel['name'],
                'vessel_type': vessel['type'],
                'length': random.uniform(20, 100),
                'width': random.uniform(5, 20),
                'draft': random.uniform(2, 10),
                'timestamp': datetime.now().isoformat(),
                'history_length': 1
            }
            self.vessel_history[mmsi] = [self.vessels[mmsi].copy()]
            self.playback_index[mmsi] = 0
        
        self.csv_loaded = True
    
    def get_all_vessels(self) -> List[Dict[str, Any]]:
        """Get all current vessel positions"""
        return list(self.vessels.values())
    
    def get_vessel(self, mmsi: str) -> Optional[Dict[str, Any]]:
        """Get a specific vessel by MMSI"""
        return self.vessels.get(mmsi)
    
    def get_vessel_history(self, mmsi: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get historical positions for a vessel"""
        history = self.vessel_history.get(mmsi, [])
        return history[-limit:] if limit else history
    
    def advance_playback(self) -> Dict[str, Any]:
        """Advance all vessels to their next position (for simulation)"""
        updated = []
        
        for mmsi in self.vessels:
            history = self.vessel_history.get(mmsi, [])
            if not history:
                continue
            
            # Advance index
            idx = self.playback_index.get(mmsi, 0)
            idx = (idx + 1) % len(history)
            self.playback_index[mmsi] = idx
            
            # Update current position
            self.vessels[mmsi] = history[idx].copy()
            self.vessels[mmsi]['history_length'] = len(history)
            updated.append(self.vessels[mmsi])
        
        return {
            'updated_count': len(updated),
            'vessels': updated,
            'timestamp': time.time()
        }
    
    def get_vessels_in_area(self, min_lat: float, max_lat: float, 
                           min_lon: float, max_lon: float) -> List[Dict[str, Any]]:
        """Get vessels within a geographic bounding box"""
        return [
            v for v in self.vessels.values()
            if min_lat <= v['lat'] <= max_lat and min_lon <= v['lon'] <= max_lon
        ]
    
    def correlate_with_rf(self, freq_min: float = 156.0, freq_max: float = 162.5) -> List[Dict[str, Any]]:
        """Correlate vessels with RF signals in maritime VHF band"""
        correlations = []
        
        for mmsi, vessel in self.vessels.items():
            # Simulate RF correlation - in real system this would check actual RF data
            has_rf_emission = random.random() > 0.7
            
            if has_rf_emission:
                correlations.append({
                    'mmsi': mmsi,
                    'vessel_name': vessel['name'],
                    'lat': vessel['lat'],
                    'lon': vessel['lon'],
                    'rf_detected': True,
                    'frequency': random.uniform(freq_min, freq_max),
                    'power': random.uniform(-80, -40),
                    'channel': f"CH{random.randint(1, 88)}",
                    'band': 'Maritime VHF',
                    'violation': random.random() > 0.8,
                    'violation_type': random.choice(['Unlicensed', 'Over Power', 'Wrong Channel', None])
                })
        
        return correlations
    
    def update_vessel(self, mmsi: str, vessel_data: Dict[str, Any]) -> None:
        """Update or add a vessel with new data from AIS stream"""
        if mmsi not in self.vessels:
            # New vessel
            self.vessels[mmsi] = {
                'mmsi': mmsi,
                'lat': vessel_data.get('lat', 0),
                'lon': vessel_data.get('lon', 0),
                'sog': vessel_data.get('speed', 0),
                'cog': vessel_data.get('course', 0),
                'heading': vessel_data.get('heading', 0),
                'name': vessel_data.get('name', f'MMSI_{mmsi}'),
                'vessel_type': vessel_data.get('vessel_type', 'Unknown'),
                'length': vessel_data.get('length', 0),
                'width': vessel_data.get('width', 0),
                'draft': vessel_data.get('draft', 0),
                'timestamp': vessel_data.get('timestamp', datetime.now().isoformat()),
                'history_length': 1
            }
            self.vessel_history[mmsi] = [self.vessels[mmsi].copy()]
            self.playback_index[mmsi] = 0
        else:
            # Update existing vessel
            self.vessels[mmsi].update({
                'lat': vessel_data.get('lat', self.vessels[mmsi]['lat']),
                'lon': vessel_data.get('lon', self.vessels[mmsi]['lon']),
                'sog': vessel_data.get('speed', self.vessels[mmsi]['sog']),
                'cog': vessel_data.get('course', self.vessels[mmsi]['cog']),
                'heading': vessel_data.get('heading', self.vessels[mmsi]['heading']),
                'timestamp': vessel_data.get('timestamp', datetime.now().isoformat())
            })
            
            # Update name and type if provided
            if 'name' in vessel_data:
                self.vessels[mmsi]['name'] = vessel_data['name']
            if 'vessel_type' in vessel_data:
                self.vessels[mmsi]['vessel_type'] = vessel_data['vessel_type']
            
            # Add to history
            self.vessel_history[mmsi].append(self.vessels[mmsi].copy())
            # Keep only last 100 positions
            if len(self.vessel_history[mmsi]) > 100:
                self.vessel_history[mmsi] = self.vessel_history[mmsi][-100:]
            self.vessels[mmsi]['history_length'] = len(self.vessel_history[mmsi])
    
    def get_vessel_types(self) -> List[str]:
        """Get list of all vessel types currently tracked"""
        types = set()
        for vessel in self.vessels.values():
            vessel_type = vessel.get('vessel_type', 'Unknown')
            if vessel_type:
                types.add(vessel_type)
        return sorted(list(types))
    
    def get_vessels_by_type(self, vessel_types: List[str]) -> List[Dict[str, Any]]:
        """Get vessels filtered by vessel types"""
        if not vessel_types:
            return list(self.vessels.values())
        
        return [
            v for v in self.vessels.values()
            if v.get('vessel_type', 'Unknown') in vessel_types
        ]
    
    def get_vessels_filtered(self, vessel_types: List[str] = None, 
                           min_lat: float = None, max_lat: float = None,
                           min_lon: float = None, max_lon: float = None) -> List[Dict[str, Any]]:
        """Get vessels with combined filtering"""
        vessels = list(self.vessels.values())
        
        # Filter by vessel type
        if vessel_types:
            vessels = [v for v in vessels if v.get('vessel_type', 'Unknown') in vessel_types]
        
        # Filter by geographic area
        if all([min_lat, max_lat, min_lon, max_lon]) is not None:
            vessels = [
                v for v in vessels
                if min_lat <= v['lat'] <= max_lat and min_lon <= v['lon'] <= max_lon
            ]
        
        return vessels
    
    def search_records(self, query: str = None, vessel_type: str = None, 
                      min_lat: float = None, max_lat: float = None,
                      min_lon: float = None, max_lon: float = None,
                      limit: int = 100, offset: int = 0, return_total: bool = False):
        """Search through all AIS records with various filters.

        Args:
            query: text query to match MMSI, VesselName, CallSign, IMO
            vessel_type: filtered vessel type (e.g. 'cargo')
            min_lat,max_lat,min_lon,max_lon: geographic bounding box
            limit: maximum number of records to return
            offset: offset into the result set (for pagination)
            return_total: if True, return (results_slice, total_matches)
        """
        results = self.all_records
        
        # Text search (MMSI, vessel name, etc.)
        if query:
            query_lower = query.lower()
            results = [
                r for r in results
                if any(query_lower in str(r.get(field, '')).lower() 
                      for field in ['MMSI', 'VesselName', 'CallSign', 'IMO'])
            ]
        
        # Vessel type filter
        if vessel_type and vessel_type != 'all':
            # For CSV records, we might need to decode vessel type from VesselType field
            if vessel_type == 'cargo':
                results = [r for r in results if str(r.get('VesselType', '')).startswith('7')]
            elif vessel_type == 'tanker':
                results = [r for r in results if str(r.get('VesselType', '')).startswith('8')]
            elif vessel_type == 'passenger':
                results = [r for r in results if str(r.get('VesselType', '')).startswith('6')]
            elif vessel_type == 'fishing':
                results = [r for r in results if str(r.get('VesselType', '')).startswith('3')]
            elif vessel_type == 'tug':
                results = [r for r in results if r.get('VesselType') == '52']
            elif vessel_type == 'pilot':
                results = [r for r in results if r.get('VesselType') == '50']
        
        # Geographic filter
        if min_lat is not None and max_lat is not None and min_lon is not None and max_lon is not None:
            results = [
                r for r in results
                if min_lat <= float(r.get('LAT', 0)) <= max_lat and 
                   min_lon <= float(r.get('LON', 0)) <= max_lon
            ]
        
        # Total matches before paging
        total_matches = len(results)

        # Apply offset/limit for pagination
        if offset and offset > 0:
            results = results[offset:offset + limit]
        else:
            results = results[:limit]

        if return_total:
            return results, total_matches

        return results
    
    def get_unique_vessels_from_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get unique vessels from search results with latest position"""
        vessel_map = {}
        
        for record in records:
            mmsi = record.get('MMSI', '')
            if mmsi:
                # Keep the most recent record for each MMSI
                if mmsi not in vessel_map:
                    vessel_map[mmsi] = record
                else:
                    # Could compare timestamps if available
                    pass
        
        return list(vessel_map.values())
    
    def _decode_vessel_type(self, ais_type_code: int) -> str:
        """Decode AIS vessel type code to human-readable string"""
        if not isinstance(ais_type_code, int) or ais_type_code == 0:
            return 'Unknown'
        
        # AIS vessel type mapping (simplified)
        type_mapping = {
            # Reserved: 0
            1: 'Reserved',
            2: 'Reserved',
            # Wing in ground: 20-29
            20: 'Wing in Ground',
            21: 'Wing in Ground (Hazardous A)',
            22: 'Wing in Ground (Hazardous B)',
            23: 'Wing in Ground (Hazardous C)',
            24: 'Wing in Ground (Hazardous D)',
            # Special craft: 30-39
            30: 'Fishing',
            31: 'Towing',
            32: 'Towing (large)',
            33: 'Dredger',
            34: 'Diving ops',
            35: 'Military ops',
            36: 'Sailing',
            37: 'Pleasure Craft',
            # High speed craft: 40-49
            40: 'High Speed Craft',
            41: 'High Speed Craft (Hazardous A)',
            42: 'High Speed Craft (Hazardous B)',
            43: 'High Speed Craft (Hazardous C)',
            44: 'High Speed Craft (Hazardous D)',
            # Special craft: 50-59
            50: 'Pilot Vessel',
            51: 'Search and Rescue',
            52: 'Tug',
            53: 'Port Tender',
            54: 'Anti-pollution',
            55: 'Law Enforcement',
            56: 'Spare - Local Vessel',
            57: 'Spare - Local Vessel',
            58: 'Medical Transport',
            59: 'Noncombatant',
            # Passenger ships: 60-69
            60: 'Passenger',
            61: 'Passenger (Hazardous A)',
            62: 'Passenger (Hazardous B)',
            63: 'Passenger (Hazardous C)',
            64: 'Passenger (Hazardous D)',
            65: 'Passenger (Reserved)',
            66: 'Passenger (Reserved)',
            67: 'Passenger (Reserved)',
            68: 'Passenger (Reserved)',
            69: 'Passenger (No additional info)',
            # Cargo ships: 70-79
            70: 'Cargo',
            71: 'Cargo (Hazardous A)',
            72: 'Cargo (Hazardous B)',
            73: 'Cargo (Hazardous C)',
            74: 'Cargo (Hazardous D)',
            75: 'Cargo (Reserved)',
            76: 'Cargo (Reserved)',
            77: 'Cargo (Reserved)',
            78: 'Cargo (Reserved)',
            79: 'Cargo (No additional info)',
            # Tankers: 80-89
            80: 'Tanker',
            81: 'Tanker (Hazardous A)',
            82: 'Tanker (Hazardous B)',
            83: 'Tanker (Hazardous C)',
            84: 'Tanker (Hazardous D)',
            85: 'Tanker (Reserved)',
            86: 'Tanker (Reserved)',
            87: 'Tanker (Reserved)',
            88: 'Tanker (Reserved)',
            89: 'Tanker (No additional info)',
            # Other: 90-99
            90: 'Other',
            91: 'Other (Hazardous A)',
            92: 'Other (Hazardous B)',
            93: 'Other (Hazardous C)',
            94: 'Other (Hazardous D)',
            95: 'Other (Reserved)',
            96: 'Other (Reserved)',
            97: 'Other (Reserved)',
            98: 'Other (Reserved)',
            99: 'Other (No additional info)'
        }
        
        return type_mapping.get(ais_type_code, f'Unknown ({ais_type_code})')


# ============================================================================
# PERFORMANCE METRICS & PROFILING
# ============================================================================

class PerformanceMetrics:
    """Track performance metrics for API endpoints and computations."""
    
    def __init__(self, max_history: int = 1000):
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self.counters: Dict[str, int] = defaultdict(int)
        self.start_time = time.time()
        self._lock = threading.Lock()
    
    def record(self, operation: str, duration_ms: float, metadata: Dict = None):
        """Record a timing measurement."""
        with self._lock:
            self.metrics[operation].append({
                'duration_ms': duration_ms,
                'timestamp': time.time(),
                'metadata': metadata or {}
            })
            self.counters[operation] += 1
    
    def increment(self, counter: str, amount: int = 1):
        """Increment a counter."""
        with self._lock:
            self.counters[counter] += amount
    
    def get_stats(self, operation: str) -> Dict[str, Any]:
        """Get statistics for an operation."""
        with self._lock:
            measurements = list(self.metrics[operation])
        
        if not measurements:
            return {'count': 0, 'avg_ms': 0, 'min_ms': 0, 'max_ms': 0, 'p95_ms': 0}
        
        durations = [m['duration_ms'] for m in measurements]
        durations.sort()
        
        return {
            'count': len(durations),
            'total_calls': self.counters[operation],
            'avg_ms': sum(durations) / len(durations),
            'min_ms': min(durations),
            'max_ms': max(durations),
            'p95_ms': durations[int(len(durations) * 0.95)] if len(durations) > 1 else durations[0],
            'recent_avg_ms': sum(durations[-100:]) / min(len(durations), 100)
        }
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get all statistics."""
        with self._lock:
            operations = list(self.metrics.keys())
        
        return {
            'uptime_seconds': time.time() - self.start_time,
            'operations': {op: self.get_stats(op) for op in operations},
            'counters': dict(self.counters)
        }


def timed_operation(metrics: PerformanceMetrics, operation_name: str):
    """Decorator to time operations and record metrics."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration_ms = (time.perf_counter() - start) * 1000
                metrics.record(operation_name, duration_ms)
        return wrapper
    return decorator


# ============================================================================
# PERSISTENT METRICS LOGGER - Append-only log for auditing & analysis
# ============================================================================

class MetricsLogger:
    """
    Persistent metrics logger for long-term storage and auditing.
    Writes to both JSON lines file and optional SQLite database.
    """
    
    def __init__(self, log_dir: str = "metrics_logs"):
        self.log_dir = log_dir
        self._ensure_log_dir()
        self._lock = threading.Lock()
        
        # JSON lines log file (append-only)
        self.log_file = os.path.join(log_dir, f"metrics_{datetime.now().strftime('%Y%m%d')}.jsonl")
        
        # SQLite database for structured queries
        self.db_path = os.path.join(log_dir, "metrics.db")
        self._init_sqlite()
        
        # In-memory aggregation for real-time dashboards
        self._session_metrics: Dict[str, List] = defaultdict(list)
        self._session_start = time.time()
        
        logger.info(f"MetricsLogger initialized: {log_dir}")
    
    def _ensure_log_dir(self):
        """Create log directory if it doesn't exist."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def _init_sqlite(self):
        """Initialize SQLite database with metrics schema."""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Main metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    session_id TEXT,
                    module TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL,
                    metadata TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Index for common queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_module ON metrics(module)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name)')
            
            # User interactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_interactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    session_id TEXT,
                    action TEXT NOT NULL,
                    target TEXT,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Missions: metadata for mission-aware namespaces
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS missions (
                    mission_id TEXT PRIMARY KEY,
                    name TEXT,
                    owner TEXT,
                    status TEXT,
                    metadata TEXT,
                    created_at REAL,
                    updated_at REAL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mission_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT NOT NULL,
                    operator_id TEXT NOT NULL,
                    role TEXT,
                    joined_at REAL,
                    UNIQUE(mission_id, operator_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mission_tasks (
                    task_id TEXT PRIMARY KEY,
                    mission_id TEXT NOT NULL,
                    title TEXT,
                    status TEXT,
                    priority INTEGER,
                    payload TEXT,
                    created_at REAL,
                    updated_at REAL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mission_watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    note TEXT,
                    added_at REAL,
                    UNIQUE(mission_id, entity_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("SQLite metrics database initialized")
        except Exception as e:
            logger.warning(f"SQLite initialization failed (will use JSON only): {e}")
    
    def log(self, module: str, metric_name: str, value: float, 
            metadata: Dict = None, session_id: str = None, user_agent: str = None):
        """
        Log a metric entry to both JSON lines file and SQLite.
        
        Args:
            module: Component name (e.g., 'recon', 'hypergraph', 'ais')
            metric_name: Metric identifier (e.g., 'update_time_ms', 'entity_count')
            value: Numeric metric value
            metadata: Optional additional context
            session_id: Client session identifier
            user_agent: Client user agent string
        """
        timestamp = time.time()
        entry = {
            'timestamp': timestamp,
            'datetime': datetime.fromtimestamp(timestamp).isoformat(),
            'session_id': session_id,
            'module': module,
            'metric_name': metric_name,
            'value': value,
            'metadata': metadata or {},
            'user_agent': user_agent
        }
        
        with self._lock:
            # Write to JSON lines file
            self._write_jsonl(entry)
            
            # Write to SQLite
            self._write_sqlite(entry)
            
            # Update in-memory aggregation
            key = f"{module}.{metric_name}"
            self._session_metrics[key].append({
                'timestamp': timestamp,
                'value': value
            })
            
            # Keep only last 1000 entries per metric in memory
            if len(self._session_metrics[key]) > 1000:
                self._session_metrics[key] = self._session_metrics[key][-1000:]
    
    def _write_jsonl(self, entry: Dict):
        """Append entry to JSON lines log file."""
        try:
            # Rotate log file daily
            today_file = os.path.join(self.log_dir, f"metrics_{datetime.now().strftime('%Y%m%d')}.jsonl")
            if today_file != self.log_file:
                self.log_file = today_file
            
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.warning(f"Failed to write JSON log: {e}")
    
    def _write_sqlite(self, entry: Dict):
        """Insert entry into SQLite database."""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO metrics (timestamp, session_id, module, metric_name, value, metadata, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry['timestamp'],
                entry.get('session_id'),
                entry['module'],
                entry['metric_name'],
                entry['value'],
                json.dumps(entry.get('metadata', {})),
                entry.get('user_agent')
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Failed to write SQLite: {e}")
    
    def log_interaction(self, action: str, target: str = None, 
                        details: Dict = None, session_id: str = None):
        """Log a user interaction event."""
        timestamp = time.time()
        entry = {
            'timestamp': timestamp,
            'datetime': datetime.fromtimestamp(timestamp).isoformat(),
            'session_id': session_id,
            'action': action,
            'target': target,
            'details': details or {}
        }
        
        with self._lock:
            # Write to JSON lines
            try:
                interactions_file = os.path.join(self.log_dir, f"interactions_{datetime.now().strftime('%Y%m%d')}.jsonl")
                with open(interactions_file, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
            except Exception as e:
                logger.warning(f"Failed to write interaction log: {e}")
            
            # Write to SQLite
            try:
                import sqlite3
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_interactions (timestamp, session_id, action, target, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (timestamp, session_id, action, target, json.dumps(details or {})))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to write interaction to SQLite: {e}")
    
    def log_batch(self, entries: List[Dict]):
        """Log multiple metric entries at once (more efficient)."""
        for entry in entries:
            self.log(
                module=entry.get('module', 'unknown'),
                metric_name=entry.get('metric_name', 'unknown'),
                value=entry.get('value', 0),
                metadata=entry.get('metadata'),
                session_id=entry.get('session_id'),
                user_agent=entry.get('user_agent')
            )
    
    def get_session_summary(self) -> Dict:
        """Get summary of metrics collected this session."""
        summary = {
            'session_duration_seconds': time.time() - self._session_start,
            'metrics': {}
        }
        
        with self._lock:
            for key, values in self._session_metrics.items():
                if values:
                    numeric_values = [v['value'] for v in values]
                    summary['metrics'][key] = {
                        'count': len(values),
                        'avg': sum(numeric_values) / len(numeric_values),
                        'min': min(numeric_values),
                        'max': max(numeric_values),
                        'last': values[-1]['value']
                    }
        
        return summary
    
    def query_metrics(self, module: str = None, metric_name: str = None,
                      start_time: float = None, end_time: float = None,
                      limit: int = 1000) -> List[Dict]:
        """Query historical metrics from SQLite."""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM metrics WHERE 1=1"
            params = []
            
            if module:
                query += " AND module = ?"
                params.append(module)
            if metric_name:
                query += " AND metric_name = ?"
                params.append(metric_name)
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            query += f" ORDER BY timestamp DESC LIMIT {limit}"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error querying metrics: {e}")
            return []


# Global metrics logger instance
metrics_logger = MetricsLogger()


# Global performance metrics instance
perf_metrics = PerformanceMetrics()

# Initialize satellites table in SQLite (if available)
def _init_satellite_table():
    try:
        import sqlite3
        db_path = metrics_logger.db_path
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS satellites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                lat REAL,
                lon REAL,
                altitude REAL,
                operator TEXT,
                type TEXT,
                frequency TEXT,
                orbit TEXT,
                coverage TEXT,
                status TEXT,
                launch_date TEXT,
                mission TEXT,
                extra JSON
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sat_name ON satellites(name)')
        conn.commit()
        conn.close()
        logger.info('Satellite table ensured in SQLite DB')
    except Exception as e:
        logger.warning(f'Could not initialize satellite table: {e}')


_init_satellite_table()

# ---------------------------------------------------------------------------
# Satellite TLE fetch & propagation utilities
# ---------------------------------------------------------------------------
def fetch_tles_from_celestrak(category: str = 'visual') -> List[Tuple[str, str, str]]:
    """Fetch TLEs from Celestrak for a given category.

    Returns a list of tuples: (name, line1, line2)
    """
    try:
        import requests

        # Try multiple Celestrak hosts/endpoints to be resilient against redirects/host changes
        candidates = [
            f'https://celestrak.com/NORAD/elements/{category}.txt',
            f'https://celestrak.org/NORAD/elements/{category}.txt',
            f'https://celestrak.org/NORAD/elements/gp.php?GROUP={category}&FORMAT=3le',
            f'https://celestrak.com/NORAD/elements/gp.php?GROUP={category}&FORMAT=3le',
            # Fallback: recent updates feed
            f'https://celestrak.org/NORAD/elements/gp.php?GROUP=last-30-days&FORMAT=3le',
        ]

        resp = None
        used_url = None
        for url in candidates:
            try:
                r = requests.get(url, timeout=12)
                if r.status_code == 200 and r.text and len(r.text) > 100:
                    resp = r
                    used_url = url
                    break
                else:
                    logger.debug(f'Celestrak attempt {url} -> {r.status_code}')
            except Exception as e:
                logger.debug(f'Error fetching {url}: {e}')

        if resp is None:
            logger.warning(f'Failed to fetch TLEs for category "{category}" from Celestrak')
            return []

        lines = [l.strip() for l in resp.text.splitlines() if l.strip()]

        def parse_three_line_groups(lines_list: List[str]) -> List[Tuple[str, str, str]]:
            out = []
            i = 0
            while i + 2 < len(lines_list):
                name = lines_list[i]
                l1 = lines_list[i+1]
                l2 = lines_list[i+2]
                # Basic validation of TLE lines
                if (l1.startswith('1 ') and l2.startswith('2 ')) or (l1[0].isdigit() and l2[0].isdigit()):
                    out.append((name, l1, l2))
                    i += 3
                else:
                    # If format doesn't match, try to slide window forward
                    i += 1
            return out

        # If the feed contains explicit 1/2 lines but no names, pair them
        def parse_pair_lines(lines_list: List[str]) -> List[Tuple[str, str, str]]:
            out = []
            i = 0
            while i < len(lines_list):
                if lines_list[i].startswith('1 ') and i + 1 < len(lines_list) and lines_list[i+1].startswith('2 '):
                    # Try to use previous line as name when available
                    name = lines_list[i-1] if i - 1 >= 0 and not lines_list[i-1].startswith(('1 ', '2 ')) else f'NO_NAME_{i}'
                    out.append((name, lines_list[i], lines_list[i+1]))
                    i += 2
                else:
                    i += 1
            return out

        # Prefer standard 3-line groups; if none found, attempt 1/2 pairing
        tles = parse_three_line_groups(lines)
        if not tles:
            tles = parse_pair_lines(lines)

        logger.info(f'Fetched {len(tles)} TLEs from {used_url or "unknown"} for category {category}')
        return tles
    except Exception as e:
        logger.warning(f'Could not fetch TLEs from Celestrak: {e}')
        return []


def fetch_tles_from_n2yo(ids: List[int]) -> List[Tuple[str, str, str]]:
    """Fetch TLEs from N2YO for a list of NORAD IDs. Requires assets/n2yo.py with API key configured.

    Returns list of (name, line1, line2)
    """
    tles = []
    try:
        # import local helper if present
        try:
            from assets import n2yo as _n2yo
        except Exception:
            # fallback to direct import by filename
            import importlib.util, sys, os
            spec = importlib.util.spec_from_file_location('n2yo', os.path.join(os.path.dirname(__file__), 'assets', 'n2yo.py'))
            n2yo_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(n2yo_mod)
            _n2yo = n2yo_mod

        for nid in ids:
            try:
                data = _n2yo.GetTLEData(str(nid))
                name = data.get('info', {}).get('satname') or f'N2YO_{nid}'
                tle = data.get('tle')
                if not tle:
                    logger.debug(f'N2YO returned no TLE for {nid}')
                    continue
                # TLE may be a string with newlines or a list
                if isinstance(tle, str):
                    lines = [l.strip() for l in tle.splitlines() if l.strip()]
                elif isinstance(tle, (list, tuple)):
                    lines = [l.strip() for l in tle if l and l.strip()]
                else:
                    lines = []

                if len(lines) >= 2:
                    l1 = lines[0] if lines[0].startswith('1 ') else lines[0]
                    l2 = lines[1] if lines[1].startswith('2 ') else lines[1]
                    tles.append((name, l1, l2))
                else:
                    logger.debug(f'Unexpected TLE format from N2YO for {nid}: {tle}')
            except Exception as e:
                logger.debug(f'Failed to fetch/parse N2YO TLE for {nid}: {e}')

    except Exception as e:
        logger.error(f'Error in fetch_tles_from_n2yo: {e}')

    return tles


def propagate_tle_to_latlon(name: str, line1: str, line2: str, when: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """Propagate a TLE to a geodetic lat/lon/alt (WGS84-ish) using SGP4.

    Returns dict with keys: name, lat, lon, altitude  (altitude in km)

    Notes:
    - Uses a simplified TEME->ECEF rotation (GMST-only). For UI visualization this is usually sufficient.
    - Avoids pyorbital's deep-space/near-space limitations that were causing many satellites to fall back to NULL altitude.
    """
    try:
        if when is None:
            when = datetime.utcnow()

        # Prefer python-sgp4: robust for near-earth and deep-space objects
        from sgp4.api import Satrec
        from sgp4.conveniences import jday_datetime
        from sgp4.ext import gstime

        def _ecef_to_geodetic_wgs84(x_m: float, y_m: float, z_m: float):
            # WGS84 constants
            a = 6378137.0
            f = 1.0 / 298.257223563
            b = a * (1.0 - f)
            e2 = 1.0 - (b*b)/(a*a)
            ep2 = (a*a - b*b)/(b*b)

            import math
            lon = math.atan2(y_m, x_m)
            p = math.hypot(x_m, y_m)

            # Bowring's method
            theta = math.atan2(z_m * a, p * b)
            st = math.sin(theta)
            ct = math.cos(theta)
            lat = math.atan2(z_m + ep2 * b * (st**3), p - e2 * a * (ct**3))

            sl = math.sin(lat)
            N = a / math.sqrt(1.0 - e2 * sl * sl)
            alt_m = p / math.cos(lat) - N

            return lat, lon, alt_m

        sat = Satrec.twoline2rv(line1, line2)
        jd, fr = jday_datetime(when)
        err, r_km, _v_km_s = sat.sgp4(jd, fr)
        if err != 0:
            # Non-zero error codes: https://pypi.org/project/sgp4/ docs; keep UI resilient
            logger.warning(f"Propagation failed for {name}: sgp4 error code {err}")
            return None

        import math
        # TEME -> ECEF via GMST rotation (approx)
        theta = gstime(jd + fr)
        c = math.cos(theta)
        s = math.sin(theta)

        x_km = r_km[0] * c + r_km[1] * s
        y_km = -r_km[0] * s + r_km[1] * c
        z_km = r_km[2]

        lat_rad, lon_rad, alt_m = _ecef_to_geodetic_wgs84(x_km * 1000.0, y_km * 1000.0, z_km * 1000.0)

        return {
            "name": name,
            "lat": float(lat_rad * 180.0 / math.pi),
            "lon": float(lon_rad * 180.0 / math.pi),
            "altitude": float(alt_m) / 1000.0,  # km
        }

    except Exception as e:
        # Fallback: keep previous behavior if SGP4 isn't installed
        try:
            from pyorbital.orbital import Orbital
            if when is None:
                when = datetime.utcnow()
            orb = Orbital(name, line1=line1, line2=line2)
            lon, lat, alt_m = orb.get_lonlatalt(when)
            return {"name": name, "lat": lat, "lon": lon, "altitude": float(alt_m) / 1000.0}
        except Exception as e2:
            logger.warning(f"Propagation failed for {name}: {e2}")
            return None

def update_satellite_db_from_tles(tles: List[Tuple[str, str, str]], operator: str = 'Celestrak'):
    """Propagate TLEs and upsert into the satellites SQLite table."""
    try:
        import sqlite3
        db_path = metrics_logger.db_path
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        for name, l1, l2 in tles:
            try:
                pos = propagate_tle_to_latlon(name, l1, l2)
                extra = {'tle': [l1, l2], 'source': 'celestrak'}
                if pos is None:
                    # Still store TLE for future processing
                    cursor.execute('SELECT id FROM satellites WHERE name = ?', (name,))
                    row = cursor.fetchone()
                    if row:
                        cursor.execute('UPDATE satellites SET operator = ?, extra = ? WHERE id = ?', (operator, json.dumps(extra), row[0]))
                    else:
                        cursor.execute('INSERT INTO satellites (name, operator, extra, status) VALUES (?, ?, ?, ?)', (name, operator, json.dumps(extra), 'stale'))
                    continue

                # Try to find existing record by name
                cursor.execute('SELECT id FROM satellites WHERE name = ?', (name,))
                row = cursor.fetchone()
                extra_json = json.dumps(extra)
                if row:
                    cursor.execute('''
                        UPDATE satellites SET lat = ?, lon = ?, altitude = ?, operator = ?, extra = ?, status = ?, launch_date = ? WHERE id = ?
                    ''', (pos['lat'], pos['lon'], pos['altitude'], operator, extra_json, 'active', None, row[0]))
                else:
                    cursor.execute('''
                        INSERT INTO satellites (name, lat, lon, altitude, operator, type, frequency, orbit, coverage, status, launch_date, mission, extra)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (name, pos['lat'], pos['lon'], pos['altitude'], operator, None, None, None, None, 'active', None, None, extra_json))
            except Exception as e:
                logger.warning(f'Failed to upsert satellite {name}: {e}')

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f'Error updating satellite DB: {e}')


# Background thread to periodically refresh satellite positions
_satellite_refresh_thread = None
_satellite_refresh_running = False

def _satellite_refresh_loop(interval_seconds: int = 60, categories: List[str] = None):
    global _satellite_refresh_running
    _satellite_refresh_running = True
    if categories is None:
        categories = ['visual', 'starlink', 'active']

    while _satellite_refresh_running:
        try:
            all_tles = []
            for cat in categories:
                tles = fetch_tles_from_celestrak(cat)
                if tles:
                    all_tles.extend(tles)

            if all_tles:
                logger.info(f'Updating satellite DB with {len(all_tles)} TLEs')
                update_satellite_db_from_tles(all_tles, operator='Celestrak')
            else:
                logger.info('No TLEs fetched for satellite refresh')
        except Exception as e:
            logger.error(f'Unhandled error in satellite refresh loop: {e}')

        time.sleep(interval_seconds)


def start_satellite_refresh(interval_seconds: int = 60, categories: List[str] = None):
    global _satellite_refresh_thread
    if _satellite_refresh_thread and _satellite_refresh_thread.is_alive():
        return
    _satellite_refresh_thread = threading.Thread(target=_satellite_refresh_loop, args=(interval_seconds, categories or None), daemon=True)
    _satellite_refresh_thread.start()


def _geodetic_to_ecef(lat_deg: float, lon_deg: float, alt_km: float) -> Tuple[float, float, float]:
    """Convert geodetic coordinates (deg,deg,km) to ECEF (km)."""
    # WGS84
    a = 6378.137  # km
    f = 1 / 298.257223563
    e2 = f * (2 - f)

    lat = math.radians(lat_deg)
    lon = math.radians(lon_deg)
    N = a / math.sqrt(1 - e2 * (math.sin(lat) ** 2))

    x = (N + alt_km) * math.cos(lat) * math.cos(lon)
    y = (N + alt_km) * math.cos(lat) * math.sin(lon)
    z = (N * (1 - e2) + alt_km) * math.sin(lat)
    return x, y, z


def _compute_az_el_range(observer_lat: float, observer_lon: float, observer_alt_km: float,
                         sat_lat: float, sat_lon: float, sat_alt_km: float) -> Dict[str, float]:
    """Compute azimuth (deg), elevation (deg) and range (km) from observer to satellite."""
    # Convert to ECEF
    ox, oy, oz = _geodetic_to_ecef(observer_lat, observer_lon, observer_alt_km)
    sx, sy, sz = _geodetic_to_ecef(sat_lat, sat_lon, sat_alt_km)

    # vector from observer to satellite
    vx = sx - ox
    vy = sy - oy
    vz = sz - oz
    # range
    rng = math.sqrt(vx * vx + vy * vy + vz * vz)

    # build local ENU axes at observer
    lat_r = math.radians(observer_lat)
    lon_r = math.radians(observer_lon)
    sin_lat = math.sin(lat_r)
    cos_lat = math.cos(lat_r)
    sin_lon = math.sin(lon_r)
    cos_lon = math.cos(lon_r)

    # East vector
    ex = -sin_lon
    ey = cos_lon
    ez = 0.0

    # North vector
    nx = -sin_lat * cos_lon
    ny = -sin_lat * sin_lon
    nz = cos_lat

    # Up vector
    ux = cos_lat * cos_lon
    uy = cos_lat * sin_lon
    uz = sin_lat

    # projections
    east_comp = ex * vx + ey * vy + ez * vz
    north_comp = nx * vx + ny * vy + nz * vz
    up_comp = ux * vx + uy * vy + uz * vz

    # azimuth: angle from north to east
    az = math.degrees(math.atan2(east_comp, north_comp)) % 360.0
    # elevation
    horiz_dist = math.sqrt(east_comp * east_comp + north_comp * north_comp)
    el = math.degrees(math.atan2(up_comp, horiz_dist))

    return {'az_deg': az, 'el_deg': el, 'range_km': rng}


def populate_satellites_for_category(category: str, observer: Dict[str, float] = None) -> int:
    """Fetch TLEs for a category, propagate, compute az/el (optional), and upsert into DB.

    observer: dict with keys 'lat','lon','alt_km' (altitude in km)
    Returns number of records processed.
    """
    tles = fetch_tles_from_celestrak(category)
    if not tles:
        return 0

    return _populate_tles_into_db(tles, operator='Celestrak', observer=observer)


def _populate_tles_into_db(tles: List[Tuple[str, str, str]], operator: str = 'Celestrak', observer: Dict[str, float] = None) -> int:
    """Common helper to propagate TLEs, compute optional observer az/el, and upsert into DB.
    tles: list of (name, line1, line2)
    operator: source string to store in operator column
    observer: optional dict with lat/lon/alt_km to compute az/el
    """
    processed = 0
    try:
        import sqlite3
        db_path = metrics_logger.db_path
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        now_iso = datetime.utcnow().isoformat()
        for name, l1, l2 in tles:
            try:
                pos = propagate_tle_to_latlon(name, l1, l2)
                extra = {'tle': [l1, l2], 'source': operator.lower() if operator else None, 'updated_at': now_iso}

                azel = None
                if observer and pos:
                    try:
                        azel = _compute_az_el_range(observer.get('lat'), observer.get('lon'), observer.get('alt_km', 0.0),
                                                     pos['lat'], pos['lon'], pos['altitude'])
                        extra['observer_az_el'] = azel
                    except Exception as e:
                        logger.debug(f'Az/el compute failed for {name}: {e}')

                # upsert
                cursor.execute('SELECT id FROM satellites WHERE name = ?', (name,))
                row = cursor.fetchone()
                extra_json = json.dumps(extra)
                if pos:
                    lat_val = pos['lat']
                    lon_val = pos['lon']
                    alt_val = pos['altitude']
                else:
                    lat_val = None
                    lon_val = None
                    alt_val = None

                if row:
                    cursor.execute('''
                        UPDATE satellites SET lat = ?, lon = ?, altitude = ?, operator = ?, extra = ?, status = ? WHERE id = ?
                    ''', (lat_val, lon_val, alt_val, operator, extra_json, 'active' if pos else 'stale', row[0]))
                else:
                    cursor.execute('''
                        INSERT INTO satellites (name, lat, lon, altitude, operator, type, frequency, orbit, coverage, status, launch_date, mission, extra)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (name, lat_val, lon_val, alt_val, operator, None, None, None, None, 'active' if pos else 'stale', None, None, extra_json))

                processed += 1
            except Exception as e:
                logger.debug(f'Failed to populate satellite {name}: {e}')
                continue

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f'Error populating satellites from TLEs (operator={operator}): {e}')

    return processed


def api_populate_satellites():
    """Populate satellite DB from a Celestrak category and optionally compute az/el for an observer.

    JSON body:
      { "category": "starlink", "observer": {"lat": 37.77, "lon": -122.42, "alt_km": 0.0} }
    """
    try:
        data = request.get_json() or {}
        category = data.get('category') or request.args.get('category') or 'starlink'
        observer = data.get('observer')
        source = data.get('source', 'celestrak')

        # If client provided explicit NORAD ids and requested n2yo source, use that
        if source.lower() == 'n2yo' and data.get('ids'):
            ids = data.get('ids')
            tles = fetch_tles_from_n2yo(ids)
            count = _populate_tles_into_db(tles, operator='N2YO', observer=observer)
            return jsonify({'status': 'ok', 'processed': count, 'source': 'n2yo', 'ids_requested': len(ids)})

        # Default: fetch by category from Celestrak
        count = populate_satellites_for_category(category, observer)
        return jsonify({'status': 'ok', 'processed': count, 'category': category})
    except Exception as e:
        logger.error(f'Error in populate API: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500



# ============================================================================
# SPATIAL INDEX FOR O(log n) PROXIMITY QUERIES
# ============================================================================

class SpatialIndex:
    """
    Spatial index using k-d tree for efficient proximity queries.
    Converts lat/lon to 3D Cartesian coordinates for accurate distance computation.
    """
    
    EARTH_RADIUS_NM = 3440.065  # Nautical miles
    
    def __init__(self):
        self._tree = None
        self._entity_ids: List[str] = []
        self._coordinates: np.ndarray = None
        self._dirty = True
        self._last_build_time = 0
        self._build_count = 0
    
    def _latlon_to_cartesian(self, lat: float, lon: float) -> Tuple[float, float, float]:
        """Convert lat/lon to 3D Cartesian coordinates on unit sphere."""
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)
        
        x = math.cos(lat_rad) * math.cos(lon_rad)
        y = math.cos(lat_rad) * math.sin(lon_rad)
        z = math.sin(lat_rad)
        
        return (x, y, z)
    
    def _chord_to_arc_distance(self, chord_distance: float) -> float:
        """Convert chord distance on unit sphere to arc distance in nautical miles."""
        # chord = 2 * sin(angle/2), so angle = 2 * arcsin(chord/2)
        if chord_distance >= 2.0:
            return math.pi * self.EARTH_RADIUS_NM  # Half circumference
        angle = 2 * math.asin(chord_distance / 2)
        return angle * self.EARTH_RADIUS_NM
    
    def _arc_to_chord_distance(self, arc_nm: float) -> float:
        """Convert arc distance in nautical miles to chord distance on unit sphere."""
        angle = arc_nm / self.EARTH_RADIUS_NM
        return 2 * math.sin(angle / 2)
    
    def build(self, entities: Dict[str, Dict[str, Any]]):
        """Build or rebuild the spatial index from entities."""
        start = time.perf_counter()
        
        if not entities:
            self._tree = None
            self._entity_ids = []
            self._coordinates = None
            self._dirty = False
            return
        
        self._entity_ids = list(entities.keys())
        coords = []
        valid_ids = []
        
        for entity_id in self._entity_ids:
            entity = entities[entity_id]
            loc = entity.get('location') or {}
            lat = loc.get('lat')
            lon = loc.get('lon')
            if lat is None or lon is None:
                continue
            try:
                lat = float(lat)
                lon = float(lon)
            except (TypeError, ValueError):
                continue
            valid_ids.append(entity_id)
            coords.append(self._latlon_to_cartesian(lat, lon))
        
        self._entity_ids = valid_ids
        self._coordinates = np.array(coords) if coords else None
        
        if SCIPY_AVAILABLE and len(coords) > 0:
            self._tree = cKDTree(self._coordinates)
        else:
            self._tree = None
        
        self._dirty = False
        self._last_build_time = time.perf_counter() - start
        self._build_count += 1
        
        perf_metrics.record('spatial_index_build', self._last_build_time * 1000, 
                           {'entity_count': len(entities)})
    
    def mark_dirty(self):
        """Mark the index as needing rebuild."""
        self._dirty = True
    
    @property
    def is_dirty(self) -> bool:
        return self._dirty
    
    def query_radius(self, lat: float, lon: float, radius_nm: float) -> List[Tuple[str, float]]:
        """
        Find all entities within radius_nm of the given point.
        Returns list of (entity_id, distance_nm) tuples, sorted by distance.
        """
        if self._tree is None or len(self._entity_ids) == 0:
            return []
        
        start = time.perf_counter()
        
        # Convert query point and radius
        query_point = np.array([self._latlon_to_cartesian(lat, lon)])
        chord_radius = self._arc_to_chord_distance(radius_nm)
        
        # Query the tree
        if SCIPY_AVAILABLE:
            indices = self._tree.query_ball_point(query_point[0], chord_radius)
        else:
            # Fallback: brute force O(n)
            distances = np.linalg.norm(self._coordinates - query_point, axis=1)
            indices = np.where(distances <= chord_radius)[0].tolist()
        
        # Convert results with accurate distances
        results = []
        for idx in indices:
            entity_id = self._entity_ids[idx]
            chord_dist = np.linalg.norm(self._coordinates[idx] - query_point[0])
            arc_dist = self._chord_to_arc_distance(chord_dist)
            results.append((entity_id, arc_dist))
        
        # Sort by distance
        results.sort(key=lambda x: x[1])
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('spatial_query_radius', duration_ms, 
                           {'radius_nm': radius_nm, 'result_count': len(results)})
        
        return results
    
    def query_nearest(self, lat: float, lon: float, k: int = 10) -> List[Tuple[str, float]]:
        """
        Find the k nearest entities to the given point.
        Returns list of (entity_id, distance_nm) tuples.
        """
        if self._tree is None or len(self._entity_ids) == 0:
            return []
        
        start = time.perf_counter()
        
        query_point = np.array([self._latlon_to_cartesian(lat, lon)])
        k = min(k, len(self._entity_ids))
        
        if SCIPY_AVAILABLE:
            distances, indices = self._tree.query(query_point, k=k)
            distances = distances[0]
            indices = indices[0]
        else:
            # Fallback: brute force
            all_distances = np.linalg.norm(self._coordinates - query_point, axis=1)
            indices = np.argsort(all_distances)[:k]
            distances = all_distances[indices]
        
        results = []
        for i, idx in enumerate(indices):
            entity_id = self._entity_ids[idx]
            arc_dist = self._chord_to_arc_distance(distances[i])
            results.append((entity_id, arc_dist))
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('spatial_query_nearest', duration_ms, {'k': k})
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get spatial index statistics."""
        return {
            'entity_count': len(self._entity_ids),
            'is_dirty': self._dirty,
            'last_build_time_ms': self._last_build_time * 1000,
            'build_count': self._build_count,
            'scipy_available': SCIPY_AVAILABLE
        }


# ============================================================================
# GRAPH EMBEDDING CACHE FOR SCALABLE GRAPH DISTANCES
# ============================================================================

class GraphEmbeddingCache:
    """
    Cache for graph node embeddings to enable O(1) approximate distance lookups.
    Supports incremental updates when graph structure changes.
    """
    
    def __init__(self, embedding_dim: int = 64):
        self.embedding_dim = embedding_dim
        self.embeddings: Dict[str, np.ndarray] = {}
        self.centrality_cache: Dict[str, float] = {}
        self.dirty_nodes: Set[str] = set()
        self._version = 0
        self._last_compute_time = 0
    
    def compute_simple_embedding(self, node_id: str, neighbors: List[str], 
                                  node_data: Dict[str, Any]) -> np.ndarray:
        """
        Compute a simple embedding for a node based on its properties and neighbors.
        This is a placeholder for more sophisticated methods like Node2Vec or GraphSAGE.
        """
        # Create feature vector from node properties
        features = np.zeros(self.embedding_dim)
        
        # Encode node type/category
        if 'type' in node_data:
            type_hash = hash(node_data['type']) % (self.embedding_dim // 4)
            features[type_hash] = 1.0
        
        # Encode frequency information if available
        if 'frequency' in node_data:
            freq_idx = int((node_data['frequency'] % 1000) / 1000 * (self.embedding_dim // 4))
            features[self.embedding_dim // 4 + freq_idx] = node_data['frequency'] / 1000
        
        # Encode degree (number of neighbors)
        degree = len(neighbors)
        features[self.embedding_dim // 2] = min(1.0, degree / 10)
        
        # Encode neighbor influence (average of neighbor embeddings if available)
        neighbor_sum = np.zeros(self.embedding_dim // 4)
        neighbor_count = 0
        for n_id in neighbors[:10]:  # Limit to 10 neighbors for efficiency
            if n_id in self.embeddings:
                neighbor_sum += self.embeddings[n_id][:self.embedding_dim // 4]
                neighbor_count += 1
        
        if neighbor_count > 0:
            features[3 * self.embedding_dim // 4:] = neighbor_sum / neighbor_count
        
        # Normalize
        norm = np.linalg.norm(features)
        if norm > 0:
            features = features / norm
        
        return features
    
    def update_embedding(self, node_id: str, neighbors: List[str], node_data: Dict[str, Any]):
        """Update embedding for a single node."""
        self.embeddings[node_id] = self.compute_simple_embedding(node_id, neighbors, node_data)
        self.dirty_nodes.discard(node_id)
    
    def mark_dirty(self, node_id: str):
        """Mark a node's embedding as needing recomputation."""
        self.dirty_nodes.add(node_id)
    
    def get_embedding(self, node_id: str) -> Optional[np.ndarray]:
        """Get the embedding for a node."""
        return self.embeddings.get(node_id)
    
    def compute_distance(self, node_id1: str, node_id2: str) -> float:
        """
        Compute approximate distance between two nodes using embeddings.
        Returns L2 distance in embedding space.
        """
        emb1 = self.embeddings.get(node_id1)
        emb2 = self.embeddings.get(node_id2)
        
        if emb1 is None or emb2 is None:
            return float('inf')
        
        return float(np.linalg.norm(emb1 - emb2))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'embedded_nodes': len(self.embeddings),
            'dirty_nodes': len(self.dirty_nodes),
            'embedding_dim': self.embedding_dim,
            'version': self._version,
            'last_compute_time_ms': self._last_compute_time * 1000
        }


# ============================================================================
# AUTO-RECONNAISSANCE SYSTEM (OPTIMIZED)
# ============================================================================

class AutoReconSystem:
    """
    Auto-Reconnaissance system inspired by Anduril Lattice integration.
    Handles entity tracking, proximity alerts, task management, and disposition tracking.
    
    OPTIMIZATIONS (Scalable Graph Distances):
    - Spatial indexing with k-d tree for O(log n) proximity queries
    - Dirty flag tracking for lazy/incremental updates
    - Cached threat levels and distances
    - Batch operations support
    """
    
    # Disposition levels (based on MIL-STD-2525)
    DISPOSITION_UNKNOWN = 'UNKNOWN'
    DISPOSITION_PENDING = 'PENDING'
    DISPOSITION_ASSUMED_FRIEND = 'ASSUMED_FRIEND'
    DISPOSITION_FRIEND = 'FRIEND'
    DISPOSITION_NEUTRAL = 'NEUTRAL'
    DISPOSITION_SUSPICIOUS = 'SUSPICIOUS'
    DISPOSITION_HOSTILE = 'HOSTILE'
    DISPOSITION_JOKER = 'JOKER'
    DISPOSITION_FAKER = 'FAKER'
    
    # Proximity thresholds (nautical miles)
    PROXIMITY_CRITICAL = 1.0    # 1 NM - immediate threat
    PROXIMITY_WARNING = 3.0     # 3 NM - close monitoring
    PROXIMITY_ALERT = 5.0       # 5 NM - standard alert radius
    PROXIMITY_AWARENESS = 10.0  # 10 NM - situational awareness
    
    # Movement threshold for dirty tracking (degrees)
    MOVEMENT_THRESHOLD = 0.001  # ~100 meters
    
    def __init__(self, cache_ttl: int = 120):
        """Initialize the Auto-Recon system"""
        self.entities: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = cache_ttl  # Time-to-live for entity cache in seconds
        self.reference_point = {'lat': 37.7749, 'lon': -122.4194}  # Default: San Francisco
        self.active = True
        self._task_counter = 0
        self._entity_counter = 0
        self.start_time = time.time()
        
        # Optimization: Spatial index for O(log n) proximity queries
        self._spatial_index = SpatialIndex()
        
        # Optimization: Track dirty entities for incremental updates
        self._dirty_entities: Set[str] = set()
        self._last_positions: Dict[str, Tuple[float, float]] = {}
        
        # Optimization: Cache for computed values
        self._cached_alerts: List[Dict[str, Any]] = []
        self._alerts_cache_valid = False
        self._last_reference_point = self.reference_point.copy()
        
        # Optimization: Graph embedding cache
        self._embedding_cache = GraphEmbeddingCache(embedding_dim=32)
        
        # Performance tracking
        self._update_count = 0
        self._query_count = 0
        
        # Initialize with sample entities
        self._generate_sample_entities()
        self._rebuild_spatial_index()
        
        logger.info(f"AutoReconSystem initialized with {len(self.entities)} sample entities (spatial index: {SCIPY_AVAILABLE})")
    
    def _generate_sample_entities(self):
        """Generate sample entities for demo purposes"""
        sample_entities = [
            {'name': 'ALPHA-01', 'lat': 37.80, 'lon': -122.45, 'disposition': self.DISPOSITION_FRIEND, 'ontology': 'aircraft.fixed_wing.patrol'},
            {'name': 'BRAVO-02', 'lat': 37.75, 'lon': -122.38, 'disposition': self.DISPOSITION_SUSPICIOUS, 'ontology': 'vessel.surface.unknown'},
            {'name': 'CHARLIE-03', 'lat': 37.82, 'lon': -122.50, 'disposition': self.DISPOSITION_NEUTRAL, 'ontology': 'vessel.surface.cargo'},
            {'name': 'DELTA-04', 'lat': 37.68, 'lon': -122.42, 'disposition': self.DISPOSITION_HOSTILE, 'ontology': 'vessel.surface.fast_attack'},
            {'name': 'ECHO-05', 'lat': 37.78, 'lon': -122.35, 'disposition': self.DISPOSITION_UNKNOWN, 'ontology': 'aircraft.rotary_wing.unknown'},
            {'name': 'FOXTROT-06', 'lat': 37.72, 'lon': -122.48, 'disposition': self.DISPOSITION_FRIEND, 'ontology': 'vessel.surface.patrol'},
            {'name': 'GOLF-07', 'lat': 37.85, 'lon': -122.40, 'disposition': self.DISPOSITION_PENDING, 'ontology': 'vessel.subsurface.unknown'},
            {'name': 'HOTEL-08', 'lat': 37.70, 'lon': -122.52, 'disposition': self.DISPOSITION_NEUTRAL, 'ontology': 'vessel.surface.fishing'},
        ]
        
        for entity in sample_entities:
            entity_id = f"ENTITY-{self._entity_counter:04d}"
            self._entity_counter += 1
            
            # Calculate distance from reference point
            distance = self._haversine_distance(
                self.reference_point['lat'], self.reference_point['lon'],
                entity['lat'], entity['lon']
            )
            
            # Calculate bearing from reference point
            bearing = self._calculate_bearing(
                self.reference_point['lat'], self.reference_point['lon'],
                entity['lat'], entity['lon']
            )
            
            self.entities[entity_id] = {
                'entity_id': entity_id,
                'name': entity['name'],
                'is_live': True,
                'location': {
                    'lat': entity['lat'],
                    'lon': entity['lon'],
                    'altitude_m': random.uniform(0, 10000) if 'aircraft' in entity['ontology'] else 0
                },
                'velocity': {
                    'speed_kts': random.uniform(5, 30),
                    'heading_deg': random.uniform(0, 360)
                },
                'disposition': entity['disposition'],
                'ontology': entity['ontology'],
                'distance_nm': distance,
                'bearing_deg': bearing,
                'threat_level': self._calculate_threat_level(entity['disposition'], distance),
                'last_update': time.time(),
                'created': time.time(),
                'rf_emissions': random.random() > 0.5,
                'iff_response': entity['disposition'] in [self.DISPOSITION_FRIEND, self.DISPOSITION_ASSUMED_FRIEND]
            }
            
            # Track initial position for dirty detection
            self._last_positions[entity_id] = (entity['lat'], entity['lon'])
    
    def _rebuild_spatial_index(self):
        """Rebuild the spatial index from all entities."""
        self._spatial_index.build(self.entities)
        self._dirty_entities.clear()
        self._invalidate_alerts_cache()
    
    def _invalidate_alerts_cache(self):
        """Invalidate the alerts cache."""
        self._alerts_cache_valid = False
    
    def _check_reference_point_changed(self) -> bool:
        """Check if reference point has changed."""
        if (self._last_reference_point['lat'] != self.reference_point['lat'] or
            self._last_reference_point['lon'] != self.reference_point['lon']):
            self._last_reference_point = self.reference_point.copy()
            return True
        return False
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate the great-circle distance between two points in nautical miles.
        Uses the Haversine formula.
        """
        R = 3440.065  # Earth's radius in nautical miles
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    def _calculate_bearing(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate initial bearing from point 1 to point 2 in degrees"""
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lon = math.radians(lon2 - lon1)
        
        x = math.sin(delta_lon) * math.cos(lat2_rad)
        y = math.cos(lat1_rad) * math.sin(lat2_rad) - math.sin(lat1_rad) * math.cos(lat2_rad) * math.cos(delta_lon)
        
        bearing = math.degrees(math.atan2(x, y))
        return (bearing + 360) % 360
    
    def _calculate_threat_level(self, disposition: str, distance_nm: float) -> str:
        """Calculate threat level based on disposition and proximity"""
        if disposition == self.DISPOSITION_HOSTILE:
            if distance_nm < self.PROXIMITY_CRITICAL:
                return 'CRITICAL'
            elif distance_nm < self.PROXIMITY_WARNING:
                return 'HIGH'
            elif distance_nm < self.PROXIMITY_ALERT:
                return 'MEDIUM'
            else:
                return 'LOW'
        elif disposition == self.DISPOSITION_SUSPICIOUS:
            if distance_nm < self.PROXIMITY_WARNING:
                return 'MEDIUM'
            elif distance_nm < self.PROXIMITY_ALERT:
                return 'LOW'
            else:
                return 'MINIMAL'
        elif disposition in [self.DISPOSITION_UNKNOWN, self.DISPOSITION_PENDING]:
            if distance_nm < self.PROXIMITY_CRITICAL:
                return 'MEDIUM'
            elif distance_nm < self.PROXIMITY_ALERT:
                return 'LOW'
            else:
                return 'MINIMAL'
        else:
            return 'NONE'
    
    def _update_entity_metrics(self, entity_id: str, force: bool = False):
        """Update distance, bearing, and threat level for a single entity."""
        if entity_id not in self.entities:
            return
        
        entity = self.entities[entity_id]
        
        # Only update if dirty or forced
        if not force and entity_id not in self._dirty_entities:
            return
            
        # Validate location data
        if 'location' not in entity or not isinstance(entity['location'], dict) or \
           'lat' not in entity['location'] or 'lon' not in entity['location']:
            # Invalid location data - mark as processed to prevent retry loops
            self._dirty_entities.discard(entity_id)
            return
        
        try:
            entity['distance_nm'] = self._haversine_distance(
                self.reference_point['lat'], self.reference_point['lon'],
                entity['location']['lat'], entity['location']['lon']
            )
            entity['bearing_deg'] = self._calculate_bearing(
                self.reference_point['lat'], self.reference_point['lon'],
                entity['location']['lat'], entity['location']['lon']
            )
            entity['threat_level'] = self._calculate_threat_level(entity.get('disposition', self.DISPOSITION_UNKNOWN), entity['distance_nm'])
        except Exception as e:
            logger.warning(f"Error updating metrics for entity {entity_id}: {e}")
        
        self._dirty_entities.discard(entity_id)
    
    def _update_all_dirty_entities(self):
        """Update metrics for all dirty entities (lazy evaluation)."""
        ref_changed = self._check_reference_point_changed()
        
        if ref_changed:
            # Reference point changed - need to update all entities
            for entity_id in self.entities:
                self._update_entity_metrics(entity_id, force=True)
            self._rebuild_spatial_index()
        elif self._dirty_entities:
            # Only update dirty entities
            for entity_id in list(self._dirty_entities):
                self._update_entity_metrics(entity_id)
            
            # Rebuild spatial index if significant changes
            if len(self._dirty_entities) > len(self.entities) * 0.1:
                self._rebuild_spatial_index()
    
    def get_all_entities(self, include_metrics: bool = True) -> List[Dict[str, Any]]:
        """
        Get all tracked entities.
        
        OPTIMIZATION: Uses lazy evaluation - only updates dirty entities.
        """
        start = time.perf_counter()
        self._query_count += 1
        
        if include_metrics:
            self._update_all_dirty_entities()
        
        result = list(self.entities.values())
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('get_all_entities', duration_ms, {'count': len(result)})
        
        return result
    
    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific entity by ID"""
        entity = self.entities.get(entity_id)
        if entity and entity_id in self._dirty_entities:
            self._update_entity_metrics(entity_id)
        return entity
    
    def get_entities_batch(self, entity_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Get multiple entities by ID in a single call.
        
        OPTIMIZATION: Batch API to reduce network round-trips.
        """
        start = time.perf_counter()
        
        results = []
        for entity_id in entity_ids:
            entity = self.get_entity(entity_id)
            if entity:
                results.append(entity)
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('get_entities_batch', duration_ms, {'requested': len(entity_ids), 'found': len(results)})
        
        return results
    
    def get_entities_in_proximity(self, radius_nm: float = None) -> List[Dict[str, Any]]:
        """
        Get all entities within a specified radius of the reference point.
        
        OPTIMIZATION: Uses spatial index for O(log n) query instead of O(n).
        """
        start = time.perf_counter()
        
        if radius_nm is None:
            radius_nm = self.PROXIMITY_ALERT
        
        # Ensure spatial index is up to date
        if self._spatial_index.is_dirty or self._dirty_entities:
            self._update_all_dirty_entities()
            if self._spatial_index.is_dirty:
                self._rebuild_spatial_index()
        
        # Use spatial index for efficient query
        results_with_dist = self._spatial_index.query_radius(
            self.reference_point['lat'],
            self.reference_point['lon'],
            radius_nm
        )
        
        # Build result list with full entity data
        proximate = []
        for entity_id, distance in results_with_dist:
            if entity_id in self.entities:
                entity = self.entities[entity_id].copy()
                entity['distance_nm'] = distance  # Use exact distance from spatial query
                proximate.append(entity)
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('get_entities_in_proximity', duration_ms, 
                           {'radius_nm': radius_nm, 'result_count': len(proximate)})
        
        return proximate
    
    def get_nearest_entities(self, k: int = 10) -> List[Dict[str, Any]]:
        """
        Get the k nearest entities to the reference point.
        
        OPTIMIZATION: Uses spatial index for O(log n) query.
        """
        start = time.perf_counter()
        
        if self._spatial_index.is_dirty:
            self._rebuild_spatial_index()
        
        results_with_dist = self._spatial_index.query_nearest(
            self.reference_point['lat'],
            self.reference_point['lon'],
            k
        )
        
        nearest = []
        for entity_id, distance in results_with_dist:
            if entity_id in self.entities:
                entity = self.entities[entity_id].copy()
                entity['distance_nm'] = distance
                nearest.append(entity)
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('get_nearest_entities', duration_ms, {'k': k, 'result_count': len(nearest)})
        
        return nearest
    
    def get_entities_by_disposition(self, disposition: str) -> List[Dict[str, Any]]:
        """Get entities filtered by disposition"""
        return [e for e in self.get_all_entities() if e['disposition'] == disposition]
    
    def get_proximity_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all proximity alerts based on threat level.
        
        OPTIMIZATION: Cached results, invalidated when entities change.
        """
        start = time.perf_counter()
        
        # Check if cache is still valid
        if self._alerts_cache_valid and not self._dirty_entities:
            perf_metrics.record('get_proximity_alerts_cached', 0.01)
            return self._cached_alerts
        
        # Rebuild alerts
        alerts = []
        for entity in self.get_all_entities():
            if entity['threat_level'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
                alerts.append({
                    'entity_id': entity['entity_id'],
                    'name': entity['name'],
                    'disposition': entity['disposition'],
                    'distance_nm': entity['distance_nm'],
                    'bearing_deg': entity['bearing_deg'],
                    'threat_level': entity['threat_level'],
                    'alert_type': 'PROXIMITY',
                    'location': entity['location'],
                    'timestamp': time.time()
                })
        
        # Sort by threat level and distance
        threat_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
        alerts.sort(key=lambda x: (threat_order.get(x['threat_level'], 99), x['distance_nm']))
        
        # Cache the result
        self._cached_alerts = alerts
        self._alerts_cache_valid = True
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('get_proximity_alerts', duration_ms, {'alert_count': len(alerts)})
        
        return alerts
    
    def set_reference_point(self, lat: float, lon: float):
        """Set the reference point for proximity calculations"""
        self.reference_point = {'lat': lat, 'lon': lon}
        self._invalidate_alerts_cache()
        # Mark all entities dirty since distances need recalculation
        self._dirty_entities = set(self.entities.keys())
        logger.info(f"Reference point set to: {lat}, {lon}")
    
    # ========================================================================
    # TASK MANAGEMENT
    # ========================================================================
    
    def create_task(self, entity_id: str, task_type: str = 'INVESTIGATE', 
                   asset_id: str = None, priority: int = 5) -> Dict[str, Any]:
        """Create a new investigation/tracking task for an entity"""
        if entity_id not in self.entities:
            return {'status': 'error', 'message': f'Entity {entity_id} not found'}
        
        entity = self.entities[entity_id]
        task_id = f"TASK-{self._task_counter:04d}"
        self._task_counter += 1
        
        task = {
            'task_id': task_id,
            'entity_id': entity_id,
            'entity_name': entity['name'],
            'task_type': task_type,
            'status': 'ASSIGNED',
            'priority': priority,
            'asset_id': asset_id or f"ASSET-{random.randint(1, 10):02d}",
            'created': time.time(),
            'updated': time.time(),
            'target_location': entity['location'].copy(),
            'notes': f"Auto-generated task for {task_type} of {entity['name']}"
        }
        
        self.tasks[task_id] = task
        logger.info(f"Created task {task_id} for entity {entity_id}")
        return {'status': 'ok', 'task': task}
    
    def get_all_tasks(self) -> List[Dict[str, Any]]:
        """Get all tasks"""
        return list(self.tasks.values())
    
    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific task"""
        return self.tasks.get(task_id)
    
    def update_task_status(self, task_id: str, status: str) -> Dict[str, Any]:
        """Update task status"""
        if task_id not in self.tasks:
            return {'status': 'error', 'message': f'Task {task_id} not found'}
        
        valid_statuses = ['PENDING', 'ASSIGNED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED']
        if status not in valid_statuses:
            return {'status': 'error', 'message': f'Invalid status. Must be one of: {valid_statuses}'}
        
        self.tasks[task_id]['status'] = status
        self.tasks[task_id]['updated'] = time.time()
        
        return {'status': 'ok', 'task': self.tasks[task_id]}
    
    def update_entity_disposition(self, entity_id: str, disposition: str) -> Dict[str, Any]:
        """Update an entity's disposition"""
        if entity_id not in self.entities:
            return {'status': 'error', 'message': f'Entity {entity_id} not found'}
        
        valid_dispositions = [
            self.DISPOSITION_UNKNOWN, self.DISPOSITION_PENDING,
            self.DISPOSITION_ASSUMED_FRIEND, self.DISPOSITION_FRIEND,
            self.DISPOSITION_NEUTRAL, self.DISPOSITION_SUSPICIOUS,
            self.DISPOSITION_HOSTILE, self.DISPOSITION_JOKER, self.DISPOSITION_FAKER
        ]
        
        if disposition not in valid_dispositions:
            return {'status': 'error', 'message': f'Invalid disposition. Must be one of: {valid_dispositions}'}
        
        old_disposition = self.entities[entity_id]['disposition']
        self.entities[entity_id]['disposition'] = disposition
        self.entities[entity_id]['last_update'] = time.time()
        
        # Recalculate threat level
        distance = self.entities[entity_id]['distance_nm']
        self.entities[entity_id]['threat_level'] = self._calculate_threat_level(disposition, distance)
        
        # Invalidate alerts cache since disposition affects threat level
        self._invalidate_alerts_cache()
        
        logger.info(f"Entity {entity_id} disposition changed: {old_disposition} -> {disposition}")
        return {'status': 'ok', 'entity': self.entities[entity_id]}
    
    def simulate_entity_movement(self):
        """
        Simulate entity movement for demo purposes.
        
        OPTIMIZATION: Only marks moved entities as dirty, tracks movement threshold.
        """
        start = time.perf_counter()
        moved_count = 0
        
        for entity_id, entity in self.entities.items():
            # Random small movement
            delta_lat = (random.random() - 0.5) * 0.01
            delta_lon = (random.random() - 0.5) * 0.01
            
            new_lat = entity['location']['lat'] + delta_lat
            new_lon = entity['location']['lon'] + delta_lon
            
            # Check if movement exceeds threshold
            old_pos = self._last_positions.get(entity_id, (entity['location']['lat'], entity['location']['lon']))
            movement = abs(new_lat - old_pos[0]) + abs(new_lon - old_pos[1])
            
            if movement > self.MOVEMENT_THRESHOLD:
                self._dirty_entities.add(entity_id)
                self._last_positions[entity_id] = (new_lat, new_lon)
                moved_count += 1
            
            entity['location']['lat'] = new_lat
            entity['location']['lon'] = new_lon
            
            # Update velocity heading
            entity['velocity']['heading_deg'] = random.uniform(0, 360)
            entity['velocity']['speed_kts'] = max(0, entity['velocity']['speed_kts'] + (random.random() - 0.5) * 2)
            entity['last_update'] = time.time()
        
        # Mark spatial index as dirty
        self._spatial_index.mark_dirty()
        self._invalidate_alerts_cache()
        
        self._update_count += 1
        
        duration_ms = (time.perf_counter() - start) * 1000
        perf_metrics.record('simulate_entity_movement', duration_ms, 
                           {'total': len(self.entities), 'moved': moved_count})
        
        return {'status': 'ok', 'updated': len(self.entities), 'significantly_moved': moved_count}
    
    def get_changed_entities(self, since_timestamp: float = None) -> List[Dict[str, Any]]:
        """
        Get entities that have changed since a given timestamp.
        
        OPTIMIZATION: For incremental frontend updates - only send changed data.
        """
        if since_timestamp is None:
            since_timestamp = time.time() - 60  # Default: last minute
        
        changed = []
        for entity in self.entities.values():
            if entity['last_update'] > since_timestamp:
                changed.append(entity)
        
        return changed
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status summary with performance metrics."""
        disposition_counts = {}
        for entity in self.entities.values():
            disp = entity['disposition']
            disposition_counts[disp] = disposition_counts.get(disp, 0) + 1
        
        task_status_counts = {}
        for task in self.tasks.values():
            status = task['status']
            task_status_counts[status] = task_status_counts.get(status, 0) + 1
        
        alerts = self.get_proximity_alerts()
        
        return {
            'active': self.active,
            'entity_count': len(self.entities),
            'task_count': len(self.tasks),
            'alert_count': len(alerts),
            'disposition_breakdown': disposition_counts,
            'task_status_breakdown': task_status_counts,
            'reference_point': self.reference_point,
            'uptime': time.time() - self.start_time,
            # Performance metrics
            'performance': {
                'dirty_entities': len(self._dirty_entities),
                'alerts_cache_valid': self._alerts_cache_valid,
                'spatial_index': self._spatial_index.get_stats(),
                'update_count': self._update_count,
                'query_count': self._query_count
            }
        }


# ============================================================================
# CREATE FLASK APP
# ============================================================================

# Import POI Manager
try:
    from poi_manager import POIManager
    POI_MANAGER_AVAILABLE = True
except ImportError:
    POI_MANAGER_AVAILABLE = False
    logger.warning("POI Manager not available - POI features disabled")

# Import Operator Session Manager
try:
    from operator_session_manager import (
        get_session_manager, 
        OperatorRole, 
        EntityEventType,
        Provenance
    )
    OPERATOR_MANAGER_AVAILABLE = True
except ImportError:
    OPERATOR_MANAGER_AVAILABLE = False
    logger.warning("Operator Session Manager not available - multi-user features disabled")

if FLASK_AVAILABLE:
    # Create Flask app
    app = Flask(__name__, static_folder='.')
    CORS(app)  # Enable CORS for all routes
    
    # Initialize SocketIO for WebSocket support
    socketio = None
    if SOCKETIO_AVAILABLE:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
        logger.info("WebSocket support enabled via Flask-SocketIO")
    else:
        logger.warning("WebSocket support not available - SSE only mode")
    
    # Global stores
    hypergraph_store = RFHypergraphStore()
    nmap_scanner = NmapScanner()
    ndpi_analyzer = NDPIAnalyzer()
    ais_tracker = AISTracker()
    recon_system = AutoReconSystem()
    # Graph event bus (optional Redis-backed durable log)
    try:
        from graph_event_bus import GraphEventBus
    except Exception:
        GraphEventBus = None

    redis_client = None
    redis_url = os.environ.get('OP_SESSION_REDIS_URL') or os.environ.get('REDIS_URL')
    if redis_url:
        try:
            import redis as _redis
            redis_client = _redis.from_url(redis_url, decode_responses=True)
            redis_client.ping()
            logger.info(f"Connected to Redis for GraphEventBus: {redis_url}")
        except Exception as e:
            logger.warning(f"Redis for GraphEventBus not available: {e}")

    if GraphEventBus:
        graph_event_bus = GraphEventBus(redis_client=redis_client, stream_key='graph:events')
        # inject into hypergraph and recon system if they support it
        try:
            hypergraph_store.event_bus = graph_event_bus
        except Exception:
            pass
        try:
            recon_system.event_bus = graph_event_bus
        except Exception:
            pass
        # Optional: create a memory-resident HypergraphEngine and subscribe it to GraphEventBus
        try:
            from hypergraph_engine import HypergraphEngine, RFHypergraphAdapter
            hypergraph_engine = HypergraphEngine()
            # attach event_bus reference
            hypergraph_engine.event_bus = graph_event_bus
            # subscribe engine to incoming graph events
            try:
                graph_event_bus.subscribe(hypergraph_engine.apply_graph_event)
                logger.info('HypergraphEngine subscribed to GraphEventBus')
            except Exception:
                logger.debug('Could not subscribe HypergraphEngine to GraphEventBus')
            # attach for optional use (keeps backward compatibility)
            try:
                hypergraph_store.hypergraph_engine = hypergraph_engine
                # provide an adapter for RF store -> engine mapping
                try:
                    hypergraph_store.rf_adapter = RFHypergraphAdapter(hypergraph_engine)
                except Exception:
                    pass
            except Exception:
                pass
            # Attempt to restore snapshot (if present)
            try:
                snapshot_path = os.path.join('metrics_logs', 'hypergraph_snapshot.json')
                loaded = False
                try:
                    loaded = hypergraph_engine.load_snapshot(snapshot_path)
                except Exception:
                    loaded = False
                if loaded:
                    logger.info(f'HypergraphEngine snapshot loaded from {snapshot_path}')
            except Exception:
                pass

            # Start background snapshot thread to persist engine periodically
            try:
                import atexit
                def _periodic_snapshot(engine, path, interval=60):
                    def _runner():
                        while True:
                            try:
                                engine.save_snapshot(path)
                            except Exception:
                                pass
                            time.sleep(interval)
                    t = threading.Thread(target=_runner, daemon=True)
                    t.start()
                    return t

                snapshot_path = os.path.join('metrics_logs', 'hypergraph_snapshot.json')
                try:
                    _periodic_snapshot(hypergraph_engine, snapshot_path, interval=60)
                except Exception:
                    pass

                def _save_on_exit():
                    try:
                        hypergraph_engine.save_snapshot(snapshot_path)
                    except Exception:
                        pass

                try:
                    atexit.register(_save_on_exit)
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            hypergraph_engine = None
    else:
        graph_event_bus = None
    
    # AISStream WebSocket client
    aisstream_ws = None
    aisstream_thread = None
    aisstream_active = False
    aisstream_bounding_box = None
    
    # POI Manager
    if POI_MANAGER_AVAILABLE:
        poi_manager = POIManager(db_path='poi_database.db')
    else:
        poi_manager = None
    
    # ============================================================================
    # REHYDRATION HELPERS
    # ============================================================================
    def ensure_global_room(operator_mgr):
        """Ensure explicit Global room exists in DB."""
        if not operator_mgr: return
        
        # Try to find Global room
        global_room = None
        if hasattr(operator_mgr, 'get_room_by_name'):
            global_room = operator_mgr.get_room_by_name("Global")
        
        if not global_room:
            # Create it if missing
            try:
                # public room, system created
                if hasattr(operator_mgr, 'create_room'):
                    res = operator_mgr.create_room("Global", "public", created_by="system")
                    logger.info(f"Created 'Global' room during rehydration: {res}")
            except Exception as e:
                logger.warning(f"Could not ensure Global room: {e}")

    def rehydrate_recon_from_operator_db(operator_mgr, recon_sys):
        """Restore entity state from durable sqlite to in-memory recon system."""
        if not operator_mgr or not recon_sys:
            return

        logger.info("Rehydrating Recon System from Operator Session DB...")

        # 1. Ensure Global room
        ensure_global_room(operator_mgr)
        
        # 2. Get Global room ID
        global_room_id = "room_global_default" 
        if hasattr(operator_mgr, 'get_room_by_name'):
            rm = operator_mgr.get_room_by_name("Global")
            if rm: global_room_id = rm.room_id

        # Types that belong in the Recon system (trackable on the globe)
        REHYDRATE_TYPES = {"RECON_ENTITY", "PCAP_HOST", "NMAP_TARGET"}

        # 3. Load snapshot
        try:
            if hasattr(operator_mgr, 'get_room_entities_snapshot'):
                snapshot = operator_mgr.get_room_entities_snapshot(global_room_id)
                count = 0
                skipped = 0
                for ent in snapshot:
                    # entity = {id:..., type:..., data:{...}}
                    entity_id = ent.get('id')
                    entity_type = ent.get('type', '')
                    data = ent.get('data') or {}

                    # Only rehydrate trackable entity types into Recon
                    if entity_type not in REHYDRATE_TYPES:
                        skipped += 1
                        continue
                    
                    if entity_id and data:
                        # Ensure 'location' dict exists for SpatialIndex (required by rebuild_spatial_index)
                        if 'location' not in data:
                             lat = data.get('lat', 0)
                             lon = data.get('lon', 0)
                             alt = data.get('alt', 0)
                             data['location'] = {
                                 'lat': lat,
                                 'lon': lon,
                                 'altitude_m': alt
                             }

                        # Ensure required metrics keys exist to prevent KeyErrors if metric calculation fails or is skipped
                        data.setdefault('threat_level', 'UNKNOWN')
                        data.setdefault('distance_nm', 0.0)
                        data.setdefault('bearing_deg', 0.0)
                        data.setdefault('disposition', 'UNKNOWN')

                        # Direct injection into recon system
                        recon_sys.entities[entity_id] = data
                        # Mark dirty to update derived stats
                        if hasattr(recon_sys, '_dirty_entities'):
                            recon_sys._dirty_entities.add(entity_id)
                        count += 1
                
                logger.info(f"Rehydrated {count} trackable entities into Recon System (skipped {skipped} non-recon types).")
                # Trigger spatial index rebuild
                if hasattr(recon_sys, '_rebuild_spatial_index'):
                    recon_sys._rebuild_spatial_index()

        except Exception as e:
            logger.error(f"Rehydration failed: {e}", exc_info=True)

    # Operator Session Manager
    if OPERATOR_MANAGER_AVAILABLE:
        operator_manager = get_session_manager()
        # REHYDRATE IMMEDIATELY
        rehydrate_recon_from_operator_db(operator_manager, recon_system)
        
        logger.info(f"Operator Session Manager initialized: {operator_manager.get_stats()}")

        # Initialize WriteBus (Core Chokepoint)
        try:
            import writebus as wb_module
            logger.info(f"[PCAP] writebus module path = {wb_module.__file__}")
            from writebus import init_writebus
            # hypergraph_engine was initialized earlier (approx line 3117)
            hg_engine_ref = globals().get('hypergraph_engine')
            ge_bus_ref = globals().get('graph_event_bus')
            
            init_writebus(
                operator_manager=operator_manager,
                hypergraph_engine=hg_engine_ref,
                default_room="Global",
                graph_event_bus=ge_bus_ref
            )
            logger.info("[OK] WriteBus initialized")
        except ImportError:
            logger.warning("[WARN] WriteBus module not found")
        except Exception as e:
            logger.warning(f"[WARN] WriteBus initialization failed: {e}")

        # SensorRegistry: clean chokepoint (only module allowed to touch BOTH
        # OperatorSessionManager.publish_to_room and HypergraphEngine.add_node/add_edge)
        sensor_registry_instance = None
        try:
            from sensor_registry import init_sensor_registry, upsert_sensor, assign_sensor, emit_activity
            hg = globals().get("hypergraph_engine")
            sensor_registry_instance = init_sensor_registry(operator_manager, hg, global_room_name="Global")
            logger.info("[OK] SensorRegistry initialized")
        except Exception as e:
            logger.warning(f"[WARN] SensorRegistry not available: {e}")

        # PcapRegistry: clean chokepoint for PCAP artifacts
        pcap_registry_instance = None
        try:
            # UPDATED: Use refactored registry inside registries/ package
            import registries.pcap_registry as pr_module
            logger.info(f"[PCAP] pcap_registry module path = {pr_module.__file__}")
            from registries.pcap_registry import init_pcap_registry, upsert_pcap_artifact, create_pcap_session, ingest_pcap_session
            hg = globals().get("hypergraph_engine")
            pcap_registry_instance = init_pcap_registry(
                operator_manager, hg, global_room_name="Global",
                enable_geoip=True,
                geoip_city_mmdb="assets/GeoLite2-City.mmdb",
                geoip_asn_mmdb="assets/GeoLite2-ASN.mmdb",
            )
            logger.info("[OK] PcapRegistry initialized (Refactored + GeoIP)")
        except ImportError:
            # Fallback for backward compatibility if file not found
            try:
                from pcap_registry import init_pcap_registry, upsert_pcap_artifact, create_pcap_session, ingest_pcap_session
                hg = globals().get("hypergraph_engine")
                pcap_registry_instance = init_pcap_registry(
                    operator_manager, hg, global_room_name="Global",
                    enable_geoip=True,
                    geoip_city_mmdb="assets/GeoLite2-City.mmdb",
                    geoip_asn_mmdb="assets/GeoLite2-ASN.mmdb",
                )
                logger.info("[OK] PcapRegistry initialized (Legacy + GeoIP)")
            except Exception as e:
                logger.warning(f"[WARN] PcapRegistry not available: {e}")
        except Exception as e:
            logger.warning(f"[WARN] PcapRegistry not available: {e}")

        # DetectionRegistry: Two-tier detection policy (Live Edge + Durable Summary)
        try:
            from registries.detection_registry import init_detection_registry
            # Singleton init using default config (Tier A/B enabled)
            # Use globals() assignment to avoid SyntaxError within large function scope
            globals()['detection_registry'] = init_detection_registry()
            logger.info("[OK] DetectionRegistry initialized")
        except ImportError:
            logger.warning("[WARN] DetectionRegistry module not found")
        except Exception as e:
            logger.warning(f"[WARN] DetectionRegistry initialization failed: {e}")


        # Subscribe operator session manager to graph events (prefer durable bus if available)
        try:
            if 'graph_event_bus' in globals() and graph_event_bus is not None:
                try:
                    operator_manager.subscribe_to_graph_events(graph_event_bus)
                except Exception:
                    pass
            elif 'hypergraph_engine' in globals() and hypergraph_engine is not None:
                try:
                    operator_manager.subscribe_to_graph_events(hypergraph_engine)
                except Exception:
                    pass
        except Exception:
            pass
    else:
        operator_manager = None
    
    # ========================================================================
    # API ROUTES - RF HYPERGRAPH
    # ========================================================================

    @app.route('/api/rf-hypergraph/visualization', methods=['GET'])
    def get_hypergraph_visualization():
        """Get hypergraph visualization data"""
        try:
            # Prefer hypergraph_engine (in-memory indices) when available for faster queries
            if 'hypergraph_engine' in globals() and hypergraph_engine is not None:
                data = hypergraph_engine.get_visualization_data() if hasattr(hypergraph_engine, 'get_visualization_data') else hypergraph_store.get_visualization_data()
            else:
                data = hypergraph_store.get_visualization_data()
            return jsonify(data)
        except Exception as e:
            logger.error(f"Error getting visualization: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rf-hypergraph/metrics', methods=['GET'])
    def get_hypergraph_metrics():
        """Get hypergraph metrics"""
        try:
            # Prefer metrics from hypergraph_engine when present
            if 'hypergraph_engine' in globals() and hypergraph_engine is not None and hasattr(hypergraph_engine, 'get_metrics'):
                metrics = hypergraph_engine.get_metrics()
            else:
                metrics = hypergraph_store.get_metrics()
            return jsonify({'status': 'ok', 'metrics': metrics})
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rf-hypergraph/generate-test', methods=['GET'])
    def generate_test_hypergraph():
        """Generate test hypergraph data"""
        try:
            num_nodes = int(request.args.get('nodes', 20))
            freq_min = float(request.args.get('freq_min', 88.0))
            freq_max = float(request.args.get('freq_max', 108.0))
            area_size = float(request.args.get('area_size', 1000.0))
            
            data = hypergraph_store.generate_test_data(num_nodes, freq_min, freq_max, area_size)
            return jsonify(data)
        except Exception as e:
            logger.error(f"Error generating test data: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rf-hypergraph/reset', methods=['POST', 'GET'])
    def reset_hypergraph():
        """Reset hypergraph session"""
        try:
            hypergraph_store.reset()
            return jsonify({'status': 'ok', 'message': 'Hypergraph session reset', 'session_id': hypergraph_store.session_id})
        except Exception as e:
            logger.error(f"Error resetting hypergraph: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rf-hypergraph/status', methods=['GET'])
    def get_hypergraph_status():
        """Get hypergraph status"""
        return jsonify({
            'status': 'ok',
            'session_id': hypergraph_store.session_id,
            'nodes': len(hypergraph_store.nodes),
            'hyperedges': len(hypergraph_store.hyperedges),
            'uptime': time.time() - hypergraph_store.start_time
        })

    # Graph Query DSL endpoint (operator-facing)
    try:
        from graph_query_dsl import parse_dsl, execute_query
    except Exception:
        parse_dsl = None
        execute_query = None

    # Registered long queries (query_id -> stored info)
    REGISTERED_QUERIES = {}
    REGISTERED_QUERIES_LOCK = threading.RLock()
    
    # Persistence helpers: prefer Redis, fall back to SQLite
    def _persist_registered_query(qid: str, entry: Dict[str, Any]):
        try:
            if 'redis_client' in globals() and redis_client:
                try:
                    # store as hash and add to index set
                    redis_client.hset(f"registered_query:{qid}", mapping={
                        'dsl': entry.get('dsl',''),
                        'parsed': json.dumps(entry.get('parsed',{})),
                        'created_at': entry.get('created_at',''),
                        'owner': entry.get('owner','')
                    })
                    redis_client.sadd('registered_queries:set', qid)
                    return True
                except Exception:
                    pass

            # SQLite fallback
            db_path = os.path.join('metrics_logs', 'registered_queries.sqlite3')
            try:
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                import sqlite3
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute('CREATE TABLE IF NOT EXISTS registered_queries (qid TEXT PRIMARY KEY, dsl TEXT, parsed TEXT, created_at TEXT, owner TEXT)')
                cur.execute('REPLACE INTO registered_queries (qid, dsl, parsed, created_at, owner) VALUES (?,?,?,?,?)', (
                    qid, entry.get('dsl',''), json.dumps(entry.get('parsed',{})), entry.get('created_at',''), entry.get('owner','')
                ))
                conn.commit()
                conn.close()
                return True
            except Exception:
                return False
        except Exception:
            return False

    def _delete_registered_query_persist(qid: str):
        try:
            if 'redis_client' in globals() and redis_client:
                try:
                    redis_client.delete(f"registered_query:{qid}")
                    redis_client.srem('registered_queries:set', qid)
                    return True
                except Exception:
                    pass
            db_path = os.path.join('metrics_logs', 'registered_queries.sqlite3')
            try:
                import sqlite3
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute('DELETE FROM registered_queries WHERE qid = ?', (qid,))
                conn.commit()
                conn.close()
                return True
            except Exception:
                return False
        except Exception:
            return False

    def _load_registered_queries_from_persist():
        try:
            loaded = {}
            if 'redis_client' in globals() and redis_client:
                try:
                    qids = redis_client.smembers('registered_queries:set') or set()
                    for qid in qids:
                        try:
                            h = redis_client.hgetall(f"registered_query:{qid}") or {}
                            if not h:
                                continue
                            parsed = {}
                            try:
                                parsed = json.loads(h.get('parsed') or '{}')
                            except Exception:
                                parsed = {}
                            loaded[qid] = {
                                'dsl': h.get('dsl') or '',
                                'parsed': parsed,
                                'created_at': h.get('created_at') or '',
                                'owner': h.get('owner') or ''
                            }
                        except Exception:
                            continue
                    with REGISTERED_QUERIES_LOCK:
                        REGISTERED_QUERIES.update(loaded)
                    return True
                except Exception:
                    pass

            # SQLite fallback
            db_path = os.path.join('metrics_logs', 'registered_queries.sqlite3')
            try:
                import sqlite3
                if not os.path.exists(db_path):
                    return False
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute('SELECT qid, dsl, parsed, created_at, owner FROM registered_queries')
                rows = cur.fetchall()
                for qid, dsl, parsed_text, created_at, owner in rows:
                    try:
                        parsed = json.loads(parsed_text or '{}')
                    except Exception:
                        parsed = {}
                    loaded[qid] = {'dsl': dsl or '', 'parsed': parsed, 'created_at': created_at or '', 'owner': owner or ''}
                conn.close()
                with REGISTERED_QUERIES_LOCK:
                    REGISTERED_QUERIES.update(loaded)
                return True
            except Exception:
                return False
        except Exception:
            return False

    # Attempt to load persisted queries at startup
    try:
        _load_registered_queries_from_persist()
    except Exception:
        pass

    @app.route('/api/hypergraph/query', methods=['POST'])
    def hypergraph_query():
        """Accept a Clarktech Graph Query DSL string and execute against the engine.

        POST JSON {"dsl": "FIND NODES\nWHERE kind = \"rf\"\nRETURN nodes"}
        or plain text body containing the DSL.
        """
        if parse_dsl is None or execute_query is None:
            return jsonify({'status': 'error', 'message': 'DSL module not available'}), 500

        try:
            data = request.get_json(silent=True) or {}
            dsl_text = data.get('dsl') if data else None
            if not dsl_text:
                # try raw body
                dsl_text = request.get_data(as_text=True) or ''
            parsed = parse_dsl(dsl_text)

            hg_eng = globals().get('hypergraph_engine')
            hg_store = globals().get('hypergraph_store')
            # Prefer populated hypergraph_engine; fall back to legacy hypergraph_store
            # Use legacy hypergraph_store by default (contains node_id records),
            # otherwise fall back to the newer hypergraph_engine if present.
            if hg_store:
                engine = hg_store
            elif hg_eng and getattr(hg_eng, 'nodes', None):
                engine = hg_eng
            else:
                engine = hg_eng or hg_store

            if engine is None:
                return jsonify({'status': 'error', 'message': 'Hypergraph engine not available'}), 503

            res = execute_query(engine, parsed)

            # Build canonical subgraph response when requested
            import uuid as _uuid
            seq = None
            try:
                if OPERATOR_MANAGER_AVAILABLE and operator_manager:
                    seq = operator_manager.entity_sequence
            except Exception:
                seq = None

            # helper normalizers
            def _norm_node(n: dict) -> dict:
                nid = n.get('id') or n.get('node_id') or n.get('nodeId') or n.get('node')
                kind = n.get('kind') or n.get('type')
                if not kind and nid and isinstance(nid, str):
                    # infer from prefix
                    if nid.lower().startswith('rf'):
                        kind = 'rf'
                    elif nid.lower().startswith('net') or nid.lower().startswith('net_'):
                        kind = 'network_host'
                position = None
                if 'position' in n and n.get('position'):
                    position = n.get('position')
                elif 'lat' in n and 'lon' in n:
                    position = [n.get('lat'), n.get('lon'), n.get('alt', 0)]

                labels = n.get('labels') if isinstance(n.get('labels'), dict) else {}
                # include common labelable fields
                for k in ('service','vessel_type','callsign','hostname'):
                    if k in n and n[k]:
                        labels[k] = n[k]

                created_at = n.get('created_at') or n.get('timestamp') or n.get('time') or None
                updated_at = n.get('updated_at') or n.get('timestamp') or created_at

                return {
                    'id': nid,
                    'kind': kind,
                    'position': position,
                    'frequency': n.get('frequency'),
                    'labels': labels,
                    'metadata': n.get('metadata') or {},
                    'created_at': created_at,
                    'updated_at': updated_at
                }

            def _norm_edge(e: dict) -> dict:
                eid = e.get('id') or e.get('edge_id') or None
                return {
                    'id': eid or None,
                    'kind': e.get('kind'),
                    'nodes': e.get('nodes') or [],
                    'weight': e.get('weight') or e.get('signal_strength') or None,
                    'labels': e.get('labels') or {},
                    'metadata': e.get('metadata') or {},
                    'timestamp': e.get('timestamp') or None
                }

            if parsed.get('return') == 'subgraph' or parsed.get('find') == 'subgraph':
                nodes = [ _norm_node(n) for n in res.get('nodes', []) ]
                edges = [ _norm_edge(e) for e in res.get('edges', []) ]
                stats = {
                    'node_count': len(nodes),
                    'edge_count': len(edges),
                    'central_nodes': [],
                    'kinds': {}
                }
                for n in nodes:
                    k = n.get('kind') or 'unknown'
                    stats['kinds'][k] = stats['kinds'].get(k, 0) + 1

                payload = {
                    'query_id': _uuid.uuid4().hex,
                    'sequence_id': seq or 0,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'nodes': nodes,
                    'edges': edges,
                    'stats': stats
                }
                return jsonify({'status': 'ok', 'query': parsed, 'result': payload})

            return jsonify({'status': 'ok', 'query': parsed, 'result': res})
        except Exception as e:
            logger.error(f"Error executing DSL query: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/satellites', methods=['GET'])
    def get_satellites():
        """Return satellite constellation records from SQLite.

        Query params:
            name: optional substring to filter satellite name
            limit: number of records to return (default 100)
            offset: pagination offset (default 0)
        """
        try:
            name_q = request.args.get('name')
            limit = int(request.args.get('limit', 100))
            offset = int(request.args.get('offset', 0))

            import sqlite3
            db_path = metrics_logger.db_path
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            base_query = 'SELECT id, name, lat, lon, altitude, operator, type, frequency, orbit, coverage, status, launch_date, mission, extra FROM satellites'
            params = []
            if name_q:
                base_query += ' WHERE name LIKE ?'
                params.append(f'%{name_q}%')

            base_query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])

            cursor.execute(base_query, params)
            rows = cursor.fetchall()
            result = []
            for r in rows:
                item = dict(r)
                # parse extra JSON if present
                try:
                    if item.get('extra'):
                        item['extra'] = json.loads(item['extra'])
                except Exception:
                    pass
                result.append(item)

            conn.close()
            return jsonify({'status': 'ok', 'satellites': result, 'count': len(result)})
        except Exception as e:
            logger.error(f'Error fetching satellites: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # Subgraph diff endpoint - incremental updates between sequences
    try:
        from subgraph_diff import SubgraphDiffGenerator, QueryPredicate
    except Exception:
        SubgraphDiffGenerator = None
        QueryPredicate = None

    @app.route('/api/hypergraph/diff', methods=['POST'])
    def hypergraph_diff():
        """Return a Clarktech Subgraph Diff between sequences for a DSL-scoped query.

        POST JSON: { "dsl": "FIND ...", "from_sequence": 123, "to_sequence": 130, "query_id": "optional" }
        """
        if SubgraphDiffGenerator is None or QueryPredicate is None:
            return jsonify({'status': 'error', 'message': 'Subgraph diff module not available'}), 500

        try:
            payload = request.get_json(silent=True) or {}
            dsl_text = payload.get('dsl') or request.get_data(as_text=True) or ''
            from_seq = int(payload.get('from_sequence') or payload.get('from') or 0)
            to_seq = int(payload.get('to_sequence') or payload.get('to') or 0)
            qid = payload.get('query_id') or None

            if not dsl_text:
                return jsonify({'status': 'error', 'message': 'Missing DSL in request'}), 400

            # parse DSL
            parsed = parse_dsl(dsl_text) if parse_dsl else {}

            # select engine (prefer in-memory hypergraph_engine)
            engine = globals().get('hypergraph_engine') or globals().get('hypergraph_store')
            if engine is None:
                return jsonify({'status': 'error', 'message': 'Hypergraph engine not available'}), 503

            # build predicate from parsed DSL
            predicate = QueryPredicate(parsed)

            # use redis_client if present
            redis_conn = globals().get('redis_client')

            gen = SubgraphDiffGenerator(engine, operator_manager=globals().get('operator_manager'), redis_client=redis_conn)

            # If requested to auto-advance to latest seq, set to_seq to current sequence
            if to_seq == 0 and OPERATOR_MANAGER_AVAILABLE and operator_manager:
                try:
                    to_seq = operator_manager.entity_sequence
                except Exception:
                    to_seq = to_seq

            diff = gen.generate_diff(qid or parsed.get('query_id') or 'query', predicate, from_seq, to_seq)
            return jsonify({'status': 'ok', 'query': parsed, 'diff': diff})
        except Exception as e:
            logger.error(f"Error generating subgraph diff: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    # ----------------------- Missions API ---------------------------------
    def _save_mission_to_db(mission):
        try:
            import sqlite3
            conn = sqlite3.connect(os.path.join('metrics_logs', 'metrics.db'))
            c = conn.cursor()
            nowt = time.time()
            c.execute('''INSERT OR REPLACE INTO missions (mission_id, name, owner, status, metadata, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM missions WHERE mission_id = ?), ?), ?)
                      ''', (
                mission.get('mission_id'), mission.get('name'), mission.get('owner'), mission.get('status', 'open'), json.dumps(mission.get('metadata', {})),
                mission.get('mission_id'), nowt, nowt
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.warning(f"Failed to persist mission: {e}")
            return False

    def _load_mission_from_db(mission_id):
        try:
            import sqlite3
            conn = sqlite3.connect(os.path.join('metrics_logs', 'metrics.db'))
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM missions WHERE mission_id = ?', (mission_id,))
            r = c.fetchone()
            conn.close()
            if not r:
                return None
            rec = dict(r)
            try:
                rec['metadata'] = json.loads(rec.get('metadata') or '{}')
            except Exception:
                rec['metadata'] = {}
            return rec
        except Exception as e:
            logger.warning(f"Failed to load mission from DB: {e}")
            return None

    @app.route('/api/missions', methods=['POST'])
    def create_mission():
        try:
            data = request.get_json() or {}
            mission_id = data.get('mission_id') or f"mission_{int(time.time()*1000)}_{random.randint(1,9999)}"
            meta = {
                'mission_id': mission_id,
                'name': data.get('name',''),
                'owner': (operator_manager.get_operator_for_session(request.headers.get('X-Session-Token')).operator_id if operator_manager and request.headers.get('X-Session-Token') else data.get('owner')),
                'status': 'open',
                'metadata': data.get('metadata', {}),
                'created_at': time.time(),
                'updated_at': time.time()
            }
            ok = _save_mission_to_db(meta)
            if not ok:
                return jsonify({'status': 'error', 'message': 'Could not persist mission'}), 500
            return jsonify({'status': 'ok', 'mission': meta}), 201
        except Exception as e:
            logger.error(f"create_mission error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>', methods=['GET'])
    def get_mission(mission_id):
        try:
            rec = _load_mission_from_db(mission_id)
            if not rec:
                return jsonify({'status':'error','message':'Not found'}),404
            return jsonify({'status':'ok','mission':rec})
        except Exception as e:
            logger.error(f"get_mission error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>', methods=['PATCH'])
    def patch_mission(mission_id):
        try:
            rec = _load_mission_from_db(mission_id)
            if not rec:
                return jsonify({'status':'error','message':'Not found'}),404
            data = request.get_json() or {}
            rec['name'] = data.get('name', rec.get('name'))
            rec['metadata'] = {**(rec.get('metadata') or {}), **(data.get('metadata') or {})}
            rec['updated_at'] = time.time()
            _save_mission_to_db(rec)
            return jsonify({'status':'ok','mission':rec})
        except Exception as e:
            logger.error(f"patch_mission error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>/end', methods=['POST'])
    def end_mission(mission_id):
        try:
            rec = _load_mission_from_db(mission_id)
            if not rec:
                return jsonify({'status':'error','message':'Not found'}),404
            rec['status'] = 'closed'
            rec['updated_at'] = time.time()
            _save_mission_to_db(rec)
            return jsonify({'status':'ok','mission':rec})
        except Exception as e:
            logger.error(f"end_mission error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>/join', methods=['POST'])
    def join_mission(mission_id):
        try:
            token = request.headers.get('X-Session-Token')
            operator_id = None
            if operator_manager and token:
                op = operator_manager.get_operator_for_session(token)
                if op: operator_id = getattr(op,'operator_id', None) or getattr(op,'id',None)
            if not operator_id:
                operator_id = request.get_json(silent=True, force=False) and request.get_json().get('operator_id')
            if not operator_id:
                return jsonify({'status':'error','message':'operator id required'}),400
            import sqlite3
            conn = sqlite3.connect(os.path.join('metrics_logs','metrics.db'))
            c = conn.cursor()
            nowt = time.time()
            c.execute('INSERT OR IGNORE INTO mission_members (mission_id, operator_id, role, joined_at) VALUES (?, ?, ?, ?)', (mission_id, operator_id, 'member', nowt))
            conn.commit()
            conn.close()
            return jsonify({'status':'ok','mission_id':mission_id,'operator_id':operator_id})
        except Exception as e:
            logger.error(f"join_mission error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>/leave', methods=['POST'])
    def leave_mission(mission_id):
        try:
            token = request.headers.get('X-Session-Token')
            operator_id = None
            if operator_manager and token:
                op = operator_manager.get_operator_for_session(token)
                if op: operator_id = getattr(op,'operator_id', None) or getattr(op,'id',None)
            if not operator_id:
                operator_id = request.get_json(silent=True, force=False) and request.get_json().get('operator_id')
            if not operator_id:
                return jsonify({'status':'error','message':'operator id required'}),400
            import sqlite3
            conn = sqlite3.connect(os.path.join('metrics_logs','metrics.db'))
            c = conn.cursor()
            c.execute('DELETE FROM mission_members WHERE mission_id = ? AND operator_id = ?', (mission_id, operator_id))
            conn.commit()
            conn.close()
            return jsonify({'status':'ok','mission_id':mission_id,'operator_id':operator_id})
        except Exception as e:
            logger.error(f"leave_mission error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>/operators', methods=['GET'])
    def list_mission_operators(mission_id):
        try:
            import sqlite3
            conn = sqlite3.connect(os.path.join('metrics_logs','metrics.db'))
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT operator_id, role, joined_at FROM mission_members WHERE mission_id = ?', (mission_id,))
            rows = [dict(r) for r in c.fetchall()]
            conn.close()
            return jsonify({'status':'ok','operators':rows})
        except Exception as e:
            logger.error(f"list_mission_operators error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/run/fusion_demo_5km', methods=['POST'])
    def run_fusion_mission_demo():
        """Run the Fusion Demo 5km Mission (RTL-SDR Simulation + AoA/TDoA)"""
        if sensor_registry_instance is None:
             return jsonify({'status':'error','message':'Sensor Registry not initialized'}), 503
        
        try:
            from mission_runner import run_fusion_demo_5km
            
            logger.info("Starting Fusion Demo 5km Mission...")
            trace = run_fusion_demo_5km(sensor_registry_instance)
            logger.info("Fusion Demo 5km Mission completed.")
            
            return jsonify({'status': 'ok', 'message': 'Mission executed successfully', 'trace': trace})
        except Exception as e:
            logger.error(f"Fusion Mission Demo Error: {e}")
            return jsonify({'status':'error', 'message': str(e)}), 500

    @app.route('/api/missions/<mission_id>/subgraph', methods=['GET'])
    def mission_subgraph(mission_id):
        try:
            # optional DSL override
            dsl = request.args.get('dsl') or ''
            parsed = {}
            if dsl and 'parse_dsl' in globals() and parse_dsl:
                try:
                    parsed = parse_dsl(dsl)
                except Exception:
                    parsed = {}

            # build mission predicate wrapper
            def _mission_filter_node(n):
                try:
                    labels = n.get('labels') or {}
                    return labels.get('missionId') == mission_id or n.get('metadata',{}).get('missionId') == mission_id
                except Exception:
                    return False

            # Query engine
            engine = globals().get('hypergraph_engine') or globals().get('hypergraph_store')
            if not engine:
                return jsonify({'status':'error','message':'Engine not available'}),503

            # Use SubgraphDiffGenerator's snapshot helper if available, else do simple scan
            snapshot = None
            try:
                if SubgraphDiffGenerator:
                    pred = QueryPredicate(parsed)
                    # wrap predicate to include mission scoping
                    def wrapped_pred(node_or_edge):
                        try:
                            if isinstance(node_or_edge, dict):
                                labels = node_or_edge.get('labels') or {}
                                if labels.get('missionId') == mission_id: return True
                                if node_or_edge.get('metadata',{}).get('missionId') == mission_id: return True
                        except Exception:
                            pass
                        return pred.matches(node_or_edge) if hasattr(pred,'matches') else False
                    # best-effort: ask engine for scan or snapshot
                    if hasattr(engine, 'query_subgraph'):
                        snapshot = engine.query_subgraph(wrapped_pred)
                    else:
                        # fallback: scan nodes/edges in hypergraph_store
                        nodes = []
                        edges = []
                        try:
                            store = globals().get('hypergraph_store')
                            for nid,n in (getattr(store,'nodes',{}) or {}).items():
                                if _mission_filter_node(n): nodes.append(n)
                            for e in (getattr(store,'hyperedges',[]) or []):
                                # coarse check on metadata
                                if e.get('metadata',{}).get('missionId') == mission_id:
                                    edges.append(e)
                        except Exception:
                            pass
                        snapshot = {'nodes': nodes, 'edges': edges}
                else:
                    snapshot = {'nodes': [], 'edges': []}
            except Exception as e:
                logger.warning(f"mission_subgraph error building snapshot: {e}")
                snapshot = {'nodes': [], 'edges': []}

            return jsonify({'status':'ok','mission_id':mission_id,'subgraph':snapshot})
        except Exception as e:
            logger.error(f"mission_subgraph error: {e}")
            return jsonify({'status':'error','message':str(e)}),500

    @app.route('/api/missions/<mission_id>/diff/stream', methods=['GET'])
    def mission_diff_stream(mission_id):
        """SSE stream of subgraph diffs scoped to a missionId."""
        if SubgraphDiffGenerator is None or QueryPredicate is None:
            return jsonify({'status': 'error', 'message': 'Subgraph diff module not available'}), 500

        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503

        token = request.args.get('token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401

        client = operator_manager.register_sse_client(token)
        if not client:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        # Build a predicate that filters to mission scope
        parsed = {}
        pred = QueryPredicate(parsed)
        def mission_pred(x):
            try:
                labels = x.get('labels') or {}
                if labels.get('missionId') == mission_id: return True
                if x.get('metadata',{}).get('missionId') == mission_id: return True
            except Exception:
                pass
            # fall back to parsed predicate
            try:
                return pred.matches(x) if hasattr(pred,'matches') else False
            except Exception:
                return False

        engine = globals().get('hypergraph_engine') or globals().get('hypergraph_store')
        redis_conn = globals().get('redis_client')
        gen = SubgraphDiffGenerator(engine, operator_manager=operator_manager, redis_client=redis_conn)

        since = request.args.get('since')
        try:
            last_seq = int(since) if since else (operator_manager.entity_sequence if operator_manager else 0)
        except Exception:
            last_seq = 0

        cond = threading.Condition()
        max_seq = {'v': last_seq}

        # subscribe to graph_event_bus if present (reuse existing pattern)
        subscription = None
        try:
            if 'graph_event_bus' in globals() and graph_event_bus is not None:
                def _on_event(ge):
                    try:
                        seq = getattr(ge, 'sequence_id', None) or ge.get('sequence_id') if isinstance(ge, dict) else None
                        if seq is None:
                            seq = getattr(ge, 'sequence', None)
                        if seq is None:
                            return
                        logger.info(f"mission_diff_stream _on_event mission={mission_id} seq={seq}")
                        with cond:
                            if seq > max_seq['v']:
                                max_seq['v'] = int(seq)
                            cond.notify()
                    except Exception:
                        pass

                try:
                    graph_event_bus.subscribe(_on_event)
                    subscription = _on_event
                except Exception:
                    subscription = None
        except Exception:
            subscription = None

        def generate():
            nonlocal last_seq
            try:
                eb = globals().get('graph_event_bus')
                while True:
                    # Fast-path: replay in-process event bus history since last_seq
                    try:
                        if eb and hasattr(eb, 'replay'):
                            recent = eb.replay(last_seq)
                            if recent:
                                # determine max sequence in recent events
                                maxseq = last_seq
                                for e in recent:
                                    try:
                                        seq = getattr(e, 'sequence_id', None) if not isinstance(e, dict) else e.get('sequence_id')
                                        if seq is None:
                                            seq = getattr(e, 'sequence', None) if not isinstance(e, dict) else e.get('sequence')
                                        if seq and int(seq) > int(maxseq):
                                            maxseq = int(seq)
                                    except Exception:
                                        continue
                                if maxseq > last_seq:
                                    try:
                                        diff = gen.generate_diff(f'mission:{mission_id}', QueryPredicate({'missionId': mission_id}), last_seq, maxseq)
                                        last_seq = maxseq
                                        payload = json.dumps(diff)
                                        yield f"event: DIFF\n"
                                        yield f"data: {payload}\n\n"
                                        # continue to next iteration without waiting
                                        continue
                                    except GeneratorExit:
                                        break
                                    except Exception as e:
                                        logger.info(f"Error producing mission diff (replay path): {e}")
                    except Exception:
                        pass

                    # Fallback: wait for condition notified by subscription or timeout
                    with cond:
                        cond.wait(timeout=5.0)
                        current = max_seq['v']
                    if current is None:
                        current = last_seq
                    if current > last_seq:
                        try:
                            diff = gen.generate_diff(f'mission:{mission_id}', QueryPredicate({'missionId': mission_id}), last_seq, current)
                            last_seq = current
                            payload = json.dumps(diff)
                            yield f"event: DIFF\n"
                            yield f"data: {payload}\n\n"
                        except GeneratorExit:
                            break
                        except Exception as e:
                            logger.info(f"Error producing mission diff: {e}")
                    else:
                        hb = json.dumps({'mission_id': mission_id, 'to_sequence': last_seq, 'timestamp': datetime.utcnow().isoformat() + 'Z'})
                        try:
                            yield f"event: HEARTBEAT\n"
                            yield f"data: {hb}\n\n"
                        except GeneratorExit:
                            break
            finally:
                try:
                    if subscription and 'graph_event_bus' in globals() and graph_event_bus is not None:
                        try:
                            graph_event_bus.unsubscribe(subscription)
                        except Exception:
                            pass
                except Exception:
                    pass

        return Response(
            generate(), mimetype='text/event-stream', headers={'Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'}
        )

    # ------------------------------------------------------------------
    # Mission Tasks CRUD
    # ------------------------------------------------------------------
    @app.route('/api/missions/<mission_id>/tasks', methods=['POST'])
    def create_mission_task(mission_id):
        """Create a task scoped to a mission."""
        try:
            # ensure mission exists
            if _load_mission_from_db(mission_id) is None:
                return jsonify({'status': 'error', 'message': 'mission not found'}), 404

            data = request.get_json() or {}
            title = data.get('title') or data.get('name') or 'task'
            status = data.get('status', 'PENDING')
            priority = int(data.get('priority', 5))
            payload = data.get('payload') or {}

            task_id = f"{mission_id}_task_{int(time.time()*1000)}_{random.randint(1,9999)}"
            nowt = time.time()

            import sqlite3
            dbp = os.path.join('metrics_logs', 'metrics.db')
            conn = sqlite3.connect(dbp)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO mission_tasks (task_id, mission_id, title, status, priority, payload, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (
                task_id, mission_id, title, status, priority, json.dumps(payload), nowt, nowt
            ))
            conn.commit()
            conn.close()

            return jsonify({'status': 'ok', 'task_id': task_id, 'mission_id': mission_id, 'title': title}), 201
        except Exception as e:
            logger.error(f"create_mission_task error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/missions/<mission_id>/tasks', methods=['GET'])
    def list_mission_tasks(mission_id):
        """List tasks for a mission."""
        try:
            import sqlite3
            dbp = os.path.join('metrics_logs', 'metrics.db')
            conn = sqlite3.connect(dbp)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT task_id, mission_id, title, status, priority, payload, created_at, updated_at FROM mission_tasks WHERE mission_id = ? ORDER BY created_at DESC', (mission_id,))
            rows = [dict(r) for r in c.fetchall()]
            conn.close()
            # parse payload JSON
            for r in rows:
                try:
                    r['payload'] = json.loads(r.get('payload') or '{}')
                except Exception:
                    r['payload'] = {}
            return jsonify({'status': 'ok', 'mission_id': mission_id, 'tasks': rows})
        except Exception as e:
            logger.error(f"list_mission_tasks error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/missions/<mission_id>/tasks/<task_id>', methods=['GET', 'PATCH', 'DELETE'])
    def mission_task_item(mission_id, task_id):
        """Get, update, or delete a mission task."""
        try:
            import sqlite3
            dbp = os.path.join('metrics_logs', 'metrics.db')
            conn = sqlite3.connect(dbp)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # ensure task exists and belongs to mission
            c.execute('SELECT * FROM mission_tasks WHERE task_id = ? AND mission_id = ?', (task_id, mission_id))
            row = c.fetchone()
            if not row:
                conn.close()
                return jsonify({'status': 'error', 'message': 'task not found'}), 404

            if request.method == 'GET':
                rec = dict(row)
                try:
                    rec['payload'] = json.loads(rec.get('payload') or '{}')
                except Exception:
                    rec['payload'] = {}
                conn.close()
                return jsonify({'status': 'ok', 'task': rec})

            if request.method == 'PATCH':
                data = request.get_json() or {}
                title = data.get('title', row['title'])
                status = data.get('status', row['status'])
                priority = int(data.get('priority', row['priority'] or 5))
                payload = data.get('payload') or json.loads(row['payload'] or '{}')
                updated = time.time()
                c.execute('''UPDATE mission_tasks SET title = ?, status = ?, priority = ?, payload = ?, updated_at = ? WHERE task_id = ?''', (
                    title, status, priority, json.dumps(payload), updated, task_id
                ))
                conn.commit()
                conn.close()
                return jsonify({'status': 'ok', 'task_id': task_id, 'mission_id': mission_id})

            if request.method == 'DELETE':
                c.execute('DELETE FROM mission_tasks WHERE task_id = ? AND mission_id = ?', (task_id, mission_id))
                conn.commit()
                conn.close()
                return jsonify({'status': 'ok', 'deleted': task_id})

        except Exception as e:
            logger.error(f"mission_task_item error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ------------------------------------------------------------------
    # Mission Watchlist CRUD
    # ------------------------------------------------------------------
    @app.route('/api/missions/<mission_id>/watchlist', methods=['POST'])
    def add_watchlist_entry(mission_id):
        """Add an entity to the mission watchlist."""
        try:
            if _load_mission_from_db(mission_id) is None:
                return jsonify({'status': 'error', 'message': 'mission not found'}), 404

            data = request.get_json() or {}
            entity_id = data.get('entity_id')
            note = data.get('note', '')
            if not entity_id:
                return jsonify({'status': 'error', 'message': 'entity_id required'}), 400

            nowt = time.time()
            import sqlite3
            dbp = os.path.join('metrics_logs', 'metrics.db')
            conn = sqlite3.connect(dbp)
            c = conn.cursor()
            try:
                c.execute('INSERT OR IGNORE INTO mission_watchlist (mission_id, entity_id, note, added_at) VALUES (?, ?, ?, ?)', (mission_id, entity_id, note, nowt))
                conn.commit()
                # fetch inserted/existing row id
                c.execute('SELECT id, mission_id, entity_id, note, added_at FROM mission_watchlist WHERE mission_id = ? AND entity_id = ?', (mission_id, entity_id))
                r = c.fetchone()
                rec = None
                if r:
                    rec = {'id': r[0], 'mission_id': r[1], 'entity_id': r[2], 'note': r[3], 'added_at': r[4]}
                conn.close()
                return jsonify({'status': 'ok', 'entry': rec}), 201
            except Exception as ie:
                conn.close()
                raise ie

        except Exception as e:
            logger.error(f"add_watchlist_entry error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/missions/<mission_id>/watchlist', methods=['GET'])
    def list_watchlist(mission_id):
        """List watchlist entries for a mission."""
        try:
            import sqlite3
            dbp = os.path.join('metrics_logs', 'metrics.db')
            conn = sqlite3.connect(dbp)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT id, mission_id, entity_id, note, added_at FROM mission_watchlist WHERE mission_id = ? ORDER BY added_at DESC', (mission_id,))
            rows = [dict(r) for r in c.fetchall()]
            conn.close()
            return jsonify({'status': 'ok', 'mission_id': mission_id, 'watchlist': rows})
        except Exception as e:
            logger.error(f"list_watchlist error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/missions/<mission_id>/watchlist/<int:entry_id>', methods=['GET', 'DELETE'])
    def mission_watchlist_item(mission_id, entry_id):
        """Get or remove a watchlist entry."""
        try:
            import sqlite3
            dbp = os.path.join('metrics_logs', 'metrics.db')
            conn = sqlite3.connect(dbp)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT id, mission_id, entity_id, note, added_at FROM mission_watchlist WHERE id = ? AND mission_id = ?', (entry_id, mission_id))
            row = c.fetchone()
            if not row:
                conn.close()
                return jsonify({'status': 'error', 'message': 'watchlist entry not found'}), 404

            if request.method == 'GET':
                rec = dict(row)
                conn.close()
                return jsonify({'status': 'ok', 'entry': rec})

            if request.method == 'DELETE':
                c.execute('DELETE FROM mission_watchlist WHERE id = ? AND mission_id = ?', (entry_id, mission_id))
                conn.commit()
                conn.close()
                return jsonify({'status': 'ok', 'deleted': entry_id})

        except Exception as e:
            logger.error(f"mission_watchlist_item error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/hypergraph/query/register', methods=['POST'])
    def register_hypergraph_query():
        """Register a DSL query server-side and return a stable `query_id`.

        Body: { "dsl": "FIND ...", "query_id": "optional_custom_id" }
        Returns: { status: ok, query_id: "...", parsed: {...} }
        """
        # Require session token (header X-Session-Token or body)
        token = request.headers.get('X-Session-Token') or (request.get_json(silent=True) or {}).get('token')
        if not token or not operator_manager:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401
        operator = operator_manager.get_operator_for_session(token)
        if not operator:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        try:
            data = request.get_json(silent=True) or {}
            dsl = data.get('dsl') or ''
            provided_qid = data.get('query_id')
            if not dsl:
                return jsonify({'status': 'error', 'message': 'dsl required'}), 400

            parsed = None
            try:
                parsed = parse_dsl(dsl) if parse_dsl else {}
            except Exception:
                parsed = {}

            import uuid as _uq
            qid = provided_qid or _uq.uuid4().hex
            entry = {
                'dsl': dsl,
                'parsed': parsed,
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'owner': getattr(operator, 'username', getattr(operator, 'session_id', 'unknown'))
            }
            with REGISTERED_QUERIES_LOCK:
                REGISTERED_QUERIES[qid] = entry

            return jsonify({'status': 'ok', 'query_id': qid, 'parsed': parsed})
        except Exception as e:
            logger.error(f"Error registering query: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/hypergraph/query/register', methods=['GET'])
    def list_registered_queries():
        """List all registered queries (returns map of query_id -> metadata)."""
        # Require session token
        token = request.headers.get('X-Session-Token') or request.args.get('token')
        if not token or not operator_manager:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401
        operator = operator_manager.get_operator_for_session(token)
        if not operator:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        try:
            with REGISTERED_QUERIES_LOCK:
                # Optionally, only return owner-owned queries; for now, return all but label ownership
                summary = {qid: {'created_at': entry.get('created_at'), 'dsl_preview': (entry.get('dsl') or '')[:200], 'owner': entry.get('owner')} for qid, entry in REGISTERED_QUERIES.items()}
            return jsonify({'status': 'ok', 'queries': summary})
        except Exception as e:
            logger.error(f"Error listing registered queries: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/hypergraph/query/register/<query_id>', methods=['GET'])
    def get_registered_query(query_id):
        """Return stored DSL and parsed AST for a `query_id`."""
        # Require session token
        token = request.headers.get('X-Session-Token') or request.args.get('token')
        if not token or not operator_manager:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401
        operator = operator_manager.get_operator_for_session(token)
        if not operator:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        try:
            with REGISTERED_QUERIES_LOCK:
                entry = REGISTERED_QUERIES.get(query_id)
            if not entry:
                return jsonify({'status': 'error', 'message': 'query_id not found'}), 404
            return jsonify({'status': 'ok', 'query_id': query_id, 'entry': entry})
        except Exception as e:
            logger.error(f"Error fetching registered query {query_id}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/hypergraph/query/register/<query_id>', methods=['DELETE'])
    def delete_registered_query(query_id):
        """Delete a registered query by id."""
        # Require session token and owner match (only owner can delete)
        token = request.headers.get('X-Session-Token') or request.args.get('token')
        if not token or not operator_manager:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401
        operator = operator_manager.get_operator_for_session(token)
        if not operator:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        try:
            with REGISTERED_QUERIES_LOCK:
                existed = REGISTERED_QUERIES.get(query_id)
                if not existed:
                    return jsonify({'status': 'error', 'message': 'query_id not found'}), 404
                owner = existed.get('owner')
                op_name = getattr(operator, 'username', getattr(operator, 'session_id', None))
                # Allow deletion if owner matches or operator has admin flag
                allow = False
                try:
                    if owner and op_name and owner == op_name:
                        allow = True
                except Exception:
                    allow = False
                # admin check (best-effort)
                try:
                    if getattr(operator, 'is_admin', False) or getattr(operator, 'role', '') == 'admin':
                        allow = True
                except Exception:
                    pass
                if not allow:
                    return jsonify({'status': 'error', 'message': 'forbidden - only owner or admin can delete'}), 403
                REGISTERED_QUERIES.pop(query_id, None)
            return jsonify({'status': 'ok', 'deleted': query_id})
        except Exception as e:
            logger.error(f"Error deleting registered query {query_id}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/satellites/refresh', methods=['POST', 'GET'])
    def refresh_satellites():
        """Trigger an immediate satellite TLE fetch & propagation (runs async)."""
        try:
            cats = request.args.get('categories', 'visual,starlink,active')
            categories = [c.strip() for c in cats.split(',') if c.strip()]

            def _run_once():
                try:
                    all_tles = []
                    for cat in categories:
                        tles = fetch_tles_from_celestrak(cat)
                        if tles:
                            all_tles.extend(tles)
                    if all_tles:
                        update_satellite_db_from_tles(all_tles, operator='Celestrak')
                        logger.info('Manual satellite refresh completed')
                except Exception as e:
                    logger.error(f'Manual satellite refresh error: {e}')

            threading.Thread(target=_run_once, daemon=True).start()
            return jsonify({'status': 'ok', 'message': 'Satellite refresh started', 'categories': categories})
        except Exception as e:
            logger.error(f'Error starting satellite refresh: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # Register populate endpoint (defined later in module) if available
    try:
        if 'api_populate_satellites' in globals():
            app.add_url_rule('/api/satellites/populate', 'api_populate_satellites', globals()['api_populate_satellites'], methods=['POST'])
            logger.info('Registered /api/satellites/populate route')
    except Exception as e:
        logger.warning(f'Could not register populate route at startup: {e}')

    @app.route('/api/rf-hypergraph/node', methods=['POST'])
    def add_hypergraph_node():
        """Add a node to the hypergraph"""
        try:
            data = request.get_json()
            node_id = hypergraph_store.add_node(data)
            return jsonify({'status': 'ok', 'node_id': node_id})
        except Exception as e:
            logger.error(f"Error adding node: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rf-hypergraph/edge', methods=['POST'])
    def add_hypergraph_edge():
        """Add a hyperedge to the hypergraph"""
        try:
            data = request.get_json()
            edge_idx = hypergraph_store.add_hyperedge(data)
            return jsonify({'status': 'ok', 'edge_index': edge_idx})
        except Exception as e:
            logger.error(f"Error adding edge: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/admin/emit', methods=['POST'])
    def admin_emit():
        """Administrative emit endpoint: accept event dict(s) and publish to GraphEventBus.

        POST JSON: { "events": [ {event}, ... ] } or single event JSON.
        If environment var ADMIN_API_KEY is set, a matching header `X-ADMIN-KEY`
        or query param `admin_key` is required.
        """
        try:
            # optional admin key protection
            admin_key = os.environ.get('ADMIN_API_KEY')
            if admin_key:
                provided = request.headers.get('X-ADMIN-KEY') or request.args.get('admin_key')
                if provided != admin_key:
                    return jsonify({'status': 'error', 'message': 'invalid admin key'}), 401

            payload = request.get_json(silent=True) or {}
            events = payload.get('events') if isinstance(payload, dict) else None
            if events is None:
                # allow a single event body
                if isinstance(payload, dict) and payload:
                    events = [payload]
                else:
                    return jsonify({'status': 'error', 'message': 'no events provided'}), 400

            if 'graph_event_bus' not in globals() or graph_event_bus is None:
                return jsonify({'status': 'error', 'message': 'GraphEventBus not configured on server'}), 503

            results = []
            from types import SimpleNamespace
            for ev in events:
                try:
                    obj = SimpleNamespace(**ev) if isinstance(ev, dict) else ev
                    pubres = graph_event_bus.publish(obj)
                    # pubres is a dict: { 'msg_id': ..., 'sequence_id': ... }
                    msg_id = pubres.get('msg_id') if isinstance(pubres, dict) else pubres
                    seq = pubres.get('sequence_id') if isinstance(pubres, dict) else getattr(obj, 'sequence_id', None)
                    results.append({'status': 'ok', 'msg_id': msg_id, 'sequence_id': seq})
                except Exception as e:
                    logger.error(f'admin_emit publish error: {e}')
                    results.append({'status': 'error', 'message': str(e)})

            return jsonify({'status': 'ok', 'results': results})
        except Exception as e:
            logger.error(f'admin_emit handler error: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - NMAP
    # ========================================================================

    @app.route('/api/nmap/scan', methods=['POST', 'GET'])
    def nmap_scan():
        """Run an nmap scan"""
        try:
            if request.method == 'POST':
                data = request.get_json() or {}
                target = data.get('target', '192.168.1.0/24')
                options = data.get('options', '-sn')
            else:
                target = request.args.get('target', '192.168.1.0/24')
                options = request.args.get('options', '-sn')
            
            results = nmap_scanner.scan(target, options)
            return jsonify(results)
        except Exception as e:
            logger.error(f"Error running nmap scan: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/nmap/status', methods=['GET'])
    def nmap_status():
        """Get nmap scanner status"""
        return jsonify({
            'available': nmap_scanner.check_nmap_available(),
            'scanning': nmap_scanner.scanning,
            'last_scan': nmap_scanner.last_scan_time,
            'cached_results': bool(nmap_scanner.scan_results)
        })

    @app.route('/api/nmap/results', methods=['GET'])
    def nmap_results():
        """Get cached nmap results"""
        return jsonify(nmap_scanner.scan_results or {'status': 'no_results'})

    # ========================================================================
    # API ROUTES - NETWORK HYPERGRAPH (NMAP + HYPERGRAPH)
    # ========================================================================

    @app.route('/api/network-hypergraph/scan', methods=['POST', 'GET'])
    def network_hypergraph_scan():
        """Scan network with nmap and create hypergraph visualization"""
        try:
            if request.method == 'POST':
                data = request.get_json() or {}
                target = data.get('target', '192.168.1.0/24')
                options = data.get('options', '-sV -sn')
                reset = data.get('reset', True)
            else:
                target = request.args.get('target', '192.168.1.0/24')
                options = request.args.get('options', '-sV -sn')
                reset = request.args.get('reset', 'true').lower() == 'true'
            
            # Reset hypergraph if requested
            if reset:
                hypergraph_store.reset()
            
            # Run nmap scan
            logger.info(f"Running network hypergraph scan on {target}")
            scan_results = nmap_scanner.scan(target, options)
            
            if scan_results.get('status') == 'error':
                return jsonify(scan_results), 500
            
            # Convert scan results to hypergraph nodes
            hosts = scan_results.get('hosts', scan_results.get('results', []))
            node_ids = []
            
            for host in hosts:
                node_id = hypergraph_store.add_network_host(host)
                node_ids.append(node_id)
                logger.info(f"Added network host: {host.get('ip')} as {node_id}")
            
            # Create service-based hyperedges
            service_edges = hypergraph_store.create_service_hyperedges()
            logger.info(f"Created {service_edges} service hyperedges")
            
            # Create subnet-based hyperedges
            subnet_edges = hypergraph_store.create_subnet_hyperedges()
            logger.info(f"Created {subnet_edges} subnet hyperedges")
            
            # Get visualization data
            viz_data = hypergraph_store.get_visualization_data()
            viz_data['scan_info'] = {
                'target': target,
                'hosts_discovered': len(hosts),
                'service_groups': service_edges,
                'subnet_groups': subnet_edges,
                'nmap_available': nmap_scanner.check_nmap_available(),
                'simulated': scan_results.get('simulated', False)
            }
            
            return jsonify(viz_data)
        except Exception as e:
            logger.error(f"Error in network hypergraph scan: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/network-hypergraph/localhost', methods=['GET'])
    def network_hypergraph_localhost():
        """Quick scan of localhost services and create hypergraph"""
        try:
            # Reset and scan localhost
            hypergraph_store.reset()
            
            # Scan localhost for open ports
            scan_results = nmap_scanner.scan('127.0.0.1', '-sV -p 1-1024')
            
            hosts = scan_results.get('hosts', scan_results.get('results', []))
            for host in hosts:
                hypergraph_store.add_network_host(host)
            
            # Also add the server itself
            hypergraph_store.add_network_host({
                'ip': '127.0.0.1',
                'hostname': 'rf-scythe-server',
                'ports': [
                    {'port': '8080/tcp', 'state': 'open', 'service': 'http-api'},
                ],
                'status': 'up'
            })
            
            # Create hyperedges
            hypergraph_store.create_service_hyperedges()
            hypergraph_store.create_subnet_hyperedges()
            
            return jsonify(hypergraph_store.get_visualization_data())
        except Exception as e:
            logger.error(f"Error scanning localhost: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/network-hypergraph/quick-scan', methods=['GET'])
    def network_hypergraph_quick_scan():
        """Quick network discovery scan (ping sweep only)"""
        try:
            target = request.args.get('target', '192.168.1.0/24')
            
            # Reset and do ping sweep only (fast)
            hypergraph_store.reset()
            scan_results = nmap_scanner.scan(target, '-sn -T4')
            
            hosts = scan_results.get('hosts', scan_results.get('results', []))
            for host in hosts:
                hypergraph_store.add_network_host(host)
            
            # Create subnet hyperedges
            hypergraph_store.create_subnet_hyperedges()
            
            viz_data = hypergraph_store.get_visualization_data()
            viz_data['scan_type'] = 'quick_discovery'
            viz_data['hosts_found'] = len(hosts)
            
            return jsonify(viz_data)
        except Exception as e:
            logger.error(f"Error in quick scan: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - NDPI
    # ========================================================================

    @app.route('/api/ndpi/analyze', methods=['POST', 'GET'])
    def ndpi_analyze():
        """Run NDPI analysis"""
        try:
            if request.method == 'POST':
                data = request.get_json() or {}
                network_interface = data.get('interface', 'eth0')
                duration = int(data.get('duration', 10))
            else:
                network_interface = request.args.get('interface', 'eth0')
                duration = int(request.args.get('duration', 10))
            
            results = ndpi_analyzer.analyze_interface(network_interface, duration)
            return jsonify(results)
        except Exception as e:
            logger.error(f"Error running NDPI analysis: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ndpi/status', methods=['GET'])
    def ndpi_status():
        """Get NDPI analyzer status"""
        return jsonify({
            'available': ndpi_analyzer.check_ndpi_available(),
            'analyzing': ndpi_analyzer.analyzing,
            'cached_results': bool(ndpi_analyzer.analysis_results)
        })

    @app.route('/api/ndpi/results', methods=['GET'])
    def ndpi_results():
        """Get cached NDPI results"""
        return jsonify(ndpi_analyzer.analysis_results or {'status': 'no_results'})

    # ========================================================================
    # API ROUTES - NETWORK CAPTURE
    # ========================================================================

    @app.route('/api/network/capture-report', methods=['GET', 'POST'])
    def network_capture_report():
        """Generate a network capture report"""
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'summary': 'Network traffic analysis complete. Active connections detected across infrastructure.',
            'geminiConfidence': random.randint(75, 95),
            'total_packets': random.randint(5000, 15000),
            'violations': [
                {'type': 'Unusual Traffic Pattern', 'severity': 'low', 'source': f'10.0.0.{random.randint(1, 254)}'},
                {'type': 'Port Scan Detected', 'severity': 'medium', 'source': f'192.168.1.{random.randint(1, 254)}'}
            ] if random.random() > 0.5 else [],
            'rf_correlation': {
                'signals_detected': random.randint(5, 15),
                'frequency_range': '2.4GHz - 5.8GHz',
                'interference_level': random.choice(['Low', 'Medium', 'Low'])
            },
            'nmap_available': nmap_scanner.check_nmap_available(),
            'ndpi_available': ndpi_analyzer.check_ndpi_available()
        })

    # ========================================================================
    # API ROUTES - AIS VESSEL TRACKING
    # ========================================================================

    @app.route('/api/ais/vessels', methods=['GET'])
    def ais_get_vessels():
        """Get all AIS vessel positions"""
        try:
            # Support server-side pagination for large live sets
            vessels = ais_tracker.get_all_vessels()

            # Pagination params: page/per_page or offset/limit
            page = request.args.get('page', type=int)
            per_page = request.args.get('per_page', type=int)
            limit = request.args.get('limit', type=int)
            offset = request.args.get('offset', default=0, type=int)

            # Determine page size
            if per_page and per_page > 0:
                page_size = min(per_page, 1000)
            elif limit and limit > 0:
                page_size = min(limit, 1000)
            else:
                page_size = 100  # default

            total_vessels = len(vessels)

            if page and page > 0:
                offset = (page - 1) * page_size

            # Clamp offset
            if offset < 0:
                offset = 0

            vessels_page = vessels[offset: offset + page_size]

            pagination = {
                'page': (offset // page_size) + 1 if page_size > 0 else 1,
                'per_page': page_size,
                'offset': offset,
                'returned': len(vessels_page),
                'total': total_vessels,
                'total_pages': (total_vessels + page_size - 1) // page_size if page_size > 0 else 1
            }

            return jsonify({
                'status': 'ok',
                'vessel_count': len(vessels_page),
                'vessels': vessels_page,
                'csv_loaded': ais_tracker.csv_loaded,
                'timestamp': time.time(),
                'pagination': pagination
            })
        except Exception as e:
            logger.error(f"Error getting AIS vessels: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/vessel/<mmsi>', methods=['GET'])
    def ais_get_vessel(mmsi):
        """Get a specific vessel by MMSI"""
        try:
            vessel = ais_tracker.get_vessel(mmsi)
            if vessel:
                return jsonify({
                    'status': 'ok',
                    'vessel': vessel,
                    'timestamp': time.time()
                })
            else:
                return jsonify({'status': 'not_found', 'message': f'Vessel {mmsi} not found'}), 404
        except Exception as e:
            logger.error(f"Error getting vessel {mmsi}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/vessel/<mmsi>/history', methods=['GET'])
    def ais_get_vessel_history(mmsi):
        """Get historical positions for a vessel"""
        try:
            limit = int(request.args.get('limit', 100))
            history = ais_tracker.get_vessel_history(mmsi, limit)
            return jsonify({
                'status': 'ok',
                'mmsi': mmsi,
                'history_count': len(history),
                'history': history,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting vessel history {mmsi}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/advance', methods=['POST', 'GET'])
    def ais_advance_playback():
        """Advance all vessels to next position (simulation playback)"""
        try:
            result = ais_tracker.advance_playback()
            return jsonify({
                'status': 'ok',
                **result
            })
        except Exception as e:
            logger.error(f"Error advancing AIS playback: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/area', methods=['GET'])
    def ais_vessels_in_area():
        """Get vessels within a geographic bounding box"""
        try:
            min_lat = float(request.args.get('min_lat', -90))
            max_lat = float(request.args.get('max_lat', 90))
            min_lon = float(request.args.get('min_lon', -180))
            max_lon = float(request.args.get('max_lon', 180))
            
            vessels = ais_tracker.get_vessels_in_area(min_lat, max_lat, min_lon, max_lon)
            return jsonify({
                'status': 'ok',
                'vessel_count': len(vessels),
                'vessels': vessels,
                'bounding_box': {
                    'min_lat': min_lat, 'max_lat': max_lat,
                    'min_lon': min_lon, 'max_lon': max_lon
                },
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting vessels in area: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/rf-correlation', methods=['GET'])
    def ais_rf_correlation():
        """Correlate AIS vessels with RF emissions"""
        try:
            freq_min = float(request.args.get('freq_min', 156.0))
            freq_max = float(request.args.get('freq_max', 162.5))
            
            correlations = ais_tracker.correlate_with_rf(freq_min, freq_max)
            return jsonify({
                'status': 'ok',
                'correlation_count': len(correlations),
                'correlations': correlations,
                'frequency_band': f'{freq_min}-{freq_max} MHz',
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error correlating AIS with RF: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/status', methods=['GET'])
    def ais_status():
        """Get AIS tracker status"""
        return jsonify({
            'status': 'ok',
            'csv_loaded': ais_tracker.csv_loaded,
            'vessel_count': len(ais_tracker.vessels),
            'total_records': len(ais_tracker.all_records),
            'unique_vessels': len(ais_tracker.vessel_history),
            'timestamp': time.time()
        })

    @app.route('/api/ais/vessel-types', methods=['GET'])
    def ais_get_vessel_types():
        """Get list of all vessel types currently tracked"""
        try:
            vessel_types = ais_tracker.get_vessel_types()
            return jsonify({
                'status': 'ok',
                'vessel_types': vessel_types,
                'count': len(vessel_types),
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting vessel types: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/vessels/filter', methods=['GET'])
    def ais_get_vessels_filtered():
        """Get vessels filtered by type and/or geographic area"""
        try:
            # Get filter parameters
            vessel_types = request.args.getlist('type')  # Multiple types allowed
            min_lat = request.args.get('min_lat', type=float)
            max_lat = request.args.get('max_lat', type=float)
            min_lon = request.args.get('min_lon', type=float)
            max_lon = request.args.get('max_lon', type=float)
            
            # Get filtered vessels
            vessels = ais_tracker.get_vessels_filtered(
                vessel_types=vessel_types if vessel_types else None,
                min_lat=min_lat, max_lat=max_lat,
                min_lon=min_lon, max_lon=max_lon
            )
            
            return jsonify({
                'status': 'ok',
                'vessel_count': len(vessels),
                'vessels': vessels,
                'filters': {
                    'vessel_types': vessel_types,
                    'min_lat': min_lat,
                    'max_lat': max_lat,
                    'min_lon': min_lon,
                    'max_lon': max_lon
                },
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting filtered vessels: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/search', methods=['GET'])
    def ais_search_records():
        """Search through all AIS records"""
        try:
            # Get search parameters
            query = request.args.get('q', '').strip()
            vessel_type = request.args.get('type', 'all')
            min_lat = request.args.get('min_lat', type=float)
            max_lat = request.args.get('max_lat', type=float)
            min_lon = request.args.get('min_lon', type=float)
            max_lon = request.args.get('max_lon', type=float)

            # Pagination: support page/per_page or offset/limit
            page = request.args.get('page', type=int)
            per_page = request.args.get('per_page', type=int)
            limit = request.args.get('limit', type=int)

            if per_page and per_page > 0:
                per_page = min(per_page, 1000)
            if limit is None:
                # default page size
                limit = 100
            else:
                limit = min(limit, 1000)

            if page and page > 0:
                # use page/per_page if provided, else page*limit
                page_size = per_page or limit
                offset = (page - 1) * page_size
                page_size = min(page_size, 1000)
                records_slice, total_matches = ais_tracker.search_records(
                    query=query if query else None,
                    vessel_type=vessel_type if vessel_type != 'all' else None,
                    min_lat=min_lat, max_lat=max_lat,
                    min_lon=min_lon, max_lon=max_lon,
                    limit=page_size, offset=offset, return_total=True
                )
                current_page = page
                per_page_used = page_size
            else:
                # fallback to offset/limit style
                offset = int(request.args.get('offset', 0) or 0)
                records_slice, total_matches = ais_tracker.search_records(
                    query=query if query else None,
                    vessel_type=vessel_type if vessel_type != 'all' else None,
                    min_lat=min_lat, max_lat=max_lat,
                    min_lon=min_lon, max_lon=max_lon,
                    limit=limit, offset=offset, return_total=True
                )
                current_page = (offset // limit) + 1 if limit > 0 else 1
                per_page_used = limit

            # Get unique vessels from results
            unique_vessels = ais_tracker.get_unique_vessels_from_records(records_slice)

            return jsonify({
                'status': 'ok',
                'total_records': len(ais_tracker.all_records),
                'search_results': len(records_slice),
                'total_matches': total_matches,
                'unique_vessels': len(unique_vessels),
                'records': records_slice,
                'vessels': unique_vessels,
                'pagination': {
                    'page': current_page,
                    'per_page': per_page_used,
                    'offset': offset,
                    'total_matches': total_matches,
                    'total_pages': (total_matches + per_page_used - 1) // per_page_used if per_page_used > 0 else 1
                },
                'search_params': {
                    'query': query,
                    'vessel_type': vessel_type,
                    'min_lat': min_lat,
                    'max_lat': max_lat,
                    'min_lon': min_lon,
                    'max_lon': max_lon,
                    'limit': limit,
                    'offset': offset
                },
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error searching AIS records: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/search/stats', methods=['GET'])
    def ais_search_stats():
        """Get statistics about AIS records for search interface"""
        try:
            total_records = len(ais_tracker.all_records)
            
            # Count by vessel type
            type_counts = {}
            for record in ais_tracker.all_records:
                vessel_type = record.get('VesselType', '')
                if vessel_type:
                    type_counts[vessel_type] = type_counts.get(vessel_type, 0) + 1
            
            # Get geographic bounds
            lats = [float(r.get('LAT', 0)) for r in ais_tracker.all_records if r.get('LAT')]
            lons = [float(r.get('LON', 0)) for r in ais_tracker.all_records if r.get('LON')]
            
            bounds = None
            if lats and lons:
                bounds = {
                    'min_lat': min(lats),
                    'max_lat': max(lats),
                    'min_lon': min(lons),
                    'max_lon': max(lons)
                }
            
            return jsonify({
                'status': 'ok',
                'total_records': total_records,
                'unique_mmsi': len(set(r.get('MMSI', '') for r in ais_tracker.all_records if r.get('MMSI'))),
                'vessel_type_counts': type_counts,
                'geographic_bounds': bounds,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting AIS search stats: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - AUTO RECONNAISSANCE
    # ========================================================================

    def _unwrap_room_value(v: Dict[str, Any]) -> Tuple[str, Any]:
        """Helper to unwrap nested OperatorSessionManager room values."""
        # OperatorSessionManager stores: {"id":..., "type":..., "data":...}
        if isinstance(v, dict) and "data" in v and "type" in v and "id" in v:
            return v.get("type", ""), v.get("data") or {}
        # fallback: treat as already-unwrapped or legacy format
        return (v.get("entity_type") or v.get("type") or ""), v

    def _rehydrate_global_room():
        """Syncs all entities (Recon & Sensors) from persisted Global room to memory."""
        if not OPERATOR_MANAGER_AVAILABLE:
            return

        try:
            manager = get_session_manager()
            global_room = manager.get_room_by_name("Global")
            if not global_room:
                return

            persisted = manager.room_entities.get(global_room.room_id, {})
            
            recon_count = 0
            
            for k, v in persisted.items():
                etype, payload = _unwrap_room_value(v)
                
                # Recon Entities + PCAP Hosts + Nmap Targets → trackable on globe
                if etype in ("RECON_ENTITY", "PCAP_HOST", "NMAP_TARGET"):
                    entity_id = payload.get("entity_id") or k
                    if entity_id:
                        recon_system.entities[entity_id] = payload
                        recon_system._dirty_entities.add(entity_id)
                        recon_count += 1

                # Sensors
                elif etype == "SENSOR":
                    node_id = payload.get('node_id') or k
                    if node_id:
                        sensor_store[node_id] = payload

                # Sensor Assignments
                elif etype == "SENSOR_ASSIGNMENT":
                    edge_id = payload.get('edge_id') or k
                    if edge_id:
                        sensor_assignments[edge_id] = payload
            
            if recon_count > 0:
                try:
                    recon_system._spatial_index.mark_dirty()
                except Exception:
                    pass
                    
        except Exception as e:
            logger.warning(f"Rehydration failed: {e}")

    # Entity types that are "trackable" on the globe / Recon panel
    RECON_TRACKABLE_TYPES = {"RECON_ENTITY", "PCAP_HOST", "NMAP_TARGET"}

    @app.route('/api/recon/entities', methods=['GET'])
    def get_recon_entities():
        """Get all tracked entities (RECON_ENTITY + PCAP_HOST + NMAP_TARGET)"""
        try:
            entities = None
            # Prefer DB-backed OperatorSessionManager entities so recon persists across restarts
            if OPERATOR_MANAGER_AVAILABLE and operator_manager is not None:
                try:
                    room = (operator_manager.get_room_by_name("Global")
                            or operator_manager.get_room_by_name("Recon")
                            or operator_manager.get_room_by_name("CommandOps")
                            or operator_manager.get_room_by_name("Command Ops"))
                    if room:
                        room_entities = operator_manager.room_entities.get(room.room_id, {})
                        entities = [entry.get("data", {}) for entry in room_entities.values()
                                    if entry.get("type") in RECON_TRACKABLE_TYPES]
                except Exception:
                    entities = None
            if not entities:
                entities = recon_system.get_all_entities()

            return jsonify({
                'status': 'ok',
                'entity_count': len(entities),
                'entities': entities,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting recon entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/entity/<entity_id>', methods=['GET'])
    def get_recon_entity(entity_id):
        """Get a specific entity by ID"""
        try:
            entity = recon_system.get_entity(entity_id)
            if entity:
                return jsonify({'status': 'ok', 'entity': entity})
            return jsonify({'status': 'error', 'message': f'Entity {entity_id} not found'}), 404
        except Exception as e:
            logger.error(f"Error getting entity {entity_id}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors', methods=['GET'])
    def get_sensors():
        """Get all registered sensors."""
        try:
            if not sensor_registry_instance:
                 return jsonify({'status': 'error', 'message': 'Sensor registry not initialized'}), 503
            
            sensors = []
            if hasattr(sensor_registry_instance, 'get_all_sensors'):
                # Assuming returns list of dicts
                sensors = sensor_registry_instance.get_all_sensors()
            elif hasattr(sensor_registry_instance, 'sensors'):
                 # Fallback to simple values list
                 sensors = list(sensor_registry_instance.sensors.values())
                 # Ensure json serializable
                 sensors = [s if isinstance(s, dict) else s.__dict__ for s in sensors]

            return jsonify({'status': 'ok', 'sensors': sensors})
        except Exception as e:
            logger.error(f"Error getting sensors: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500



    @app.route('/api/recon/entity', methods=['POST'])
    def create_recon_entity():
        """Create or persist a new reconnaissance entity via WriteBus/Registry"""
        try:
            from writebus import WriteContext
            from registries.recon_registry import upsert_recon_entity
            
            data = request.get_json() or {}
            
            # Build context from request headers
            ctx = WriteContext(
                room_name="Global",
                mission_id=data.get("mission_id") or data.get("missionId"),
                operator_id=request.headers.get("X-Operator-Id"),
                session_token=request.headers.get("X-Session-Token"),
                request_id=request.headers.get("X-Request-Id"),
                source="manual_ui",
            )
            
            # Execute write via registry (chokepoint)
            result = upsert_recon_entity(data, ctx)
            entity = result['entity']
            
            # --- LEGACY CACHE UPDATE ---
            # Update in-memory recon_system for GET /api/recon/entity/<id> immediate consistency
            if 'recon_system' in globals():
                try:
                    eid = entity['entity_id']
                    # Preserve calculated fields if we can, or let recon_system re-calc on next tick if it does that.
                    # For now, just ensuring presence.
                    recon_system.entities[eid] = entity
                    if hasattr(recon_system, '_dirty_entities'):
                        recon_system._dirty_entities.add(eid)
                    if hasattr(recon_system, '_spatial_index'):
                        recon_system._spatial_index.mark_dirty()
                except Exception as e_cache:
                    logger.warning(f"Failed to update legacy recon_system cache: {e_cache}")
            # ---------------------------

            logger.info(f"Created recon entity: {entity['entity_id']}")
            return jsonify({
                'status': 'ok', 
                'entity': entity,
                'debug': result.get('write_result', {}).get('debug', {})
            })
        except Exception as e:
            logger.error(f"Error creating recon entity: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return jsonify({'status': 'error', 'message': str(e)}), 500
            logger.error(f"Error creating recon entity: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/entity/<entity_id>/disposition', methods=['POST', 'PUT'])
    def update_entity_disposition(entity_id):
        """Update an entity's disposition via WriteBus/Registry"""
        try:
            from writebus import WriteContext
            from registries.recon_registry import update_disposition
            
            data = request.get_json() or {}
            disposition = data.get('disposition') or request.args.get('disposition')
            
            if not disposition:
                return jsonify({'status': 'error', 'message': 'disposition required'}), 400
            
            # Legacy system update (handles logic checks)
            legacy_result = recon_system.update_entity_disposition(entity_id, disposition.upper())
            
            if legacy_result['status'] == 'ok':
                try:
                    # WriteBus update
                    ctx = WriteContext(
                        room_name="Global",
                        operator_id=request.headers.get("X-Operator-Id"),
                        session_token=request.headers.get("X-Session-Token"),
                        request_id=request.headers.get("X-Request-Id"),
                        source="manual_ui",
                    )
                    
                    update_disposition(entity_id, disposition.upper(), ctx)
                except Exception as wb_err:
                    logger.warning(f"WriteBus update failed for disposition: {wb_err}")
                
                return jsonify(legacy_result)
            return jsonify(legacy_result), 400
        except Exception as e:
            logger.error(f"Error updating entity disposition: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/detection/emit', methods=['POST'])
    def emit_detection_route():
        """
        Emit a high-volume detection event via DetectionRegistry.
        This handles transient graph edges (Tier A) and durable summaries (Tier B).
        """
        try:
            from writebus import WriteContext
            # detection_registry is initialized globally at startup
            global detection_registry

            if detection_registry is None:
                # Attempt lazy init if missing (e.g. testing)
                try:
                    from registries.detection_registry import init_detection_registry
                    detection_registry = init_detection_registry()
                except Exception as e:
                    logger.error(f"Lazy init of detection_registry failed: {e}")
                    return jsonify({'status': 'error', 'message': 'detection_registry not initialized'}), 503
            
            data = request.get_json() or {}
            
            # Allow wrapper format {"detection": {...}} or direct {...}
            detection_data = data.get('detection', data)
            
            ctx = WriteContext(
                room_name="Global",
                operator_id=request.headers.get("X-Operator-Id"),
                session_token=request.headers.get("X-Session-Token"),
                request_id=request.headers.get("X-Request-Id"),
                source=f"api:{request.remote_addr}",
                origin_host=request.headers.get("Host")
            )
            
            result = detection_registry.emit_detection(detection_data, ctx)
            return jsonify({'status': 'ok', 'result': result})

        except Exception as e:
            logger.error(f"Error emitting detection: {e}")
            # Identify known validation errors (ValueError) vs system errors
            if isinstance(e, ValueError):
                return jsonify({'status': 'error', 'message': str(e)}), 400
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - SENSORS (Tx+Rx) - Assignable to Recon Entities
    # ========================================================================
    # NOTE: The canonical sensor upsert route is registered below as
    # POST/PUT /api/sensors (upsert_sensor_endpoint) with full normalization,
    # persistence, and provenance. assign_sensor + sensor_activity routes are
    # also registered below with full rehydration support.
    # Do NOT add duplicate route registrations here.

    @app.route('/api/recon/proximity', methods=['GET'])
    def get_proximity_entities():
        """Get entities within proximity of reference point"""
        try:
            radius = float(request.args.get('radius', 5.0))  # Default 5 NM
            entities = recon_system.get_entities_in_proximity(radius)
            return jsonify({
                'status': 'ok',
                'radius_nm': radius,
                'entity_count': len(entities),
                'entities': entities,
                'reference_point': recon_system.reference_point,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting proximity entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/alerts', methods=['GET'])
    def get_recon_alerts():
        """Get proximity alerts for threatening entities"""
        try:
            alerts = recon_system.get_proximity_alerts()
            return jsonify({
                'status': 'ok',
                'alert_count': len(alerts),
                'alerts': alerts,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/reference', methods=['POST', 'PUT'])
    def set_reference_point():
        """Set the reference point for proximity calculations"""
        try:
            data = request.get_json() or {}
            lat = data.get('lat') or float(request.args.get('lat', 37.7749))
            lon = data.get('lon') or float(request.args.get('lon', -122.4194))
            
            recon_system.set_reference_point(lat, lon)
            return jsonify({
                'status': 'ok',
                'reference_point': recon_system.reference_point,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error setting reference point: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/tasks', methods=['GET'])
    def get_recon_tasks():
        """Get all tasks"""
        try:
            tasks = recon_system.get_all_tasks()
            return jsonify({
                'status': 'ok',
                'task_count': len(tasks),
                'tasks': tasks,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting tasks: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/task', methods=['POST'])
    def create_recon_task():
        """Create a new investigation task"""
        try:
            data = request.get_json() or {}
            entity_id = data.get('entity_id')
            task_type = data.get('task_type', 'INVESTIGATE')
            asset_id = data.get('asset_id')
            priority = data.get('priority', 5)
            
            if not entity_id:
                return jsonify({'status': 'error', 'message': 'entity_id required'}), 400
            
            result = recon_system.create_task(entity_id, task_type, asset_id, priority)
            if result['status'] == 'ok':
                return jsonify(result)
            return jsonify(result), 400
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/task/<task_id>', methods=['GET'])
    def get_recon_task(task_id):
        """Get a specific task"""
        try:
            task = recon_system.get_task(task_id)
            if task:
                return jsonify({'status': 'ok', 'task': task})
            return jsonify({'status': 'error', 'message': f'Task {task_id} not found'}), 404
        except Exception as e:
            logger.error(f"Error getting task: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/task/<task_id>/status', methods=['POST', 'PUT'])
    def update_task_status(task_id):
        """Update a task's status"""
        try:
            data = request.get_json() or {}
            status = data.get('status') or request.args.get('status')
            
            if not status:
                return jsonify({'status': 'error', 'message': 'status required'}), 400
            
            result = recon_system.update_task_status(task_id, status.upper())
            if result['status'] == 'ok':
                return jsonify(result)
            return jsonify(result), 400
        except Exception as e:
            logger.error(f"Error updating task status: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/simulate', methods=['POST', 'GET'])
    def simulate_entity_movement():
        """Simulate entity movement for demo"""
        try:
            result = recon_system.simulate_entity_movement()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error simulating movement: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/status', methods=['GET'])
    def get_recon_status():
        """Get recon system status"""
        try:
            status = recon_system.get_status()
            return jsonify({'status': 'ok', **status})
        except Exception as e:
            logger.error(f"Error getting recon status: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/geolocate', methods=['GET'])
    def recon_geolocate():
        """Geolocate an IP address or hostname using public geolocation services."""
        try:
            target = request.args.get('target')
            if not target:
                return jsonify({'status': 'error', 'message': 'target parameter required'}), 400

            # Simple private network rejection
            private_patterns = [
                lambda t: t.startswith('192.168.'),
                lambda t: t.startswith('10.'),
                lambda t: t.startswith('127.'),
                lambda t: t.startswith('localhost'),
                lambda t: t.startswith('172.') and 16 <= int(t.split('.')[1]) <= 31 if '.' in t and t.split('.')[1].isdigit() else False
            ]
            # If it looks like a private IP or localhost, return 400 so client can fallback
            try:
                if any(p(target) for p in private_patterns):
                    return jsonify({'status': 'error', 'message': 'private network target'}), 400
            except Exception:
                pass

            # Try ip-api.com first (supports hostnames)
            url = f'http://ip-api.com/json/{urllib.parse.quote(target)}'
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'rf-scythe/1.0'})
                with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                    raw = resp.read().decode('utf-8')
                    data = json.loads(raw)
                    if data.get('status') == 'success' and data.get('lat') and data.get('lon'):
                        return jsonify({
                            'status': 'ok',
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'city': data.get('city'),
                            'region': data.get('regionName'),
                            'country': data.get('country'),
                            'org': data.get('org') or data.get('isp')
                        })
            except Exception as e:
                logger.debug(f"ip-api lookup failed for {target}: {e}")

            # Fallback: ipinfo.io (rate-limited) - use unauthenticated endpoint
            try:
                url2 = f'https://ipinfo.io/{urllib.parse.quote(target)}/json'
                req2 = urllib.request.Request(url2, headers={'User-Agent': 'rf-scythe/1.0'})
                with urllib.request.urlopen(req2, timeout=6, context=ctx) as resp2:
                    txt = resp2.read().decode('utf-8')
                    info = json.loads(txt)
                    # ipinfo returns 'loc' as 'lat,lon'
                    loc = info.get('loc')
                    if loc:
                        lat_s, lon_s = loc.split(',')
                        return jsonify({
                            'status': 'ok',
                            'lat': float(lat_s),
                            'lon': float(lon_s),
                            'city': info.get('city'),
                            'region': info.get('region'),
                            'country': info.get('country'),
                            'org': info.get('org')
                        })
            except Exception as e:
                logger.debug(f"ipinfo lookup failed for {target}: {e}")

            return jsonify({'status': 'error', 'message': 'geolocation failed'}), 404
        except Exception as e:
            logger.error(f"Error in recon_geolocate: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - SENSORS (Tx+Rx) - Assignable to Recon Entities
    # ========================================================================
    
    # In-memory sensor store (persisted to OperatorSessionManager for durability)
    sensor_store = {}
    sensor_assignments = {}  # edge_id -> assignment edge
    
    @app.route('/api/sensors', methods=['GET'])
    def get_all_sensors():
        """Get all sensors"""
        try:
            # Sync from OperatorSessionManager if available
            _rehydrate_global_room()
            
            sensors = list(sensor_store.values())
            return jsonify({
                'status': 'ok',
                'sensor_count': len(sensors),
                'sensors': sensors,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting sensors: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors/<sensor_id>', methods=['GET'])
    def get_sensor(sensor_id):
        """Get a specific sensor by ID"""
        try:
            node_id = f"sensor:{sensor_id}" if not sensor_id.startswith('sensor:') else sensor_id
            sensor = sensor_store.get(node_id)
            if sensor:
                return jsonify({'status': 'ok', 'sensor': sensor})
            return jsonify({'status': 'error', 'message': f'Sensor {sensor_id} not found'}), 404
        except Exception as e:
            logger.error(f"Error getting sensor {sensor_id}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors', methods=['POST', 'PUT'])
    def upsert_sensor_endpoint():
        """Create or update a sensor (Tx+Rx)"""
        try:
            data = request.get_json() or {}
            
            # Generate sensor ID if not provided
            sensor_id = data.get('sensor_id') or data.get('id') or f"SENSOR-{int(time.time()*1000) % 100000:05d}"
            if sensor_id.startswith('sensor:'):
                sensor_id = sensor_id[7:]  # Strip prefix for clean ID
            
            node_id = f"sensor:{sensor_id}"
            
            # Normalize position
            location = data.get('position') or data.get('location') or {}
            lat = float(location.get('lat', 0))
            lon = float(location.get('lon', location.get('lng', 0)))
            alt = float(location.get('alt_m', location.get('alt', 0)))
            
            # Build sensor object
            sensor = {
                'sensor_id': sensor_id,
                'node_id': node_id,
                'entity_type': 'SENSOR',
                'type': 'SENSOR',
                'name': data.get('name') or data.get('label') or sensor_id,
                'kind': 'sensor',
                'position': [lat, lon, alt],  # Normalized for hypergraph/UI
                'location': {'lat': lat, 'lon': lon, 'alt_m': alt},
                'tx': data.get('tx') or {
                    'enabled': False,
                    'bands_mhz': [],
                    'max_eirp_dbm': 0,
                    'waveforms': []
                },
                'rx': data.get('rx') or {
                    'enabled': True,
                    'bands_mhz': [[30, 6000]],  # Default wideband
                    'sensitivity_dbm': -110,
                    'sample_rate_hz': 2400000
                },
                'status': data.get('status') or {'state': 'ONLINE', 'last_seen': time.time()},
                'role': data.get('role') or 'static',
                'tags': data.get('tags') or [],
                'labels': {
                    'missionId': data.get('mission_id') or data.get('missionId') or (data.get('labels') or {}).get('missionId'),
                    'teamId': data.get('team_id') or (data.get('labels') or {}).get('teamId'),
                    'roles': ['rx'] if not (data.get('tx') or {}).get('enabled') else ['rx', 'tx'],
                    'tags': data.get('tags') or []
                },
                'metadata': {
                    'owner': data.get('owner') or 'operators',
                    'trust': data.get('trust') or 'full',
                    'notes': data.get('notes') or '',
                    'provenance': {
                        'source_id': None,
                        'source_update_time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        'confidence': data.get('confidence', 1.0)
                    }
                },
                'last_update': time.time(),
                'created': sensor_store.get(node_id, {}).get('created') or time.time()
            }
            
            # Get operator for provenance
            token = request.headers.get("X-Session-Token") or data.get("session_token")
            operator = None
            if OPERATOR_MANAGER_AVAILABLE and token:
                try:
                    manager = get_session_manager()
                    operator = manager.get_operator_for_session(token)
                    if operator:
                        sensor['metadata']['provenance']['source_id'] = f"operator:{operator.operator_id}"
                except Exception:
                    pass
            
            # Store in memory
            sensor_store[node_id] = sensor
            
            # Persist to Global room (same pattern as recon entities)
            if OPERATOR_MANAGER_AVAILABLE:
                try:
                    manager = get_session_manager()
                    global_room = manager.get_room_by_name("Global")
                    if global_room:
                        manager.publish_to_room(
                            room_id=global_room.room_id,
                            entity_id=node_id,
                            entity_type="SENSOR",
                            entity_data=sensor,
                            operator=operator
                        )
                        logger.info(f"Persisted sensor {sensor_id} to Global room")
                except Exception as ex:
                    logger.warning(f"Failed to persist sensor {sensor_id}: {ex}")
            
            # Emit to hypergraph (so graph overlay / diffs see it)
            if 'hypergraph_engine' in dir() and hypergraph_engine is not None:
                try:
                    hypergraph_engine.add_node({
                        'id': node_id,
                        'kind': 'sensor',
                        'position': [lat, lon, alt],
                        'labels': sensor['labels'],
                        'metadata': sensor['metadata']
                    })
                except Exception as ex:
                    logger.debug(f"Hypergraph node add failed: {ex}")
            
            logger.info(f"Created/updated sensor: {sensor_id}")
            return jsonify({'status': 'ok', 'sensor': sensor})
        except Exception as e:
            logger.error(f"Error creating/updating sensor: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors/<sensor_id>', methods=['DELETE'])
    def delete_sensor(sensor_id):
        """Delete a sensor"""
        try:
            node_id = f"sensor:{sensor_id}" if not sensor_id.startswith('sensor:') else sensor_id
            
            if node_id not in sensor_store:
                return jsonify({'status': 'error', 'message': f'Sensor {sensor_id} not found'}), 404
            
            # Remove from memory
            deleted = sensor_store.pop(node_id, None)
            
            # Remove any assignments involving this sensor
            to_remove = [eid for eid in sensor_assignments if node_id in eid]
            for eid in to_remove:
                sensor_assignments.pop(eid, None)
            
            # Delete from Global room
            if OPERATOR_MANAGER_AVAILABLE:
                try:
                    manager = get_session_manager()
                    global_room = manager.get_room_by_name("Global")
                    if global_room:
                        manager.delete_from_room(global_room.room_id, node_id)
                        # Also delete assignments
                        for eid in to_remove:
                            manager.delete_from_room(global_room.room_id, eid)
                except Exception as ex:
                    logger.warning(f"Failed to delete sensor from room: {ex}")
            
            logger.info(f"Deleted sensor: {sensor_id}")
            return jsonify({'status': 'ok', 'deleted': sensor_id, 'assignments_removed': len(to_remove)})
        except Exception as e:
            logger.error(f"Error deleting sensor: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ------------------------------------------------------------------------
    # PCAP Helper Utilities
    # ------------------------------------------------------------------------
    
    def _q_int(name: str, default: int, lo: int = None, hi: int = None) -> int:
        try:
            v = int(request.args.get(name, default))
        except Exception:
            v = default
        if lo is not None: v = max(lo, v)
        if hi is not None: v = min(hi, v)
        return v

    def _q_float(name: str, default: float, lo: float = None, hi: float = None) -> float:
        try:
            v = float(request.args.get(name, default))
        except Exception:
            v = default
        if lo is not None: v = max(lo, v)
        if hi is not None: v = min(hi, v)
        return v

    def _parse_pcap_ip_from_id(s: str) -> str:
        # Handles "PCAP-93_184_216_34" -> "93.184.216.34"
        if not s:
            return ""
        if s.startswith("PCAP-"):
            s = s[len("PCAP-"):]
        return s.replace("_", ".")

    def _first_geo_from_endpoints(endpoints: list) -> dict:
        for ep in endpoints or []:
            geo = (ep or {}).get("geo") or {}
            if geo.get("lat") is not None and geo.get("lon") is not None:
                return geo
        return {}
    
    # ------------------------------------------------------------------------
    # PCAP Ingestion Endpoints (Operator Workflow)
    # ------------------------------------------------------------------------
    
    @app.route('/api/pcap/upload', methods=['POST'])
    def pcap_upload():
        """Upload a PCAP and create a session"""
        if not pcap_registry_instance:
             return jsonify({'status': 'error', 'message': 'PcapRegistry not available'}), 503
             
        try:
            # 1. Handle File
            file = request.files.get('file')
            file_bytes = None
            original_name = None
            
            if file:
                file_bytes = file.read()
                original_name = file.filename
            
            # 2. Extract Metadata
            sensor_id = request.form.get('sensor_id')
            mission_id = request.form.get('mission_id')
            tags_json = request.form.get('tags')
            tags = json.loads(tags_json) if tags_json else []
            
            operator = "unknown"
            if OPERATOR_MANAGER_AVAILABLE:
                token = request.headers.get("X-Session-Token")
                if token:
                    manager = get_session_manager()
                    op_obj = manager.get_operator_for_session(token)
                    if op_obj:
                        operator = getattr(op_obj, 'callsign', None) or getattr(op_obj, 'operator_id', 'unknown')
            
            # 3. Upsert Artifact
            artifact = pcap_registry_instance.upsert_pcap_artifact(
                file_bytes=file_bytes,
                original_name=original_name,
                operator=operator,
                mission_id=mission_id,
                sensor_id=sensor_id,
                tags=tags
            )
            
            # 4. Create Session (Receipt)
            session = pcap_registry_instance.create_pcap_session(
                artifact_sha256=artifact['sha256'],
                operator=operator,
                mission_id=mission_id,
                sensor_id=sensor_id,
                tags=tags,
                ingest_plan={"mode": "flows", "dpi": True} # Default plan
            )
            
            return jsonify({
                'status': 'ok',
                'artifact': artifact,
                'session': session
            })

        except Exception as e:
            logger.error(f"PCAP upload failed: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/pcap/<session_id>/ingest', methods=['POST'])
    def pcap_ingest(session_id):
        """Trigger ingestion for a PCAP session"""
        if not pcap_registry_instance:
             return jsonify({'status': 'error', 'message': 'PcapRegistry not available'}), 503
             
        try:
            data = request.get_json() or {}
            mode = data.get('mode', 'flows')
            dpi = data.get('dpi', True)
            
            result = pcap_registry_instance.ingest_pcap_session(
                session_id=session_id,
                mode=mode,
                dpi=dpi
            )
            
            return jsonify({'status': 'ok', 'result': result})

        except Exception as e:
            logger.error(f"PCAP ingest failed: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/pcap/sessions', methods=['GET'])
    def pcap_list_sessions():
        """List all persisted PCAP sessions available for replay"""
        if not pcap_registry_instance:
            return jsonify({'ok': False, 'error': 'registry_unavailable', 'message': 'PcapRegistry not available'}), 503
        try:
            # Debugging code
            if not hasattr(pcap_registry_instance, 'list_sessions'):
                logger.error(f"PcapRegistry instance ({type(pcap_registry_instance)}) missing list_sessions. Dir: {dir(pcap_registry_instance)}")
                # Attempt to hot-patch or reload?
                return jsonify({'ok': False, 'error': 'method_missing', 'message': f'PcapRegistry missing list_sessions. Type: {type(pcap_registry_instance)}'}), 500
            
            sessions = pcap_registry_instance.list_sessions()
            
            # Normalize keys for UI compatibility
            norm = []
            for s in (sessions or []):
                if not isinstance(s, dict):
                    continue
                sid = s.get("session_id") or s.get("id") or s.get("sessionId") or s.get("name")
                s.setdefault("session_id", sid)
                s.setdefault("id", sid)
                s.setdefault("name", sid)
                s.setdefault("display_name", sid)
                norm.append(s)

            return jsonify({'ok': True, 'sessions': norm, 'count': len(norm)})
        except Exception as e:
            logger.error(f"PCAP list sessions failed: {e}")
            return jsonify({'ok': False, 'error': 'list_failed', 'message': str(e)}), 500

    @app.route('/api/pcap/<session_id>/subgraph', methods=['GET'])
    def pcap_session_subgraph(session_id):
        try:
            # Reject obvious bad IDs early (prevents empty modal + weird traversal)
            if not session_id or session_id in ("undefined", "null", ""):
                return jsonify({"ok": False, "error": "invalid_session_id", "message": "Invalid session_id"}), 400

            # Depth clamp (prevents accidental graph-walk explosions)
            depth_raw = request.args.get("depth", "2")
            try:
                max_depth = int(depth_raw)
            except Exception:
                max_depth = 2
            max_depth = max(0, min(10, max_depth))

            # Durable-first subgraph (works even when hypergraph is empty after restart)
            if pcap_registry_instance and hasattr(pcap_registry_instance, "get_session_subgraph"):
                sg = pcap_registry_instance.get_session_subgraph(session_id, depth=max_depth, hydrate_graph=True)
                if sg:
                    return jsonify({"ok": True, "session_id": session_id, "subgraph": sg})

            # Fallback: hypergraph-based subgraph (for sessions not yet in durable storage)
            hg = globals().get('hypergraph_engine')
            if not hg:
                 return jsonify({'ok': False, 'error': 'hypergraph_unavailable', 'message': 'Hypergraph engine not available'}), 503

            def _id_of(x):
                """Extract a stable string ID from node-ish objects."""
                if x is None:
                    return None
                if isinstance(x, str):
                    return x
                if isinstance(x, dict):
                    return x.get("id") or x.get("node_id")
                return getattr(x, "id", None)

            def _as_dict(x):
                """JSON-safe conversion for HGNode/HGEdge OR raw dicts OR unknown objects."""
                if x is None:
                    return None
                if isinstance(x, dict):
                    return x
                if hasattr(x, "to_dict") and callable(getattr(x, "to_dict")):
                    return x.to_dict()
                if hasattr(x, "__dict__"):
                    return dict(x.__dict__)
                # last-resort: don’t crash, return something inspectable
                return {"id": _id_of(x), "raw": str(x)}

            # Helpful: if the session node doesn’t exist, say so explicitly
            root = hg.get_node(session_id) if hasattr(hg, "get_node") else None
            if root is None:
                return jsonify({
                    "ok": False, "error": "session_not_found",
                    "message": f"Unknown session_id: {session_id}",
                    "session_id": session_id
                }), 404

            visited_nodes = set([session_id])
            visited_edges = set()
            frontier = set([session_id])

            for _ in range(max_depth):
                next_frontier = set()
                for nid in list(frontier):
                    # tolerate missing edges_for_node
                    edge_iter = hg.edges_for_node(nid) if hasattr(hg, "edges_for_node") else []
                    for edge in edge_iter:
                        if isinstance(edge, dict):
                            eid = edge.get("id")
                            edge_nodes = edge.get("nodes") or []
                        else:
                            eid = getattr(edge, "id", None)
                            edge_nodes = getattr(edge, "nodes", []) or []

                        if eid:
                            visited_edges.add(eid)

                        # edge_nodes may contain dicts/objects: normalize → id strings only
                        for t in edge_nodes:
                            tid = _id_of(t)
                            if not tid:
                                continue
                            if tid not in visited_nodes:
                                visited_nodes.add(tid)
                                next_frontier.add(tid)

                frontier = next_frontier
                if not frontier:
                    break

            nodes_out = []
            for nid in visited_nodes:
                n = hg.get_node(nid) if hasattr(hg, "get_node") else None
                if n is None:
                    # include a stub so UI can still show the edge endpoints
                    nodes_out.append({"id": nid, "kind": "missing", "metadata": {"stub": True}})
                else:
                    nodes_out.append(_as_dict(n))

            edges_out = []
            for eid in visited_edges:
                e = hg.get_edge(eid) if hasattr(hg, "get_edge") else None
                if e is not None:
                    edges_out.append(_as_dict(e))

            return jsonify({
                "ok": True,
                "session_id": session_id,
                "subgraph": {
                    "nodes": nodes_out,
                    "edges": edges_out,
                    "stats": {"depth": max_depth, "node_count": len(nodes_out), "edge_count": len(edges_out)}
                }
            })

        except Exception as e:
            # IMPORTANT: traceback in server logs, JSON to client
            logger.exception(f"pcap_session_subgraph failed: session_id={session_id}")
            return jsonify({
                "ok": False,
                "error": str(e),
                "session_id": session_id
            }), 500

    # -----------------------------------------------------------------
    # PCAP Globe Overlay — spatial projection for Cesium
    # Modes: ports (default), top, geo_asn
    # -----------------------------------------------------------------
    @app.route('/api/pcap/<session_id>/globe', methods=['GET'])
    def pcap_session_globe(session_id: str):
        try:
            if not session_id or session_id in ("undefined", "null", ""):
                return jsonify({"ok": False, "message": "Invalid session_id"}), 400

            # Query params expected by the UI
            mode = (request.args.get("mode", "ports") or "ports").lower()
            proto_filter = (request.args.get("proto") or "").lower().strip()
            port_filter = request.args.get("port", None)

            limit_ports   = _q_int("limit_ports", 6, 1, 64)
            limit_talkers = _q_int("limit_talkers", 18, 1, 200)

            include_tls = _q_int("include_tls", 1, 0, 1) == 1
            include_geo = _q_int("include_geo", 1, 0, 1) == 1

            hub_alt_m      = _q_float("hub_alt_m", 120000, 0, 2_000_000)
            hub_radius_m   = _q_float("hub_radius_m", 250000, 0, 5_000_000)
            arc_peak_alt_m = _q_float("arc_peak_alt_m", 220000, 0, 5_000_000)
            arc_samples    = _q_int("arc_samples", 48, 8, 256)

            layout = {
                "hub_alt_m": hub_alt_m,
                "hub_radius_m": hub_radius_m,
                "arc_peak_alt_m": arc_peak_alt_m,
                "arc_samples": arc_samples,
            }

            # Prefer a registry-provided implementation if present
            if 'pcap_registry_instance' in globals():
                reg = globals().get('pcap_registry_instance')
                for fn_name in ("build_globe_overlay", "get_globe_overlay", "globe_overlay"):
                    if reg is not None and hasattr(reg, fn_name) and callable(getattr(reg, fn_name)):
                        out = getattr(reg, fn_name)(session_id, dict(request.args))
                        # Expect out already in UI format; just ensure required keys exist
                        if isinstance(out, dict):
                            out.setdefault("ok", True)
                            out.setdefault("layout", layout)
                            out.setdefault("session", {"session_id": session_id, "id": session_id, "name": session_id, "display_name": session_id})
                            return jsonify(out)

            # -----------------------------
            # Fallback: synthesize globe data from what we already have in-memory.
            # This prevents 404 and keeps the UI operational even if the registry
            # hasn't implemented a real port/talker summarizer yet.
            # -----------------------------

            # Session object (minimal)
            session_obj = {"session_id": session_id, "id": session_id, "name": session_id, "display_name": session_id}

            # Collect candidate endpoints from persisted recon entities / room entities.
            # Heuristic: anything with id prefix "PCAP-" and a location/geo.
            endpoints = []
            try:
                # If you have an in-memory recon system
                rs = globals().get("recon_system")
                if rs is not None and hasattr(rs, "entities"):
                    for rid, ent in list(getattr(rs, "entities", {}).items()):
                        if not isinstance(rid, str) or not rid.startswith("PCAP-"):
                            continue
                        if not isinstance(ent, dict):
                            continue
                        loc = ent.get("location") or ent.get("geo") or (ent.get("metadata") or {}).get("geo") or {}
                        lat = loc.get("lat") if isinstance(loc, dict) else None
                        lon = loc.get("lon") if isinstance(loc, dict) else None
                        if lat is None or lon is None:
                            continue
                        endpoints.append({
                            "endpoint_id": rid,
                            "ip": _parse_pcap_ip_from_id(rid),
                            "role": ent.get("role") or "talker",
                            "bytes_total": ent.get("bytes_total") or (ent.get("stats") or {}).get("bytes_total") or 0,
                            "flows": ent.get("flows") or (ent.get("stats") or {}).get("flows") or 1,
                            "scanner_like_mean": (ent.get("scores") or {}).get("scanner_like_mean", 0.2),
                            "geo": {
                                "lat": float(lat),
                                "lon": float(lon),
                                "country_iso": (loc.get("country_iso") if isinstance(loc, dict) else None),
                                "city": (loc.get("city") if isinstance(loc, dict) else None),
                            } if include_geo else None,
                            "geo_provenance": {
                                "geo_source": ((ent.get("metadata") or {}).get("geo_provenance") or {}).get("geo_source", "recon"),
                                "geo_confidence": ((ent.get("metadata") or {}).get("geo_provenance") or {}).get("geo_confidence", 0.4),
                            } if include_geo else None,
                            "tls": (ent.get("tls") if include_tls else None),
                        })
            except Exception:
                logger.exception("[PCAP] globe fallback endpoint harvest failed")

            # Clamp endpoints
            endpoints = endpoints[:limit_talkers]

            # Choose a capture site:
            # 1) if endpoints exist, anchor at the first endpoint (better than 0,0)
            # 2) otherwise default to 0,0
            g0 = _first_geo_from_endpoints(endpoints)
            capture_site = {
                "lat": float(g0.get("lat", 0.0)),
                "lon": float(g0.get("lon", 0.0)),
                "alt_m": 0,
                "label": "PCAP Capture",
            }

            # Build hubs.
            # If you don't have port summaries yet, we create a single "ip:talkers" hub.
            hubs = []
            if endpoints:
                hubs.append({
                    "hub_id": "hub_ip_talkers",
                    "proto": (proto_filter.upper() if proto_filter else "IP"),
                    "port": (int(port_filter) if (port_filter and str(port_filter).isdigit()) else "talkers"),
                    "flow_count": len(endpoints),
                    "scanner_like_p95": 0.3,
                    "top_talkers": endpoints[:limit_talkers],
                })

            # If the UI asked for a specific proto/port, keep response consistent
            if proto_filter or port_filter:
                # "expand hub" re-fetch expects hubs[0].top_talkers
                pass

            return jsonify({
                "ok": True,
                "mode": mode,
                "session": session_obj,
                "capture_site": capture_site,
                "layout": layout,
                "hubs": hubs[:limit_ports],
            })

        except Exception as e:
            logger.exception(f"[PCAP] globe route failed: session_id={session_id}")
            return jsonify({"ok": False, "message": str(e), "session_id": session_id}), 500

    @app.route('/api/recon/entity/<entity_id>/assign_sensor', methods=['POST'])
    def assign_sensor_to_entity(entity_id):
        """Assign a sensor to a recon entity (via sensor_registry)"""
        try:
            # Delegate directly to sensor registry
            if not sensor_registry_instance:
                 return jsonify({'status': 'error', 'message': 'Sensor Registry not available'}), 503

            data = request.get_json() or {}
            sensor_id = data.get('sensor_id')
            if not sensor_id:
                  return jsonify({'status': 'error', 'message': 'sensor_id required'}), 400
            
            # Use the refactored registry logic
            if hasattr(sensor_registry_instance, 'assign_sensor'):
                result = sensor_registry_instance.assign_sensor(sensor_id, target_id=entity_id)
                return jsonify({'status': 'ok', 'assignment': result})
            else:
                 return jsonify({'status': 'error', 'message': 'SensorRegistry missing assign_sensor'}), 500

        except Exception as e:
            logger.error(f"Error assigning sensor: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/recon/entity/<entity_id>/sensors', methods=['GET'])
    def get_entity_sensors(entity_id):
        """Get all sensors assigned to a recon entity"""
        try:
            to_id = entity_id if entity_id.startswith('recon:') else f"recon:{entity_id}"
            
            # Find all assignments to this entity
            assigned = []
            for edge_id, assignment in sensor_assignments.items():
                if assignment.get('to') == to_id or assignment.get('recon_entity_id') == entity_id.replace('recon:', ''):
                    sensor_node_id = assignment.get('from') or f"sensor:{assignment.get('sensor_id')}"
                    sensor = sensor_store.get(sensor_node_id)
                    if sensor:
                        assigned.append({
                            'assignment': assignment,
                            'sensor': sensor
                        })
            
            return jsonify({
                'status': 'ok',
                'entity_id': entity_id,
                'assigned_count': len(assigned),
                'assignments': assigned,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting entity sensors: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors/<sensor_id>/unassign/<entity_id>', methods=['DELETE', 'POST'])
    def unassign_sensor(sensor_id, entity_id):
        """Remove a sensor assignment from a recon entity"""
        try:
            from_id = f"sensor:{sensor_id}" if not sensor_id.startswith('sensor:') else sensor_id
            to_id = entity_id if entity_id.startswith('recon:') else f"recon:{entity_id}"
            edge_id = f"edge:{from_id}->{to_id}"
            
            if edge_id not in sensor_assignments:
                return jsonify({'status': 'error', 'message': 'Assignment not found'}), 404
            
            # Remove from memory
            deleted = sensor_assignments.pop(edge_id, None)
            
            # Delete from Global room
            if OPERATOR_MANAGER_AVAILABLE:
                try:
                    manager = get_session_manager()
                    global_room = manager.get_room_by_name("Global")
                    if global_room:
                        manager.delete_from_room(global_room.room_id, edge_id)
                except Exception as ex:
                    logger.warning(f"Failed to delete assignment from room: {ex}")
            
            # Remove from hypergraph
            if 'hypergraph_engine' in dir() and hypergraph_engine is not None:
                try:
                    hypergraph_engine.remove_edge(edge_id)
                except Exception:
                    pass
            
            logger.info(f"Unassigned sensor {sensor_id} from entity {entity_id}")
            return jsonify({'status': 'ok', 'unassigned': edge_id})
        except Exception as e:
            logger.error(f"Error unassigning sensor: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors/<sensor_id>/activity', methods=['POST'])
    def emit_sensor_activity(sensor_id):
        """Emit sensor activity (creates an activity edge in the hypergraph)"""
        try:
            data = request.get_json() or {}
            activity_kind = data.get('kind') or data.get('activity_type') or 'signal_detected'
            
            from_id = f"sensor:{sensor_id}" if not sensor_id.startswith('sensor:') else sensor_id
            
            if from_id not in sensor_store:
                return jsonify({'status': 'error', 'message': f'Sensor {sensor_id} not found'}), 404
            
            # Build activity edge
            activity_id = f"activity:{sensor_id}:{int(time.time()*1000)}"
            
            # Determine target nodes (sensor + optional RF/recon entity)
            nodes = [from_id]
            recon_entity_id = data.get('recon_entity_id')
            if recon_entity_id:
                nodes.append(f"recon:{recon_entity_id}" if not recon_entity_id.startswith('recon:') else recon_entity_id)
            
            rf_node_id = data.get('rf_node_id')
            if rf_node_id:
                nodes.append(rf_node_id)
            
            activity = {
                'activity_id': activity_id,
                'entity_type': 'SENSOR_ACTIVITY',
                'kind': activity_kind,
                'nodes': nodes,
                'sensor_id': sensor_id,
                'payload': {
                    'frequency_mhz': data.get('frequency_mhz'),
                    'power_dbm': data.get('power_dbm'),
                    'snr_db': data.get('snr_db'),
                    'modulation': data.get('modulation'),
                    'confidence': data.get('confidence', 0.5),
                    'bandwidth_hz': data.get('bandwidth_hz'),
                    'bearing_deg': data.get('bearing_deg'),
                    'timestamp': data.get('timestamp') or time.time(),
                    # LPI Fields - Pace/LPI theory support
                    'algo': data.get('algo'), # {name, version, params}
                    'feature_set_id': data.get('feature_set_id'),
                    'window': data.get('window'), # {t0, t1, sample_rate, center_freq, bandwidth}
                    'evidence': data.get('evidence'), # {iq_hash, artifact_ptrs}
                    'estimated_params': data.get('estimated_params'),
                    'classes': data.get('classes'),
                    'association': data.get('association'),
                    'belief': data.get('belief')
                },
                'labels': {
                    'missionId': data.get('mission_id') or data.get('missionId')
                },
                'metadata': {
                    'sensor_name': sensor_store.get(from_id, {}).get('name'),
                    'sensor_position': sensor_store.get(from_id, {}).get('position')
                },
                'timestamp': time.time()
            }
            
            # Update sensor last_seen
            if from_id in sensor_store:
                sensor_store[from_id]['status']['last_seen'] = time.time()
                sensor_store[from_id]['status']['state'] = 'ACTIVE'
            
            # Emit to hypergraph as edge (high-volume, not persisted to room by default)
            persist_to_room = data.get('persist_to_room', False)
            
            if 'hypergraph_engine' in dir() and hypergraph_engine is not None:
                try:
                    hypergraph_engine.add_edge({
                        'id': activity_id,
                        'kind': activity_kind,
                        'nodes': nodes,
                        'labels': activity['labels'],
                        'metadata': activity['payload'],
                        'timestamp': activity['timestamp']
                    })
                except Exception as ex:
                    logger.debug(f"Hypergraph activity edge add failed: {ex}")
            
            # Optionally persist to room (for important detections)
            if persist_to_room and OPERATOR_MANAGER_AVAILABLE:
                try:
                    manager = get_session_manager()
                    global_room = manager.get_room_by_name("Global")
                    if global_room:
                        manager.publish_to_room(
                            room_id=global_room.room_id,
                            entity_id=activity_id,
                            entity_type="SENSOR_ACTIVITY",
                            entity_data=activity
                        )
                except Exception:
                    pass
            
            return jsonify({'status': 'ok', 'activity': activity})
        except Exception as e:
            logger.error(f"Error emitting sensor activity: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/sensors/<sensor_id>/process/lpi', methods=['POST'])
    def process_lpi_window(sensor_id):
        """
        LPI Worker: Process an IQ window through the LPI detection pipeline.
        Generates events: iq_window_received -> [tf_computed] -> [candidate_detected] -> [classified]
        
        Supports input Gating and Signal Simulation.
        """
        try:
            data = request.get_json() or {}
            
            # --- 1. Window & Format Standardization ---
            # Helper to merge defaults with request window
            req_window = data.get('window', {})
            t_now = time.time()
            window = {
                "t0": req_window.get('t0', t_now - 0.5),
                "t1": req_window.get('t1', t_now),
                "sample_rate_hz": req_window.get('sample_rate_hz', 2400000),
                "center_freq_hz": req_window.get('center_freq_hz', 915000000),
                "bandwidth_hz": req_window.get('bandwidth_hz', 2400000),
                "iq_format": req_window.get('iq_format', "cs16_iq_interleaved"),
                "endianness": req_window.get('endianness', "little"),
                "scale": req_window.get('scale', "full_scale=32767")
            }

            # Helper: Artifact Storage Stub
            def _store_artifact_stub(suffix: str = '.bin'):
                 # Simulate SHA256 of content
                import hashlib
                import uuid
                h = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
                return h, f"file:///var/data/artifacts/{h}{suffix}"

            # --- 2. Stage 0: Acquisition Event ---
            iq_hash, iq_ptr = _store_artifact_stub('.iq')
            iq_event = {
                'kind': 'iq_window_received',
                'timestamp': window['t1'],
                'window': window,
                'evidence': {
                    'iq_hash': iq_hash,
                    'iq_ptr': iq_ptr
                },
                'algo': {'name': 'acq', 'version': '1.0.0', 'params': {}},
                'confidence': 1.0,
                'persist_to_room': False # High volume, only local/ephemeral usually
            }
            
            events_generated = [iq_event]

            # --- 3. Simulation & Gating Logic ---
            simulate = data.get('simulate_detection', False)
            signal_family = data.get('signal_family', 'fmcw') # fmcw, phase_coded, noise_like
            snr_db = float(data.get('snr_db', 10.0))
            
            # Thresholds
            detection_threshold_snr = 3.0
            classification_threshold_snr = 6.0
            
            # Compute TF? (Always efficient if simulated)
            if simulate:
                tf_hash, tf_ptr = _store_artifact_stub('.npz')
                tf_event = {
                   'kind': 'tf_computed',
                   'timestamp': t_now + 0.05,
                   'algo': {'name': 'stft', 'version': '2.1.0', 'params': {'nfft': 2048, 'hop': 256}},
                   'feature_set_id': 'tf/stft/v2',
                   'payload': {
                       'summary': {
                           'max_bin_db': -40.0 + snr_db,
                           'occupied_bw_hz': window['bandwidth_hz'] * 0.4,
                           'noise_floor_db': -110.0
                       }
                   },
                   'evidence': {'iq_hash': iq_hash, 'artifact_ptrs': {'tf_matrix_npz': tf_ptr}},
                   'confidence': 0.95,
                   'persist_to_room': False
                }
                events_generated.append(tf_event)

                # Detection Gate
                if snr_db >= detection_threshold_snr:
                    # Stage 3: Candidate Detected
                    cand_hash, cand_ptr = _store_artifact_stub('.json')
                    candidate_event = {
                        'kind': 'lpi_candidate_detected',
                        'timestamp': t_now + 0.1,
                        'algo': {'name': 'lpi_detector', 'version': '1.0.0', 'params': {'algorithm': 'energy_detector'}},
                        'evidence': {'iq_hash': iq_hash, 'candidate_meta_ptr': cand_ptr},
                        'confidence': min(0.99, 0.5 + snr_db/40.0),
                        'persist_to_room': True
                    }
                    events_generated.append(candidate_event)

                    # Classification Gate
                    if snr_db >= classification_threshold_snr:
                        classes = []
                        est_params = {}
                        
                        # Generate payload based on family
                        if signal_family == 'fmcw':
                            classes = [{'label': 'FMCW', 'p': 0.85}, {'label': 'LFM', 'p': 0.10}]
                            est_params = {'sweep_rate_hz_s': 1.2e12, 'bw_hz': 5e6}
                        elif signal_family == 'phase_coded':
                            classes = [{'label': 'PHASE_CODED', 'p': 0.78}, {'label': 'BPSK', 'p': 0.15}]
                            est_params = {'chip_rate_hz': 1.023e6, 'code_len': 1023}
                        elif signal_family == 'noise_like':
                            classes = [{'label': 'NOISE_LIKE', 'p': 0.65}, {'label': 'WIDEBAND_NOISE', 'p': 0.30}]
                            est_params = {'bandwidth_hz': 20e6, 'kurtosis': 3.1}
                        
                        class_event = {
                            'kind': 'waveform_classified',
                            'timestamp': t_now + 0.2,
                            'algo': {'name': 'lpi_classifier', 'version': '0.3.2', 'params': {'model': 'xgb_v7'}},
                            'feature_set_id': 'lpi/features/v7',
                            'classes': [{"class": c['label'], "confidence": c['p']} for c in classes],
                            'estimated_params': est_params,
                            'confidence': classes[0]['p'],
                            'evidence': {'iq_hash': iq_hash},
                            'persist_to_room': True
                        }
                        events_generated.append(class_event)

            # --- 4. Emission to Room/Clients ---
            import uuid
            for evt in events_generated:
                # Inject SNR for UI convenience
                evt['snr_db'] = snr_db
                
                # Emit
                try:
                    activity_id = f"act:{sensor_id}:{evt['kind']}:{uuid.uuid4().hex[:8]}"
                    wrapper = {
                        'activity_id': activity_id,
                        'entity_type': 'SENSOR_ACTIVITY',
                        'activity_type': evt['kind'],
                        'sensor_id': sensor_id,
                        'payload': evt,
                        'timestamp': evt['timestamp']
                    }
                    
                    if OPERATOR_MANAGER_AVAILABLE:
                         manager = get_session_manager()
                         global_room = manager.get_room_by_name("Global")
                         if global_room:
                             manager.publish_to_room(
                                 room_id=global_room.room_id,
                                 entity_id=activity_id,
                                 entity_type="SENSOR_ACTIVITY",
                                 entity_data=wrapper
                             )
                except Exception as ex:
                    logger.warning(f"LPI Activity Emit Error: {ex}")

            return jsonify({
                'status': 'ok',
                'pipeline_trace': events_generated,
                'message': f'LPI pipeline processed (simulated={simulate}, family={signal_family}, snr={snr_db}dB)'
            })
        except Exception as e:
             logger.error(f"Error in LPI worker: {e}")
             return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # BATCH API ENDPOINTS (Optimization: reduce network round-trips)
    # ========================================================================

    @app.route('/api/recon/entities/batch', methods=['POST'])
    def get_recon_entities_batch():
        """
        Get multiple entities by ID in a single request.
        
        OPTIMIZATION: Reduces N API calls to 1 for fetching multiple entities.
        """
        try:
            data = request.get_json() or {}
            entity_ids = data.get('entity_ids', [])
            
            if not entity_ids:
                return jsonify({'status': 'error', 'message': 'entity_ids required'}), 400
            
            entities = recon_system.get_entities_batch(entity_ids)
            return jsonify({
                'status': 'ok',
                'requested': len(entity_ids),
                'found': len(entities),
                'entities': entities,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting batch entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/nearest', methods=['GET'])
    def get_nearest_entities():
        """
        Get the k nearest entities to the reference point.
        
        OPTIMIZATION: Uses spatial index for O(log n) query.
        """
        try:
            k = int(request.args.get('k', 10))
            entities = recon_system.get_nearest_entities(k)
            return jsonify({
                'status': 'ok',
                'k': k,
                'entity_count': len(entities),
                'entities': entities,
                'reference_point': recon_system.reference_point,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting nearest entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/recon/changes', methods=['GET'])
    def get_changed_entities():
        """
        Get entities that have changed since a timestamp.
        
        OPTIMIZATION: For incremental frontend updates - only fetch changed data.
        """
        try:
            since = request.args.get('since')
            since_timestamp = float(since) if since else None
            
            entities = recon_system.get_changed_entities(since_timestamp)
            return jsonify({
                'status': 'ok',
                'entity_count': len(entities),
                'entities': entities,
                'since': since_timestamp,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting changed entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ais/vessels/batch', methods=['POST'])
    def get_ais_vessels_batch():
        """
        Get multiple AIS vessels by MMSI in a single request.
        
        OPTIMIZATION: Batch endpoint for AIS vessel data.
        """
        try:
            data = request.get_json() or {}
            mmsi_list = data.get('mmsi_list', [])
            
            if not mmsi_list:
                return jsonify({'status': 'error', 'message': 'mmsi_list required'}), 400
            
            vessels = []
            for mmsi in mmsi_list:
                vessel = ais_tracker.get_vessel(str(mmsi))
                if vessel:
                    vessels.append(vessel)
            
            return jsonify({
                'status': 'ok',
                'requested': len(mmsi_list),
                'found': len(vessels),
                'vessels': vessels,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error getting batch vessels: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # PERFORMANCE METRICS ENDPOINT
    # ========================================================================

    @app.route('/api/metrics', methods=['GET'])
    def get_performance_metrics():
        """
        Get performance metrics for monitoring and optimization.
        
        Returns timing statistics for all tracked operations.
        """
        try:
            metrics = perf_metrics.get_all_stats()
            metrics['recon_performance'] = recon_system.get_status().get('performance', {})
            metrics['spatial_index'] = recon_system._spatial_index.get_stats()
            
            return jsonify({
                'status': 'ok',
                **metrics
            })
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/metrics/log', methods=['POST'])
    def log_metrics():
        """
        Log metrics from frontend for persistent storage.
        
        Accepts single metric or batch of metrics.
        Request body:
        {
            "module": "recon",
            "metric_name": "update_time_ms",
            "value": 12.5,
            "metadata": {...},
            "session_id": "abc123"
        }
        
        Or for batch:
        {
            "batch": [
                {"module": "recon", "metric_name": "update_time_ms", "value": 12.5},
                {"module": "hypergraph", "metric_name": "node_count", "value": 150}
            ],
            "session_id": "abc123"
        }
        """
        try:
            data = request.get_json() or {}
            user_agent = request.headers.get('User-Agent', 'unknown')
            session_id = data.get('session_id', request.remote_addr)
            
            # Handle batch logging
            if 'batch' in data:
                entries = data['batch']
                for entry in entries:
                    entry['session_id'] = session_id
                    entry['user_agent'] = user_agent
                metrics_logger.log_batch(entries)
                return jsonify({
                    'status': 'ok',
                    'logged': len(entries),
                    'timestamp': time.time()
                })
            
            # Handle single metric
            module = data.get('module', 'frontend')
            metric_name = data.get('metric_name', 'unknown')
            value = data.get('value', 0)
            metadata = data.get('metadata', {})
            
            metrics_logger.log(
                module=module,
                metric_name=metric_name,
                value=value,
                metadata=metadata,
                session_id=session_id,
                user_agent=user_agent
            )
            
            return jsonify({
                'status': 'ok',
                'logged': 1,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error logging metrics: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/metrics/interaction', methods=['POST'])
    def log_interaction():
        """
        Log user interaction events for analytics.
        
        Request body:
        {
            "action": "clicked_entity",
            "target": "drone-1",
            "details": {"panel": "recon", "zoom_level": 5000},
            "session_id": "abc123"
        }
        """
        try:
            data = request.get_json() or {}
            session_id = data.get('session_id', request.remote_addr)
            
            metrics_logger.log_interaction(
                action=data.get('action', 'unknown'),
                target=data.get('target'),
                details=data.get('details'),
                session_id=session_id
            )
            
            return jsonify({
                'status': 'ok',
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error logging interaction: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/metrics/session', methods=['GET'])
    def get_session_metrics():
        """Get summary of metrics collected this session."""
        try:
            summary = metrics_logger.get_session_summary()
            return jsonify({
                'status': 'ok',
                **summary
            })
        except Exception as e:
            logger.error(f"Error getting session metrics: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/metrics/query', methods=['GET'])
    def query_historical_metrics():
        """
        Query historical metrics from persistent storage.
        
        Query params:
            module: Filter by module name
            metric_name: Filter by metric name
            start_time: Unix timestamp start
            end_time: Unix timestamp end
            limit: Max results (default 1000)
        """
        try:
            module = request.args.get('module')
            metric_name = request.args.get('metric_name')
            start_time = request.args.get('start_time', type=float)
            end_time = request.args.get('end_time', type=float)
            limit = request.args.get('limit', 1000, type=int)
            
            results = metrics_logger.query_metrics(
                module=module,
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time,
                limit=limit
            )
            
            return jsonify({
                'status': 'ok',
                'count': len(results),
                'metrics': results
            })
        except Exception as e:
            logger.error(f"Error querying metrics: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - POINTS OF INTEREST
    # ========================================================================

    @app.route('/api/poi/all', methods=['GET'])
    def get_all_pois():
        """Get all Points of Interest"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            pois = poi_manager.get_all_pois()
            return jsonify({
                'status': 'ok',
                'count': len(pois),
                'pois': pois
            })
        except Exception as e:
            logger.error(f"Error getting POIs: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/visualization', methods=['GET'])
    def get_poi_visualization():
        """Get POI data formatted for Cesium visualization"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            data = poi_manager.get_visualization_data()
            return jsonify({
                'status': 'ok',
                **data
            })
        except Exception as e:
            logger.error(f"Error getting POI visualization: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/category/<category>', methods=['GET'])
    def get_pois_by_category(category):
        """Get POIs filtered by category"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            pois = poi_manager.get_pois_by_category(category)
            return jsonify({
                'status': 'ok',
                'category': category,
                'count': len(pois),
                'pois': pois
            })
        except Exception as e:
            logger.error(f"Error getting POIs by category: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/area', methods=['GET'])
    def get_pois_in_area():
        """Get POIs within a bounding box"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            min_lat = float(request.args.get('min_lat', -90))
            max_lat = float(request.args.get('max_lat', 90))
            min_lon = float(request.args.get('min_lon', -180))
            max_lon = float(request.args.get('max_lon', 180))
            
            pois = poi_manager.get_pois_in_area(min_lat, max_lat, min_lon, max_lon)
            return jsonify({
                'status': 'ok',
                'bounds': {'min_lat': min_lat, 'max_lat': max_lat, 'min_lon': min_lon, 'max_lon': max_lon},
                'count': len(pois),
                'pois': pois
            })
        except Exception as e:
            logger.error(f"Error getting POIs in area: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/add', methods=['POST'])
    def add_poi():
        """Add a new POI manually"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
            required = ['name', 'latitude', 'longitude']
            for field in required:
                if field not in data:
                    return jsonify({'status': 'error', 'message': f'Missing field: {field}'}), 400
            
            poi_id = poi_manager.add_poi(
                name=data['name'],
                latitude=float(data['latitude']),
                longitude=float(data['longitude']),
                description=data.get('description', ''),
                category=data.get('category', 'manual'),
                altitude=float(data.get('altitude', 0)),
                metadata=data.get('metadata')
            )
            
            return jsonify({
                'status': 'ok',
                'message': 'POI added successfully',
                'poi_id': poi_id
            })
        except Exception as e:
            logger.error(f"Error adding POI: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/delete/<int:poi_id>', methods=['DELETE'])
    def delete_poi(poi_id):
        """Delete a POI by ID"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            deleted = poi_manager.delete_poi(poi_id)
            if deleted:
                return jsonify({'status': 'ok', 'message': f'POI {poi_id} deleted'})
            else:
                return jsonify({'status': 'error', 'message': f'POI {poi_id} not found'}), 404
        except Exception as e:
            logger.error(f"Error deleting POI: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/import', methods=['POST'])
    def import_kmz():
        """Import POIs from a KMZ file path"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            data = request.get_json()
            if not data or 'file_path' not in data:
                return jsonify({'status': 'error', 'message': 'file_path required'}), 400
            
            file_path = data['file_path']
            category = data.get('category', 'imported')
            
            count = poi_manager.import_kmz(file_path, category=category)
            return jsonify({
                'status': 'ok',
                'message': f'Imported {count} POIs from {file_path}',
                'count': count
            })
        except Exception as e:
            logger.error(f"Error importing KMZ: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/categories', methods=['GET'])
    def get_poi_categories():
        """Get list of POI categories"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available'}), 503
        try:
            categories = poi_manager.get_categories()
            return jsonify({
                'status': 'ok',
                'categories': categories
            })
        except Exception as e:
            logger.error(f"Error getting categories: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/poi/status', methods=['GET'])
    def get_poi_status():
        """Get POI system status"""
        if not poi_manager:
            return jsonify({'status': 'error', 'message': 'POI Manager not available', 'available': False}), 503
        try:
            return jsonify({
                'status': 'ok',
                'available': True,
                'total_pois': poi_manager.get_poi_count(),
                'categories': poi_manager.get_categories(),
                'database': poi_manager.db_path
            })
        except Exception as e:
            logger.error(f"Error getting POI status: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - OPERATOR SESSION MANAGEMENT & SSE STREAMING
    # ========================================================================

    @app.route('/api/operator/register', methods=['POST'])
    def operator_register():
        """Register a new operator"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            data = request.get_json() or {}
            callsign = data.get('callsign')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role', 'operator')
            team_id = data.get('team_id')
            
            if not all([callsign, email, password]):
                return jsonify({'status': 'error', 'message': 'Missing required fields: callsign, email, password'}), 400
            
            # Map role string to enum
            role_map = {
                'observer': OperatorRole.OBSERVER,
                'operator': OperatorRole.OPERATOR,
                'supervisor': OperatorRole.SUPERVISOR,
                'admin': OperatorRole.ADMIN
            }
            operator_role = role_map.get(role, OperatorRole.OPERATOR)
            
            operator = operator_manager.register_operator(
                callsign=callsign,
                email=email,
                password=password,
                role=operator_role,
                team_id=team_id
            )
            
            if operator:
                return jsonify({
                    'status': 'ok',
                    'message': 'Operator registered successfully',
                    'operator': operator.to_dict()
                })
            else:
                return jsonify({'status': 'error', 'message': 'Registration failed - callsign or email already exists'}), 409
                
        except Exception as e:
            logger.error(f"Error registering operator: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/operator/login', methods=['POST'])
    def operator_login():
        """Authenticate operator and create session"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            data = request.get_json() or {}
            callsign = data.get('callsign')
            password = data.get('password')
            
            if not all([callsign, password]):
                return jsonify({'status': 'error', 'message': 'Missing callsign or password'}), 400
            
            session = operator_manager.authenticate(callsign, password)
            
            if session:
                operator = operator_manager.get_operator(session.operator_id)
                return jsonify({
                    'status': 'ok',
                    'message': 'Login successful',
                    'session': session.to_dict(),
                    'operator': operator.to_dict() if operator else None
                })
            else:
                return jsonify({'status': 'error', 'message': 'Invalid callsign or password'}), 401
                
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/operator/logout', methods=['POST'])
    def operator_logout():
        """End operator session"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            # Get token from header or body
            token = request.headers.get('X-Session-Token') or (request.get_json() or {}).get('session_token')
            
            if not token:
                return jsonify({'status': 'error', 'message': 'No session token provided'}), 400
            
            if operator_manager.logout(token):
                return jsonify({'status': 'ok', 'message': 'Logged out successfully'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401
                
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/operator/session', methods=['GET'])
    def operator_session_info():
        """Get current session info"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token') or request.args.get('token')
            
            if not token:
                return jsonify({'status': 'error', 'message': 'No session token provided'}), 400
            
            session = operator_manager.validate_session(token)
            if session:
                operator = operator_manager.get_operator(session.operator_id)
                return jsonify({
                    'status': 'ok',
                    'session': session.to_dict(),
                    'operator': operator.to_dict() if operator else None
                })
            else:
                return jsonify({'status': 'error', 'message': 'Invalid or expired session'}), 401
                
        except Exception as e:
            logger.error(f"Error getting session info: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/operator/heartbeat', methods=['POST'])
    def operator_heartbeat():
        """Update session heartbeat and current view"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token') or (request.get_json() or {}).get('session_token')
            data = request.get_json() or {}
            current_view = data.get('current_view')
            
            if not token:
                return jsonify({'status': 'error', 'message': 'No session token provided'}), 400
            
            if operator_manager.heartbeat(token, current_view):
                return jsonify({'status': 'ok', 'message': 'Heartbeat received'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
                
        except Exception as e:
            logger.error(f"Error processing heartbeat: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/operator/active', methods=['GET'])
    def get_active_operators():
        """Get list of currently active operators"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            active = operator_manager.get_active_operators()
            return jsonify({
                'status': 'ok',
                'count': len(active),
                'operators': active
            })
        except Exception as e:
            logger.error(f"Error getting active operators: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/operator/stats', methods=['GET'])
    def get_operator_stats():
        """Get operator system statistics"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available', 'available': False}), 503
        
        try:
            stats = operator_manager.get_stats()
            return jsonify({
                'status': 'ok',
                'available': True,
                'stats': stats
            })
        except Exception as e:
            logger.error(f"Error getting operator stats: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - SSE ENTITY STREAMING
    # ========================================================================

    @app.route('/api/entities/stream', methods=['GET'])
    def entity_stream():
        """
        Server-Sent Events endpoint for real-time entity synchronization.
        
        Query params:
            token: Session token for authentication
            
        Events:
            PREEXISTING - Initial sync of existing entities
            CREATE - New entity created
            UPDATE - Entity modified
            DELETE - Entity removed
            HEARTBEAT - Keep-alive signal
        """
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        token = request.args.get('token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401
        
        client = operator_manager.register_sse_client(token)
        if not client:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        # Optional replay since sequence id
        since = request.args.get('since')
        if since:
            try:
                operator_manager.replay_events_since(client, int(since))
            except Exception:
                pass
        
        def generate():
            try:
                for event_data in operator_manager.sse_event_generator(client):
                    yield event_data
            except GeneratorExit:
                operator_manager.unregister_sse_client(client.session_id)
            except Exception as e:
                logger.error(f"SSE stream error: {e}")
                operator_manager.unregister_sse_client(client.session_id)
        
        return Response(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'  # Disable nginx buffering
            }
        )

    @app.route('/api/hypergraph/diff/stream', methods=['GET'])
    def hypergraph_diff_stream():
        """SSE stream that pushes Subgraph Diffs scoped to a DSL query.

        Query params:
            token: session token (required)
            dsl: URL-encoded DSL string (required)
            since: optional sequence id to start from
            query_id: optional client query id
        """
        if SubgraphDiffGenerator is None or QueryPredicate is None:
            return jsonify({'status': 'error', 'message': 'Subgraph diff module not available'}), 500

        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503

        token = request.args.get('token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Session token required'}), 401

        client = operator_manager.register_sse_client(token)
        if not client:
            return jsonify({'status': 'error', 'message': 'Invalid session token'}), 401

        # Accept either a query_id referencing a registered DSL, or a raw dsl param
        query_id_param = request.args.get('query_id')
        dsl = request.args.get('dsl') or ''
        parsed = {}
        query_id = query_id_param

        if query_id_param:
            try:
                with REGISTERED_QUERIES_LOCK:
                    entry = REGISTERED_QUERIES.get(query_id_param)
                if entry:
                    parsed = entry.get('parsed') or {}
                else:
                    return jsonify({'status': 'error', 'message': 'Unknown query_id'}), 404
            except Exception:
                parsed = {}
        else:
            if not dsl:
                return jsonify({'status': 'error', 'message': 'DSL required as query param when no query_id provided'}), 400
            try:
                parsed = parse_dsl(dsl) if parse_dsl else {}
            except Exception:
                parsed = {}
            query_id = query_id or (parsed.get('query_id') if isinstance(parsed, dict) else None) or 'query'

        predicate = QueryPredicate(parsed)

        # engine selection
        engine = globals().get('hypergraph_engine') or globals().get('hypergraph_store')
        redis_conn = globals().get('redis_client')
        gen = SubgraphDiffGenerator(engine, operator_manager=operator_manager, redis_client=redis_conn)

        # starting sequence
        since = request.args.get('since')
        try:
            last_seq = int(since) if since else (operator_manager.entity_sequence if operator_manager else 0)
        except Exception:
            last_seq = 0

        query_id = request.args.get('query_id') or parsed.get('query_id') or 'query'

        cond = threading.Condition()
        max_seq = {'v': last_seq}

        # subscribe to graph_event_bus if present
        subscription = None
        try:
            if 'graph_event_bus' in globals() and graph_event_bus is not None:
                def _on_event(ge):
                    try:
                        seq = getattr(ge, 'sequence_id', None) or ge.get('sequence_id') if isinstance(ge, dict) else None
                        if seq is None:
                            seq = getattr(ge, 'sequence', None)
                        if seq is None:
                            return
                        with cond:
                            if seq > max_seq['v']:
                                max_seq['v'] = int(seq)
                            cond.notify()
                    except Exception:
                        pass

                try:
                    graph_event_bus.subscribe(_on_event)
                    subscription = _on_event
                except Exception:
                    subscription = None
        except Exception:
            subscription = None

        def generate():
            nonlocal last_seq
            try:
                while True:
                    # wait until new events or timeout
                    with cond:
                        cond.wait(timeout=25.0)
                        current = max_seq['v']

                    if current is None:
                        current = last_seq

                    if current > last_seq:
                        try:
                            diff = gen.generate_diff(query_id, predicate, last_seq, current)
                            last_seq = current
                            payload = json.dumps(diff)
                            yield f"event: DIFF\n"
                            yield f"data: {payload}\n\n"
                        except GeneratorExit:
                            break
                        except Exception as e:
                            logger.debug(f"Error producing diff: {e}")
                    else:
                        # heartbeat with current sequence
                        hb = json.dumps({'query_id': query_id, 'to_sequence': last_seq, 'timestamp': datetime.utcnow().isoformat() + 'Z'})
                        try:
                            yield f"event: HEARTBEAT\n"
                            yield f"data: {hb}\n\n"
                        except GeneratorExit:
                            break
                    # loop continues
            finally:
                try:
                    if subscription and 'graph_event_bus' in globals() and graph_event_bus is not None:
                        try:
                            graph_event_bus.unsubscribe(subscription)
                        except Exception:
                            pass
                except Exception:
                    pass

        return Response(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )

    @app.route('/api/entities/publish', methods=['POST'])
    def publish_entity():
        """
        Publish or update an entity - broadcasts to all connected clients.
        
        Request body:
            entity_id: Unique entity identifier
            entity_type: Type of entity (poi, target, asset, etc.)
            entity_data: Entity data object
        """
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            if not token:
                return jsonify({'status': 'error', 'message': 'Session token required'}), 401
            
            operator = operator_manager.get_operator_for_session(token)
            if not operator:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
            
            data = request.get_json() or {}
            entity_id = data.get('entity_id')
            entity_type = data.get('entity_type', 'unknown')
            entity_data = data.get('entity_data', {})
            
            if not entity_id:
                return jsonify({'status': 'error', 'message': 'entity_id required'}), 400
            
            # Determine if this is a create or update
            is_new = entity_id not in operator_manager.entity_cache
            event_type = EntityEventType.CREATE if is_new else EntityEventType.UPDATE
            
            # Broadcast the entity event
            operator_manager.broadcast_entity_event(
                event_type=event_type,
                entity_id=entity_id,
                entity_type=entity_type,
                entity_data=entity_data,
                operator=operator
            )
            
            return jsonify({
                'status': 'ok',
                'message': f'Entity {"created" if is_new else "updated"}',
                'entity_id': entity_id,
                'event_type': event_type.value
            })
            
        except Exception as e:
            logger.error(f"Error publishing entity: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/entities/delete/<entity_id>', methods=['DELETE'])
    def delete_entity(entity_id):
        """Delete an entity - broadcasts removal to all connected clients"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            if not token:
                return jsonify({'status': 'error', 'message': 'Session token required'}), 401
            
            operator = operator_manager.get_operator_for_session(token)
            if not operator:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
            
            # Broadcast delete event
            operator_manager.broadcast_entity_event(
                event_type=EntityEventType.DELETE,
                entity_id=entity_id,
                entity_type='deleted',
                entity_data={'deleted': True},
                operator=operator
            )
            
            return jsonify({
                'status': 'ok',
                'message': 'Entity deleted',
                'entity_id': entity_id
            })
            
        except Exception as e:
            logger.error(f"Error deleting entity: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/entities/cached', methods=['GET'])
    def get_cached_entities():
        """Get all currently cached entities"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            return jsonify({
                'status': 'ok',
                'count': len(operator_manager.entity_cache),
                'entities': list(operator_manager.entity_cache.values())
            })
        except Exception as e:
            logger.error(f"Error getting cached entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - TEAM MANAGEMENT
    # ========================================================================

    @app.route('/api/team/create', methods=['POST'])
    def create_team():
        """Create a new team"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            data = request.get_json() or {}
            team_name = data.get('team_name')
            
            if not team_name:
                return jsonify({'status': 'error', 'message': 'team_name required'}), 400
            
            operator = operator_manager.get_operator_for_session(token) if token else None
            team_id = operator_manager.create_team(team_name, operator.operator_id if operator else None)
            
            if team_id:
                return jsonify({
                    'status': 'ok',
                    'message': 'Team created',
                    'team_id': team_id,
                    'team_name': team_name
                })
            else:
                return jsonify({'status': 'error', 'message': 'Team name already exists'}), 409
                
        except Exception as e:
            logger.error(f"Error creating team: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/team/<team_id>/members', methods=['GET'])
    def get_team_members(team_id):
        """Get members of a team"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            members = operator_manager.get_team_members(team_id)
            return jsonify({
                'status': 'ok',
                'team_id': team_id,
                'count': len(members),
                'members': [m.to_dict() for m in members]
            })
        except Exception as e:
            logger.error(f"Error getting team members: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/team/<team_id>/assign', methods=['POST'])
    def assign_to_team(team_id):
        """Assign an operator to a team"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            data = request.get_json() or {}
            operator_id = data.get('operator_id')
            
            if not operator_id:
                return jsonify({'status': 'error', 'message': 'operator_id required'}), 400
            
            if operator_manager.assign_to_team(operator_id, team_id):
                return jsonify({
                    'status': 'ok',
                    'message': 'Operator assigned to team',
                    'operator_id': operator_id,
                    'team_id': team_id
                })
            else:
                return jsonify({'status': 'error', 'message': 'Assignment failed'}), 400
                
        except Exception as e:
            logger.error(f"Error assigning to team: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - ROOM/CHANNEL MANAGEMENT
    # ========================================================================

    @app.route('/api/rooms', methods=['GET'])
    def list_rooms():
        """List all available rooms"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            include_private = request.args.get('include_private', 'false').lower() == 'true'
            rooms = operator_manager.list_rooms(include_private=include_private)
            return jsonify({
                'status': 'ok',
                'count': len(rooms),
                'rooms': rooms
            })
        except Exception as e:
            logger.error(f"Error listing rooms: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/create', methods=['POST'])
    def create_room():
        """Create a new room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            data = request.get_json() or {}
            
            room_name = data.get('room_name')
            if not room_name:
                return jsonify({'status': 'error', 'message': 'room_name required'}), 400
            
            operator = operator_manager.get_operator_for_session(token) if token else None
            
            room = operator_manager.create_room(
                room_name=room_name,
                room_type=data.get('room_type', 'custom'),
                created_by=operator.operator_id if operator else None,
                capacity=data.get('capacity', 50),
                is_private=data.get('is_private', False),
                password=data.get('password'),
                metadata=data.get('metadata')
            )
            
            if room:
                # Auto-join creator to the room
                session = operator_manager.validate_session(token) if token else None
                if session:
                    operator_manager.join_room(room.room_id, session.session_id)
                
                return jsonify({
                    'status': 'ok',
                    'message': 'Room created',
                    'room': room.to_dict()
                })
            else:
                return jsonify({'status': 'error', 'message': 'Room name already exists'}), 409
                
        except Exception as e:
            logger.error(f"Error creating room: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>', methods=['GET'])
    def get_room(room_id):
        """Get room details"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            room = operator_manager.get_room(room_id)
            if not room:
                return jsonify({'status': 'error', 'message': 'Room not found'}), 404
            
            members = operator_manager.get_room_members(room_id)
            entities = operator_manager.room_entities.get(room_id, {})
            
            return jsonify({
                'status': 'ok',
                'room': room.to_dict(),
                'member_count': len(members),
                'members': members,
                'entity_count': len(entities),
                'entities': list(entities.values())
            })
        except Exception as e:
            logger.error(f"Error getting room: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/join', methods=['POST'])
    def join_room_route(room_id):
        """Join a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            if not token:
                return jsonify({'status': 'error', 'message': 'Session token required'}), 401
            
            session = operator_manager.validate_session(token)
            if not session:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
            
            data = request.get_json() or {}
            password = data.get('password')
            
            success, message = operator_manager.join_room(room_id, session.session_id, password)
            
            if success:
                room = operator_manager.get_room(room_id)
                return jsonify({
                    'status': 'ok',
                    'message': message,
                    'room': room.to_dict() if room else None
                })
            else:
                return jsonify({'status': 'error', 'message': message}), 400
                
        except Exception as e:
            logger.error(f"Error joining room: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/leave', methods=['POST'])
    def leave_room_route(room_id):
        """Leave a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            if not token:
                return jsonify({'status': 'error', 'message': 'Session token required'}), 401
            
            session = operator_manager.validate_session(token)
            if not session:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
            
            success, message = operator_manager.leave_room(room_id, session.session_id)
            
            return jsonify({
                'status': 'ok' if success else 'error',
                'message': message
            })
                
        except Exception as e:
            logger.error(f"Error leaving room: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/close', methods=['DELETE'])
    def close_room_route(room_id):
        """Close/delete a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            operator = operator_manager.get_operator_for_session(token) if token else None
            
            success, message = operator_manager.close_room(
                room_id, 
                operator.operator_id if operator else "system"
            )
            
            return jsonify({
                'status': 'ok' if success else 'error',
                'message': message
            })
                
        except Exception as e:
            logger.error(f"Error closing room: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/members', methods=['GET'])
    def get_room_members_route(room_id):
        """Get members of a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            members = operator_manager.get_room_members(room_id)
            return jsonify({
                'status': 'ok',
                'room_id': room_id,
                'count': len(members),
                'members': members
            })
        except Exception as e:
            logger.error(f"Error getting room members: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/entities', methods=['GET'])
    def get_room_entities_route(room_id):
        """Get entities in a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            entities = operator_manager.room_entities.get(room_id, {})
            return jsonify({
                'status': 'ok',
                'room_id': room_id,
                'count': len(entities),
                'entities': list(entities.values())
            })
        except Exception as e:
            logger.error(f"Error getting room entities: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/publish', methods=['POST'])
    def publish_to_room_route(room_id):
        """Publish an entity to a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            session = operator_manager.validate_session(token) if token else None
            operator = operator_manager.get_operator_for_session(token) if token else None
            
            data = request.get_json() or {}
            entity_id = data.get('entity_id')
            entity_type = data.get('entity_type', 'entity')
            entity_data = data.get('entity_data', {})
            
            if not entity_id:
                return jsonify({'status': 'error', 'message': 'entity_id required'}), 400
            
            success = operator_manager.publish_to_room(
                room_id, entity_id, entity_type, entity_data,
                operator, session.session_id if session else None
            )
            
            if success:
                return jsonify({
                    'status': 'ok',
                    'message': 'Entity published to room',
                    'room_id': room_id,
                    'entity_id': entity_id
                })
            else:
                return jsonify({'status': 'error', 'message': 'Room not found'}), 404
                
        except Exception as e:
            logger.error(f"Error publishing to room: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/<room_id>/message', methods=['POST'])
    def send_room_message_route(room_id):
        """Send a message to a room"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            if not token:
                return jsonify({'status': 'error', 'message': 'Session token required'}), 401
            
            operator = operator_manager.get_operator_for_session(token)
            if not operator:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
            
            data = request.get_json() or {}
            message = data.get('message', '')
            message_type = data.get('message_type', 'chat')
            
            if not message:
                return jsonify({'status': 'error', 'message': 'message required'}), 400
            
            success = operator_manager.send_message_to_room(room_id, message, operator, message_type)
            
            if success:
                return jsonify({'status': 'ok', 'message': 'Message sent'})
            else:
                return jsonify({'status': 'error', 'message': 'Room not found'}), 404
                
        except Exception as e:
            logger.error(f"Error sending room message: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/rooms/my', methods=['GET'])
    def get_my_rooms():
        """Get rooms the current operator has joined"""
        if not operator_manager:
            return jsonify({'status': 'error', 'message': 'Operator Manager not available'}), 503
        
        try:
            token = request.headers.get('X-Session-Token')
            if not token:
                return jsonify({'status': 'error', 'message': 'Session token required'}), 401
            
            session = operator_manager.validate_session(token)
            if not session:
                return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
            
            # Find rooms this session has joined
            my_rooms = []
            for room_id, members in operator_manager.room_members.items():
                if session.session_id in members:
                    room = operator_manager.get_room(room_id)
                    if room:
                        my_rooms.append({
                            **room.to_dict(),
                            'member_count': len(members),
                            'entity_count': len(operator_manager.room_entities.get(room_id, {}))
                        })
            
            return jsonify({
                'status': 'ok',
                'count': len(my_rooms),
                'rooms': my_rooms
            })
                
        except Exception as e:
            logger.error(f"Error getting my rooms: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # WEBSOCKET EVENT HANDLERS (Flask-SocketIO)
    # ========================================================================

    if SOCKETIO_AVAILABLE and socketio:
        
        @socketio.on('connect')
        def ws_connect():
            """Handle WebSocket connection"""
            token = request.args.get('token')
            if not token or not operator_manager:
                disconnect()
                return False
            
            session = operator_manager.validate_session(token)
            if not session:
                disconnect()
                return False
            
            operator = operator_manager.get_operator(session.operator_id)
            if operator:
                # Store session ID in socket session
                from flask import session as flask_session
                flask_session['session_id'] = session.session_id
                flask_session['operator_id'] = operator.operator_id
                
                # Register WebSocket client
                # Note: websocket object passed to register_ws_client would need socketio context
                # For now we use SSE client registration with WebSocket-like behavior
                logger.info(f"[WebSocket] Client connected: {operator.callsign}")
                
                # Auto-join Global room via SocketIO rooms
                global_room = operator_manager.get_room_by_name("Global")
                if global_room:
                    join_room(global_room.room_id)
                    operator_manager.join_room(global_room.room_id, session.session_id)
                
                emit('connected', {
                    'status': 'ok',
                    'operator': operator.to_dict(),
                    'session_id': session.session_id
                })
                return True
            
            disconnect()
            return False
        
        @socketio.on('disconnect')
        def ws_disconnect():
            """Handle WebSocket disconnection"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            
            if session_id and operator_manager:
                operator_manager.unregister_ws_client(session_id)
                logger.info(f"[WebSocket] Client disconnected: {session_id}")
        
        @socketio.on('join_room')
        def ws_join_room(data):
            """Handle room join request via WebSocket"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            
            if not session_id or not operator_manager:
                emit('error', {'message': 'Not authenticated'})
                return
            
            room_id = data.get('room_id')
            password = data.get('password')
            
            success, message = operator_manager.join_room(room_id, session_id, password)
            
            if success:
                join_room(room_id)  # SocketIO room
                room = operator_manager.get_room(room_id)
                emit('room_joined', {
                    'status': 'ok',
                    'room': room.to_dict() if room else None,
                    'message': message
                })
            else:
                emit('error', {'message': message})
        
        @socketio.on('leave_room')
        def ws_leave_room(data):
            """Handle room leave request via WebSocket"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            
            if not session_id or not operator_manager:
                emit('error', {'message': 'Not authenticated'})
                return
            
            room_id = data.get('room_id')
            success, message = operator_manager.leave_room(room_id, session_id)
            
            if success:
                leave_room(room_id)  # SocketIO room
                emit('room_left', {'status': 'ok', 'room_id': room_id, 'message': message})
            else:
                emit('error', {'message': message})
        
        @socketio.on('create_room')
        def ws_create_room(data):
            """Handle room creation via WebSocket"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            operator_id = flask_session.get('operator_id')
            
            if not session_id or not operator_manager:
                emit('error', {'message': 'Not authenticated'})
                return
            
            room = operator_manager.create_room(
                room_name=data.get('room_name'),
                room_type=data.get('room_type', 'custom'),
                created_by=operator_id,
                capacity=data.get('capacity', 50),
                is_private=data.get('is_private', False),
                password=data.get('password'),
                metadata=data.get('metadata')
            )
            
            if room:
                # Auto-join creator
                operator_manager.join_room(room.room_id, session_id)
                join_room(room.room_id)
                emit('room_created', {'status': 'ok', 'room': room.to_dict()})
            else:
                emit('error', {'message': 'Failed to create room'})
        
        @socketio.on('list_rooms')
        def ws_list_rooms(data=None):
            """List available rooms via WebSocket"""
            if not operator_manager:
                emit('error', {'message': 'Not available'})
                return
            
            data = data or {}
            rooms = operator_manager.list_rooms(include_private=data.get('include_private', False))
            emit('rooms_list', {'status': 'ok', 'rooms': rooms})
        
        @socketio.on('publish_entity')
        def ws_publish_entity(data):
            """Publish entity to room via WebSocket"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            operator_id = flask_session.get('operator_id')
            
            if not session_id or not operator_manager:
                emit('error', {'message': 'Not authenticated'})
                return
            
            room_id = data.get('room_id')
            entity_id = data.get('entity_id')
            entity_type = data.get('entity_type', 'entity')
            entity_data = data.get('entity_data', {})
            
            operator = operator_manager.get_operator(operator_id)
            
            if room_id:
                success = operator_manager.publish_to_room(
                    room_id, entity_id, entity_type, entity_data,
                    operator, session_id
                )
            else:
                # Global publish
                operator_manager.broadcast_entity_event(
                    EntityEventType.UPDATE if entity_id in operator_manager.entity_cache else EntityEventType.CREATE,
                    entity_id, entity_type, entity_data, operator, session_id
                )
                success = True
            
            emit('entity_published', {'status': 'ok' if success else 'error', 'entity_id': entity_id})
        
        @socketio.on('send_message')
        def ws_send_message(data):
            """Send message to room via WebSocket"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            operator_id = flask_session.get('operator_id')
            
            if not session_id or not operator_manager:
                emit('error', {'message': 'Not authenticated'})
                return
            
            room_id = data.get('room_id')
            message = data.get('message', '')
            message_type = data.get('message_type', 'chat')
            
            operator = operator_manager.get_operator(operator_id)
            
            if operator and room_id:
                success = operator_manager.send_message_to_room(room_id, message, operator, message_type)
                if success:
                    emit('message_sent', {'status': 'ok'})
                else:
                    emit('error', {'message': 'Failed to send message'})
            else:
                emit('error', {'message': 'Invalid operator or room'})
        
        @socketio.on('heartbeat')
        def ws_heartbeat(data=None):
            """Handle heartbeat via WebSocket"""
            from flask import session as flask_session
            session_id = flask_session.get('session_id')
            
            if session_id and operator_manager:
                session = operator_manager.sessions.get(session_id)
                if session:
                    data = data or {}
                    operator_manager.heartbeat(session.session_token, data.get('current_view'))
                    emit('heartbeat_ack', {'status': 'ok', 'timestamp': time.time()})

    # ========================================================================
    # API ROUTES - REVENGE ECOSYSTEM HYPERGRAPH
    # ========================================================================
    
    # Initialize Revenge Ecosystem Engine
    revenge_ecosystem = None
    try:
        from revenge_ecosystem_hypergraph import (
            RevengeEcosystemEngine, EcosystemNode, EcosystemHyperedge, 
            EcosystemEvent, OrganMask, ActorKind, InfrastructureKind,
            ArtifactKind, HyperedgeKind, EcosystemEventType, export_shader_uniforms
        )
        revenge_ecosystem = RevengeEcosystemEngine(
            hypergraph_engine=hypergraph_engine if 'hypergraph_engine' in dir() else None
        )
        logger.info("Revenge Ecosystem Engine initialized")
    except ImportError as e:
        logger.warning(f"Revenge Ecosystem module not available: {e}")
    except Exception as e:
        logger.error(f"Failed to initialize Revenge Ecosystem: {e}")

    @app.route('/api/ecosystem/nodes', methods=['GET'])
    def get_ecosystem_nodes():
        """Get all ecosystem nodes"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            nodes = [node.to_dict() for node in revenge_ecosystem.nodes.values()]
            return jsonify({'status': 'ok', 'nodes': nodes, 'count': len(nodes)})
        except Exception as e:
            logger.error(f"Error getting ecosystem nodes: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/nodes/<node_id>', methods=['GET'])
    def get_ecosystem_node(node_id):
        """Get a specific ecosystem node"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            node = revenge_ecosystem.get_node(node_id)
            if node:
                return jsonify({'status': 'ok', 'node': node.to_dict()})
            return jsonify({'status': 'error', 'message': 'Node not found'}), 404
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/edges', methods=['GET'])
    def get_ecosystem_edges():
        """Get all ecosystem hyperedges"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            edges = [edge.to_dict() for edge in revenge_ecosystem.edges.values()]
            return jsonify({'status': 'ok', 'edges': edges, 'count': len(edges)})
        except Exception as e:
            logger.error(f"Error getting ecosystem edges: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/organ-state', methods=['GET'])
    def get_ecosystem_organ_state():
        """Get current organ state (intensities)"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            return jsonify({
                'status': 'ok',
                **revenge_ecosystem.organ_state.to_dict()
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/metrics', methods=['GET'])
    def get_ecosystem_metrics():
        """Get ecosystem metrics"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            metrics = revenge_ecosystem.get_metrics()
            return jsonify({'status': 'ok', 'metrics': metrics})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/shader-uniforms', methods=['GET'])
    def get_ecosystem_shader_uniforms():
        """Get shader uniforms for GPU rendering"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            uniforms = export_shader_uniforms(revenge_ecosystem)
            return jsonify({'status': 'ok', 'uniforms': uniforms})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/generate-scenario', methods=['POST'])
    def generate_ecosystem_scenario():
        """Generate a test scenario"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            data = request.get_json() or {}
            scenario_type = data.get('scenario_type', 'harassment_campaign')
            result = revenge_ecosystem.generate_scenario(scenario_type)
            return jsonify({'status': 'ok', 'scenario': result})
        except Exception as e:
            logger.error(f"Error generating scenario: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/process-event', methods=['POST'])
    def process_ecosystem_event():
        """Process an ecosystem event"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            data = request.get_json() or {}
            event = EcosystemEvent(
                id=data.get('id', f"event_{int(time.time()*1000)}"),
                event_type=data.get('event_type', 'CommissionCreated'),
                node_ids=data.get('node_ids', []),
                edge_ids=data.get('edge_ids', []),
                intensity=data.get('intensity', 0.5),
                budget=data.get('budget', 0),
                organ_mask=data.get('organ_mask', 0)
            )
            revenge_ecosystem.process_event(event)
            return jsonify({'status': 'ok', 'event_id': event.id})
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/tick', methods=['POST'])
    def tick_ecosystem():
        """Advance ecosystem simulation by one tick"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            data = request.get_json() or {}
            delta_time = data.get('delta_time', None)
            revenge_ecosystem.tick(delta_time)
            return jsonify({
                'status': 'ok',
                'organ_state': revenge_ecosystem.organ_state.to_dict()
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/attack-surface/<victim_id>', methods=['GET'])
    def get_attack_surface(victim_id):
        """Get attack surface for a victim"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            surface = revenge_ecosystem.get_attack_surface(victim_id)
            if surface:
                return jsonify({'status': 'ok', 'attack_surface': surface})
            return jsonify({'status': 'error', 'message': 'Victim not found'}), 404
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/obfuscation-layers/<operator_id>', methods=['GET'])
    def get_obfuscation_layers(operator_id):
        """Trace obfuscation layers from an operator"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            layers = revenge_ecosystem.trace_obfuscation_layers(operator_id)
            return jsonify({'status': 'ok', 'layers': layers, 'depth': len(layers)})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ecosystem/organ/<organ_name>/nodes', methods=['GET'])
    def get_organ_nodes(organ_name):
        """Get all nodes in a specific organ"""
        if not revenge_ecosystem:
            return jsonify({'status': 'error', 'message': 'Ecosystem not available'}), 503
        try:
            organ_map = {
                'harassment': OrganMask.HARASSMENT,
                'doxxing': OrganMask.DOXXING,
                'reputation': OrganMask.REPUTATION,
                'obfuscation': OrganMask.OBFUSCATION,
                'escalation': OrganMask.ESCALATION
            }
            organ = organ_map.get(organ_name.lower())
            if not organ:
                return jsonify({'status': 'error', 'message': 'Unknown organ'}), 400
            nodes = [n.to_dict() for n in revenge_ecosystem.get_organ_nodes(organ)]
            return jsonify({'status': 'ok', 'organ': organ_name, 'nodes': nodes, 'count': len(nodes)})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ========================================================================
    # API ROUTES - SYSTEM STATUS
    # ========================================================================

    @app.route('/api/status', methods=['GET'])
    def get_status():
        """Get overall system status"""
        status_data = {
            'status': 'ok',
            'server': 'RF SCYTHE Integrated Server',
            'version': '1.3.0',
            'uptime': time.time() - hypergraph_store.start_time,
            'components': {
                'hypergraph': {
                    'nodes': len(hypergraph_store.nodes),
                    'edges': len(hypergraph_store.hyperedges),
                    'session_id': hypergraph_store.session_id
                },
                'ecosystem': {
                    'available': revenge_ecosystem is not None,
                    'nodes': len(revenge_ecosystem.nodes) if revenge_ecosystem else 0,
                    'edges': len(revenge_ecosystem.edges) if revenge_ecosystem else 0,
                    'events': len(revenge_ecosystem.events) if revenge_ecosystem else 0,
                    'organ_state': revenge_ecosystem.organ_state.to_dict() if revenge_ecosystem else None
                },
                'nmap': {
                    'available': nmap_scanner.check_nmap_available(),
                    'scanning': nmap_scanner.scanning
                },
                'ndpi': {
                    'available': ndpi_analyzer.check_ndpi_available(),
                    'analyzing': ndpi_analyzer.analyzing
                },
                'ais': {
                    'available': ais_tracker.csv_loaded,
                    'vessel_count': len(ais_tracker.vessels)
                },
                'recon': {
                    'active': recon_system.active,
                    'entity_count': len(recon_system.entities),
                    'task_count': len(recon_system.tasks),
                    'alert_count': len(recon_system.get_proximity_alerts())
                },
                'operators': {
                    'available': operator_manager is not None,
                    'stats': operator_manager.get_stats() if operator_manager else None
                },
                'rooms': {
                    'available': operator_manager is not None,
                    'count': len(operator_manager.rooms) if operator_manager else 0,
                    'websocket_available': SOCKETIO_AVAILABLE
                },
                'poi': {
                    'available': poi_manager is not None,
                    'count': poi_manager.get_poi_count() if poi_manager else 0
                }
            },
            'timestamp': time.time()
        }
        return jsonify(status_data)

    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({'status': 'healthy', 'timestamp': time.time()})

    # ========================================================================
    # STATIC FILE SERVING
    # ========================================================================

    @app.route('/')
    def serve_index():
        """Serve the main visualization page"""
        return send_from_directory('.', 'command-ops-visualization.html')

    @app.route('/<path:filename>')
    def serve_static(filename):
        """Serve static files"""
        return send_from_directory('.', filename)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    if not FLASK_AVAILABLE:
        print("❌ Flask is required. Install with:")
        print("   pip install flask flask-cors")
        sys.exit(1)
    
    import argparse
    
    parser = argparse.ArgumentParser(description='RF SCYTHE Integrated API Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--generate-test', action='store_true', help='Generate test data on startup')
    args = parser.parse_args()
    
    # Generate initial test data if requested
    if args.generate_test:
        logger.info("Generating initial test data...")
        hypergraph_store.generate_test_data(20, 88.0, 108.0, 1000.0)
    
    # Check for available tools
    nmap_available = nmap_scanner.check_nmap_available()
    ndpi_available = ndpi_analyzer.check_ndpi_available()
    ais_loaded = ais_tracker.csv_loaded
    ais_vessels = len(ais_tracker.vessels)
    recon_entities = len(recon_system.entities)
    recon_alerts = len(recon_system.get_proximity_alerts())
    
    # Check room system
    room_count = len(operator_manager.rooms) if operator_manager else 0
    
    # ========================================================================
    # AISSTREAM WEBSOCKET CLIENT
    # ========================================================================
    
    import asyncio
    try:
        import websockets
        WEBSOCKETS_AVAILABLE = True
    except ImportError:
        WEBSOCKETS_AVAILABLE = False
        logger.warning("websockets not available - AISStream disabled. Install with: pip install websockets")
    
    async def connect_aisstream():
        """Connect to AISStream.io and forward vessel updates via SocketIO"""
        global aisstream_active
        
        if not WEBSOCKETS_AVAILABLE:
            logger.error("websockets library not available")
            return
            
        API_KEY = "fb05649aa20b7b9bbc6192a1074ef72978b58254"
        
        # exponential reconnect delay (seconds)
        reconnect_delay = 1

        while aisstream_active:
            try:
                # Enable ping/pong keepalive and reasonable close timeout to detect half-open sockets
                async with websockets.connect(
                    "wss://stream.aisstream.io/v0/stream",
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5,
                    max_size=None
                ) as websocket:
                    logger.info("[AISStream] Connected to stream")
                    # Reset reconnect delay on successful connect
                    reconnect_delay = 1
                    
                    # Subscribe with bounding box (or use current if set)
                    bbox = aisstream_bounding_box or [[[-180, -90], [180, 90]]]  # Global by default
                    subscribe_message = {
                        "APIKey": API_KEY, 
                        "BoundingBoxes": bbox,
                        "FilterMessageTypes": ["PositionReport", "StaticDataReport"]  # Include vessel info
                    }
                    await websocket.send(json.dumps(subscribe_message))
                    
                    async for message_json in websocket:
                        message = json.loads(message_json)
                        message_type = message.get("MessageType")
                        
                        if message_type == "PositionReport":
                            ais_msg = message['Message']['PositionReport']
                            vessel_data = {
                                'mmsi': ais_msg.get('UserID'),
                                'lat': ais_msg.get('Latitude'),
                                'lon': ais_msg.get('Longitude'),
                                'speed': ais_msg.get('Sog'),  # Speed over ground
                                'course': ais_msg.get('Cog'),  # Course over ground
                                'heading': ais_msg.get('TrueHeading'),
                                'timestamp': datetime.now(timezone.utc).isoformat()
                            }
                            
                            # Update local AIS tracker
                            ais_tracker.update_vessel(vessel_data['mmsi'], vessel_data)
                            
                            # Broadcast via SocketIO if available
                            if socketio:
                                socketio.emit('ais_update', vessel_data, broadcast=True)
                            
                            logger.debug(f"[AISStream] Position update: Vessel {vessel_data['mmsi']} @ {vessel_data['lat']},{vessel_data['lon']}")
                            
                        elif message_type == "StaticDataReport":
                            ais_msg = message['Message']['StaticDataReport']
                            mmsi = ais_msg.get('UserID')
                            
                            # Extract vessel type from AIS type code
                            ais_type_code = ais_msg.get('Type', 0)
                            vessel_type = ais_tracker._decode_vessel_type(ais_type_code)
                            
                            vessel_data = {
                                'mmsi': mmsi,
                                'name': ais_msg.get('Name', '').strip() or f'MMSI_{mmsi}',
                                'vessel_type': vessel_type,
                                'length': ais_msg.get('Length', 0),
                                'width': ais_msg.get('Width', 0),
                                'draft': ais_msg.get('MaximumStaticDraught', 0),
                                'timestamp': datetime.now(timezone.utc).isoformat()
                            }
                            
                            # Update local AIS tracker with vessel info
                            ais_tracker.update_vessel(mmsi, vessel_data)
                            
                            logger.debug(f"[AISStream] Static data: Vessel {mmsi} ({vessel_type}) - {vessel_data['name']}")
                            
                        # Note: Could also handle other message types like BinaryBroadcast for additional data
                            
            except Exception as e:
                # Prefer structured handling for websockets close events so logs are actionable
                try:
                    from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
                except Exception:
                    ConnectionClosedOK = ConnectionClosedError = None

                if ConnectionClosedOK and isinstance(e, ConnectionClosedOK):
                    logger.info(f"[AISStream] Connection closed cleanly: {e}")
                elif ConnectionClosedError and isinstance(e, ConnectionClosedError):
                    # Often remote servers will drop connections without a close frame; log as warning
                    logger.warning(f"[AISStream] Connection closed with error: code={getattr(e, 'code', None)} reason={getattr(e, 'reason', None)} - {e}")
                else:
                    # Unknown exception - log stack for debugging
                    logger.exception(f"[AISStream] Connection error: {e}")

                # Exponential backoff for reconnects (cap at 60s)
                if aisstream_active:
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, 60)
                    
    def start_aisstream():
        """Start AISStream in background thread"""
        global aisstream_active, aisstream_thread
        
        if not WEBSOCKETS_AVAILABLE:
            logger.warning("[AISStream] Not starting - websockets library not installed")
            return
            
        aisstream_active = True
        
        def run_async_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(connect_aisstream())
            
        aisstream_thread = threading.Thread(target=run_async_loop, daemon=True)
        aisstream_thread.start()
        logger.info("[AISStream] Started in background thread")
        
    def stop_aisstream():
        """Stop AISStream"""
        global aisstream_active
        aisstream_active = False
        logger.info("[AISStream] Stopped")
    
    # API endpoint to control AISStream
    @app.route('/api/ais/stream/start', methods=['POST'])
    def start_ais_stream():
        """Start AISStream with optional bounding box"""
        global aisstream_bounding_box
        
        data = request.get_json() or {}
        bbox = data.get('bounding_box')
        
        if bbox:
            aisstream_bounding_box = bbox
            logger.info(f"[AISStream] Bounding box updated: {bbox}")
            
        start_aisstream()
        return jsonify({'status': 'started', 'bounding_box': aisstream_bounding_box})
    
    @app.route('/api/ais/stream/stop', methods=['POST'])
    def stop_ais_stream():
        """Stop AISStream"""
        stop_aisstream()
        return jsonify({'status': 'stopped'})
    
    @app.route('/api/ais/stream/status', methods=['GET'])
    def ais_stream_status():
        """Get AISStream status"""
        return jsonify({
            'active': aisstream_active,
            'bounding_box': aisstream_bounding_box,
            'vessel_count': len(ais_tracker.vessels)
        })
    
    # ========================================================================
    
    logger.info(f"nmap available: {nmap_available}")
    logger.info(f"nDPI available: {ndpi_available}")
    logger.info(f"AIS loaded: {ais_loaded}, vessels: {ais_vessels}")
    logger.info(f"Recon system: {recon_entities} entities, {recon_alerts} alerts")
    logger.info(f"Rooms: {room_count} active, WebSocket: {SOCKETIO_AVAILABLE}")
    
    # Print startup info
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║         RF SCYTHE Integrated API Server v1.3.0                   ║
╠══════════════════════════════════════════════════════════════════╣
║  🌐 Server: http://{args.host}:{args.port}                             
║  📡 Console: http://localhost:{args.port}/command-ops-visualization.html
║                                                                  ║
║  API Endpoints:                                                  ║
║    /api/rf-hypergraph/*    - Hypergraph visualization            ║
║    /api/nmap/*             - Network scanning                    ║
║    /api/ndpi/*             - Deep packet inspection              ║
║    /api/ais/*              - AIS vessel tracking                 ║
║    /api/recon/*            - Auto-reconnaissance system          ║
║    /api/rooms/*            - Room/Channel management             ║
║    /api/status             - System status                       ║
║                                                                  ║
║  nmap:      {'✅ Available' if nmap_available else '❌ Not installed'}
║  nDPI:      {'✅ Available' if ndpi_available else '❌ Not installed'}
║  AIS:       {'✅ Loaded (' + str(ais_vessels) + ' vessels)' if ais_loaded else '❌ No data'}
║  Recon:     ✅ Active ({recon_entities} entities)
║  Rooms:     ✅ Active ({room_count} rooms)
║  WebSocket: {'✅ Enabled' if SOCKETIO_AVAILABLE else '❌ SSE only (pip install flask-socketio)'}
╚══════════════════════════════════════════════════════════════════╝
    """)
    # Start background satellite refresh (default every 5 minutes)
    try:
        start_satellite_refresh(interval_seconds=300, categories=['starlink','visual','active'])
        logger.info('Satellite refresh background thread started (300s interval)')
    except Exception as e:
        logger.warning(f'Could not start satellite refresh thread: {e}')
    
    # Run the server with WebSocket support if available
    if SOCKETIO_AVAILABLE and socketio:
        socketio.run(app, host=args.host, port=args.port, debug=args.debug, allow_unsafe_werkzeug=True)
    else:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == '__main__':
    main()