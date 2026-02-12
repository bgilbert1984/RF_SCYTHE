// This file provides mock API responses for RF SCYTHE system
// It intercepts fetch requests to specific endpoints and returns predefined responses

document.addEventListener('DOMContentLoaded', function() {
    console.log('[Mock API] Initializing RF SCYTHE API mock server');
    
    // Generate mock hypergraph data
    function generateMockHypergraphData() {
        const nodes = [];
        const hyperedges = [];
        const centralNodes = [];
        
        // Generate random RF nodes
        for (let i = 0; i < 15; i++) {
            const node = {
                node_id: `rf_node_${i}_${Date.now()}`,
                position: [
                    37.7749 + (Math.random() - 0.5) * 0.1,  // lat
                    -122.4194 + (Math.random() - 0.5) * 0.1, // lon
                    Math.random() * 500  // altitude
                ],
                frequency: 88 + Math.random() * 20, // 88-108 MHz FM band
                power: -80 + Math.random() * 40,    // -80 to -40 dBm
                modulation: ['FM', 'AM', 'PSK', 'FSK'][Math.floor(Math.random() * 4)],
                timestamp: Date.now() / 1000
            };
            nodes.push(node);
            
            // Mark some as central nodes
            if (i < 3) {
                centralNodes.push({
                    node_id: node.node_id,
                    centrality: 0.8 - i * 0.1,
                    frequency: node.frequency
                });
            }
        }
        
        // Generate hyperedges between nodes
        for (let i = 0; i < 8; i++) {
            const cardinality = 2 + Math.floor(Math.random() * 3); // 2-4 nodes
            const edgeNodes = [];
            for (let j = 0; j < cardinality; j++) {
                const nodeIdx = Math.floor(Math.random() * nodes.length);
                if (!edgeNodes.includes(nodes[nodeIdx].node_id)) {
                    edgeNodes.push(nodes[nodeIdx].node_id);
                }
            }
            if (edgeNodes.length >= 2) {
                hyperedges.push({
                    nodes: edgeNodes,
                    cardinality: edgeNodes.length,
                    signal_strength: -80 + Math.random() * 50,
                    metadata: {
                        coherence: Math.random(),
                        timestamp: Date.now() / 1000
                    }
                });
            }
        }
        
        return { nodes, hyperedges, central_nodes: centralNodes };
    }
    
    // Generate mock metrics
    function generateMockHypergraphMetrics() {
        return {
            total_nodes: 15,
            total_hyperedges: 8,
            session_id: `session_${Date.now()}`,
            collection_duration: Math.floor(Math.random() * 3600),
            frequency_distribution: {
                '88-92': Math.floor(Math.random() * 5),
                '92-96': Math.floor(Math.random() * 5),
                '96-100': Math.floor(Math.random() * 5),
                '100-104': Math.floor(Math.random() * 5),
                '104-108': Math.floor(Math.random() * 5)
            },
            high_centrality_nodes: [
                { node_id: 'rf_node_0', centrality: 0.85, frequency: 95.5 },
                { node_id: 'rf_node_1', centrality: 0.72, frequency: 101.3 },
                { node_id: 'rf_node_2', centrality: 0.65, frequency: 88.9 }
            ]
        };
    }
    
    // Define mock API endpoints and their responses
    const mockApis = [
        { 
            url: '/api/ionosphere/layers', 
            response: {
                status: 'success',
                data: {
                    layers: {
                        D: { active: true, minHeight: 60, maxHeight: 90 },
                        E: { active: true, minHeight: 90, maxHeight: 150 },
                        F1: { active: true, minHeight: 150, maxHeight: 250 },
                        F2: { active: true, minHeight: 250, maxHeight: 500 }
                    },
                    solarActivity: {
                        solarFlux: 120.5,
                        kpIndex: 3.2
                    },
                    lastUpdate: new Date().getTime()
                }
            }
        },
        {
            url: '/api/strf/satellites',
            response: {
                status: 'success',
                data: {
                    satellites: [
                        { id: 'SAT-001', name: 'RF Monitor 1', lat: 37.7749, lon: -122.4194, alt: 500000, type: 'LEO', status: 'active' },
                        { id: 'SAT-002', name: 'RF Monitor 2', lat: 40.7128, lon: -74.0060, alt: 520000, type: 'LEO', status: 'active' },
                        { id: 'SAT-003', name: 'SIGINT Alpha', lat: 34.0522, lon: -118.2437, alt: 480000, type: 'LEO', status: 'standby' }
                    ]
                }
            }
        },
        {
            url: '/api/classify-signal',
            response: {
                success: true,
                classification: {
                    modulation: 'FSK',
                    confidence: 0.92,
                    source_types: ['Wireless IoT Device', 'Smart Home System', 'Industrial Control']
                }
            }
        },
        {
            url: '/api/rf-hypergraph/visualization',
            dynamic: true,
            getResponse: generateMockHypergraphData
        },
        {
            url: '/api/rf-hypergraph/metrics',
            dynamic: true,
            getResponse: () => ({ status: 'ok', metrics: generateMockHypergraphMetrics() })
        },
        {
            url: '/api/rf-hypergraph/generate-test',
            dynamic: true,
            getResponse: generateMockHypergraphData
        },
        {
            url: '/api/rf-hypergraph/reset',
            response: { status: 'ok', message: 'Hypergraph session reset successfully' }
        },
        {
            url: '/api/rf-hypergraph/status',
            response: { status: 'ok', collector_stats: { nodes_processed: 15, hyperedges_detected: 8 } }
        }
    ];
    
    // Store the original fetch function
    const originalFetch = window.fetch;
    
    // Override fetch to intercept requests to our mock endpoints
    window.fetch = function(url, options) {
        // Normalize the URL to extract just the path
        let urlPath = url;
        if (typeof url === 'string') {
            try {
                // Handle both relative and absolute URLs
                if (url.startsWith('http://') || url.startsWith('https://')) {
                    urlPath = new URL(url).pathname + new URL(url).search;
                }
            } catch (e) {
                // If URL parsing fails, use the original
                urlPath = url;
            }
        }
        
        // Check if the request URL matches any of our mock APIs
        for (const mockApi of mockApis) {
            if (typeof urlPath === 'string' && urlPath.includes(mockApi.url)) {
                console.log(`[Mock API] Intercepted request to ${urlPath}`);
                
                // Handle dynamic responses
                const response = mockApi.dynamic ? mockApi.getResponse() : mockApi.response;
                
                // Return a Promise that resolves with a mock Response object
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: () => Promise.resolve(response),
                    text: () => Promise.resolve(JSON.stringify(response))
                });
            }
        }
        
        // For any other requests, pass through to the original fetch
        console.log(`[Mock API] Passing through request to ${url}`);
        return originalFetch(url, options);
    };
    
    // Add RF_SCYTHE.generateNetworkCaptureReport function
    window.RF_SCYTHE = window.RF_SCYTHE || {};
    window.RF_SCYTHE.generateNetworkCaptureReport = function(options) {
        return Promise.resolve({
            timestamp: options.timestamp || new Date().toISOString(),
            summary: {
                total_packets: Math.floor(Math.random() * 10000) + 1000,
                unique_sources: Math.floor(Math.random() * 50) + 10,
                unique_destinations: Math.floor(Math.random() * 100) + 20,
                protocols_detected: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS'],
                anomalies_detected: Math.floor(Math.random() * 5)
            },
            traffic_analysis: {
                top_talkers: [
                    { ip: '192.168.1.100', packets: 2500, bytes: 1500000 },
                    { ip: '10.0.0.50', packets: 1800, bytes: 900000 },
                    { ip: '172.16.0.25', packets: 1200, bytes: 600000 }
                ],
                protocol_distribution: {
                    'TCP': 65,
                    'UDP': 25,
                    'ICMP': 5,
                    'Other': 5
                }
            },
            security_events: [
                { type: 'Port Scan Detected', severity: 'medium', source: '192.168.1.200', timestamp: new Date().toISOString() },
                { type: 'Unusual Traffic Pattern', severity: 'low', source: '10.0.0.75', timestamp: new Date().toISOString() }
            ],
            rf_correlation: {
                signals_detected: Math.floor(Math.random() * 10) + 5,
                frequency_range: '2.4GHz - 5.8GHz',
                interference_level: 'Low'
            }
        });
    };
    
    console.log('[Mock API] RF SCYTHE API mock server ready');
});
