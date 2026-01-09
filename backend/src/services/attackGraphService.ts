import { supabase } from '../db/supabase';
import { log, LogLevel, withRetry, validate } from '../utils/dbUtils';

const CONTEXT = 'AttackGraphService';

// Type definitions
export interface NodePosition {
    x: number;
    y: number;
}

export interface NodeData {
    description: string;
    severity?: 'critical' | 'high' | 'medium' | 'low';
    endpoint?: string;
    method?: string;
    vulnerability_id?: string;
    recommendation?: string;
    cwe?: string;
    owasp?: string;
    label?: string;
}

export interface AttackNode {
    id: string;
    type: 'start' | 'api_call' | 'exploit' | 'vulnerability' | 'end';
    label: string;
    data: NodeData;
    position: NodePosition;
}

export interface AttackEdge {
    id: string;
    source: string;
    target: string;
    label?: string;
    type?: 'default' | 'exploit' | 'vulnerable';
}

export interface AttackGraph {
    nodes: AttackNode[];
    edges: AttackEdge[];
    scan_id?: string;
    created_at?: string;
    updated_at?: string;
}

export interface NodeDetails {
    node: AttackNode;
    scan_id: string | null;
    requests: RequestEvidence[];
    analysis: string;
    relatedNodes: AttackNode[];
    attackPaths: AttackPath[];
}

export interface RequestEvidence {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: any;
    response: {
        status: number;
        headers: Record<string, string>;
        body: any;
    };
}

export interface AttackPath {
    id: string;
    name: string;
    nodes: string[];
    severity: string;
    description: string;
}

// Layout configuration
const LAYOUT_CONFIG = {
    nodeWidth: 200,
    nodeHeight: 80,
    horizontalSpacing: 280,
    verticalSpacing: 150,
    startX: 100,
    startY: 100,
    maxNodesPerColumn: 6
};

// Type order for hierarchical layout
const TYPE_ORDER: Record<string, number> = {
    'start': 0,
    'api_call': 1,
    'vulnerability': 2,
    'exploit': 3,
    'end': 4
};

/**
 * Validates a node position object
 */
function isValidPosition(position: any): position is NodePosition {
    return (
        position &&
        typeof position === 'object' &&
        typeof position.x === 'number' &&
        typeof position.y === 'number' &&
        !isNaN(position.x) &&
        !isNaN(position.y) &&
        isFinite(position.x) &&
        isFinite(position.y)
    );
}

/**
 * Validates a node data object
 */
function isValidNodeData(data: any): data is NodeData {
    return (
        data &&
        typeof data === 'object' &&
        typeof data.description === 'string'
    );
}

/**
 * Validates a single node
 */
function isValidNode(node: any): boolean {
    return (
        node &&
        typeof node === 'object' &&
        typeof node.id === 'string' &&
        node.id.length > 0 &&
        typeof node.type === 'string' &&
        ['start', 'api_call', 'exploit', 'vulnerability', 'end'].includes(node.type)
    );
}

/**
 * Validates a single edge
 */
function isValidEdge(edge: any, nodeIds: Set<string>): boolean {
    return (
        edge &&
        typeof edge === 'object' &&
        typeof edge.id === 'string' &&
        edge.id.length > 0 &&
        typeof edge.source === 'string' &&
        typeof edge.target === 'string' &&
        nodeIds.has(edge.source) &&
        nodeIds.has(edge.target) &&
        edge.source !== edge.target // No self-loops
    );
}

/**
 * Calculates optimal node positions using hierarchical layout
 */
function calculateNodePositions(nodes: AttackNode[]): AttackNode[] {
    const context = `${CONTEXT}.calculateNodePositions`;

    // Group nodes by type
    const nodesByType: Record<string, AttackNode[]> = {};

    nodes.forEach(node => {
        const type = node.type || 'api_call';
        if (!nodesByType[type]) {
            nodesByType[type] = [];
        }
        nodesByType[type].push(node);
    });

    log(LogLevel.DEBUG, context, 'Grouped nodes by type', {
        types: Object.keys(nodesByType),
        counts: Object.fromEntries(Object.entries(nodesByType).map(([k, v]) => [k, v.length]))
    });

    // Calculate positions based on type hierarchy
    const positionedNodes: AttackNode[] = [];
    const typeKeys = Object.keys(nodesByType).sort((a, b) =>
        (TYPE_ORDER[a] ?? 5) - (TYPE_ORDER[b] ?? 5)
    );

    typeKeys.forEach((type, colIndex) => {
        const typeNodes = nodesByType[type];
        const nodesInColumn = typeNodes.length;

        // Center nodes vertically in their column
        const totalHeight = (nodesInColumn - 1) * LAYOUT_CONFIG.verticalSpacing;
        const startY = LAYOUT_CONFIG.startY + Math.max(0, (LAYOUT_CONFIG.maxNodesPerColumn * LAYOUT_CONFIG.verticalSpacing - totalHeight) / 2);

        typeNodes.forEach((node, rowIndex) => {
            const position: NodePosition = {
                x: LAYOUT_CONFIG.startX + colIndex * LAYOUT_CONFIG.horizontalSpacing,
                y: startY + rowIndex * LAYOUT_CONFIG.verticalSpacing
            };

            positionedNodes.push({
                ...node,
                position
            });
        });
    });

    log(LogLevel.DEBUG, context, `Positioned ${positionedNodes.length} nodes`);
    return positionedNodes;
}

/**
 * Validates and fixes a node, ensuring all required fields are present
 */
function validateAndFixNode(node: any, index: number): AttackNode {
    const id = node.id || `node-${index}-${Date.now()}`;
    const type = ['start', 'api_call', 'exploit', 'vulnerability', 'end'].includes(node.type)
        ? node.type
        : 'api_call';

    // Build data object with defaults
    const data: NodeData = {
        description: node.data?.description || node.description || `Node ${index}`,
        severity: node.data?.severity || node.severity || 'medium',
        endpoint: node.data?.endpoint || node.endpoint,
        method: node.data?.method || node.method,
        vulnerability_id: node.data?.vulnerability_id,
        recommendation: node.data?.recommendation,
        cwe: node.data?.cwe,
        owasp: node.data?.owasp,
        label: node.label || node.data?.label || id
    };

    // Validate position or use default
    const position: NodePosition = isValidPosition(node.position)
        ? node.position
        : {
            x: LAYOUT_CONFIG.startX + (index % 4) * LAYOUT_CONFIG.horizontalSpacing,
            y: LAYOUT_CONFIG.startY + Math.floor(index / 4) * LAYOUT_CONFIG.verticalSpacing
        };

    return {
        id,
        type,
        label: node.label || data.label || id,
        data,
        position
    };
}

/**
 * Validates and fixes an edge
 */
function validateAndFixEdge(edge: any, index: number, nodeIds: Set<string>): AttackEdge | null {
    if (!edge.source || !edge.target) {
        return null;
    }

    // Skip edges referencing non-existent nodes
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) {
        log(LogLevel.WARN, `${CONTEXT}.validateAndFixEdge`, 'Edge references non-existent node', {
            edgeId: edge.id,
            source: edge.source,
            target: edge.target,
            existingNodes: Array.from(nodeIds)
        });
        return null;
    }

    // Skip self-loops
    if (edge.source === edge.target) {
        return null;
    }

    return {
        id: edge.id || `edge-${index}-${Date.now()}`,
        source: edge.source,
        target: edge.target,
        label: edge.label || '',
        type: ['default', 'exploit', 'vulnerable'].includes(edge.type) ? edge.type : 'default'
    };
}

/**
 * Validates and fixes an entire attack graph
 */
export function validateAttackGraph(graph: any, scanId?: string): AttackGraph {
    const context = `${CONTEXT}.validateAttackGraph`;

    if (!graph || typeof graph !== 'object') {
        log(LogLevel.WARN, context, 'Invalid graph object, returning empty graph');
        return { nodes: [], edges: [], scan_id: scanId };
    }

    // Validate and fix nodes
    const rawNodes: any[] = Array.isArray(graph.nodes) ? graph.nodes : [];
    const validatedNodes: AttackNode[] = rawNodes.map((node: any, index: number) => validateAndFixNode(node, index));

    // Check if positions need recalculation
    const needsPositioning = validatedNodes.some((node: AttackNode) => !isValidPosition(node.position));
    const positionedNodes: AttackNode[] = needsPositioning
        ? calculateNodePositions(validatedNodes)
        : validatedNodes;

    // Create set of valid node IDs for edge validation
    const nodeIds = new Set<string>(positionedNodes.map((n: AttackNode) => n.id));

    // Validate and fix edges
    const rawEdges: any[] = Array.isArray(graph.edges) ? graph.edges : [];
    const validatedEdges: AttackEdge[] = rawEdges
        .map((edge: any, index: number) => validateAndFixEdge(edge, index, nodeIds))
        .filter((edge: AttackEdge | null): edge is AttackEdge => edge !== null);

    // Remove duplicate edges
    const edgeKeys = new Set<string>();
    const uniqueEdges = validatedEdges.filter((edge: AttackEdge) => {
        const key = `${edge.source}->${edge.target}`;
        if (edgeKeys.has(key)) {
            return false;
        }
        edgeKeys.add(key);
        return true;
    });

    log(LogLevel.INFO, context, 'Graph validated', {
        originalNodes: rawNodes.length,
        validatedNodes: positionedNodes.length,
        originalEdges: rawEdges.length,
        validatedEdges: uniqueEdges.length
    });

    return {
        nodes: positionedNodes,
        edges: uniqueEdges,
        scan_id: scanId || graph.scan_id
    };
}

/**
 * Generates request evidence for a node based on its type
 */
function generateRequestEvidence(node: AttackNode): RequestEvidence[] {
    const requests: RequestEvidence[] = [];

    if (node.type === 'api_call' && node.data.endpoint) {
        requests.push({
            method: node.data.method || 'GET',
            url: node.data.endpoint,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer <token>'
            },
            body: ['POST', 'PUT', 'PATCH'].includes(node.data.method || '')
                ? { example: 'request body' }
                : null,
            response: {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
                body: { message: 'Example response' }
            }
        });
    }

    if (node.type === 'vulnerability') {
        requests.push({
            method: 'POST',
            url: node.data.endpoint || '/api/vulnerable-endpoint',
            headers: { 'Content-Type': 'application/json' },
            body: { payload: '<malicious input>' },
            response: {
                status: 500,
                headers: { 'Content-Type': 'application/json' },
                body: { error: 'Unexpected error - vulnerability triggered' }
            }
        });
    }

    if (node.type === 'exploit') {
        requests.push({
            method: 'POST',
            url: node.data.endpoint || '/api/exploit-target',
            headers: {
                'Content-Type': 'application/json',
                'X-Exploit-Header': 'malicious-value'
            },
            body: { exploit_payload: '...' },
            response: {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
                body: { compromised: true }
            }
        });
    }

    return requests;
}

/**
 * Generates analysis text for a node
 */
function generateNodeAnalysis(node: AttackNode): string {
    const severity = node.data.severity || 'medium';
    const type = node.type;

    const severityDescriptions: Record<string, string> = {
        critical: 'CRITICAL severity - Requires immediate attention and remediation.',
        high: 'HIGH severity - Should be addressed urgently within 24-48 hours.',
        medium: 'MEDIUM severity - Should be reviewed and addressed in the next sprint.',
        low: 'LOW severity - Should be tracked and addressed when resources allow.'
    };

    let analysis = `## ${node.label}\n\n`;
    analysis += `**Type:** ${type.replace('_', ' ').toUpperCase()}\n`;
    analysis += `**Severity:** ${severityDescriptions[severity] || 'Unknown severity'}\n\n`;

    if (node.data.description) {
        analysis += `### Description\n${node.data.description}\n\n`;
    }

    if (type === 'vulnerability') {
        analysis += `### Security Impact\n`;
        analysis += `This vulnerability could allow an attacker to:\n`;

        if (node.data.cwe) {
            analysis += `- Exploit ${node.data.cwe} weakness\n`;
        }
        if (node.data.owasp) {
            analysis += `- Target ${node.data.owasp} vulnerability class\n`;
        }

        analysis += `\n### Recommendation\n`;
        analysis += node.data.recommendation ||
            'Implement proper input validation, access controls, and security best practices.';
    }

    if (type === 'api_call') {
        analysis += `### Endpoint Details\n`;
        analysis += `- **Method:** ${node.data.method || 'GET'}\n`;
        analysis += `- **Path:** ${node.data.endpoint || 'Unknown'}\n\n`;
        analysis += `### Security Considerations\n`;
        analysis += `- Verify authentication requirements\n`;
        analysis += `- Check input validation\n`;
        analysis += `- Review rate limiting\n`;
        analysis += `- Ensure proper error handling\n`;
    }

    if (type === 'exploit') {
        analysis += `### Attack Vector\n`;
        analysis += `This represents a potential exploitation path that could be used to compromise the system.\n\n`;
        analysis += `### Mitigation\n`;
        analysis += node.data.recommendation || 'Implement defense-in-depth security controls.';
    }

    return analysis;
}

/**
 * Finds related nodes (connected via edges)
 */
function findRelatedNodes(nodeId: string, graph: AttackGraph): AttackNode[] {
    const relatedIds = new Set<string>();

    graph.edges.forEach(edge => {
        if (edge.source === nodeId) {
            relatedIds.add(edge.target);
        }
        if (edge.target === nodeId) {
            relatedIds.add(edge.source);
        }
    });

    return graph.nodes.filter(n => relatedIds.has(n.id));
}

/**
 * Finds attack paths that include a specific node
 */
function findAttackPaths(nodeId: string, graph: AttackGraph): AttackPath[] {
    const paths: AttackPath[] = [];

    // Find all paths from start nodes to end nodes that pass through this node
    const startNodes = graph.nodes.filter(n => n.type === 'start');
    const endNodes = graph.nodes.filter(n => n.type === 'end');

    // Build adjacency list
    const adjacency: Record<string, string[]> = {};
    graph.nodes.forEach(n => { adjacency[n.id] = []; });
    graph.edges.forEach(e => {
        if (adjacency[e.source]) {
            adjacency[e.source].push(e.target);
        }
    });

    // DFS to find paths
    function findPathsDFS(
        current: string,
        target: string,
        visited: Set<string>,
        path: string[]
    ): string[][] {
        if (current === target) {
            return [path];
        }

        const results: string[][] = [];
        visited.add(current);

        for (const next of adjacency[current] || []) {
            if (!visited.has(next)) {
                const newPaths = findPathsDFS(next, target, new Set(visited), [...path, next]);
                results.push(...newPaths);
            }
        }

        return results;
    }

    // Find paths that include the target node
    let pathIndex = 0;
    startNodes.forEach(start => {
        endNodes.forEach(end => {
            const allPaths = findPathsDFS(start.id, end.id, new Set(), [start.id]);

            allPaths.forEach(pathNodes => {
                if (pathNodes.includes(nodeId)) {
                    // Calculate path severity (highest severity node)
                    const pathNodeObjects = pathNodes
                        .map(id => graph.nodes.find(n => n.id === id))
                        .filter((n): n is AttackNode => n !== undefined);

                    const severityOrder = ['critical', 'high', 'medium', 'low'];
                    const highestSeverity = pathNodeObjects.reduce((highest, node) => {
                        const nodeSeverity = node.data.severity || 'low';
                        return severityOrder.indexOf(nodeSeverity) < severityOrder.indexOf(highest)
                            ? nodeSeverity
                            : highest;
                    }, 'low' as string);

                    paths.push({
                        id: `path-${pathIndex++}`,
                        name: `${start.label} → ${end.label}`,
                        nodes: pathNodes,
                        severity: highestSeverity,
                        description: `Attack path from ${start.label} to ${end.label} via ${pathNodes.length} nodes`
                    });
                }
            });
        });
    });

    return paths;
}

// Main service object
export const attackGraphService = {
    /**
     * Fetches and validates an attack graph for a scan
     */
    async getAttackGraph(scanId: string): Promise<AttackGraph> {
        const context = `${CONTEXT}.getAttackGraph`;

        if (scanId === 'demo' || scanId === 'scan-1') {
            log(LogLevel.INFO, context, 'Serving demo attack graph');
            return this.getMockDemoGraph();
        }

        log(LogLevel.INFO, context, `Fetching attack graph for scan: ${scanId}`);

        return withRetry(async () => {
            const { data: scan, error } = await supabase
                .from('scans')
                .select('id, attack_graph, status, started_at')
                .eq('id', scanId)
                .single();

            if (error) {
                if (error.code === 'PGRST116') {
                    throw new Error('Scan not found');
                }
                throw new Error(`Database error: ${error.message}`);
            }

            if (!scan) {
                throw new Error('Scan not found');
            }

            if (!scan.attack_graph) {
                log(LogLevel.WARN, context, 'Scan has no attack graph', {
                    scanId,
                    status: scan.status
                });

                // Return empty graph with metadata
                return {
                    nodes: [],
                    edges: [],
                    scan_id: scanId
                };
            }

            // Validate and fix the graph
            const validatedGraph = validateAttackGraph(scan.attack_graph, scanId);

            log(LogLevel.INFO, context, 'Attack graph retrieved and validated', {
                scanId,
                nodeCount: validatedGraph.nodes.length,
                edgeCount: validatedGraph.edges.length
            });

            return validatedGraph;
        }, context);
    },

    /**
     * Fetches detailed information about a specific node
     */
    async getNodeDetails(nodeId: string, scanId?: string): Promise<NodeDetails> {
        const context = `${CONTEXT}.getNodeDetails`;

        log(LogLevel.INFO, context, `Fetching node details: ${nodeId}`, { scanId });

        return withRetry(async () => {
            let foundNode: AttackNode | null = null;
            let foundScanId: string | null = null;
            let fullGraph: AttackGraph | null = null;

            // If scanId provided, search in that specific scan
            if (scanId) {
                const { data: scan, error } = await supabase
                    .from('scans')
                    .select('id, attack_graph')
                    .eq('id', scanId)
                    .single();

                if (!error && scan?.attack_graph) {
                    fullGraph = validateAttackGraph(scan.attack_graph, scanId);
                    foundNode = fullGraph.nodes.find(n => n.id === nodeId) || null;
                    if (foundNode) {
                        foundScanId = scanId;
                    }
                }
            }

            // If not found, search across recent scans
            if (!foundNode) {
                log(LogLevel.DEBUG, context, 'Searching across recent scans for node');

                const { data: scans, error } = await supabase
                    .from('scans')
                    .select('id, attack_graph')
                    .order('started_at', { ascending: false })
                    .limit(20);

                if (!error && scans) {
                    for (const scan of scans) {
                        if (scan.attack_graph) {
                            fullGraph = validateAttackGraph(scan.attack_graph, scan.id);
                            foundNode = fullGraph.nodes.find(n => n.id === nodeId) || null;
                            if (foundNode) {
                                foundScanId = scan.id;
                                break;
                            }
                        }
                    }
                }
            }

            if (!foundNode) {
                throw new Error('Node not found');
            }

            // Generate comprehensive node details
            const details: NodeDetails = {
                node: foundNode,
                scan_id: foundScanId,
                requests: generateRequestEvidence(foundNode),
                analysis: generateNodeAnalysis(foundNode),
                relatedNodes: fullGraph ? findRelatedNodes(nodeId, fullGraph) : [],
                attackPaths: fullGraph ? findAttackPaths(nodeId, fullGraph) : []
            };

            log(LogLevel.INFO, context, 'Node details retrieved', {
                nodeId,
                scanId: foundScanId,
                relatedNodesCount: details.relatedNodes.length,
                attackPathsCount: details.attackPaths.length
            });

            return details;
        }, context);
    },

    /**
     * Updates an attack graph in the database (with transaction-like behavior)
     */
    async updateAttackGraph(scanId: string, graph: AttackGraph): Promise<AttackGraph> {
        const context = `${CONTEXT}.updateAttackGraph`;

        log(LogLevel.INFO, context, `Updating attack graph for scan: ${scanId}`);

        // Validate the graph before saving
        const validatedGraph = validateAttackGraph(graph, scanId);

        return withRetry(async () => {
            // First, verify the scan exists
            const { data: existingScan, error: fetchError } = await supabase
                .from('scans')
                .select('id, status')
                .eq('id', scanId)
                .single();

            if (fetchError || !existingScan) {
                throw new Error('Scan not found');
            }

            // Update the attack graph
            const { data: updatedScan, error: updateError } = await supabase
                .from('scans')
                .update({
                    attack_graph: validatedGraph,
                    updated_at: new Date().toISOString()
                })
                .eq('id', scanId)
                .select()
                .single();

            if (updateError) {
                throw new Error(`Failed to update attack graph: ${updateError.message}`);
            }

            log(LogLevel.INFO, context, 'Attack graph updated successfully', {
                scanId,
                nodeCount: validatedGraph.nodes.length,
                edgeCount: validatedGraph.edges.length
            });

            return validatedGraph;
        }, context);
    },

    /**
     * Generates a default attack graph for a scan with no data
     */
    generateDefaultGraph(scanId: string): AttackGraph {
        return {
            nodes: [
                {
                    id: 'start',
                    type: 'start',
                    label: 'Entry Point',
                    data: {
                        description: 'Initial access point for security analysis',
                        severity: 'low'
                    },
                    position: { x: 100, y: 300 }
                },
                {
                    id: 'analysis-pending',
                    type: 'api_call',
                    label: 'Analysis Pending',
                    data: {
                        description: 'Security analysis is in progress or no vulnerabilities were detected',
                        severity: 'low'
                    },
                    position: { x: 400, y: 300 }
                }
            ],
            edges: [
                {
                    id: 'edge-start-pending',
                    source: 'start',
                    target: 'analysis-pending',
                    label: 'Analyzing...',
                    type: 'default'
                }
            ],
            scan_id: scanId
        };
    },

    getMockDemoGraph(): AttackGraph {
        return {
            scan_id: 'demo',
            nodes: [
                { id: 'internet', type: 'start', label: 'Internet', position: { x: 0, y: 250 }, data: { description: 'External Network' } },
                { id: 'login-api', type: 'api_call', label: 'POST /api/login', position: { x: 200, y: 250 }, data: { description: 'Authentication Endpoint', method: 'POST', endpoint: '/api/login' } },
                { id: 'sql-injection', type: 'vulnerability', label: 'SQL Injection', position: { x: 400, y: 150 }, data: { description: 'Blind SQL Injection in username parameter', severity: 'critical', recommendation: 'Use parameterized queries', cwe: 'CWE-89' } },
                { id: 'auth-bypass', type: 'exploit', label: 'Auth Bypass', position: { x: 600, y: 150 }, data: { description: 'Successfully skipped authentication', severity: 'critical' } },
                { id: 'admin-dashboard', type: 'api_call', label: 'GET /admin', position: { x: 800, y: 250 }, data: { description: 'Admin Dashboard', method: 'GET', endpoint: '/admin' } },
                { id: 'xss-stored', type: 'vulnerability', label: 'Stored XSS', position: { x: 1000, y: 250 }, data: { description: 'Stored Cross-Site Scripting in logs', severity: 'high', recommendation: 'Encode output', cwe: 'CWE-79' } },
                { id: 'data-exfil', type: 'end', label: 'Data Exfiltration', position: { x: 1200, y: 250 }, data: { description: 'User data leaked' } }
            ],
            edges: [
                { id: 'e1', source: 'internet', target: 'login-api', type: 'default' },
                { id: 'e2', source: 'login-api', target: 'sql-injection', type: 'vulnerable', label: 'Malicious Payload' },
                { id: 'e3', source: 'sql-injection', target: 'auth-bypass', type: 'exploit', label: 'Exploited' },
                { id: 'e4', source: 'auth-bypass', target: 'admin-dashboard', type: 'default', label: 'Access Granted' },
                { id: 'e5', source: 'admin-dashboard', target: 'xss-stored', type: 'vulnerable' },
                { id: 'e6', source: 'xss-stored', target: 'data-exfil', type: 'exploit' }
            ]
        };
    }
};

export default attackGraphService;