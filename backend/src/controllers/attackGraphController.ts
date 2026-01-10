import { Request, Response } from 'express';
import { log, LogLevel, validate, createErrorResponse, createSuccessResponse } from '../utils/dbUtils';
import { attackGraphService, validateAttackGraph, AttackGraph } from '../services/attackGraphService';

const CONTEXT = 'AttackGraphController';

/**
 * GET /api/attack-graph/:scanId
 * Fetches the attack graph for a specific scan
 */
export const getAttackGraph = async (req: Request, res: Response): Promise<void> => {
    const { scanId } = req.params;
    const context = `${CONTEXT}.getAttackGraph`;

    log(LogLevel.INFO, context, `Request received for scan: ${scanId}`);

    // Validate scan ID
    if (!scanId) {
        createErrorResponse(res, 400, 'Scan ID is required', context);
        return;
    }

    if (!validate.isValidId(scanId)) {
        createErrorResponse(res, 400, 'Invalid scan ID format', context, { scanId });
        return;
    }

    try {
        const graph = await attackGraphService.getAttackGraph(scanId);

        // If graph is empty, return a default graph
        if (!graph.nodes || graph.nodes.length === 0) {
            log(LogLevel.WARN, context, 'No attack graph data found, returning default graph', { scanId });
            const defaultGraph = attackGraphService.generateDefaultGraph(scanId);
            createSuccessResponse(res, defaultGraph, context, 'Default graph returned');
            return;
        }

        log(LogLevel.INFO, context, 'Attack graph retrieved successfully', {
            scanId,
            nodeCount: graph.nodes.length,
            edgeCount: graph.edges.length
        });

        createSuccessResponse(res, graph, context);

    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch attack graph: ${error.message}`, {
            stack: error.stack,
            scanId
        });

        if (error.message === 'Scan not found') {
            createErrorResponse(res, 404, 'Scan not found', context, { scanId });
            return;
        }

        createErrorResponse(res, 500, 'Failed to fetch attack graph', context, {
            error: error.message
        });
    }
};

/**
 * GET /api/attack-graph/node/:nodeId
 * Fetches detailed information about a specific node
 */
export const getNodeDetails = async (req: Request, res: Response): Promise<void> => {
    const { nodeId } = req.params;
    const { scanId } = req.query;
    const context = `${CONTEXT}.getNodeDetails`;

    log(LogLevel.INFO, context, `Request received for node: ${nodeId}`, { scanId });

    // Validate node ID
    if (!nodeId) {
        createErrorResponse(res, 400, 'Node ID is required', context);
        return;
    }

    // Validate scanId if provided
    if (scanId && typeof scanId === 'string' && !validate.isValidId(scanId)) {
        createErrorResponse(res, 400, 'Invalid scan ID format', context, { scanId });
        return;
    }

    try {
        const details = await attackGraphService.getNodeDetails(
            nodeId,
            typeof scanId === 'string' ? scanId : undefined
        );

        log(LogLevel.INFO, context, 'Node details retrieved successfully', {
            nodeId,
            scanId: details.scan_id,
            relatedNodesCount: details.relatedNodes.length,
            attackPathsCount: details.attackPaths.length
        });

        createSuccessResponse(res, details, context);

    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch node details: ${error.message}`, {
            stack: error.stack,
            nodeId,
            scanId
        });

        if (error.message === 'Node not found') {
            createErrorResponse(res, 404, 'Node not found', context, { nodeId });
            return;
        }

        createErrorResponse(res, 500, 'Failed to fetch node details', context, {
            error: error.message
        });
    }
};

/**
 * PUT /api/attack-graph/:scanId
 * Updates the attack graph for a specific scan
 */
export const updateAttackGraph = async (req: Request, res: Response): Promise<void> => {
    const { scanId } = req.params;
    const graphData = req.body;
    const context = `${CONTEXT}.updateAttackGraph`;

    log(LogLevel.INFO, context, `Update request received for scan: ${scanId}`);

    // Validate scan ID
    if (!scanId) {
        createErrorResponse(res, 400, 'Scan ID is required', context);
        return;
    }

    if (!validate.isValidId(scanId)) {
        createErrorResponse(res, 400, 'Invalid scan ID format', context, { scanId });
        return;
    }

    // Validate graph data
    if (!graphData || typeof graphData !== 'object') {
        createErrorResponse(res, 400, 'Invalid graph data', context);
        return;
    }

    try {
        // Validate the incoming graph
        const validatedGraph = validateAttackGraph(graphData, scanId);

        // Update in database
        const updatedGraph = await attackGraphService.updateAttackGraph(scanId, validatedGraph);

        log(LogLevel.INFO, context, 'Attack graph updated successfully', {
            scanId,
            nodeCount: updatedGraph.nodes.length,
            edgeCount: updatedGraph.edges.length
        });

        createSuccessResponse(res, updatedGraph, context, 'Attack graph updated');

    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to update attack graph: ${error.message}`, {
            stack: error.stack,
            scanId
        });

        if (error.message === 'Scan not found') {
            createErrorResponse(res, 404, 'Scan not found', context, { scanId });
            return;
        }

        createErrorResponse(res, 500, 'Failed to update attack graph', context, {
            error: error.message
        });
    }
};

/**
 * POST /api/attack-graph/:scanId/analyze
 * Triggers AI analysis of the attack graph
 */
export const analyzeAttackGraph = async (req: Request, res: Response): Promise<void> => {
    const { scanId } = req.params;
    const context = `${CONTEXT}.analyzeAttackGraph`;

    log(LogLevel.INFO, context, `Analysis request received for scan: ${scanId}`);

    // Validate scan ID
    if (!scanId) {
        createErrorResponse(res, 400, 'Scan ID is required', context);
        return;
    }

    if (!validate.isValidId(scanId)) {
        createErrorResponse(res, 400, 'Invalid scan ID format', context, { scanId });
        return;
    }

    try {
        // Fetch the current graph
        const graph = await attackGraphService.getAttackGraph(scanId);

        if (!graph.nodes || graph.nodes.length === 0) {
            createErrorResponse(res, 400, 'No attack graph data available for analysis', context, { scanId });
            return;
        }

        // Perform analysis
        const analysis = performGraphAnalysis(graph);

        log(LogLevel.INFO, context, 'Attack graph analysis completed', {
            scanId,
            vulnerabilityCount: analysis.vulnerabilities.length,
            attackPathCount: analysis.attackPaths.length
        });

        createSuccessResponse(res, analysis, context, 'Analysis completed');

    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to analyze attack graph: ${error.message}`, {
            stack: error.stack,
            scanId
        });

        createErrorResponse(res, 500, 'Failed to analyze attack graph', context, {
            error: error.message
        });
    }
};

/**
 * Performs comprehensive analysis of an attack graph
 */
function performGraphAnalysis(graph: AttackGraph): GraphAnalysis {
    const vulnerabilities = graph.nodes.filter(n => n.type === 'vulnerability');
    const exploits = graph.nodes.filter(n => n.type === 'exploit');
    const apiCalls = graph.nodes.filter(n => n.type === 'api_call');

    // Count by severity
    const severityCounts = {
        critical: vulnerabilities.filter(v => v.data.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.data.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.data.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.data.severity === 'low').length
    };

    // Find attack paths (simplified - from start to end nodes)
    const startNodes = graph.nodes.filter(n => n.type === 'start');
    const endNodes = graph.nodes.filter(n => n.type === 'end');

    // Build adjacency for path finding
    const adjacency: Record<string, string[]> = {};
    graph.nodes.forEach(n => { adjacency[n.id] = []; });
    graph.edges.forEach(e => {
        if (adjacency[e.source]) {
            adjacency[e.source].push(e.target);
        }
    });

    // Find all paths
    const attackPaths: AttackPathInfo[] = [];

    function findPaths(current: string, target: string, visited: Set<string>, path: string[]): string[][] {
        if (current === target) return [path];

        const results: string[][] = [];
        visited.add(current);

        for (const next of adjacency[current] || []) {
            if (!visited.has(next)) {
                const newPaths = findPaths(next, target, new Set(visited), [...path, next]);
                results.push(...newPaths);
            }
        }

        return results;
    }

    startNodes.forEach(start => {
        endNodes.forEach(end => {
            const paths = findPaths(start.id, end.id, new Set(), [start.id]);
            paths.forEach((pathNodes, idx) => {
                const pathVulns = pathNodes
                    .map(id => graph.nodes.find(n => n.id === id))
                    .filter(n => n?.type === 'vulnerability');

                const maxSeverity = pathVulns.reduce((max, v) => {
                    const severityOrder = ['critical', 'high', 'medium', 'low'];
                    const vSeverity = v?.data.severity || 'low';
                    return severityOrder.indexOf(vSeverity) < severityOrder.indexOf(max) ? vSeverity : max;
                }, 'low' as string);

                attackPaths.push({
                    id: `path-${start.id}-${end.id}-${idx}`,
                    name: `${start.label} → ${end.label}`,
                    nodeCount: pathNodes.length,
                    vulnerabilityCount: pathVulns.length,
                    severity: maxSeverity,
                    nodes: pathNodes
                });
            });
        });
    });

    // Generate recommendations
    const recommendations: string[] = [];

    if (severityCounts.critical > 0) {
        recommendations.push(`URGENT: Address ${severityCounts.critical} critical vulnerabilities immediately`);
    }
    if (severityCounts.high > 0) {
        recommendations.push(`HIGH PRIORITY: Fix ${severityCounts.high} high-severity issues within 24-48 hours`);
    }
    if (attackPaths.length > 0) {
        recommendations.push(`Review ${attackPaths.length} potential attack paths identified`);
    }
    if (apiCalls.length > 0) {
        recommendations.push(`Audit ${apiCalls.length} API endpoints for security best practices`);
    }

    // Calculate risk score (0-100)
    const riskScore = Math.min(100,
        severityCounts.critical * 25 +
        severityCounts.high * 15 +
        severityCounts.medium * 5 +
        severityCounts.low * 1 +
        attackPaths.filter(p => p.severity === 'critical').length * 10
    );

    return {
        summary: {
            totalNodes: graph.nodes.length,
            totalEdges: graph.edges.length,
            vulnerabilityCount: vulnerabilities.length,
            exploitCount: exploits.length,
            apiCallCount: apiCalls.length,
            riskScore
        },
        severityCounts,
        vulnerabilities: vulnerabilities.map(v => ({
            id: v.id,
            label: v.label,
            severity: v.data.severity || 'medium',
            description: v.data.description,
            recommendation: v.data.recommendation
        })),
        attackPaths,
        recommendations,
        riskLevel: riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low'
    };
}

// Type definitions for analysis
interface GraphAnalysis {
    summary: {
        totalNodes: number;
        totalEdges: number;
        vulnerabilityCount: number;
        exploitCount: number;
        apiCallCount: number;
        riskScore: number;
    };
    severityCounts: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    vulnerabilities: Array<{
        id: string;
        label: string;
        severity: string;
        description: string;
        recommendation?: string;
    }>;
    attackPaths: AttackPathInfo[];
    recommendations: string[];
    riskLevel: string;
}

interface AttackPathInfo {
    id: string;
    name: string;
    nodeCount: number;
    vulnerabilityCount: number;
    severity: string;
    nodes: string[];
}
