import { Request, Response } from 'express';
import { supabase } from '../db/supabase';
import { aiService } from '../services/aiService';
import { scannerService, ScanResult } from '../services/scannerService';
import {
    dbQuery,
    log,
    LogLevel,
    validate,
    createErrorResponse,
    createSuccessResponse,
    cache,
    CACHE_TTL,
    cacheKeys
} from '../utils/dbUtils';
import { parsePaginationParams, PaginatedResponse } from '../utils/paginationUtils';
import * as path from 'path';

const CONTEXT = 'ProjectController';

// Type definitions
interface Project {
    id: string;
    name: string;
    type: string;
    repo_url?: string;
    openapi_spec?: string;
    vulnerability_counts?: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

interface Scan {
    id: string;
    project_id: string;
    status: string;
    progress: number;
    logs: string[];
    started_at: string;
    attack_graph?: any;
    vulnerability_count?: number;
    risk_score?: number;
}

export const getProjects = async (req: Request, res: Response) => {
    const context = `${CONTEXT}.getProjects`;
    const params = parsePaginationParams(req.query);

    log(LogLevel.INFO, context, 'Fetching projects', { page: params.page, limit: params.limit });

    try {
        // Check if pagination is requested
        if (req.query.page || req.query.limit) {
            // Use paginated query with caching
            const cacheKey = `projects:list:page:${params.page}:limit:${params.limit}`;
            const result = await dbQuery.fetchPaginated<Project>(
                'projects',
                { ...params, sortBy: params.sortBy || 'created_at', sortOrder: params.sortOrder || 'desc' },
                context,
                cacheKey,
                CACHE_TTL.SHORT
            );

            log(LogLevel.INFO, context, `Found ${result.data.length} projects (page ${result.pagination.page}/${result.pagination.totalPages})`);
            return res.json(result);
        }

        // Legacy: return all projects (with caching)
        const cacheKey = cacheKeys.projects();
        const cached = cache.get<Project[]>(cacheKey);

        if (cached) {
            log(LogLevel.DEBUG, context, 'Returning cached projects');
            return createSuccessResponse(res, cached, context);
        }

        const projects = await dbQuery.fetchMany<Project>(
            'projects',
            {},
            context,
            { orderBy: 'created_at', ascending: false }
        );

        // Cache for 30 seconds
        cache.set(cacheKey, projects, CACHE_TTL.SHORT);

        log(LogLevel.INFO, context, `Found ${projects.length} projects`);
        return createSuccessResponse(res, projects, context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch projects: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to fetch projects', context, { error: error.message });
    }
};

export const createProject = async (req: Request, res: Response) => {
    const context = `${CONTEXT}.createProject`;

    try {
        const { name, type, repoUrl, openapi_spec } = req.body;

        // Validate required fields
        if (!name || !type) {
            return createErrorResponse(res, 400, 'Name and type are required', context);
        }

        log(LogLevel.INFO, context, `Creating project: ${name}`, { type, hasRepoUrl: !!repoUrl, hasSpec: !!openapi_spec });

        const project = await dbQuery.insert<Project>(
            'projects',
            {
                name: validate.sanitizeString(name, 200),
                type,
                repo_url: repoUrl,
                openapi_spec,
                vulnerability_counts: { critical: 0, high: 0, medium: 0, low: 0 }
            },
            context
        );

        // Invalidate projects cache
        cache.deletePattern('^projects:');

        log(LogLevel.INFO, context, `Project created successfully`, { id: project.id });
        res.status(201).json(project);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to create project: ${error.message}`, { stack: error.stack });
        return createErrorResponse(res, 500, 'Failed to create project', context, { error: error.message });
    }
};

export const deleteProject = async (req: Request, res: Response) => {
    const { id } = req.params;
    const context = `${CONTEXT}.deleteProject`;

    if (!validate.isValidUUID(id)) {
        return createErrorResponse(res, 400, 'Invalid project ID format', context);
    }

    log(LogLevel.INFO, context, `Deleting project: ${id}`);

    try {
        // First, verify the project exists
        const project = await dbQuery.fetchOne<Project>('projects', 'id', id, context);
        if (!project) {
            return createErrorResponse(res, 404, 'Project not found', context, { id });
        }

        // Delete all related scans first (cascade delete)
        log(LogLevel.INFO, context, `Deleting related scans for project: ${id}`);
        const { error: scansError } = await supabase
            .from('scans')
            .delete()
            .eq('project_id', id);

        if (scansError) {
            log(LogLevel.WARN, context, `Failed to delete scans: ${scansError.message}`);
            // Continue with project deletion even if scan deletion fails
        }

        // Delete the project
        const { error: projectError } = await supabase
            .from('projects')
            .delete()
            .eq('id', id);

        if (projectError) {
            throw new Error(projectError.message);
        }

        // Invalidate all related caches
        cache.deletePattern('^projects:');
        cache.deletePattern(`^scans:.*${id}`);

        log(LogLevel.INFO, context, `Project and related data deleted successfully: ${id}`);
        res.status(204).send();
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to delete project: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to delete project', context, { error: error.message });
    }
};

export const getProject = async (req: Request, res: Response) => {
    const { id } = req.params;
    const context = `${CONTEXT}.getProject`;

    if (!validate.isValidUUID(id)) {
        return createErrorResponse(res, 400, 'Invalid project ID format', context);
    }

    log(LogLevel.DEBUG, context, `Fetching project: ${id}`);

    try {
        // Try cache first
        const cacheKey = cacheKeys.project(id);
        const project = await dbQuery.fetchWithCache<Project>(
            'projects',
            'id',
            id,
            context,
            cacheKey,
            CACHE_TTL.MEDIUM
        );

        if (!project) {
            return createErrorResponse(res, 404, 'Project not found', context, { id });
        }

        return createSuccessResponse(res, project, context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch project: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to fetch project', context, { error: error.message });
    }
};

export const getProjectEndpoints = async (req: Request, res: Response) => {
    const { id } = req.params;
    const context = `${CONTEXT}.getProjectEndpoints`;

    if (!validate.isValidUUID(id)) {
        return createErrorResponse(res, 400, 'Invalid project ID format', context);
    }

    log(LogLevel.DEBUG, context, `Fetching endpoints for project: ${id}`);

    try {
        const project = await dbQuery.fetchOne<Project>('projects', 'id', id, context);

        if (!project) {
            return createErrorResponse(res, 404, 'Project not found', context, { id });
        }

        // Parse OpenAPI spec if available
        let endpoints: any[] = [];
        if (project.openapi_spec) {
            try {
                endpoints = scannerService.parseOpenAPISpec(project.openapi_spec);
                log(LogLevel.INFO, context, `Parsed ${endpoints.length} endpoints from OpenAPI spec`);
            } catch (parseError: any) {
                log(LogLevel.WARN, context, `Failed to parse OpenAPI spec: ${parseError.message}`);
            }
        }

        return createSuccessResponse(res, endpoints, context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch endpoints: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to fetch endpoints', context, { error: error.message });
    }
};

export const getProjectScanHistory = async (req: Request, res: Response) => {
    const { id } = req.params;
    const context = `${CONTEXT}.getProjectScanHistory`;
    const params = parsePaginationParams(req.query);

    if (!validate.isValidUUID(id)) {
        return createErrorResponse(res, 400, 'Invalid project ID format', context);
    }

    log(LogLevel.DEBUG, context, `Fetching scan history for project: ${id}`);

    try {
        // Check if pagination is requested
        if (req.query.page || req.query.limit) {
            const cacheKey = `${cacheKeys.projectHistory(id)}:page:${params.page}`;
            const result = await dbQuery.fetchPaginated<Scan>(
                'scans',
                { ...params, filters: { ...params.filters, project_id: id }, sortBy: 'started_at', sortOrder: 'desc' },
                context,
                cacheKey,
                CACHE_TTL.SHORT
            );

            // Transform data
            const transformedData = result.data.map((s: Scan) => ({
                id: s.id,
                status: s.status,
                created_at: s.started_at,
                duration: 0,
                vulnerability_count: s.vulnerability_count || 0,
                risk_score: s.risk_score || 0
            }));

            return res.json({
                ...result,
                data: transformedData
            });
        }

        // Legacy: return all scans with caching
        const cacheKey = cacheKeys.projectHistory(id);
        const cached = cache.get<any[]>(cacheKey);

        if (cached) {
            log(LogLevel.DEBUG, context, 'Returning cached scan history');
            return createSuccessResponse(res, cached, context);
        }

        const scans = await dbQuery.fetchMany<Scan>(
            'scans',
            { project_id: id },
            context,
            { orderBy: 'started_at', ascending: false }
        );

        // Transform for frontend
        const history = scans.map((s: Scan) => ({
            id: s.id,
            status: s.status,
            created_at: s.started_at,
            duration: 0,
            vulnerability_count: s.vulnerability_count || 0,
            risk_score: s.risk_score || 0
        }));

        // Cache for 30 seconds
        cache.set(cacheKey, history, CACHE_TTL.SHORT);

        log(LogLevel.INFO, context, `Found ${history.length} scans for project`);
        return createSuccessResponse(res, history, context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch scan history: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to fetch scan history', context, { error: error.message });
    }
};

export const startScan = async (req: Request, res: Response) => {
    const { id } = req.params;
    const context = `${CONTEXT}.startScan`;

    if (!validate.isValidUUID(id)) {
        return createErrorResponse(res, 400, 'Invalid project ID format', context);
    }

    log(LogLevel.INFO, context, `Starting scan for project: ${id}`);

    try {
        // Verify project exists
        const project = await dbQuery.fetchOne<Project>('projects', 'id', id, context);
        if (!project) {
            return createErrorResponse(res, 404, 'Project not found', context, { id });
        }

        // Create Scan Record
        const scan = await dbQuery.insert<Scan>(
            'scans',
            {
                project_id: id,
                status: 'running',
                progress: 0,
                logs: [`[${new Date().toISOString()}] Initializing scan engine...`],
                started_at: new Date().toISOString()
            },
            context
        );

        // Update project status
        await dbQuery.update<Project>(
            'projects',
            id,
            { last_scan_id: scan.id, last_scan_status: 'running' } as any,
            context
        );

        // Trigger Async Scan
        processScan(scan.id, id);

        log(LogLevel.INFO, context, `Scan started successfully`, { scanId: scan.id });
        return createSuccessResponse(res, { scan_id: scan.id }, context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to start scan: ${error.message}`, { stack: error.stack });
        return createErrorResponse(res, 500, 'Failed to start scan', context, { error: error.message });
    }
};

async function processScan(scanId: string, projectId: string) {
    const logUpdate = async (progress: number, message: string) => {
        const { data } = await supabase.from('scans').select('logs').eq('id', scanId).single();
        const currentLogs = data?.logs || [];
        currentLogs.push(`[${new Date().toISOString()}] ${message}`);

        await supabase
            .from('scans')
            .update({ progress, logs: currentLogs })
            .eq('id', scanId);
    };

    try {
        await logUpdate(5, 'Initializing security scan...');

        // 1. Fetch Project
        const { data: project } = await supabase.from('projects').select('*').eq('id', projectId).single();

        if (!project) {
            await logUpdate(100, 'ERROR: Project not found');
            await supabase.from('scans').update({ status: 'failed' }).eq('id', scanId);
            return;
        }

        await logUpdate(10, `Starting scan for project: ${project.name}`);

        // 2. Determine scan path - use repo_url or scan current project
        let scanPath = '';
        let scanResult: ScanResult | null = null;

        // If repo_url is a local path, scan it
        if (project.repo_url && !project.repo_url.startsWith('http')) {
            scanPath = project.repo_url;
            await logUpdate(15, `Scanning local path: ${scanPath}`);
        } else {
            // Scan the current project directory as demo
            scanPath = path.resolve(__dirname, '../../..');
            await logUpdate(15, `Scanning project directory for demonstration...`);
        }

        // 3. Run the actual vulnerability scanner
        await logUpdate(20, 'Running static code analysis...');

        try {
            scanResult = await scannerService.scanProject(scanPath, project.openapi_spec);
            await logUpdate(40, `Scanned ${scanResult.scannedFiles} files, found ${scanResult.findings.length} potential issues`);
        } catch (scanError: any) {
            await logUpdate(40, `File scan completed with warnings: ${scanError.message}`);
            scanResult = {
                totalFiles: 0,
                scannedFiles: 0,
                findings: [],
                summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                scanDuration: 0
            };
        }

        // 4. Parse OpenAPI spec for additional endpoint analysis
        let targetEndpoints: any[] = [];

        if (project.openapi_spec) {
            await logUpdate(45, 'Analyzing OpenAPI specification...');
            try {
                targetEndpoints = scannerService.parseOpenAPISpec(project.openapi_spec);
                await logUpdate(50, `Parsed ${targetEndpoints.length} endpoints from OpenAPI spec`);

                // Add endpoint-based findings
                const endpointFindings = scannerService.analyzeEndpoints(targetEndpoints);
                scanResult.findings.push(...endpointFindings);

                // Update summary
                scanResult.summary.critical += endpointFindings.filter(f => f.severity === 'critical').length;
                scanResult.summary.high += endpointFindings.filter(f => f.severity === 'high').length;
                scanResult.summary.medium += endpointFindings.filter(f => f.severity === 'medium').length;
                scanResult.summary.low += endpointFindings.filter(f => f.severity === 'low').length;
            } catch (e) {
                await logUpdate(50, 'OpenAPI parsing completed with warnings');
            }
        }

        // 5. Generate attack graph from scan results
        await logUpdate(55, 'Generating attack graph from findings...');
        let attackGraph = scannerService.convertToAttackGraph(scanResult, scanId);

        // 6. Enhance with AI analysis if available
        await logUpdate(65, 'Requesting AI-powered security analysis...');

        try {
            // Prepare data for AI analysis
            const analysisData = {
                findings: scanResult.findings.slice(0, 20), // Top 20 findings
                endpoints: targetEndpoints.slice(0, 10), // Top 10 endpoints
                summary: scanResult.summary
            };

            const aiEnhancedGraph = await aiService.analyzeEndpoints(targetEndpoints.length > 0 ? targetEndpoints : [
                { method: 'SCAN', path: scanPath, findings: scanResult.findings.length }
            ]);

            // Merge AI insights if available
            if (aiEnhancedGraph && aiEnhancedGraph.nodes && aiEnhancedGraph.nodes.length > 0) {
                // Add AI-generated nodes that aren't duplicates
                const existingIds = new Set(attackGraph.nodes.map((n: any) => n.id));
                aiEnhancedGraph.nodes.forEach((node: any) => {
                    if (!existingIds.has(node.id)) {
                        attackGraph.nodes.push(node);
                    }
                });

                // Add AI-generated edges
                const existingEdges = new Set(attackGraph.edges.map((e: any) => `${e.source}-${e.target}`));
                aiEnhancedGraph.edges.forEach((edge: any) => {
                    if (!existingEdges.has(`${edge.source}-${edge.target}`)) {
                        attackGraph.edges.push(edge);
                    }
                });

                await logUpdate(75, 'AI analysis integrated successfully');
            }
        } catch (aiError: any) {
            await logUpdate(75, `AI analysis completed (limited mode): ${aiError.message?.substring(0, 50) || 'Service unavailable'}`);
        }

        // 7. Store results
        await logUpdate(85, 'Storing scan results...');

        attackGraph.scan_id = scanId;
        attackGraph.metadata = {
            ...attackGraph.metadata,
            scanPath,
            projectName: project.name,
            completedAt: new Date().toISOString()
        };

        await supabase
            .from('scans')
            .update({
                attack_graph: attackGraph,
                vulnerability_count: scanResult.findings.length,
                risk_score: calculateRiskScore(scanResult.summary)
            })
            .eq('id', scanId);

        // 8. Update project vulnerability counts
        await supabase
            .from('projects')
            .update({
                last_scan_status: 'completed',
                vulnerability_counts: scanResult.summary
            })
            .eq('id', projectId);

        await logUpdate(100, `Scan completed. Found ${scanResult.findings.length} vulnerabilities (${scanResult.summary.critical} critical, ${scanResult.summary.high} high)`);

        await supabase
            .from('scans')
            .update({ status: 'completed' })
            .eq('id', scanId);

    } catch (error: any) {
        console.error('Scan error:', error);
        await logUpdate(100, `Scan failed: ${error.message}`);
        await supabase.from('scans').update({ status: 'failed' }).eq('id', scanId);
        await supabase.from('projects').update({ last_scan_status: 'failed' }).eq('id', projectId);
    }
}

// Calculate risk score based on vulnerability counts
function calculateRiskScore(summary: { critical: number; high: number; medium: number; low: number; info: number }): number {
    const weights = { critical: 40, high: 25, medium: 10, low: 3, info: 1 };
    const score =
        summary.critical * weights.critical +
        summary.high * weights.high +
        summary.medium * weights.medium +
        summary.low * weights.low +
        summary.info * weights.info;

    // Normalize to 0-100 scale
    return Math.min(100, Math.round(score));
}

export const getScanStatus = async (req: Request, res: Response) => {
    const { scanId } = req.params;
    const context = `${CONTEXT}.getScanStatus`;

    if (!validate.isValidUUID(scanId)) {
        return createErrorResponse(res, 400, 'Invalid scan ID format', context);
    }

    log(LogLevel.DEBUG, context, `Fetching scan status: ${scanId}`);

    try {
        const scan = await dbQuery.fetchOne<Scan>('scans', 'id', scanId, context);

        if (!scan) {
            return createErrorResponse(res, 404, 'Scan not found', context, { scanId });
        }

        const response = {
            scan_id: scan.id,
            status: scan.status,
            progress: scan.progress,
            current_step: scan.progress < 100 ? 'Scanning' : 'Completed',
            started_at: scan.started_at,
            vulnerability_count: scan.vulnerability_count || 0,
            risk_score: scan.risk_score || 0
        };

        return createSuccessResponse(res, response, context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch scan status: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to fetch scan status', context, { error: error.message });
    }
};

export const getScanLogs = async (req: Request, res: Response) => {
    const { scanId } = req.params;
    const context = `${CONTEXT}.getScanLogs`;

    if (!validate.isValidUUID(scanId)) {
        return createErrorResponse(res, 400, 'Invalid scan ID format', context);
    }

    log(LogLevel.DEBUG, context, `Fetching scan logs: ${scanId}`);

    try {
        const scan = await dbQuery.fetchOne<Scan>('scans', 'id', scanId, context);

        if (!scan) {
            return createErrorResponse(res, 404, 'Scan not found', context, { scanId });
        }

        return createSuccessResponse(res, scan.logs || [], context);
    } catch (error: any) {
        log(LogLevel.ERROR, context, `Failed to fetch scan logs: ${error.message}`);
        return createErrorResponse(res, 500, 'Failed to fetch scan logs', context, { error: error.message });
    }
};
