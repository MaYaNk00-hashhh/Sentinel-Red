import { Request, Response } from 'express';
import { dbQuery, log, LogLevel, validate, createErrorResponse, createSuccessResponse } from '../utils/dbUtils';
import { generateSecurityRecommendations } from '../services/aiService';
import { attackGraphService } from '../services/attackGraphService';

const CONTEXT = 'ReportController';

// Type definitions
interface Scan {
    id: string;
    project_id: string;
    status: string;
    progress: number;
    started_at: string;
    attack_graph: any;
    vulnerability_count: number;
    risk_score: number;
    logs: string[];
}

interface Project {
    id: string;
    name: string;
    type: string;
    vulnerability_counts: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

interface VulnerabilityNode {
    id: string;
    type: string;
    label: string;
    data: {
        description?: string;
        severity?: string;
        endpoint?: string;
        recommendation?: string;
        cwe?: string;
        owasp?: string;
        category?: string;
    };
}

// Helper function to safely extract vulnerability nodes from attack graph
function extractVulnerabilityNodes(attackGraph: any): VulnerabilityNode[] {
    if (!attackGraph || !attackGraph.nodes || !Array.isArray(attackGraph.nodes)) {
        log(LogLevel.WARN, CONTEXT, 'Attack graph has no nodes or invalid structure');
        return [];
    }

    return attackGraph.nodes.filter((node: any) => node.type === 'vulnerability');
}

// Helper function to count vulnerabilities by severity
function countBySeverity(nodes: VulnerabilityNode[]): { critical: number; high: number; medium: number; low: number; info: number } {
    return {
        critical: nodes.filter(n => n.data?.severity === 'critical').length,
        high: nodes.filter(n => n.data?.severity === 'high').length,
        medium: nodes.filter(n => n.data?.severity === 'medium').length,
        low: nodes.filter(n => n.data?.severity === 'low').length,
        info: nodes.filter(n => n.data?.severity === 'info').length
    };
}

// Helper function to calculate risk score
function calculateRiskScore(counts: { critical: number; high: number; medium: number; low: number }): number {
    const weights = { critical: 40, high: 25, medium: 10, low: 3 };
    const score =
        counts.critical * weights.critical +
        counts.high * weights.high +
        counts.medium * weights.medium +
        counts.low * weights.low;
    return Math.min(100, Math.round(score));
}

// Helper function to determine overall risk level
function determineRiskLevel(counts: { critical: number; high: number; medium: number; low: number }): string {
    if (counts.critical > 0) return 'critical';
    if (counts.high > 0) return 'high';
    if (counts.medium > 0) return 'medium';
    if (counts.low > 0) return 'low';
    return 'info';
}

// Helper function to get recommendation for a vulnerability
function getRecommendation(node: VulnerabilityNode): string {
    // Return existing recommendation if available
    if (node.data?.recommendation) {
        return node.data.recommendation;
    }

    const label = (node.label || '').toLowerCase();
    const description = (node.data?.description || '').toLowerCase();

    if (label.includes('sql') || description.includes('sql')) {
        return 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.';
    }
    if (label.includes('xss') || description.includes('xss') || description.includes('script')) {
        return 'Implement output encoding. Use Content Security Policy headers. Sanitize user input.';
    }
    if (label.includes('auth') || description.includes('auth') || description.includes('authentication')) {
        return 'Implement strong authentication mechanisms. Use multi-factor authentication. Enforce password policies.';
    }
    if (label.includes('idor') || description.includes('idor') || description.includes('direct object')) {
        return 'Implement proper access controls. Validate user permissions for each resource access.';
    }
    if (label.includes('injection') || description.includes('injection')) {
        return 'Validate and sanitize all user inputs. Use parameterized queries and prepared statements.';
    }
    if (label.includes('validation') || description.includes('validation')) {
        return 'Implement comprehensive input validation on both client and server side.';
    }
    if (label.includes('password') || description.includes('password') || description.includes('credential')) {
        return 'Store credentials securely using environment variables or a secrets manager. Never hardcode sensitive data.';
    }

    return 'Review this vulnerability and implement appropriate security controls based on industry best practices.';
}

// Map category to vulnerability type
function mapCategoryToType(category?: string): string {
    if (!category) return 'Other';

    const categoryLower = category.toLowerCase();
    if (categoryLower.includes('idor') || categoryLower.includes('access')) return 'IDOR';
    if (categoryLower.includes('auth')) return 'Auth Bypass';
    if (categoryLower.includes('logic')) return 'Business Logic';
    if (categoryLower.includes('injection') || categoryLower.includes('xss') || categoryLower.includes('validation')) return 'Input Validation';
    if (categoryLower.includes('bypass')) return 'Logic Bypass';

    return 'Other';
}

// Get impact description based on severity
function getImpactDescription(severity?: string): string {
    switch (severity) {
        case 'critical':
            return 'Complete system compromise, data breach, or service disruption';
        case 'high':
            return 'Significant security risk with potential for data exposure';
        case 'medium':
            return 'Moderate security concern requiring attention';
        case 'low':
            return 'Minor security issue with limited impact';
        default:
            return 'Security concern requiring review';
    }
}

// Get exploit complexity based on severity
function getExploitComplexity(severity?: string): string {
    switch (severity) {
        case 'critical':
            return 'low';
        case 'high':
            return 'low';
        case 'medium':
            return 'medium';
        case 'low':
            return 'high';
        default:
            return 'medium';
    }
}

// Get CVSS score based on severity
function getCVSSScore(severity?: string): number {
    switch (severity) {
        case 'critical':
            return 9.5;
        case 'high':
            return 7.5;
        case 'medium':
            return 5.0;
        case 'low':
            return 2.5;
        default:
            return 5.0;
    }
}

// Generate default recommendations based on findings
function generateDefaultRecommendations(vulnNodes: VulnerabilityNode[]): {
    immediate_actions: string[];
    short_term_fixes: string[];
    long_term_improvements: string[];
    compliance_notes: string[];
} {
    const recommendations = {
        immediate_actions: [] as string[],
        short_term_fixes: [] as string[],
        long_term_improvements: [] as string[],
        compliance_notes: [] as string[]
    };

    const hasCritical = vulnNodes.some(n => n.data?.severity === 'critical');
    const hasHigh = vulnNodes.some(n => n.data?.severity === 'high');

    const hasAuth = vulnNodes.some(n =>
        (n.label || '').toLowerCase().includes('auth') ||
        (n.data?.description || '').toLowerCase().includes('auth')
    );
    const hasInjection = vulnNodes.some(n =>
        (n.label || '').toLowerCase().includes('injection') ||
        (n.data?.description || '').toLowerCase().includes('injection')
    );
    const hasXSS = vulnNodes.some(n =>
        (n.label || '').toLowerCase().includes('xss') ||
        (n.data?.description || '').toLowerCase().includes('script')
    );
    const hasCredentials = vulnNodes.some(n =>
        (n.label || '').toLowerCase().includes('password') ||
        (n.label || '').toLowerCase().includes('credential') ||
        (n.label || '').toLowerCase().includes('secret')
    );

    // Immediate actions
    if (hasCritical) {
        recommendations.immediate_actions.push('URGENT: Address all critical vulnerabilities immediately before deployment.');
    }
    if (hasCredentials) {
        recommendations.immediate_actions.push('Rotate any exposed credentials and secrets immediately.');
    }
    if (hasHigh && !hasCritical) {
        recommendations.immediate_actions.push('Prioritize fixing high-severity vulnerabilities in the next sprint.');
    }
    if (recommendations.immediate_actions.length === 0) {
        recommendations.immediate_actions.push('Review and prioritize identified vulnerabilities based on business impact.');
    }

    // Short-term fixes
    if (hasAuth) {
        recommendations.short_term_fixes.push('Review and strengthen authentication mechanisms across all endpoints.');
        recommendations.short_term_fixes.push('Implement rate limiting on authentication endpoints.');
    }
    if (hasInjection) {
        recommendations.short_term_fixes.push('Implement parameterized queries for all database operations.');
        recommendations.short_term_fixes.push('Add input validation layer for all user inputs.');
    }
    if (hasXSS) {
        recommendations.short_term_fixes.push('Implement Content Security Policy (CSP) headers.');
        recommendations.short_term_fixes.push('Use framework-provided output encoding for all user content.');
    }
    recommendations.short_term_fixes.push('Implement security logging and monitoring.');

    // Long-term improvements
    recommendations.long_term_improvements.push('Establish regular security assessment schedule (quarterly recommended).');
    recommendations.long_term_improvements.push('Implement security training program for development team.');
    recommendations.long_term_improvements.push('Set up automated security scanning in CI/CD pipeline.');
    if (hasAuth) {
        recommendations.long_term_improvements.push('Consider implementing multi-factor authentication.');
    }

    // Compliance notes
    recommendations.compliance_notes.push('Document all vulnerability remediation for audit purposes.');
    recommendations.compliance_notes.push('Review data handling practices for GDPR compliance.');
    if (hasCredentials) {
        recommendations.compliance_notes.push('Ensure secrets management complies with SOC2 requirements.');
    }

    return recommendations;
}

// Main report endpoint
export const getReport = async (req: Request, res: Response) => {
    const { scanId } = req.params;
    const context = `${CONTEXT}.getReport`;

    log(LogLevel.INFO, context, `Generating report for scan: ${scanId}`);

    // Validate scan ID
    if (!scanId) {
        return createErrorResponse(res, 400, 'Scan ID is required', context);
    }

    if (!validate.isValidId(scanId)) {
        return createErrorResponse(res, 400, 'Invalid scan ID format', context, { scanId });
    }

    try {
        let scan: Scan | null = null;
        let project: Project | null = null;

        if (scanId === 'demo' || scanId === 'scan-1') {
            log(LogLevel.INFO, context, 'Serving demo report data');
            scan = {
                id: scanId,
                project_id: 'demo-project',
                status: 'completed',
                progress: 100,
                started_at: new Date().toISOString(),
                attack_graph: attackGraphService.getMockDemoGraph(),
                vulnerability_count: 2,
                risk_score: 85,
                logs: []
            };
            project = {
                id: 'demo-project',
                name: 'Demo E-Commerce API',
                type: 'API',
                vulnerability_counts: { critical: 1, high: 1, medium: 0, low: 0 }
            };
        } else {
            // Fetch scan data with retry
            log(LogLevel.DEBUG, context, 'Fetching scan data...');
            scan = await dbQuery.fetchOne<Scan>('scans', 'id', scanId, context);

            if (!scan) {
                return createErrorResponse(res, 404, 'Scan not found', context, { scanId });
            }

            // Check if scan is completed
            if (scan.status !== 'completed') {
                log(LogLevel.WARN, context, `Scan not completed, status: ${scan.status}`);
                return createErrorResponse(res, 400, `Scan is not completed. Current status: ${scan.status}`, context);
            }

            // Fetch project data with retry
            log(LogLevel.DEBUG, context, 'Fetching project data...');
            project = await dbQuery.fetchOne<Project>('projects', 'id', scan.project_id, context);
        }

        // Extract vulnerability data
        const graph = scan.attack_graph || { nodes: [], edges: [] };
        const vulnNodes = extractVulnerabilityNodes(graph);
        const severityCounts = countBySeverity(vulnNodes);

        log(LogLevel.INFO, context, `Found ${vulnNodes.length} vulnerabilities`, severityCounts);

        // Get AI-powered recommendations (with fallback)
        let aiRecommendations = null;
        try {
            log(LogLevel.DEBUG, context, 'Requesting AI recommendations...');
            const findingsForAI = vulnNodes.map(node => ({
                id: node.id,
                pattern: node.label,
                severity: node.data?.severity || 'medium',
                description: node.data?.description,
                category: node.data?.category || 'general'
            }));

            if (findingsForAI.length > 0) {
                aiRecommendations = await generateSecurityRecommendations(findingsForAI);
                log(LogLevel.INFO, context, 'AI recommendations generated successfully');
            }
        } catch (aiError: any) {
            log(LogLevel.WARN, context, `AI recommendations failed, using defaults: ${aiError.message}`);
        }

        // Calculate scan duration in seconds
        const scanDurationMs = graph.metadata?.scanDuration || 0;
        const scanDurationSeconds = Math.round(scanDurationMs / 1000) || 60; // Default to 60 seconds
        const endpointsTested = graph.nodes?.filter((n: any) => n.type === 'api_call').length || 0;
        const testCasesExecuted = (graph.edges?.length || 0) * 2 + vulnNodes.length;

        // Build comprehensive report matching frontend SecurityReport type
        const report = {
            scan_id: scan.id,
            project_name: project?.name || 'Unknown Project',
            generated_at: new Date().toISOString(),

            executive_summary: {
                total_vulnerabilities: vulnNodes.length,
                critical_count: severityCounts.critical,
                high_count: severityCounts.high,
                medium_count: severityCounts.medium,
                low_count: severityCounts.low,
                overall_risk: determineRiskLevel(severityCounts) as 'critical' | 'high' | 'medium' | 'low',
                summary: aiRecommendations?.executive_summary ||
                    `Security assessment completed on ${new Date(scan.started_at).toLocaleDateString()}. ` +
                    `Found ${vulnNodes.length} potential vulnerabilities: ` +
                    `${severityCounts.critical} critical, ${severityCounts.high} high, ` +
                    `${severityCounts.medium} medium, ${severityCounts.low} low severity issues.`
            },

            // Findings matching Vulnerability type
            findings: vulnNodes.map(node => ({
                id: node.id,
                scan_id: scan.id,
                title: node.label || 'Unknown Vulnerability',
                severity: (node.data?.severity || 'medium') as 'critical' | 'high' | 'medium' | 'low' | 'info',
                type: mapCategoryToType(node.data?.category) as 'IDOR' | 'Logic Bypass' | 'Auth Bypass' | 'Business Logic' | 'Input Validation' | 'Other',
                description: node.data?.description || 'No description available',
                impact: getImpactDescription(node.data?.severity),
                exploit_complexity: getExploitComplexity(node.data?.severity) as 'low' | 'medium' | 'high',
                cvss_score: getCVSSScore(node.data?.severity),
                discovered_at: scan.started_at,
                attack_chain: [],
                affected_endpoints: node.data?.endpoint ? [node.data.endpoint] : [],
                recommended_fixes: [getRecommendation(node)]
            })),

            // Recommendations in the expected format
            recommendations: aiRecommendations ? {
                immediate_actions: aiRecommendations.immediate_actions || [],
                short_term_fixes: aiRecommendations.short_term_fixes || [],
                long_term_improvements: aiRecommendations.long_term_improvements || [],
                compliance_notes: aiRecommendations.compliance_notes || []
            } : generateDefaultRecommendations(vulnNodes),

            // Metadata matching frontend expectations
            metadata: {
                scan_duration: scanDurationSeconds,
                endpoints_tested: endpointsTested,
                test_cases_executed: testCasesExecuted
            }
        };

        log(LogLevel.INFO, context, 'Report generated successfully', {
            vulnCount: vulnNodes.length,
            riskLevel: report.executive_summary.overall_risk
        });

        return createSuccessResponse(res, report, context, 'Report generated successfully');

    } catch (error: any) {
        log(LogLevel.ERROR, context, `Report generation failed: ${error.message}`, {
            stack: error.stack,
            scanId
        });
        return createErrorResponse(res, 500, 'Failed to generate report', context, {
            error: error.message
        });
    }
};

// PDF Export endpoint
export const exportReportPDF = async (req: Request, res: Response) => {
    const { scanId } = req.params;
    const context = `${CONTEXT}.exportReportPDF`;

    log(LogLevel.INFO, context, `Exporting PDF report for scan: ${scanId}`);

    // Validate scan ID
    if (!scanId) {
        return createErrorResponse(res, 400, 'Scan ID is required', context);
    }

    if (!validate.isValidId(scanId)) {
        return createErrorResponse(res, 400, 'Invalid scan ID format', context, { scanId });
    }

    try {
        let scan: Scan | null = null;
        let project: Project | null = null;

        if (scanId === 'demo') {
            scan = {
                id: 'demo',
                project_id: 'demo-project',
                status: 'completed',
                progress: 100,
                started_at: new Date().toISOString(),
                attack_graph: attackGraphService.getMockDemoGraph(),
                vulnerability_count: 2,
                risk_score: 85,
                logs: []
            };
            project = {
                id: 'demo-project',
                name: 'Demo E-Commerce API',
                type: 'API',
                vulnerability_counts: { critical: 1, high: 1, medium: 0, low: 0 }
            };
        } else {
            // Fetch scan data
            scan = await dbQuery.fetchOne<Scan>('scans', 'id', scanId, context);

            if (!scan) {
                return createErrorResponse(res, 404, 'Scan not found', context, { scanId });
            }

            // Fetch project data
            project = await dbQuery.fetchOne<Project>('projects', 'id', scan.project_id, context);
        }

        // Extract vulnerability data
        const graph = scan.attack_graph || { nodes: [], edges: [] };
        const vulnNodes = extractVulnerabilityNodes(graph);
        const severityCounts = countBySeverity(vulnNodes);

        // Generate PDF content
        const pdfContent = generatePDFContent({
            projectName: project?.name || 'Unknown Project',
            scanId: scan.id,
            scanDate: scan.started_at,
            status: scan.status,
            totalVulnerabilities: vulnNodes.length,
            ...severityCounts,
            vulnerabilities: vulnNodes,
            recommendations: generateDefaultRecommendations(vulnNodes),
            riskScore: scan.risk_score || calculateRiskScore(severityCounts),
            metadata: graph.metadata
        });

        // Set headers for PDF download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=security-report-${scanId}.pdf`);
        res.setHeader('Content-Length', Buffer.byteLength(pdfContent, 'utf-8'));

        log(LogLevel.INFO, context, 'PDF report generated successfully');
        res.send(Buffer.from(pdfContent, 'utf-8'));

    } catch (error: any) {
        log(LogLevel.ERROR, context, `PDF export failed: ${error.message}`, {
            stack: error.stack,
            scanId
        });
        return createErrorResponse(res, 500, 'Failed to export PDF report', context, {
            error: error.message
        });
    }
};

// Generate PDF content as formatted text
function generatePDFContent(data: {
    projectName: string;
    scanId: string;
    scanDate: string;
    status: string;
    totalVulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    vulnerabilities: VulnerabilityNode[];
    recommendations: {
        immediate_actions: string[];
        short_term_fixes: string[];
        long_term_improvements: string[];
        compliance_notes: string[];
    };
    riskScore: number;
    metadata?: any;
}): string {
    const separator = '='.repeat(70);
    const subSeparator = '-'.repeat(70);
    const lines: string[] = [];

    // Header
    lines.push(separator);
    lines.push('                    SENTINEL AI - SECURITY ASSESSMENT REPORT');
    lines.push(separator);
    lines.push('');

    // Project Info
    lines.push(`Project:        ${data.projectName}`);
    lines.push(`Scan ID:        ${data.scanId}`);
    lines.push(`Scan Date:      ${new Date(data.scanDate).toLocaleString()}`);
    lines.push(`Report Generated: ${new Date().toLocaleString()}`);
    lines.push(`Status:         ${data.status.toUpperCase()}`);
    lines.push(`Risk Score:     ${data.riskScore}/100`);
    lines.push('');

    // Executive Summary
    lines.push(separator);
    lines.push('                         EXECUTIVE SUMMARY');
    lines.push(separator);
    lines.push('');
    lines.push(`Total Vulnerabilities Found: ${data.totalVulnerabilities}`);
    lines.push('');
    lines.push('Severity Breakdown:');
    lines.push(`  ● Critical:  ${data.critical} ${data.critical > 0 ? '⚠️  IMMEDIATE ACTION REQUIRED' : ''}`);
    lines.push(`  ● High:      ${data.high} ${data.high > 0 ? '⚠️  Urgent attention needed' : ''}`);
    lines.push(`  ● Medium:    ${data.medium}`);
    lines.push(`  ● Low:       ${data.low}`);
    lines.push(`  ● Info:      ${data.info}`);
    lines.push('');

    // Risk Assessment
    const riskLevel = data.critical > 0 ? 'CRITICAL' : data.high > 0 ? 'HIGH' : data.medium > 0 ? 'MEDIUM' : 'LOW';
    lines.push(`Overall Risk Level: ${riskLevel}`);
    lines.push('');

    // Detailed Findings
    if (data.vulnerabilities.length > 0) {
        lines.push(separator);
        lines.push('                         DETAILED FINDINGS');
        lines.push(separator);
        lines.push('');

        data.vulnerabilities.forEach((vuln, index) => {
            const severity = (vuln.data?.severity || 'medium').toUpperCase();
            const severityIcon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : severity === 'MEDIUM' ? '🟡' : '🟢';

            lines.push(`${index + 1}. ${severityIcon} ${vuln.label || 'Unknown Vulnerability'}`);
            lines.push(subSeparator);
            lines.push(`   Severity:      ${severity}`);
            lines.push(`   Description:   ${vuln.data?.description || 'No description available'}`);
            if (vuln.data?.endpoint) {
                lines.push(`   Endpoint:      ${vuln.data.endpoint}`);
            }
            if (vuln.data?.cwe) {
                lines.push(`   CWE:           ${vuln.data.cwe}`);
            }
            if (vuln.data?.owasp) {
                lines.push(`   OWASP:         ${vuln.data.owasp}`);
            }
            lines.push(`   Recommendation: ${getRecommendation(vuln)}`);
            lines.push('');
        });
    } else {
        lines.push(separator);
        lines.push('                         DETAILED FINDINGS');
        lines.push(separator);
        lines.push('');
        lines.push('No vulnerabilities detected in this scan.');
        lines.push('');
    }

    // Recommendations
    lines.push(separator);
    lines.push('                         RECOMMENDATIONS');
    lines.push(separator);
    lines.push('');

    if (data.recommendations.immediate_actions.length > 0) {
        lines.push('IMMEDIATE ACTIONS (Do Now):');
        data.recommendations.immediate_actions.forEach((rec, i) => {
            lines.push(`  ${i + 1}. ${rec}`);
        });
        lines.push('');
    }

    if (data.recommendations.short_term_fixes.length > 0) {
        lines.push('SHORT-TERM FIXES (This Sprint):');
        data.recommendations.short_term_fixes.forEach((rec, i) => {
            lines.push(`  ${i + 1}. ${rec}`);
        });
        lines.push('');
    }

    if (data.recommendations.long_term_improvements.length > 0) {
        lines.push('LONG-TERM IMPROVEMENTS (Roadmap):');
        data.recommendations.long_term_improvements.forEach((rec, i) => {
            lines.push(`  ${i + 1}. ${rec}`);
        });
        lines.push('');
    }

    if (data.recommendations.compliance_notes.length > 0) {
        lines.push('COMPLIANCE NOTES:');
        data.recommendations.compliance_notes.forEach((note, i) => {
            lines.push(`  ${i + 1}. ${note}`);
        });
        lines.push('');
    }

    // Metadata
    if (data.metadata) {
        lines.push(separator);
        lines.push('                         SCAN METADATA');
        lines.push(separator);
        lines.push('');
        if (data.metadata.scannedFiles) {
            lines.push(`Files Scanned:    ${data.metadata.scannedFiles}`);
        }
        if (data.metadata.scanDuration) {
            lines.push(`Scan Duration:    ${data.metadata.scanDuration}ms`);
        }
        if (data.metadata.scanPath) {
            lines.push(`Scan Path:        ${data.metadata.scanPath}`);
        }
        lines.push('');
    }

    // Footer
    lines.push(separator);
    lines.push('                           END OF REPORT');
    lines.push(separator);
    lines.push('');
    lines.push('Generated by Sentinel AI Security Scanner');
    lines.push('For questions or support, contact your security team.');
    lines.push('');

    return lines.join('\n');
}