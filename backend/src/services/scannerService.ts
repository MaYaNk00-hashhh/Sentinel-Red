import * as fs from 'fs';
import * as path from 'path';

// Vulnerability patterns to detect in code
const VULNERABILITY_PATTERNS = {
    // SQL Injection patterns
    sqlInjection: [
        { pattern: /query\s*\(\s*['"`].*\$\{.*\}.*['"`]\s*\)/gi, name: 'SQL Injection (Template Literal)', severity: 'critical' },
        { pattern: /query\s*\(\s*['"`].*\+.*['"`]\s*\)/gi, name: 'SQL Injection (String Concatenation)', severity: 'critical' },
        { pattern: /execute\s*\(\s*['"`].*\$\{.*\}.*['"`]\s*\)/gi, name: 'SQL Injection in Execute', severity: 'critical' },
        { pattern: /raw\s*\(\s*['"`].*\+/gi, name: 'Raw SQL Query', severity: 'high' },
        { pattern: /\beval\s*\(/gi, name: 'Eval Usage (Code Injection Risk)', severity: 'critical' },
    ],

    // XSS patterns
    xss: [
        { pattern: /innerHTML\s*=/gi, name: 'innerHTML Assignment (XSS Risk)', severity: 'high' },
        { pattern: /document\.write\s*\(/gi, name: 'document.write (XSS Risk)', severity: 'high' },
        { pattern: /dangerouslySetInnerHTML/gi, name: 'React dangerouslySetInnerHTML', severity: 'medium' },
        { pattern: /v-html\s*=/gi, name: 'Vue v-html Directive', severity: 'medium' },
        { pattern: /\[innerHTML\]/gi, name: 'Angular innerHTML Binding', severity: 'medium' },
    ],

    // Authentication issues
    authIssues: [
        { pattern: /password\s*[=:]\s*['"`][^'"`]+['"`]/gi, name: 'Hardcoded Password', severity: 'critical' },
        { pattern: /api[_-]?key\s*[=:]\s*['"`][^'"`]+['"`]/gi, name: 'Hardcoded API Key', severity: 'critical' },
        { pattern: /secret\s*[=:]\s*['"`][^'"`]+['"`]/gi, name: 'Hardcoded Secret', severity: 'critical' },
        { pattern: /token\s*[=:]\s*['"`][A-Za-z0-9+/=]{20,}['"`]/gi, name: 'Hardcoded Token', severity: 'critical' },
        { pattern: /jwt[_-]?secret\s*[=:]/gi, name: 'JWT Secret in Code', severity: 'high' },
        { pattern: /private[_-]?key\s*[=:]/gi, name: 'Private Key in Code', severity: 'critical' },
    ],

    // Insecure configurations
    insecureConfig: [
        { pattern: /cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]/gi, name: 'CORS Allow All Origins', severity: 'medium' },
        { pattern: /disable.*security/gi, name: 'Security Disabled', severity: 'high' },
        { pattern: /verify\s*[=:]\s*false/gi, name: 'SSL Verification Disabled', severity: 'high' },
        { pattern: /rejectUnauthorized\s*:\s*false/gi, name: 'TLS Verification Disabled', severity: 'high' },
        { pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/gi, name: 'TLS Rejection Disabled', severity: 'high' },
    ],

    // Path traversal
    pathTraversal: [
        { pattern: /readFile\s*\([^)]*\+/gi, name: 'Path Traversal Risk (readFile)', severity: 'high' },
        { pattern: /readFileSync\s*\([^)]*\+/gi, name: 'Path Traversal Risk (readFileSync)', severity: 'high' },
        { pattern: /\.\.\/|\.\.\\|%2e%2e/gi, name: 'Directory Traversal Pattern', severity: 'medium' },
    ],

    // Command injection
    commandInjection: [
        { pattern: /exec\s*\([^)]*\+/gi, name: 'Command Injection (exec)', severity: 'critical' },
        { pattern: /execSync\s*\([^)]*\+/gi, name: 'Command Injection (execSync)', severity: 'critical' },
        { pattern: /spawn\s*\([^)]*\+/gi, name: 'Command Injection (spawn)', severity: 'high' },
        { pattern: /child_process/gi, name: 'Child Process Usage', severity: 'medium' },
    ],

    // Insecure dependencies/imports
    insecureDeps: [
        { pattern: /require\s*\(\s*['"`]crypto['"`]\s*\)/gi, name: 'Crypto Module (Review Usage)', severity: 'low' },
        { pattern: /Math\.random\s*\(/gi, name: 'Insecure Random (Math.random)', severity: 'medium' },
    ],

    // Information disclosure
    infoDisclosure: [
        { pattern: /console\.(log|debug|info)\s*\([^)]*password/gi, name: 'Password in Console Log', severity: 'high' },
        { pattern: /console\.(log|debug|info)\s*\([^)]*token/gi, name: 'Token in Console Log', severity: 'high' },
        { pattern: /console\.(log|debug|info)\s*\([^)]*secret/gi, name: 'Secret in Console Log', severity: 'high' },
        { pattern: /stackTrace|stack\s*:/gi, name: 'Stack Trace Exposure', severity: 'medium' },
    ],

    // IDOR patterns
    idor: [
        { pattern: /params\.(id|userId|user_id)/gi, name: 'Potential IDOR (params.id)', severity: 'medium' },
        { pattern: /req\.params\.\w+.*(?:findOne|findById|delete|update)/gi, name: 'IDOR Risk in DB Operation', severity: 'high' },
    ],

    // Missing security headers
    missingHeaders: [
        { pattern: /helmet/gi, name: 'Helmet Usage (Good)', severity: 'info', positive: true },
        { pattern: /x-frame-options/gi, name: 'X-Frame-Options Header', severity: 'info', positive: true },
        { pattern: /content-security-policy/gi, name: 'CSP Header', severity: 'info', positive: true },
    ],
};

// File extensions to scan
const SCANNABLE_EXTENSIONS = [
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.py', '.rb', '.php', '.java', '.go', '.rs',
    '.vue', '.svelte', '.html', '.htm',
    '.json', '.yaml', '.yml', '.env', '.config'
];

// Directories to skip
const SKIP_DIRECTORIES = [
    'node_modules', '.git', 'dist', 'build', 'coverage',
    '.next', '.nuxt', '__pycache__', 'venv', '.venv',
    'vendor', 'target', 'bin', 'obj'
];

export interface VulnerabilityFinding {
    id: string;
    file: string;
    line: number;
    column: number;
    code: string;
    pattern: string;
    category: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;
    recommendation: string;
}

export interface ScanResult {
    totalFiles: number;
    scannedFiles: number;
    findings: VulnerabilityFinding[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    scanDuration: number;
}

// Generate unique ID
function generateId(): string {
    return `vuln-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Get recommendation based on vulnerability type
function getRecommendation(category: string, patternName: string): string {
    const recommendations: Record<string, string> = {
        sqlInjection: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
        xss: 'Sanitize and encode all user input before rendering. Use framework-provided escaping mechanisms.',
        authIssues: 'Store secrets in environment variables or a secure vault. Never commit credentials to source control.',
        insecureConfig: 'Review and tighten security configurations. Enable SSL verification and restrict CORS origins.',
        pathTraversal: 'Validate and sanitize file paths. Use path.resolve() and check against allowed directories.',
        commandInjection: 'Avoid executing shell commands with user input. If necessary, use strict input validation and escaping.',
        insecureDeps: 'Review usage of security-sensitive modules. Use crypto.randomBytes() instead of Math.random() for security.',
        infoDisclosure: 'Remove sensitive data from logs. Use proper logging levels and redact sensitive information.',
        idor: 'Implement proper authorization checks. Verify the user has permission to access the requested resource.',
        missingHeaders: 'Implement security headers using helmet.js or manually configure CSP, X-Frame-Options, etc.',
    };
    return recommendations[category] || 'Review this code for potential security issues.';
}

// Scan a single file for vulnerabilities
function scanFile(filePath: string, content: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];
    const lines = content.split('\n');

    for (const [category, patterns] of Object.entries(VULNERABILITY_PATTERNS)) {
        for (const { pattern, name, severity, positive } of patterns as any[]) {
            // Skip positive patterns (they indicate good practices)
            if (positive) continue;

            lines.forEach((line, lineIndex) => {
                const matches = line.match(pattern);
                if (matches) {
                    matches.forEach(match => {
                        const column = line.indexOf(match);
                        findings.push({
                            id: generateId(),
                            file: filePath,
                            line: lineIndex + 1,
                            column: column + 1,
                            code: line.trim().substring(0, 100),
                            pattern: name,
                            category,
                            severity: severity as any,
                            description: `Detected ${name} at line ${lineIndex + 1}`,
                            recommendation: getRecommendation(category, name)
                        });
                    });
                }
            });
        }
    }

    return findings;
}

// Recursively get all files in a directory
function getAllFiles(dirPath: string, arrayOfFiles: string[] = []): string[] {
    try {
        const files = fs.readdirSync(dirPath);

        files.forEach(file => {
            const fullPath = path.join(dirPath, file);

            try {
                const stat = fs.statSync(fullPath);

                if (stat.isDirectory()) {
                    if (!SKIP_DIRECTORIES.includes(file)) {
                        getAllFiles(fullPath, arrayOfFiles);
                    }
                } else {
                    const ext = path.extname(file).toLowerCase();
                    if (SCANNABLE_EXTENSIONS.includes(ext)) {
                        arrayOfFiles.push(fullPath);
                    }
                }
            } catch (e) {
                // Skip files we can't access
            }
        });
    } catch (e) {
        // Skip directories we can't access
    }

    return arrayOfFiles;
}

// Parse OpenAPI spec for endpoint analysis
export function parseOpenAPISpec(spec: string): any[] {
    try {
        const parsed = JSON.parse(spec);
        const endpoints: any[] = [];

        if (parsed.paths) {
            Object.entries(parsed.paths).forEach(([path, methods]: [string, any]) => {
                Object.entries(methods).forEach(([method, details]: [string, any]) => {
                    endpoints.push({
                        path,
                        method: method.toUpperCase(),
                        summary: details.summary || '',
                        description: details.description || '',
                        parameters: details.parameters || [],
                        requestBody: details.requestBody,
                        responses: details.responses,
                        security: details.security || []
                    });
                });
            });
        }

        return endpoints;
    } catch (e) {
        return [];
    }
}

// Analyze endpoints for security issues
export function analyzeEndpoints(endpoints: any[]): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    endpoints.forEach((endpoint, index) => {
        const path = endpoint.path || '';
        const method = endpoint.method || 'GET';

        // Check for missing authentication
        if (!endpoint.security || endpoint.security.length === 0) {
            if (path.includes('admin') || path.includes('user') || path.includes('account')) {
                findings.push({
                    id: generateId(),
                    file: 'OpenAPI Spec',
                    line: index + 1,
                    column: 1,
                    code: `${method} ${path}`,
                    pattern: 'Missing Authentication',
                    category: 'authIssues',
                    severity: 'high',
                    description: `Endpoint ${method} ${path} appears to handle sensitive data but has no security defined`,
                    recommendation: 'Add authentication requirements to this endpoint'
                });
            }
        }

        // Check for potential IDOR
        if (path.match(/\{.*id.*\}/i) && !endpoint.security?.length) {
            findings.push({
                id: generateId(),
                file: 'OpenAPI Spec',
                line: index + 1,
                column: 1,
                code: `${method} ${path}`,
                pattern: 'Potential IDOR',
                category: 'idor',
                severity: 'medium',
                description: `Endpoint ${method} ${path} uses ID parameter without apparent authorization`,
                recommendation: 'Ensure proper authorization checks are implemented for this endpoint'
            });
        }

        // Check for mass assignment risk
        if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && endpoint.requestBody) {
            findings.push({
                id: generateId(),
                file: 'OpenAPI Spec',
                line: index + 1,
                column: 1,
                code: `${method} ${path}`,
                pattern: 'Mass Assignment Risk',
                category: 'insecureConfig',
                severity: 'medium',
                description: `Endpoint ${method} ${path} accepts request body - verify input validation`,
                recommendation: 'Implement strict input validation and whitelist allowed fields'
            });
        }

        // Check for sensitive data in GET parameters
        if (method === 'GET' && endpoint.parameters) {
            const sensitiveParams = endpoint.parameters.filter((p: any) =>
                /password|token|secret|key|auth/i.test(p.name)
            );
            if (sensitiveParams.length > 0) {
                findings.push({
                    id: generateId(),
                    file: 'OpenAPI Spec',
                    line: index + 1,
                    column: 1,
                    code: `${method} ${path}`,
                    pattern: 'Sensitive Data in URL',
                    category: 'infoDisclosure',
                    severity: 'high',
                    description: `Endpoint ${method} ${path} may expose sensitive data in URL parameters`,
                    recommendation: 'Move sensitive data to request body or headers'
                });
            }
        }
    });

    return findings;
}

// Main scan function
export async function scanProject(projectPath: string, openApiSpec?: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: VulnerabilityFinding[] = [];
    let totalFiles = 0;
    let scannedFiles = 0;

    // Scan files if path exists
    if (projectPath && fs.existsSync(projectPath)) {
        const files = getAllFiles(projectPath);
        totalFiles = files.length;

        for (const file of files) {
            try {
                const content = fs.readFileSync(file, 'utf-8');
                const fileFindings = scanFile(file, content);
                findings.push(...fileFindings);
                scannedFiles++;
            } catch (e) {
                // Skip files we can't read
            }
        }
    }

    // Analyze OpenAPI spec if provided
    if (openApiSpec) {
        const endpoints = parseOpenAPISpec(openApiSpec);
        const endpointFindings = analyzeEndpoints(endpoints);
        findings.push(...endpointFindings);
    }

    // Calculate summary
    const summary = {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
    };

    return {
        totalFiles,
        scannedFiles,
        findings,
        summary,
        scanDuration: Date.now() - startTime
    };
}

// Convert scan results to attack graph format
export function convertToAttackGraph(scanResult: ScanResult, scanId: string): any {
    const nodes: any[] = [];
    const edges: any[] = [];
    let nodeIndex = 0;
    let edgeIndex = 0;

    // Start node
    nodes.push({
        id: 'start',
        type: 'start',
        label: 'Attack Surface',
        data: {
            description: `Scanned ${scanResult.scannedFiles} files, found ${scanResult.findings.length} potential vulnerabilities`,
            severity: 'low'
        },
        position: { x: 100, y: 300 }
    });

    // Group findings by category
    const byCategory: Record<string, VulnerabilityFinding[]> = {};
    scanResult.findings.forEach(finding => {
        if (!byCategory[finding.category]) {
            byCategory[finding.category] = [];
        }
        byCategory[finding.category].push(finding);
    });

    // Create nodes for each category
    const categories = Object.keys(byCategory);
    categories.forEach((category, catIndex) => {
        const categoryFindings = byCategory[category];
        const maxSeverity = getMaxSeverity(categoryFindings);

        // Category node (as API call representing attack vector)
        const catNodeId = `cat-${category}`;
        nodes.push({
            id: catNodeId,
            type: 'api_call',
            label: formatCategoryName(category),
            data: {
                description: `${categoryFindings.length} findings in this category`,
                severity: maxSeverity,
                method: 'SCAN',
                endpoint: category
            },
            position: { x: 350, y: 100 + catIndex * 120 }
        });

        // Connect from start
        edges.push({
            id: `e-${edgeIndex++}`,
            source: 'start',
            target: catNodeId,
            label: 'Attack Vector',
            type: 'default'
        });

        // Create vulnerability nodes for critical/high findings
        const importantFindings = categoryFindings.filter(f =>
            f.severity === 'critical' || f.severity === 'high'
        ).slice(0, 3); // Limit to 3 per category

        importantFindings.forEach((finding, findIndex) => {
            const vulnNodeId = `vuln-${nodeIndex++}`;
            nodes.push({
                id: vulnNodeId,
                type: 'vulnerability',
                label: finding.pattern,
                data: {
                    description: finding.description,
                    severity: finding.severity,
                    endpoint: finding.file,
                    line: finding.line,
                    code: finding.code,
                    recommendation: finding.recommendation
                },
                position: { x: 600, y: 50 + catIndex * 120 + findIndex * 80 }
            });

            edges.push({
                id: `e-${edgeIndex++}`,
                source: catNodeId,
                target: vulnNodeId,
                label: `Line ${finding.line}`,
                type: 'vulnerable'
            });
        });
    });

    // Add end node if critical vulnerabilities exist
    if (scanResult.summary.critical > 0) {
        const endNode = {
            id: 'end',
            type: 'end',
            label: 'System Compromise',
            data: {
                description: `${scanResult.summary.critical} critical vulnerabilities could lead to system compromise`,
                severity: 'critical'
            },
            position: { x: 850, y: 300 }
        };
        nodes.push(endNode);

        // Connect critical vulnerabilities to end
        nodes.filter(n => n.type === 'vulnerability' && n.data.severity === 'critical')
            .forEach(vuln => {
                edges.push({
                    id: `e-${edgeIndex++}`,
                    source: vuln.id,
                    target: 'end',
                    label: 'Exploit',
                    type: 'exploit'
                });
            });
    }

    return {
        nodes,
        edges,
        scan_id: scanId,
        metadata: {
            totalFiles: scanResult.totalFiles,
            scannedFiles: scanResult.scannedFiles,
            scanDuration: scanResult.scanDuration,
            summary: scanResult.summary
        }
    };
}

function getMaxSeverity(findings: VulnerabilityFinding[]): string {
    if (findings.some(f => f.severity === 'critical')) return 'critical';
    if (findings.some(f => f.severity === 'high')) return 'high';
    if (findings.some(f => f.severity === 'medium')) return 'medium';
    if (findings.some(f => f.severity === 'low')) return 'low';
    return 'info';
}

function formatCategoryName(category: string): string {
    const names: Record<string, string> = {
        sqlInjection: 'SQL Injection',
        xss: 'Cross-Site Scripting',
        authIssues: 'Authentication Issues',
        insecureConfig: 'Insecure Configuration',
        pathTraversal: 'Path Traversal',
        commandInjection: 'Command Injection',
        insecureDeps: 'Insecure Dependencies',
        infoDisclosure: 'Information Disclosure',
        idor: 'IDOR Vulnerabilities',
        missingHeaders: 'Missing Security Headers'
    };
    return names[category] || category;
}

export const scannerService = {
    scanProject,
    parseOpenAPISpec,
    analyzeEndpoints,
    convertToAttackGraph
};