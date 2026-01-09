import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from "@google/generative-ai";
import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";
import * as fs from 'fs';

// Helper to generate node positions in a hierarchical layout
function generateNodePositions(nodes: any[]): any[] {
    const typeOrder = ['start', 'api_call', 'vulnerability', 'exploit', 'end'];
    const nodesByType: Record<string, any[]> = {};

    // Group nodes by type
    nodes.forEach(node => {
        const type = node.type || 'api_call';
        if (!nodesByType[type]) nodesByType[type] = [];
        nodesByType[type].push(node);
    });

    // Assign positions based on type (column) and index within type (row)
    const positionedNodes: any[] = [];
    typeOrder.forEach((type, colIndex) => {
        const typeNodes = nodesByType[type] || [];
        typeNodes.forEach((node, rowIndex) => {
            positionedNodes.push({
                ...node,
                position: {
                    x: 150 + colIndex * 250,
                    y: 100 + rowIndex * 150
                }
            });
        });
    });

    // Add any nodes with types not in typeOrder
    Object.keys(nodesByType).forEach(type => {
        if (!typeOrder.includes(type)) {
            nodesByType[type].forEach((node, idx) => {
                if (!positionedNodes.find(n => n.id === node.id)) {
                    positionedNodes.push({
                        ...node,
                        position: {
                            x: 150 + typeOrder.length * 250,
                            y: 100 + idx * 150
                        }
                    });
                }
            });
        }
    });

    return positionedNodes;
}

// Validate and fix attack graph structure
function validateAndFixGraph(graph: any): any {
    if (!graph || typeof graph !== 'object') {
        return null;
    }

    // Ensure nodes array exists
    if (!Array.isArray(graph.nodes)) {
        graph.nodes = [];
    }

    // Ensure edges array exists
    if (!Array.isArray(graph.edges)) {
        graph.edges = [];
    }

    // Fix each node
    graph.nodes = graph.nodes.map((node: any, index: number) => ({
        id: node.id || `node-${index}`,
        type: node.type || 'api_call',
        label: node.label || node.id || `Node ${index}`,
        data: {
            description: node.data?.description || node.description || 'No description',
            severity: node.data?.severity || node.severity || 'medium',
            endpoint: node.data?.endpoint || node.endpoint,
            method: node.data?.method || node.method,
            ...(node.data || {})
        },
        position: node.position || { x: 100 + (index % 4) * 200, y: 100 + Math.floor(index / 4) * 150 }
    }));

    // Fix each edge
    graph.edges = graph.edges.map((edge: any, index: number) => ({
        id: edge.id || `edge-${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.label || '',
        type: edge.type || 'default'
    })).filter((edge: any) => edge.source && edge.target);

    // Generate proper positions if not present
    if (graph.nodes.some((n: any) => !n.position || typeof n.position.x !== 'number')) {
        graph.nodes = generateNodePositions(graph.nodes);
    }

    return graph;
}

const getGenAI = (key: string) => {
    try {
        const genAI = new GoogleGenerativeAI(key);
        return genAI.getGenerativeModel({
            model: "gemini-2.0-flash-exp", // Attempting newest model
            safetySettings: [
                { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
                { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
                { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
                { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE }
            ]
        });
    } catch (e) {
        return null;
    }
};

const getBedrockClient = () => {
    try {
        let key = (process.env.LLM_API_KEY || '').trim();
        if (!key) return null;

        let region = "us-east-1";
        let accessKeyId = "";
        let secretAccessKey = "";

        // Attempt "Hashira" ABSK parsing (Best Effort)
        if (key.startsWith('ABSK')) {
            const raw = key.substring(4);
            const decoded = Buffer.from(raw, 'base64').toString('utf-8').trim();
            const parts = decoded.split(':');

            if (parts.length >= 4) {
                region = parts[1] || "us-east-1";
                accessKeyId = parts[2];
                secretAccessKey = parts[3];
            } else if (parts.length === 2 && parts[1].length === 60) {
                accessKeyId = parts[1].substring(0, 20);
                secretAccessKey = parts[1].substring(20);
            }
        }
        else if (key.includes(':')) {
            const parts = key.split(':');
            if (parts.length === 2) {
                accessKeyId = parts[0];
                secretAccessKey = parts[1];
            }
        }

        if (accessKeyId && secretAccessKey) {
            return new BedrockRuntimeClient({
                region,
                credentials: { accessKeyId, secretAccessKey }
            });
        }
        return null;
    } catch (e) {
        return null;
    }
};

// Detailed prompt for security analysis
const SECURITY_ANALYSIS_PROMPT = `You are an expert security analyst performing a comprehensive security assessment.
Analyze the provided data and generate a detailed attack graph showing vulnerabilities and potential attack paths.

Your analysis should consider:
1. OWASP Top 10 vulnerabilities (Injection, Broken Auth, XSS, IDOR, Security Misconfig, etc.)
2. Authentication and Authorization flaws
3. Input validation issues
4. Business logic vulnerabilities
5. Data exposure risks
6. API security issues (mass assignment, rate limiting, etc.)
7. Cryptographic weaknesses
8. Security header configurations

Generate a JSON attack graph with this EXACT structure:
{
  "nodes": [
    {
      "id": "unique-id",
      "type": "start|api_call|vulnerability|exploit|end",
      "label": "Short descriptive label",
      "data": {
        "description": "Detailed description of the issue",
        "severity": "critical|high|medium|low",
        "endpoint": "/api/path (for api_call nodes)",
        "method": "GET|POST|PUT|DELETE (for api_call nodes)",
        "recommendation": "How to fix this issue",
        "cwe": "CWE-XXX (if applicable)",
        "owasp": "OWASP category (if applicable)"
      }
    }
  ],
  "edges": [
    {
      "id": "edge-id",
      "source": "source-node-id",
      "target": "target-node-id",
      "label": "Description of attack flow",
      "type": "default|vulnerable|exploit"
    }
  ]
}

Node types:
- "start": Entry point (Internet, Attacker, Malicious User)
- "api_call": API endpoint or code location being analyzed
- "vulnerability": Identified security vulnerability with details
- "exploit": Exploitation technique showing how vulnerability is exploited
- "end": Final impact (Data Breach, System Compromise, etc.)

Edge types:
- "default": Normal application flow
- "vulnerable": Path through a vulnerability
- "exploit": Active exploitation path

IMPORTANT RULES:
1. Always start with a "start" node representing the attacker's entry point
2. Create detailed vulnerability nodes with specific descriptions
3. Show realistic attack chains from vulnerability to impact
4. Include remediation recommendations in each vulnerability node
5. Prioritize findings by severity (critical first)
6. Be specific about the type of vulnerability and its impact

Data to analyze:
`;

// Prompt for generating security recommendations
const RECOMMENDATIONS_PROMPT = `You are a senior security consultant providing actionable security recommendations.
Based on the following vulnerability findings, provide:
1. Executive summary of the security posture
2. Prioritized list of remediation actions
3. Quick wins that can be implemented immediately
4. Long-term security improvements
5. Compliance considerations (GDPR, PCI-DSS, SOC2 if applicable)

Format your response as JSON:
{
  "executive_summary": "Brief overview of security status",
  "risk_level": "critical|high|medium|low",
  "immediate_actions": ["action1", "action2"],
  "short_term_fixes": ["fix1", "fix2"],
  "long_term_improvements": ["improvement1", "improvement2"],
  "compliance_notes": ["note1", "note2"]
}

Findings to analyze:
`;

export const aiService = {
    async analyzeEndpoints(endpoints: any[]): Promise<any> {
        // Logging helper
        const log = (msg: string) => {
            try {
                fs.appendFileSync('ai_debug.log', new Date().toISOString() + ': ' + msg + '\n');
            } catch (e) { }
        };

        const rawKey = (process.env.LLM_API_KEY || '').trim();
        log(`Analyzing ${endpoints.length} Endpoints. Key Starts With: ${rawKey.substring(0, 4)}...`);

        const fullPrompt = SECURITY_ANALYSIS_PROMPT + JSON.stringify(endpoints, null, 2);

        // --- STRATEGY 1: GEMINI ---
        if (rawKey.startsWith('AIza')) {
            log("Detected Provider: Google Gemini");
            try {
                const model = getGenAI(rawKey);
                if (model) {
                    const result = await model.generateContent(fullPrompt);
                    const response = await result.response;
                    const text = response.text();
                    log(`Gemini Response Length: ${text.length}`);
                    const jsonMatch = text.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        const parsed = JSON.parse(jsonMatch[0]);
                        const validated = validateAndFixGraph(parsed);
                        if (validated) {
                            log("Gemini Success - Graph validated");
                            return validated;
                        }
                    }
                }
            } catch (e: any) {
                log(`Gemini Error: ${e.message}`);
            }
        }

        // --- STRATEGY 2: AWS BEDROCK ---
        if (rawKey.startsWith('ABSK') || rawKey.includes(':')) {
            log("Detected Provider: AWS Bedrock (Hashira/Standard)");
            const client = getBedrockClient();
            if (client) {
                try {
                    const payload = {
                        prompt: `\n\nHuman: ${fullPrompt}\n\nAssistant: Here is the attack graph JSON:\n`,
                        max_tokens_to_sample: 4000,
                        temperature: 0.3,
                        top_p: 0.9,
                    };
                    const command = new InvokeModelCommand({
                        modelId: "anthropic.claude-v2",
                        contentType: "application/json",
                        accept: "application/json",
                        body: JSON.stringify(payload),
                    });

                    const response = await client.send(command);
                    const bodyStr = new TextDecoder().decode(response.body);
                    log(`Bedrock Response Length: ${bodyStr.length}`);
                    const responseBody = JSON.parse(bodyStr);
                    const jsonMatch = responseBody.completion.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        const parsed = JSON.parse(jsonMatch[0]);
                        const validated = validateAndFixGraph(parsed);
                        if (validated) {
                            log("Bedrock Success - Graph validated");
                            return validated;
                        }
                    }
                } catch (e: any) {
                    log(`Bedrock Error: ${e.message}`);
                    console.error("Bedrock Failed:", e);
                }
            } else {
                log("Bedrock Client Init Failed (Invalid Key Format)");
            }
        }

        // --- STRATEGY 3: GENERATE BASIC GRAPH FROM ENDPOINTS ---
        log("⚠️ AI unavailable. Generating basic graph from endpoint analysis.");
        return generateBasicGraphFromEndpoints(endpoints);
    }
};

// Generate security recommendations from findings
export async function generateSecurityRecommendations(findings: any[]): Promise<any> {
    const rawKey = (process.env.LLM_API_KEY || '').trim();

    const prompt = RECOMMENDATIONS_PROMPT + JSON.stringify(findings.slice(0, 30), null, 2);

    // Try Gemini
    if (rawKey.startsWith('AIza')) {
        try {
            const model = getGenAI(rawKey);
            if (model) {
                const result = await model.generateContent(prompt);
                const response = await result.response;
                const text = response.text();
                const jsonMatch = text.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    return JSON.parse(jsonMatch[0]);
                }
            }
        } catch (e) {
            console.error('Gemini recommendations error:', e);
        }
    }

    // Try Bedrock
    if (rawKey.startsWith('ABSK') || rawKey.includes(':')) {
        const client = getBedrockClient();
        if (client) {
            try {
                const payload = {
                    prompt: `\n\nHuman: ${prompt}\n\nAssistant:`,
                    max_tokens_to_sample: 2000,
                    temperature: 0.3,
                };
                const command = new InvokeModelCommand({
                    modelId: "anthropic.claude-v2",
                    contentType: "application/json",
                    accept: "application/json",
                    body: JSON.stringify(payload),
                });
                const response = await client.send(command);
                const bodyStr = new TextDecoder().decode(response.body);
                const responseBody = JSON.parse(bodyStr);
                const jsonMatch = responseBody.completion.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    return JSON.parse(jsonMatch[0]);
                }
            } catch (e) {
                console.error('Bedrock recommendations error:', e);
            }
        }
    }

    // Fallback recommendations based on findings analysis
    return generateFallbackRecommendations(findings);
}

function generateFallbackRecommendations(findings: any[]): any {
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const mediumCount = findings.filter(f => f.severity === 'medium').length;

    const riskLevel = criticalCount > 0 ? 'critical' : highCount > 0 ? 'high' : mediumCount > 0 ? 'medium' : 'low';

    const immediateActions: string[] = [];
    const shortTermFixes: string[] = [];
    const longTermImprovements: string[] = [];

    // Analyze findings for specific recommendations
    const categories = new Set(findings.map(f => f.category));

    if (categories.has('sqlInjection') || findings.some(f => f.pattern?.toLowerCase().includes('injection'))) {
        immediateActions.push('Implement parameterized queries for all database operations');
        shortTermFixes.push('Add input validation layer for all user inputs');
    }

    if (categories.has('xss') || findings.some(f => f.pattern?.toLowerCase().includes('xss'))) {
        immediateActions.push('Enable Content Security Policy headers');
        shortTermFixes.push('Implement output encoding for all user-generated content');
    }

    if (categories.has('authIssues') || findings.some(f => f.pattern?.toLowerCase().includes('auth') || f.pattern?.toLowerCase().includes('password'))) {
        immediateActions.push('Rotate any exposed credentials immediately');
        shortTermFixes.push('Implement secrets management solution (e.g., HashiCorp Vault)');
        longTermImprovements.push('Implement multi-factor authentication');
    }

    if (categories.has('idor')) {
        shortTermFixes.push('Implement proper authorization checks for all resource access');
        longTermImprovements.push('Adopt attribute-based access control (ABAC)');
    }

    // Default recommendations
    if (immediateActions.length === 0) {
        immediateActions.push('Review and prioritize identified vulnerabilities');
    }

    shortTermFixes.push('Implement security logging and monitoring');
    longTermImprovements.push('Establish regular security assessment schedule');
    longTermImprovements.push('Implement security training for development team');

    return {
        executive_summary: `Security assessment identified ${findings.length} potential vulnerabilities: ${criticalCount} critical, ${highCount} high, ${mediumCount} medium severity issues. ${riskLevel === 'critical' ? 'Immediate action required.' : riskLevel === 'high' ? 'Prompt attention recommended.' : 'Review and address findings.'}`,
        risk_level: riskLevel,
        immediate_actions: immediateActions,
        short_term_fixes: shortTermFixes,
        long_term_improvements: longTermImprovements,
        compliance_notes: [
            'Ensure vulnerability remediation is documented for audit purposes',
            'Review data handling practices for GDPR compliance',
            'Consider SOC2 Type II certification for enterprise clients'
        ]
    };
}

// Generate a basic attack graph from endpoints when AI is unavailable
function generateBasicGraphFromEndpoints(endpoints: any[]): any {
    const nodes: any[] = [
        {
            id: "start",
            type: "start",
            label: "Internet",
            data: { description: "Public Internet - Entry Point", severity: "low" }
        }
    ];

    const edges: any[] = [];
    let nodeIndex = 0;
    let edgeIndex = 0;

    // Create API call nodes for each endpoint
    endpoints.forEach((endpoint, idx) => {
        const nodeId = `api-${idx}`;
        nodes.push({
            id: nodeId,
            type: "api_call",
            label: `${endpoint.method || 'GET'} ${endpoint.path || endpoint.endpoint || '/api'}`,
            data: {
                description: endpoint.description || `API Endpoint: ${endpoint.path || endpoint.endpoint}`,
                severity: "low",
                endpoint: endpoint.path || endpoint.endpoint,
                method: endpoint.method || 'GET'
            }
        });

        // Connect from start
        edges.push({
            id: `e-${edgeIndex++}`,
            source: "start",
            target: nodeId,
            label: "HTTP Request",
            type: "default"
        });

        // Analyze for potential vulnerabilities based on endpoint patterns
        const path = (endpoint.path || endpoint.endpoint || '').toLowerCase();
        const method = (endpoint.method || 'GET').toUpperCase();

        // Check for common vulnerability patterns
        if (path.includes('login') || path.includes('auth')) {
            const vulnId = `vuln-${nodeIndex++}`;
            nodes.push({
                id: vulnId,
                type: "vulnerability",
                label: "Potential Auth Bypass",
                data: {
                    description: "Authentication endpoint may be vulnerable to brute force or credential stuffing attacks",
                    severity: "high",
                    endpoint: path
                }
            });
            edges.push({
                id: `e-${edgeIndex++}`,
                source: nodeId,
                target: vulnId,
                label: "Auth Attack Vector",
                type: "vulnerable"
            });
        }

        if (path.includes('user') || path.includes('admin') || path.includes('profile')) {
            const vulnId = `vuln-${nodeIndex++}`;
            nodes.push({
                id: vulnId,
                type: "vulnerability",
                label: "Potential IDOR",
                data: {
                    description: "User-related endpoint may be vulnerable to Insecure Direct Object Reference",
                    severity: "high",
                    endpoint: path
                }
            });
            edges.push({
                id: `e-${edgeIndex++}`,
                source: nodeId,
                target: vulnId,
                label: "Access Control Issue",
                type: "vulnerable"
            });
        }

        if (method === 'POST' || method === 'PUT') {
            const vulnId = `vuln-${nodeIndex++}`;
            nodes.push({
                id: vulnId,
                type: "vulnerability",
                label: "Input Validation Required",
                data: {
                    description: "Data submission endpoint requires input validation review",
                    severity: "medium",
                    endpoint: path
                }
            });
            edges.push({
                id: `e-${edgeIndex++}`,
                source: nodeId,
                target: vulnId,
                label: "Unvalidated Input",
                type: "vulnerable"
            });
        }

        if (path.includes('search') || path.includes('query') || path.includes('filter')) {
            const vulnId = `vuln-${nodeIndex++}`;
            nodes.push({
                id: vulnId,
                type: "vulnerability",
                label: "Potential Injection",
                data: {
                    description: "Search/query endpoint may be vulnerable to SQL or NoSQL injection",
                    severity: "critical",
                    endpoint: path
                }
            });
            edges.push({
                id: `e-${edgeIndex++}`,
                source: nodeId,
                target: vulnId,
                label: "Injection Vector",
                type: "vulnerable"
            });
        }
    });

    // Add end node if vulnerabilities were found
    const vulnNodes = nodes.filter(n => n.type === 'vulnerability');
    if (vulnNodes.length > 0) {
        const endNode = {
            id: "end",
            type: "end",
            label: "Potential Data Breach",
            data: { description: "Exploitation of vulnerabilities could lead to data breach", severity: "critical" }
        };
        nodes.push(endNode);

        // Connect critical/high vulnerabilities to end
        vulnNodes
            .filter(v => v.data.severity === 'critical' || v.data.severity === 'high')
            .forEach(vuln => {
                edges.push({
                    id: `e-${edgeIndex++}`,
                    source: vuln.id,
                    target: "end",
                    label: "Exploitation",
                    type: "exploit"
                });
            });
    }

    // Generate positions
    const positionedNodes = generateNodePositions(nodes);

    return {
        nodes: positionedNodes,
        edges
    };
}
