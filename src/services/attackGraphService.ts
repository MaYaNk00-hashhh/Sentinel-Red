import apiClient from '@/lib/api'
import { AttackGraph, AttackNode } from '@/types/attackGraph'

// Types for API responses
export interface NodeDetails {
  node: AttackNode
  scan_id: string | null
  requests: RequestEvidence[]
  analysis: string
  relatedNodes: AttackNode[]
  attackPaths: AttackPath[]
}

export interface RequestEvidence {
  method: string
  url: string
  headers: Record<string, string>
  body: any
  response: {
    status: number
    headers: Record<string, string>
    body: any
  }
}

export interface AttackPath {
  id: string
  name: string
  nodes: string[]
  severity: string
  description: string
}

export interface GraphAnalysis {
  summary: {
    totalNodes: number
    totalEdges: number
    vulnerabilityCount: number
    exploitCount: number
    apiCallCount: number
    riskScore: number
  }
  severityCounts: {
    critical: number
    high: number
    medium: number
    low: number
  }
  vulnerabilities: Array<{
    id: string
    label: string
    severity: string
    description: string
    recommendation?: string
  }>
  attackPaths: Array<{
    id: string
    name: string
    nodeCount: number
    vulnerabilityCount: number
    severity: string
    nodes: string[]
  }>
  recommendations: string[]
  riskLevel: string
}

export const attackGraphService = {
  /**
   * Fetches the attack graph for a specific scan
   */
  async getAttackGraph(scanId: string): Promise<AttackGraph> {
    try {
      const { data } = await apiClient.get<AttackGraph>(`/attack-graph/${scanId}`)

      // Validate response structure
      if (!data) {
        throw new Error('No data received from server')
      }

      // Ensure nodes and edges arrays exist
      return {
        nodes: Array.isArray(data.nodes) ? data.nodes : [],
        edges: Array.isArray(data.edges) ? data.edges : [],
        scan_id: data.scan_id || scanId
      }
    } catch (error: any) {
      console.error('AttackGraphService.getAttackGraph Error:', error)

      // Re-throw with more context
      if (error.response?.status === 404) {
        throw new Error('Scan not found')
      }
      if (error.response?.status === 400) {
        throw new Error('Invalid scan ID')
      }

      throw new Error(error.response?.data?.message || error.message || 'Failed to fetch attack graph')
    }
  },

  /**
   * Fetches detailed information about a specific node
   */
  async getNodeDetails(nodeId: string, scanId?: string): Promise<NodeDetails> {
    try {
      const params = scanId ? { scanId } : {}
      const { data } = await apiClient.get<NodeDetails>(`/attack-graph/node/${nodeId}`, { params })

      // Validate response
      if (!data) {
        throw new Error('No data received from server')
      }

      // Ensure required fields exist
      return {
        node: data.node || {} as AttackNode,
        scan_id: data.scan_id || null,
        requests: Array.isArray(data.requests) ? data.requests : [],
        analysis: data.analysis || 'No analysis available',
        relatedNodes: Array.isArray(data.relatedNodes) ? data.relatedNodes : [],
        attackPaths: Array.isArray(data.attackPaths) ? data.attackPaths : []
      }
    } catch (error: any) {
      console.error('AttackGraphService.getNodeDetails Error:', error)

      if (error.response?.status === 404) {
        throw new Error('Node not found')
      }

      throw new Error(error.response?.data?.message || error.message || 'Failed to fetch node details')
    }
  },

  /**
   * Updates the attack graph for a specific scan
   */
  async updateAttackGraph(scanId: string, graph: AttackGraph): Promise<AttackGraph> {
    try {
      const { data } = await apiClient.put<AttackGraph>(`/attack-graph/${scanId}`, graph)

      if (!data) {
        throw new Error('No data received from server')
      }

      return {
        nodes: Array.isArray(data.nodes) ? data.nodes : [],
        edges: Array.isArray(data.edges) ? data.edges : [],
        scan_id: data.scan_id || scanId
      }
    } catch (error: any) {
      console.error('AttackGraphService.updateAttackGraph Error:', error)

      if (error.response?.status === 404) {
        throw new Error('Scan not found')
      }

      throw new Error(error.response?.data?.message || error.message || 'Failed to update attack graph')
    }
  },

  /**
   * Triggers AI analysis of the attack graph
   */
  async analyzeAttackGraph(scanId: string): Promise<GraphAnalysis> {
    try {
      const { data } = await apiClient.post<GraphAnalysis>(`/attack-graph/${scanId}/analyze`)

      if (!data) {
        throw new Error('No data received from server')
      }

      return data
    } catch (error: any) {
      console.error('AttackGraphService.analyzeAttackGraph Error:', error)

      if (error.response?.status === 404) {
        throw new Error('Scan not found')
      }
      if (error.response?.status === 400) {
        throw new Error('No attack graph data available for analysis')
      }

      throw new Error(error.response?.data?.message || error.message || 'Failed to analyze attack graph')
    }
  }
}

export default attackGraphService
