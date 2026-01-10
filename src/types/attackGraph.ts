export type NodeType = 'start' | 'api_call' | 'exploit' | 'vulnerability' | 'end'

export interface AttackNode {
  id: string
  type: NodeType
  label: string
  data: {
    endpoint?: string
    method?: string
    vulnerability_id?: string
    description: string
    request?: {
      method: string
      url: string
      headers: Record<string, string>
      body: unknown
    }
    response?: {
      status: number
      headers: Record<string, string>
      body: unknown
    }
    severity?: 'critical' | 'high' | 'medium' | 'low'
  }
  position: {
    x: number
    y: number
  }
}

export interface AttackEdge {
  id: string
  source: string
  target: string
  label?: string
  type?: 'default' | 'exploit' | 'vulnerable'
}

export interface AttackGraph {
  nodes: AttackNode[]
  edges: AttackEdge[]
  scan_id: string
  project_id?: string
  project_name?: string
  created_at?: string
  metadata?: {
    scanDate?: string
    scanDuration?: number
    scannedFiles?: number
    scanPath?: string
  }
}
