import { useState, useEffect, useCallback, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  BackgroundVariant,
  MiniMap,
  useNodesState,
  useEdgesState,
  ConnectionMode,
  Panel,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { attackGraphService } from '@/services/attackGraphService'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, RotateCw, ExternalLink, AlertTriangle, Shield, Activity } from 'lucide-react'
import type { AttackGraph, AttackNode } from '@/types/attackGraph'
import { useToast } from '@/components/ui/use-toast'

// Custom node components with proper error handling
const nodeTypes = {
  start: ({ data }: { data: any }) => (
    <div className="px-4 py-2 rounded-lg bg-primary/20 border-2 border-primary text-primary font-semibold min-w-[120px] text-center">
      {data?.label || 'Start'}
    </div>
  ),
  api_call: ({ data }: { data: any }) => (
    <div className="px-4 py-2 rounded-lg bg-blue-500/20 border-2 border-blue-500 text-blue-400 min-w-[150px]">
      <div className="font-semibold">{data?.method || 'API'}</div>
      <div className="text-xs text-muted-foreground mt-1 truncate max-w-[200px]">
        {data?.endpoint || data?.label || 'Endpoint'}
      </div>
    </div>
  ),
  exploit: ({ data }: { data: any }) => (
    <div className="px-4 py-2 rounded-lg bg-orange-500/20 border-2 border-orange-500 text-orange-400 font-semibold min-w-[120px] text-center">
      ⚡ {data?.label || 'Exploit'}
    </div>
  ),
  vulnerability: ({ data }: { data: any }) => (
    <div className={`px-4 py-2 rounded-lg font-semibold min-w-[150px] text-center ${data?.severity === 'critical'
        ? 'bg-red-500/20 border-2 border-red-500 text-red-400'
        : data?.severity === 'high'
          ? 'bg-orange-500/20 border-2 border-orange-500 text-orange-400'
          : data?.severity === 'medium'
            ? 'bg-yellow-500/20 border-2 border-yellow-500 text-yellow-400'
            : 'bg-blue-500/20 border-2 border-blue-500 text-blue-400'
      }`}>
      ⚠️ {data?.label || 'Vulnerability'}
    </div>
  ),
  end: ({ data }: { data: any }) => (
    <div className="px-4 py-2 rounded-lg bg-muted border-2 border-muted-foreground text-muted-foreground font-semibold min-w-[120px] text-center">
      {data?.label || 'End'}
    </div>
  ),
}

// Validate node position
function isValidPosition(position: any): boolean {
  return (
    position &&
    typeof position === 'object' &&
    typeof position.x === 'number' &&
    typeof position.y === 'number' &&
    !isNaN(position.x) &&
    !isNaN(position.y) &&
    isFinite(position.x) &&
    isFinite(position.y)
  )
}

// Calculate fallback position based on index
function getFallbackPosition(index: number): { x: number; y: number } {
  const cols = 4
  const xSpacing = 250
  const ySpacing = 150
  return {
    x: 100 + (index % cols) * xSpacing,
    y: 100 + Math.floor(index / cols) * ySpacing
  }
}

export default function AttackGraphPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const toast = useToast()

  // State
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [graph, setGraph] = useState<AttackGraph | null>(null)
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null)
  const [nodeDetails, setNodeDetails] = useState<any>(null)
  const [nodeDetailsLoading, setNodeDetailsLoading] = useState(false)
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisResult, setAnalysisResult] = useState<any>(null)

  // Load attack graph on mount
  useEffect(() => {
    if (scanId) {
      loadAttackGraph()
    } else {
      setError('No scan ID provided')
      setLoading(false)
    }
  }, [scanId])

  // Transform graph data to ReactFlow format when graph changes
  useEffect(() => {
    if (!graph) {
      setNodes([])
      setEdges([])
      return
    }

    try {
      // Transform nodes with validation
      const flowNodes: Node[] = (graph.nodes || []).map((node, index) => {
        // Validate and fix position
        const position = isValidPosition(node.position)
          ? node.position
          : getFallbackPosition(index)

        // Ensure data object exists with required fields
        const nodeData = {
          label: node.label || node.id || `Node ${index}`,
          severity: node.data?.severity || 'medium',
          endpoint: node.data?.endpoint,
          method: node.data?.method,
          description: node.data?.description || '',
        }

        return {
          id: node.id || `node-${index}`,
          type: ['start', 'api_call', 'exploit', 'vulnerability', 'end'].includes(node.type)
            ? node.type
            : 'api_call',
          position,
          data: nodeData,
          style: {
            background: 'transparent',
            border: 'none',
          },
        }
      })

      // Create set of valid node IDs for edge validation
      const validNodeIds = new Set(flowNodes.map(n => n.id))

      // Transform edges with validation
      const flowEdges: Edge[] = (graph.edges || [])
        .filter(edge => {
          // Validate edge has required fields and references valid nodes
          if (!edge.source || !edge.target) return false
          if (!validNodeIds.has(edge.source) || !validNodeIds.has(edge.target)) return false
          if (edge.source === edge.target) return false // No self-loops
          return true
        })
        .map((edge, index) => ({
          id: edge.id || `edge-${index}`,
          source: edge.source,
          target: edge.target,
          label: edge.label || '',
          type: 'smoothstep',
          animated: edge.type === 'exploit' || edge.type === 'vulnerable',
          style: {
            stroke: edge.type === 'vulnerable'
              ? '#ef4444'
              : edge.type === 'exploit'
                ? '#f97316'
                : '#3b82f6',
            strokeWidth: 2,
          },
        }))

      setNodes(flowNodes)
      setEdges(flowEdges)
    } catch (err: any) {
      console.error('Error transforming graph data:', err)
      toast({
        title: 'Warning',
        description: 'Some graph elements could not be rendered properly',
        variant: 'destructive'
      })
    }
  }, [graph, setNodes, setEdges, toast])

  // Load attack graph from API
  const loadAttackGraph = async () => {
    if (!scanId) return

    try {
      setLoading(true)
      setError(null)

      const data = await attackGraphService.getAttackGraph(scanId)

      // Validate response
      if (!data) {
        throw new Error('No data received from server')
      }

      setGraph(data)

      // Show warning if graph is empty
      if (!data.nodes || data.nodes.length === 0) {
        toast({
          title: 'No Attack Graph Data',
          description: 'The scan has not generated an attack graph yet.',
        })
      }
    } catch (err: any) {
      console.error('Failed to load attack graph:', err)
      setError(err.message || 'Failed to load attack graph')
      toast({
        title: 'Error',
        description: err.message || 'Failed to load attack graph',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  // Handle node click
  const handleNodeClick = useCallback(async (_: React.MouseEvent, node: Node) => {
    const attackNode = graph?.nodes.find((n) => n.id === node.id)
    if (!attackNode) {
      console.warn('Node not found in graph:', node.id)
      return
    }

    setSelectedNode(attackNode)
    setNodeDetails(null)
    setNodeDetailsLoading(true)

    try {
      const details = await attackGraphService.getNodeDetails(node.id)
      setNodeDetails(details)
    } catch (err: any) {
      console.error('Failed to load node details:', err)
      setNodeDetails({
        node: attackNode,
        requests: [],
        analysis: attackNode.data?.description || 'No additional details available.'
      })
    } finally {
      setNodeDetailsLoading(false)
    }
  }, [graph])

  // Reset view
  const handleResetView = useCallback(() => {
    setNodes((nds) =>
      nds.map((node) => ({
        ...node,
        selected: false
      }))
    )
    setEdges((eds) =>
      eds.map((edge) => ({
        ...edge,
        selected: false
      }))
    )
  }, [setNodes, setEdges])

  // Analyze graph
  const handleAnalyzeGraph = useCallback(async () => {
    if (!graph || !graph.nodes || graph.nodes.length === 0) {
      toast({
        title: 'Cannot Analyze',
        description: 'No attack graph data available for analysis',
        variant: 'destructive'
      })
      return
    }

    setIsAnalyzing(true)
    setAnalysisResult(null)

    try {
      const vulnNodes = graph.nodes.filter(n => n.type === 'vulnerability')
      const exploitNodes = graph.nodes.filter(n => n.type === 'exploit')
      const criticalVulns = vulnNodes.filter(n => n.data?.severity === 'critical')
      const highVulns = vulnNodes.filter(n => n.data?.severity === 'high')

      const riskScore = Math.min(100,
        criticalVulns.length * 25 +
        highVulns.length * 15 +
        vulnNodes.filter(n => n.data?.severity === 'medium').length * 5 +
        exploitNodes.length * 10
      )

      const analysis = {
        summary: {
          totalNodes: graph.nodes.length,
          totalEdges: graph.edges.length,
          vulnerabilityCount: vulnNodes.length,
          exploitCount: exploitNodes.length,
          riskScore
        },
        severityCounts: {
          critical: criticalVulns.length,
          high: highVulns.length,
          medium: vulnNodes.filter(n => n.data?.severity === 'medium').length,
          low: vulnNodes.filter(n => n.data?.severity === 'low').length
        },
        vulnerabilities: vulnNodes.map(n => ({
          id: n.id,
          label: n.label,
          severity: n.data?.severity || 'medium',
          description: n.data?.description
        })),
        recommendations: [] as string[],
        riskLevel: riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low'
      }

      if (criticalVulns.length > 0) {
        analysis.recommendations.push(`URGENT: Address ${criticalVulns.length} critical vulnerabilities immediately`)
      }
      if (highVulns.length > 0) {
        analysis.recommendations.push(`HIGH PRIORITY: Fix ${highVulns.length} high-severity issues within 24-48 hours`)
      }
      if (exploitNodes.length > 0) {
        analysis.recommendations.push(`Review ${exploitNodes.length} potential exploit paths identified`)
      }
      if (analysis.recommendations.length === 0) {
        analysis.recommendations.push('No critical issues detected. Continue monitoring.')
      }

      await new Promise(resolve => setTimeout(resolve, 1000))
      setAnalysisResult(analysis)
    } catch (err: any) {
      console.error('Analysis failed:', err)
      toast({
        title: 'Analysis Failed',
        description: err.message || 'Failed to analyze attack graph',
        variant: 'destructive'
      })
    } finally {
      setIsAnalyzing(false)
    }
  }, [graph, toast])

  const handleCloseNodeDialog = useCallback(() => {
    setSelectedNode(null)
    setNodeDetails(null)
  }, [])

  const graphStats = useMemo(() => {
    if (!graph || !graph.nodes) return null

    const vulns = graph.nodes.filter(n => n.type === 'vulnerability')
    return {
      total: graph.nodes.length,
      vulnerabilities: vulns.length,
      critical: vulns.filter(v => v.data?.severity === 'critical').length,
      high: vulns.filter(v => v.data?.severity === 'high').length
    }
  }, [graph])

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10" />
          <div>
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-48 mt-2" />
          </div>
        </div>
        <Skeleton className="h-[600px] w-full" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12 space-y-4">
        <AlertTriangle className="h-16 w-16 text-destructive" />
        <h2 className="text-xl font-semibold">Failed to Load Attack Graph</h2>
        <p className="text-muted-foreground text-center max-w-md">{error}</p>
        <div className="flex gap-4">
          <Button variant="outline" onClick={() => navigate(-1)}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Go Back
          </Button>
          <Button onClick={loadAttackGraph}>
            <RotateCw className="mr-2 h-4 w-4" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 space-y-4">
        <Shield className="h-16 w-16 text-muted-foreground" />
        <h2 className="text-xl font-semibold">No Attack Graph Available</h2>
        <p className="text-muted-foreground text-center max-w-md">
          The scan has not generated an attack graph yet.
        </p>
        <div className="flex gap-4">
          <Button variant="outline" onClick={() => navigate(-1)}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Go Back
          </Button>
          <Button onClick={loadAttackGraph}>
            <RotateCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 h-[calc(100vh-12rem)]">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold">Attack Graph</h1>
            <p className="text-muted-foreground">
              Visualization of attack paths and vulnerabilities
              {graphStats && (
                <span className="ml-2">
                  • {graphStats.total} nodes • {graphStats.vulnerabilities} vulnerabilities
                  {graphStats.critical > 0 && (
                    <Badge variant="destructive" className="ml-2">{graphStats.critical} Critical</Badge>
                  )}
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="default"
            size="sm"
            onClick={handleAnalyzeGraph}
            disabled={isAnalyzing}
            className="bg-purple-600 hover:bg-purple-700"
          >
            {isAnalyzing ? (
              <>
                <RotateCw className="mr-2 h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Activity className="mr-2 h-4 w-4" />
                Analyze Graph
              </>
            )}
          </Button>
          <Button variant="outline" size="sm" onClick={handleResetView}>
            <RotateCw className="mr-2 h-4 w-4" />
            Reset View
          </Button>
          {scanId && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/dashboard/report/${scanId}`)}
            >
              <ExternalLink className="mr-2 h-4 w-4" />
              View Report
            </Button>
          )}
        </div>
      </div>

      <div className="grid lg:grid-cols-4 gap-6 h-full">
        <Card className={`bg-card border-yellow-green/30 shadow-lg shadow-yellow-green/20 h-full ${analysisResult ? 'lg:col-span-3' : 'lg:col-span-4'
          } transition-all duration-300`}>
          <CardContent className="p-0 h-full">
            <div style={{ width: '100%', height: '100%', minHeight: '500px' }}>
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={handleNodeClick}
                connectionMode={ConnectionMode.Loose}
                fitView
                fitViewOptions={{ padding: 0.2 }}
                nodeTypes={nodeTypes}
                minZoom={0.1}
                maxZoom={2}
              >
                <Controls />
                <MiniMap
                  nodeColor={(node) => {
                    switch (node.type) {
                      case 'vulnerability': return '#ef4444'
                      case 'exploit': return '#f97316'
                      case 'start': return '#22c55e'
                      case 'end': return '#6b7280'
                      default: return '#3b82f6'
                    }
                  }}
                />
                <Background variant={BackgroundVariant.Dots} gap={12} size={1} />
                <Panel position="top-left" className="bg-background/80 backdrop-blur p-2 rounded">
                  <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded bg-primary"></div>
                      <span>Start</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded bg-blue-500"></div>
                      <span>API Call</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded bg-orange-500"></div>
                      <span>Exploit</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded bg-red-500"></div>
                      <span>Vulnerability</span>
                    </div>
                  </div>
                </Panel>
              </ReactFlow>
            </div>
          </CardContent>
        </Card>

        {analysisResult && (
          <Card className="lg:col-span-1 h-full bg-card border-purple-500/30 shadow-lg shadow-purple-500/10 animate-in slide-in-from-right duration-500 overflow-auto">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-purple-400">
                <Activity className="h-5 w-5" />
                Security Analysis
              </CardTitle>
              <CardDescription>
                Risk Level: <Badge variant={
                  analysisResult.riskLevel === 'critical' ? 'destructive' :
                    analysisResult.riskLevel === 'high' ? 'destructive' :
                      analysisResult.riskLevel === 'medium' ? 'default' : 'secondary'
                }>{analysisResult.riskLevel.toUpperCase()}</Badge>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="bg-muted p-2 rounded">
                  <div className="text-muted-foreground">Risk Score</div>
                  <div className="text-xl font-bold">{analysisResult.summary.riskScore}/100</div>
                </div>
                <div className="bg-muted p-2 rounded">
                  <div className="text-muted-foreground">Vulnerabilities</div>
                  <div className="text-xl font-bold">{analysisResult.summary.vulnerabilityCount}</div>
                </div>
              </div>

              <div>
                <h4 className="font-semibold mb-2">Severity Breakdown</h4>
                <div className="space-y-1 text-sm">
                  {analysisResult.severityCounts.critical > 0 && (
                    <div className="flex justify-between">
                      <span className="text-red-400">Critical</span>
                      <span>{analysisResult.severityCounts.critical}</span>
                    </div>
                  )}
                  {analysisResult.severityCounts.high > 0 && (
                    <div className="flex justify-between">
                      <span className="text-orange-400">High</span>
                      <span>{analysisResult.severityCounts.high}</span>
                    </div>
                  )}
                  {analysisResult.severityCounts.medium > 0 && (
                    <div className="flex justify-between">
                      <span className="text-yellow-400">Medium</span>
                      <span>{analysisResult.severityCounts.medium}</span>
                    </div>
                  )}
                  {analysisResult.severityCounts.low > 0 && (
                    <div className="flex justify-between">
                      <span className="text-blue-400">Low</span>
                      <span>{analysisResult.severityCounts.low}</span>
                    </div>
                  )}
                </div>
              </div>

              <div>
                <h4 className="font-semibold mb-2">Recommendations</h4>
                <ul className="space-y-2 text-sm">
                  {analysisResult.recommendations.map((rec: string, idx: number) => (
                    <li key={idx} className="flex gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-500 flex-shrink-0 mt-0.5" />
                      <span className="text-muted-foreground">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <Button
                className="w-full"
                variant="outline"
                onClick={() => setAnalysisResult(null)}
              >
                Close Analysis
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      <Dialog open={!!selectedNode} onOpenChange={handleCloseNodeDialog}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedNode?.type === 'vulnerability' && <AlertTriangle className="h-5 w-5 text-red-500" />}
              {selectedNode?.label || selectedNode?.id}
            </DialogTitle>
            <DialogDescription>
              {selectedNode?.data?.description || 'No description available'}
            </DialogDescription>
          </DialogHeader>

          {nodeDetailsLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-40 w-full" />
            </div>
          ) : nodeDetails ? (
            <Tabs defaultValue="details">
              <TabsList>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="evidence">Evidence</TabsTrigger>
              </TabsList>

              <TabsContent value="details" className="space-y-4">
                <div className="flex gap-2">
                  <Badge variant="outline">{selectedNode?.type}</Badge>
                  {selectedNode?.data?.severity && (
                    <Badge variant={
                      selectedNode.data.severity === 'critical' ? 'destructive' :
                        selectedNode.data.severity === 'high' ? 'destructive' : 'default'
                    }>
                      {selectedNode.data.severity}
                    </Badge>
                  )}
                </div>

                {selectedNode?.data?.endpoint && (
                  <div>
                    <h4 className="font-semibold mb-2">Endpoint</h4>
                    <code className="text-sm bg-muted p-2 rounded block">
                      {selectedNode.data.method || 'GET'} {selectedNode.data.endpoint}
                    </code>
                  </div>
                )}

                {nodeDetails.analysis && (
                  <div>
                    <h4 className="font-semibold mb-2">Analysis</h4>
                    <div className="text-sm text-muted-foreground whitespace-pre-wrap bg-muted p-3 rounded">
                      {nodeDetails.analysis}
                    </div>
                  </div>
                )}

                {nodeDetails.relatedNodes?.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Related Nodes</h4>
                    <div className="flex flex-wrap gap-2">
                      {nodeDetails.relatedNodes.map((n: any) => (
                        <Badge key={n.id} variant="outline">{n.label}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selectedNode?.data?.vulnerability_id && (
                  <Button
                    variant="outline"
                    onClick={() => navigate(`/dashboard/vulnerabilities/${selectedNode.data.vulnerability_id}`)}
                  >
                    View Vulnerability Details
                  </Button>
                )}
              </TabsContent>

              <TabsContent value="evidence" className="space-y-4">
                {nodeDetails.requests && nodeDetails.requests.length > 0 ? (
                  nodeDetails.requests.map((req: any, idx: number) => (
                    <Card key={idx}>
                      <CardHeader>
                        <CardTitle className="text-sm">
                          {req.method} {req.url}
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div>
                          <h4 className="font-semibold mb-2">Request</h4>
                          <pre className="text-xs bg-muted p-3 rounded overflow-x-auto">
                            {req.body ? JSON.stringify(req.body, null, 2) : 'No body'}
                          </pre>
                        </div>
                        <div>
                          <h4 className="font-semibold mb-2">Response</h4>
                          <pre className="text-xs bg-muted p-3 rounded overflow-x-auto">
                            Status: {req.response?.status || 'N/A'}
                            {'\n'}
                            {req.response?.body ? JSON.stringify(req.response.body, null, 2) : 'No body'}
                          </pre>
                        </div>
                      </CardContent>
                    </Card>
                  ))
                ) : (
                  <div className="text-center py-6 text-muted-foreground">
                    No request/response evidence captured for this node.
                  </div>
                )}
              </TabsContent>
            </Tabs>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  )
}
