import { useState, useEffect, useRef } from 'react'
import { useParams, useSearchParams, useNavigate } from 'react-router-dom'
import { projectService } from '@/services/projectService'
import { useScanStore } from '@/stores/scanStore'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Play, Pause, Square, Terminal, Loader2, AlertCircle } from 'lucide-react'

import { useToast } from '@/components/ui/use-toast'

export default function ScanControlPanel() {
  const { projectId } = useParams<{ projectId: string }>()
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scanId')
  const navigate = useNavigate()
  const toast = useToast()
  const {
    scanStatus,
    scanProgress,
    scanLogs,
    currentStep,
    error,
    updateScanStatus,
    addScanLog,
    setError,
    setActiveScan,
  } = useScanStore()
  const [loading, setLoading] = useState(true)
  const logsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scanId) {
      setActiveScan(scanId)
      loadScanStatus()
      const interval = setInterval(loadScanStatus, 2000)
      return () => clearInterval(interval)
    } else {
      setLoading(false)
    }
  }, [scanId])

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [scanLogs])

  const loadScanStatus = async () => {
    if (!scanId) return

    try {
      const status = await projectService.getScanStatus(scanId)
      updateScanStatus(status.status, status.progress, status.current_step || undefined)
      setError(status.error || null)

      if (status.status === 'completed') {
        toast({ title: 'Scan Complete', description: 'Security scan finished successfully' })
        setTimeout(() => {
          navigate(`/dashboard/attack-graph/${scanId}`)
        }, 2000)
      } else if (status.status === 'failed') {
        toast({ title: 'Scan Failed', description: status.error || 'Unknown error', variant: 'destructive' })
      }
    } catch (error: any) {
      setError(error.message || 'Failed to load scan status')
    } finally {
      setLoading(false)
    }
  }

  const loadLogs = async () => {
    if (!scanId) return

    try {
      const logs = await projectService.getScanLogs(scanId)
      logs.forEach((log) => addScanLog(log))
    } catch (error) {
      console.error('Failed to load logs:', error)
    }
  }

  useEffect(() => {
    if (scanId && scanStatus === 'running') {
      loadLogs()
      const interval = setInterval(loadLogs, 3000)
      return () => clearInterval(interval)
    }
  }, [scanId, scanStatus])

  const handleStartScan = async () => {
    if (!projectId) return

    try {
      const { scan_id } = await projectService.startScan(projectId)
      setActiveScan(scan_id)
      updateScanStatus('running', 0)
      navigate(`/dashboard/scan/${projectId}?scanId=${scan_id}`)
      toast({ title: 'Scan Started', description: 'Security scan has begun' })
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to start scan', variant: 'destructive' })
    }
  }

  const handlePauseScan = async () => {
    if (!scanId) return

    try {
      await projectService.pauseScan(scanId)
      updateScanStatus('paused', scanProgress)
      toast({ title: 'Scan Paused', description: 'Scan has been paused' })
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to pause scan', variant: 'destructive' })
    }
  }

  const handleStopScan = async () => {
    if (!scanId) return

    if (!confirm('Are you sure you want to stop the scan?')) return

    try {
      await projectService.stopScan(scanId)
      updateScanStatus('failed', scanProgress)
      toast({ title: 'Scan Stopped', description: 'Scan has been stopped' })
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to stop scan', variant: 'destructive' })
    }
  }

  if (loading && !scanStatus) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }

  const getStatusColor = (status: string | null) => {
    switch (status) {
      case 'running':
        return 'info'
      case 'completed':
        return 'info'
      case 'failed':
        return 'destructive'
      case 'paused':
        return 'medium'
      default:
        return 'secondary'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scan Control Panel</h1>
          <p className="text-muted-foreground">Monitor and control your security scan</p>
        </div>
        {!scanStatus && (
          <Button onClick={handleStartScan}>
            <Play className="mr-2 h-4 w-4" />
            Start Scan
          </Button>
        )}
      </div>

      {/* Status Card */}
      {scanStatus && (
        <Card className="bg-card border-yellow-green/30 shadow-lg shadow-yellow-green/20">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Scan Status</CardTitle>
                <CardDescription>Scan ID: {scanId}</CardDescription>
              </div>
              <Badge variant={getStatusColor(scanStatus) as any}>
                {scanStatus?.toUpperCase()}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Progress</span>
                <span className="text-sm text-muted-foreground">{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} />
            </div>

            {currentStep && (
              <div className="flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                <span className="text-sm text-muted-foreground">{currentStep}</span>
              </div>
            )}

            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/20">
                <AlertCircle className="h-4 w-4 text-destructive" />
                <span className="text-sm text-destructive">{error}</span>
              </div>
            )}

            <div className="flex items-center gap-2">
              {scanStatus === 'running' && (
                <>
                  <Button variant="outline" size="sm" onClick={handlePauseScan}>
                    <Pause className="mr-2 h-4 w-4" />
                    Pause
                  </Button>
                  <Button variant="destructive" size="sm" onClick={handleStopScan}>
                    <Square className="mr-2 h-4 w-4" />
                    Stop
                  </Button>
                </>
              )}
              {scanStatus === 'paused' && (
                <Button size="sm" onClick={handleStartScan}>
                  <Play className="mr-2 h-4 w-4" />
                  Resume
                </Button>
              )}
              {scanStatus === 'completed' && scanId && (
                <Button
                  size="sm"
                  onClick={() => navigate(`/dashboard/attack-graph/${scanId}`)}
                >
                  View Attack Graph
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Terminal Logs */}
      <Card className="bg-card border-yellow-green/30 shadow-lg shadow-yellow-green/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-lg bg-yellow-green flex items-center justify-center border-2 border-yellow-green shadow-lg shadow-yellow-green/50">
              <Terminal className="h-5 w-5 text-background" />
            </div>
            Scan Logs
          </CardTitle>
          <CardDescription>Real-time scan execution logs</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="bg-black rounded-xl p-4 font-mono text-sm h-96 overflow-y-auto border-2 border-yellow-green/30 shadow-inner">
            {scanLogs.length === 0 ? (
              <div className="text-muted-foreground">No logs available yet...</div>
            ) : (
              scanLogs.map((log, index) => (
                <div key={index} className="text-yellow-green mb-1 hover:text-yellow-green/80 transition-colors">
                  <span className="text-dim-grey-light">[{new Date().toLocaleTimeString()}]</span>{' '}
                  <span className="text-yellow-green">{log}</span>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
