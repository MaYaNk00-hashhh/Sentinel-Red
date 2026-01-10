import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { reportService } from '@/services/reportService'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, Download, FileText, ShieldAlert, AlertTriangle, CheckCircle2, Shield, RefreshCw, Clock, ChevronDown, ChevronUp, Code, Target, Lightbulb } from 'lucide-react'
import { formatDate, downloadJSON } from '@/lib/utils'
import type { SecurityReport } from '@/types/report'
import { useToast } from '@/components/ui/use-toast'
import { generatePDF } from '@/lib/pdfGenerator'

export default function ReportViewerPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const toast = useToast()
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [report, setReport] = useState<SecurityReport | null>(null)
  const [loadTime, setLoadTime] = useState<number | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())

  const toggleFinding = (findingId: string) => {
    setExpandedFindings(prev => {
      const newSet = new Set(prev)
      if (newSet.has(findingId)) {
        newSet.delete(findingId)
      } else {
        newSet.add(findingId)
      }
      return newSet
    })
  }

  const loadReport = useCallback(async (isRefresh = false) => {
    if (!scanId) return

    try {
      if (isRefresh) {
        setRefreshing(true)
      } else {
        setLoading(true)
      }
      const startTime = Date.now()
      const data = await reportService.getReport(scanId)
      setLoadTime(Date.now() - startTime)
      setReport(data)
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to load report', variant: 'destructive' })
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [scanId, toast])

  useEffect(() => {
    if (scanId) {
      loadReport()
    }
  }, [scanId, loadReport])

  const handleRefresh = () => {
    loadReport(true)
  }



  const handleExportPDF = () => {
    if (!report) return

    try {
      generatePDF(report)
      toast({ title: 'Success', description: 'PDF exported successfully' })
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to export PDF', variant: 'destructive' })
    }
  }

  const handleExportJSON = async () => {
    if (!scanId) return

    try {
      const data = await reportService.exportReportJSON(scanId)
      downloadJSON(data, `security-report-${scanId}.json`)
      toast({ title: 'Success', description: 'JSON exported successfully' })
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to export JSON', variant: 'destructive' })
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }

  if (!report) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground">Report not found</p>
      </div>
    )
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical':
        return 'critical'
      case 'high':
        return 'high'
      case 'medium':
        return 'medium'
      case 'low':
        return 'low'
      default:
        return 'info'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold">Security Report</h1>
            <p className="text-muted-foreground">{report.project_name}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {loadTime && (
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Clock className="h-3 w-3" />
              Loaded in {loadTime}ms
            </span>
          )}
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="outline" onClick={handleExportPDF}>
            <Download className="mr-2 h-4 w-4" />
            Export PDF
          </Button>
          <Button variant="outline" onClick={handleExportJSON}>
            <Download className="mr-2 h-4 w-4" />
            Export JSON
          </Button>
        </div>
      </div>

      {/* Executive Summary */}
      <Card className="bg-card border-yellow-green/30 shadow-lg shadow-yellow-green/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <div className="h-10 w-10 rounded-xl bg-yellow-green flex items-center justify-center border-2 border-yellow-green shadow-lg shadow-yellow-green/50">
              <FileText className="h-6 w-6 text-background" />
            </div>
            Executive Summary
          </CardTitle>
          <CardDescription>Generated: {formatDate(report.generated_at)}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid md:grid-cols-5 gap-4">
            <Card className="text-center p-6 border-dim-grey/30 bg-card">
              <div className="text-4xl font-black text-white">{report.executive_summary.total_vulnerabilities}</div>
              <div className="text-sm font-semibold text-dim-grey-light mt-2">Total Issues</div>
            </Card>
            <Card className="text-center p-6 border-critical/40 bg-card shadow-lg shadow-critical/20">
              <div className="text-4xl font-black text-critical">{report.executive_summary.critical_count}</div>
              <div className="text-sm font-semibold text-critical mt-2">Critical</div>
            </Card>
            <Card className="text-center p-6 border-high/40 bg-card shadow-lg shadow-high/20">
              <div className="text-4xl font-black text-high">{report.executive_summary.high_count}</div>
              <div className="text-sm font-semibold text-high mt-2">High</div>
            </Card>
            <Card className="text-center p-6 border-yellow-green/40 bg-card shadow-lg shadow-yellow-green/20">
              <div className="text-4xl font-black text-yellow-green">{report.executive_summary.medium_count}</div>
              <div className="text-sm font-semibold text-yellow-green mt-2">Medium</div>
            </Card>
            <Card className="text-center p-6 border-low/40 bg-card shadow-lg shadow-low/20">
              <div className="text-4xl font-black text-low">{report.executive_summary.low_count}</div>
              <div className="text-sm font-semibold text-low mt-2">Low</div>
            </Card>
          </div>
          <div className="flex items-center gap-2 pt-4 border-t">
            <span className="font-semibold">Overall Risk:</span>
            <Badge variant={getRiskColor(report.executive_summary.overall_risk) as any}>
              {report.executive_summary.overall_risk.toUpperCase()}
            </Badge>
          </div>
          <p className="text-muted-foreground whitespace-pre-wrap">{report.executive_summary.summary}</p>
        </CardContent>
      </Card>

      {/* Findings */}
      <Card className="bg-card border-dim-grey/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <div className="h-10 w-10 rounded-xl bg-yellow-green flex items-center justify-center border-2 border-yellow-green shadow-lg shadow-yellow-green/50">
              <ShieldAlert className="h-6 w-6 text-background" />
            </div>
            Findings
          </CardTitle>
          <CardDescription>{report.findings.length} vulnerabilities discovered</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="all">
            <TabsList>
              <TabsTrigger value="all">All ({report.findings.length})</TabsTrigger>
              <TabsTrigger value="critical">
                Critical ({report.executive_summary.critical_count})
              </TabsTrigger>
              <TabsTrigger value="high">High ({report.executive_summary.high_count})</TabsTrigger>
              <TabsTrigger value="medium">
                Medium ({report.executive_summary.medium_count})
              </TabsTrigger>
              <TabsTrigger value="low">Low ({report.executive_summary.low_count})</TabsTrigger>
            </TabsList>
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((severity) => (
              <TabsContent key={severity} value={severity} className="space-y-4 mt-4">
                {report.findings
                  .filter((v) => severity === 'all' || v.severity === severity)
                  .map((finding) => {
                    const isExpanded = expandedFindings.has(finding.id)
                    return (
                      <Card
                        key={finding.id}
                        className={`transition-all bg-card border-dim-grey/30 cursor-pointer ${isExpanded ? 'border-yellow-green/50 shadow-lg shadow-yellow-green/20' : 'hover:border-yellow-green/30 hover:shadow-md hover:shadow-yellow-green/10'}`}
                        onClick={() => toggleFinding(finding.id)}
                      >
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <CardTitle className="text-lg mb-2 flex items-center gap-2 flex-wrap">
                                {finding.title}
                                <Badge variant={finding.severity as any}>{finding.severity}</Badge>
                                <Badge variant="outline">{finding.type}</Badge>
                              </CardTitle>
                              <CardDescription>{finding.description}</CardDescription>
                            </div>
                            <div className="flex items-center gap-2 ml-4">
                              {isExpanded ? (
                                <ChevronUp className="h-5 w-5 text-yellow-green" />
                              ) : (
                                <ChevronDown className="h-5 w-5 text-muted-foreground" />
                              )}
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="pt-0">
                          <div className="flex items-center gap-4 text-sm text-muted-foreground">
                            <span>Impact: {finding.impact}</span>
                            <span>•</span>
                            <span>Complexity: {finding.exploit_complexity}</span>
                          </div>

                          {/* Expanded Details */}
                          {isExpanded && (
                            <div className="mt-6 space-y-6 border-t border-dim-grey/30 pt-6" onClick={(e) => e.stopPropagation()}>
                              {/* Affected Endpoints */}
                              {finding.affected_endpoints && finding.affected_endpoints.length > 0 && (
                                <div className="space-y-2">
                                  <h4 className="font-semibold text-sm flex items-center gap-2 text-yellow-green">
                                    <Target className="h-4 w-4" />
                                    Affected Endpoints
                                  </h4>
                                  <ul className="text-sm text-muted-foreground bg-background/50 p-3 rounded-lg border border-dim-grey/20 space-y-1">
                                    {finding.affected_endpoints.map((endpoint, idx) => (
                                      <li key={idx} className="font-mono text-xs">{endpoint}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}

                              {/* Evidence / Proof of Concept */}
                              {finding.evidence && (
                                <div className="space-y-2">
                                  <h4 className="font-semibold text-sm flex items-center gap-2 text-yellow-green">
                                    <Code className="h-4 w-4" />
                                    Evidence / Proof of Concept
                                  </h4>
                                  <div className="bg-background/80 p-4 rounded-lg border border-dim-grey/20 space-y-4">
                                    <div>
                                      <span className="text-xs font-semibold text-yellow-green">Request:</span>
                                      <pre className="text-xs text-muted-foreground mt-1 overflow-x-auto whitespace-pre-wrap font-mono">
                                        {finding.evidence.request.method} {finding.evidence.request.url}
                                        {'\n'}Headers: {JSON.stringify(finding.evidence.request.headers, null, 2)}
                                        {finding.evidence.request.body ? `\nBody: ${JSON.stringify(finding.evidence.request.body, null, 2)}` : ''}
                                      </pre>
                                    </div>
                                    <div>
                                      <span className="text-xs font-semibold text-yellow-green">Response:</span>
                                      <pre className="text-xs text-muted-foreground mt-1 overflow-x-auto whitespace-pre-wrap font-mono">
                                        Status: {finding.evidence.response.status}
                                        {'\n'}Headers: {JSON.stringify(finding.evidence.response.headers, null, 2)}
                                        {finding.evidence.response.body ? `\nBody: ${JSON.stringify(finding.evidence.response.body, null, 2)}` : ''}
                                      </pre>
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* Recommended Fixes */}
                              {finding.recommended_fixes && finding.recommended_fixes.length > 0 && (
                                <div className="space-y-2">
                                  <h4 className="font-semibold text-sm flex items-center gap-2 text-yellow-green">
                                    <Lightbulb className="h-4 w-4" />
                                    Recommended Fixes
                                  </h4>
                                  <ul className="text-sm text-muted-foreground bg-background/50 p-3 rounded-lg border border-dim-grey/20 space-y-2">
                                    {finding.recommended_fixes.map((fix, idx) => (
                                      <li key={idx} className="flex items-start gap-2">
                                        <CheckCircle2 className="h-4 w-4 text-yellow-green mt-0.5 flex-shrink-0" />
                                        <span>{fix}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}

                              {/* Attack Chain */}
                              {finding.attack_chain && finding.attack_chain.length > 0 && (
                                <div className="space-y-2">
                                  <h4 className="font-semibold text-sm flex items-center gap-2 text-yellow-green">
                                    <ShieldAlert className="h-4 w-4" />
                                    Attack Chain
                                  </h4>
                                  <div className="space-y-3">
                                    {finding.attack_chain.map((step, idx) => (
                                      <div key={idx} className="bg-background/50 p-3 rounded-lg border border-dim-grey/20">
                                        <div className="flex items-center gap-2 mb-2">
                                          <span className="bg-yellow-green text-background text-xs font-bold px-2 py-1 rounded">
                                            Step {step.step}
                                          </span>
                                          <span className="text-sm font-medium">{step.action}</span>
                                        </div>
                                        <p className="text-sm text-muted-foreground mb-2">{step.description}</p>
                                        {step.endpoint && (
                                          <p className="text-xs font-mono text-muted-foreground">Endpoint: {step.endpoint}</p>
                                        )}
                                        <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
                                          <div>
                                            <span className="text-yellow-green">Expected:</span>
                                            <p className="text-muted-foreground">{step.expected_outcome}</p>
                                          </div>
                                          <div>
                                            <span className="text-yellow-green">Actual:</span>
                                            <p className="text-muted-foreground">{step.actual_outcome}</p>
                                          </div>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Additional Details Grid */}
                              <div className="grid grid-cols-2 md:grid-cols-3 gap-4 pt-4 border-t border-dim-grey/20">
                                {finding.cvss_score !== undefined && (
                                  <div className="text-center p-3 bg-background/50 rounded-lg border border-dim-grey/20">
                                    <div className="text-lg font-bold text-yellow-green">{finding.cvss_score}</div>
                                    <div className="text-xs text-muted-foreground">CVSS Score</div>
                                  </div>
                                )}
                                <div className="text-center p-3 bg-background/50 rounded-lg border border-dim-grey/20">
                                  <div className="text-sm font-bold text-yellow-green capitalize">{finding.exploit_complexity}</div>
                                  <div className="text-xs text-muted-foreground">Exploit Complexity</div>
                                </div>
                                <div className="text-center p-3 bg-background/50 rounded-lg border border-dim-grey/20">
                                  <div className="text-sm font-bold text-yellow-green">{formatDate(finding.discovered_at)}</div>
                                  <div className="text-xs text-muted-foreground">Discovered</div>
                                </div>
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    )
                  })}
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>

      {/* Recommendations */}
      {/* Recommendations */}
      <Card className="bg-card border-yellow-green/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <div className="h-10 w-10 rounded-xl bg-yellow-green flex items-center justify-center border-2 border-yellow-green shadow-lg shadow-yellow-green/50">
              <CheckCircle2 className="h-6 w-6 text-background" />
            </div>
            Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {!Array.isArray(report.recommendations) && report.recommendations.immediate_actions && report.recommendations.immediate_actions.length > 0 && (
            <div>
              <h3 className="font-semibold text-critical mb-3">Immediate Actions</h3>
              <ul className="space-y-2">
                {report.recommendations.immediate_actions.map((rec: string, index: number) => (
                  <li key={index} className="flex gap-3">
                    <AlertTriangle className="h-4 w-4 text-critical mt-0.5 flex-shrink-0" />
                    <span className="text-muted-foreground">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!Array.isArray(report.recommendations) && report.recommendations.short_term_fixes && report.recommendations.short_term_fixes.length > 0 && (
            <div>
              <h3 className="font-semibold text-high mb-3">Short-term Fixes</h3>
              <ul className="space-y-2">
                {report.recommendations.short_term_fixes.map((rec: string, index: number) => (
                  <li key={index} className="flex gap-3">
                    <CheckCircle2 className="h-4 w-4 text-high mt-0.5 flex-shrink-0" />
                    <span className="text-muted-foreground">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!Array.isArray(report.recommendations) && report.recommendations.long_term_improvements && report.recommendations.long_term_improvements.length > 0 && (
            <div>
              <h3 className="font-semibold text-yellow-green mb-3">Long-term Improvements</h3>
              <ul className="space-y-2">
                {report.recommendations.long_term_improvements.map((rec: string, index: number) => (
                  <li key={index} className="flex gap-3">
                    <CheckCircle2 className="h-4 w-4 text-yellow-green mt-0.5 flex-shrink-0" />
                    <span className="text-muted-foreground">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Compliance Notes */}
          {!Array.isArray(report.recommendations) && report.recommendations.compliance_notes && report.recommendations.compliance_notes.length > 0 && (
            <div>
              <h3 className="font-semibold text-blue-400 mb-3 flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Compliance Notes
              </h3>
              <ul className="space-y-2">
                {report.recommendations.compliance_notes.map((note: string, index: number) => (
                  <li key={index} className="flex gap-3">
                    <Shield className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                    <span className="text-muted-foreground">{note}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Fallback for legacy flat array if needed */}
          {Array.isArray(report.recommendations) && (
            <ul className="space-y-3">
              {report.recommendations.map((rec: string, index: number) => (
                <li key={index} className="flex gap-3">
                  <CheckCircle2 className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                  <span className="text-muted-foreground">{rec}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Metadata */}
      <Card className="bg-card border-dim-grey/30">
        <CardHeader>
          <CardTitle>Scan Metadata</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-3 gap-4">
            <div>
              <span className="text-sm font-medium text-muted-foreground">Scan Duration</span>
              <p className="text-sm mt-1">
                {report.metadata.scan_duration >= 60
                  ? `${Math.round(report.metadata.scan_duration / 60)} minutes`
                  : `${report.metadata.scan_duration} seconds`}
              </p>
            </div>
            <div>
              <span className="text-sm font-medium text-muted-foreground">Endpoints Tested</span>
              <p className="text-sm mt-1">{report.metadata.endpoints_tested}</p>
            </div>
            <div>
              <span className="text-sm font-medium text-muted-foreground">Test Cases Executed</span>
              <p className="text-sm mt-1">{report.metadata.test_cases_executed}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
