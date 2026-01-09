import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { reportService } from '@/services/reportService'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, Download, FileText, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { formatDate, downloadJSON } from '@/lib/utils'
import type { SecurityReport } from '@/types/report'
import { useToast } from '@/components/ui/use-toast'
import { generatePDF } from '@/lib/pdfGenerator'

export default function ReportViewerPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const toast = useToast()
  const [loading, setLoading] = useState(true)
  const [report, setReport] = useState<SecurityReport | null>(null)

  useEffect(() => {
    if (scanId) {
      loadReport()
    }
  }, [scanId])

  const loadReport = async () => {
    if (!scanId) return

    try {
      setLoading(true)
      const data = await reportService.getReport(scanId)
      setReport(data)
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to load report', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
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
                  .map((finding) => (
                    <Card key={finding.id} className="hover:border-yellow-green/50 transition-all bg-card border-dim-grey/30 hover:shadow-lg hover:shadow-yellow-green/20">
                      <CardHeader>
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <CardTitle className="text-lg mb-2 flex items-center gap-2">
                              {finding.title}
                              <Badge variant={finding.severity as any}>{finding.severity}</Badge>
                              <Badge variant="outline">{finding.type}</Badge>
                            </CardTitle>
                            <CardDescription>{finding.description}</CardDescription>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => navigate(`/dashboard/vulnerabilities/${finding.id}`)}
                          >
                            View Details
                          </Button>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>Impact: {finding.impact}</span>
                          <span>•</span>
                          <span>Complexity: {finding.exploit_complexity}</span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
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

          {/* Fallback for legacy flat array if needed, or compliance notes */}
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
              <p className="text-sm mt-1">{Math.round(report.metadata.scan_duration / 60)} minutes</p>
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
