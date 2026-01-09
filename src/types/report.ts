import type { Vulnerability } from './vulnerability'

export interface SecurityReport {
  scan_id: string
  project_name: string
  generated_at: string
  executive_summary: {
    total_vulnerabilities: number
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
    overall_risk: 'critical' | 'high' | 'medium' | 'low'
    summary: string
  }
  findings: Vulnerability[]
  recommendations: {
    immediate_actions: string[]
    short_term_fixes: string[]
    long_term_improvements: string[]
    compliance_notes: string[]
  } | string[]
  metadata: {
    scan_duration: number
    endpoints_tested: number
    test_cases_executed: number
  }
}
