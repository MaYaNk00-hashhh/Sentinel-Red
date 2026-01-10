import type { SecurityReport } from '@/types/report'
import apiClient from '@/lib/api'

// Timeout for report generation (15 seconds - allows for AI processing)
const REPORT_TIMEOUT = 15000

export const reportService = {
  async getReport(scanId: string): Promise<SecurityReport> {
    try {
      const { data } = await apiClient.get<SecurityReport>(`/reports/${scanId}`, {
        timeout: REPORT_TIMEOUT
      })
      return data
    } catch (e: any) {
      if (e.code === 'ECONNABORTED') {
        console.error("Report Generation Timeout - server took too long")
        throw new Error('Report generation timed out. Please try again.')
      }
      console.error("Report Generation Error:", e)
      throw e
    }
  },

  async exportReportPDF(scanId: string): Promise<Blob> {
    try {
      const response = await apiClient.get(`/reports/${scanId}/pdf`, {
        responseType: 'blob',
        timeout: REPORT_TIMEOUT
      })
      return new Blob([response.data], { type: 'application/pdf' })
    } catch (e: any) {
      if (e.code === 'ECONNABORTED') {
        console.error("PDF Export Timeout")
        throw new Error('PDF export timed out. Please try again.')
      }
      console.error("PDF Export Error:", e)
      throw e
    }
  },

  async exportReportJSON(scanId: string): Promise<object> {
    const report = await this.getReport(scanId)
    return report
  },
}
