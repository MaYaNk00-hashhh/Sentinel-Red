import type { SecurityReport } from '@/types/report'
import apiClient from '@/lib/api'

export const reportService = {
  async getReport(scanId: string): Promise<SecurityReport> {
    try {
      const { data } = await apiClient.get<SecurityReport>(`/reports/${scanId}`)
      return data
    } catch (e) {
      console.error("Report Generation Error:", e)
      throw e
    }
  },

  async exportReportPDF(scanId: string): Promise<Blob> {
    try {
      const response = await apiClient.get(`/reports/${scanId}/pdf`, {
        responseType: 'blob'
      })
      return new Blob([response.data], { type: 'application/pdf' })
    } catch (e) {
      console.error("PDF Export Error:", e)
      throw e
    }
  },

  async exportReportJSON(scanId: string): Promise<object> {
    const report = await this.getReport(scanId)
    return report
  },
}
