import jsPDF from 'jspdf'
import type { SecurityReport } from '@/types/report'
import { formatDate } from '@/lib/utils'

export const generatePDF = (report: SecurityReport) => {
    const doc = new jsPDF()
    const pageWidth = doc.internal.pageSize.width
    const margin = 20
    let y = 20

    // Helper for text formatting
    const addTitle = (text: string) => {
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(20)
        doc.setTextColor(220, 38, 38) // Red color for title
        doc.text(text, pageWidth / 2, y, { align: 'center' })
        y += 15
        doc.setTextColor(0, 0, 0) // Reset color
    }

    const addSectionTitle = (text: string) => {
        if (y > 270) {
            doc.addPage()
            y = 20
        }
        y += 10
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(16)
        doc.setFillColor(240, 240, 240)
        doc.rect(margin, y - 6, pageWidth - (margin * 2), 8, 'F')
        doc.text(text, margin + 2, y)
        y += 15
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(12)
    }

    const addText = (text: string, indent = 0) => {
        if (y > 280) {
            doc.addPage()
            y = 20
        }
        const safeText = text || ''
        const splitText = doc.splitTextToSize(safeText, pageWidth - (margin * 2) - indent)
        doc.text(splitText, margin + indent, y)
        y += (splitText.length * 6) + 2
    }

    const addKeyValue = (key: string, value: string | number) => {
        if (y > 280) {
            doc.addPage()
            y = 20
        }
        doc.setFont('helvetica', 'bold')
        doc.text(`${key}:`, margin, y)
        doc.setFont('helvetica', 'normal')
        doc.text(`${value}`, margin + 40, y)
        y += 7
    }

    // --- CONTENT GENERATION ---

    // Header
    addTitle('SENTINEL RED SECURITY REPORT')

    doc.setFontSize(10)
    doc.setTextColor(100, 100, 100)
    doc.text(`Generated on: ${formatDate(report.generated_at)}`, pageWidth / 2, y, { align: 'center' })
    doc.text(`Project: ${report.project_name}`, pageWidth / 2, y + 5, { align: 'center' })
    y += 15

    // Executive Summary
    addSectionTitle('EXECUTIVE SUMMARY')
    doc.setFontSize(12)

    // Stats Grid
    doc.setFont('helvetica', 'bold')

    doc.setTextColor(0, 0, 0)
    doc.text('Total Issues', margin, y)
    doc.text(`${report.executive_summary.total_vulnerabilities}`, margin, y + 7)

    doc.setTextColor(220, 38, 38)
    doc.text('Critical', margin + 40, y)
    doc.text(`${report.executive_summary.critical_count}`, margin + 40, y + 7)

    doc.setTextColor(234, 88, 12)
    doc.text('High', margin + 70, y)
    doc.text(`${report.executive_summary.high_count}`, margin + 70, y + 7)

    doc.setTextColor(202, 138, 4)
    doc.text('Medium', margin + 100, y)
    doc.text(`${report.executive_summary.medium_count}`, margin + 100, y + 7)

    doc.setTextColor(22, 163, 74)
    doc.text('Low', margin + 130, y)
    doc.text(`${report.executive_summary.low_count}`, margin + 130, y + 7)

    y += 20
    doc.setTextColor(0, 0, 0)

    // Summary Text
    addText(report.executive_summary.summary)

    // Scope & Metadata
    addSectionTitle('SCAN METADATA')
    addKeyValue('Scan ID', report.scan_id)
    addKeyValue('Duration', `${Math.round(report.metadata.scan_duration / 60)} mins`)
    addKeyValue('Endpoints', report.metadata.endpoints_tested)
    addKeyValue('Test Cases', report.metadata.test_cases_executed)
    addKeyValue('Risk Level', report.executive_summary.overall_risk.toUpperCase())

    // Findings
    if (report.findings.length > 0) {
        addSectionTitle('DETAILED FINDINGS')

        report.findings.forEach((finding, index) => {
            if (y > 250) {
                doc.addPage()
                y = 20
            }

            // Finding Header
            doc.setFillColor(245, 245, 245)
            doc.rect(margin, y - 5, pageWidth - (margin * 2), 10, 'F')
            doc.setFont('helvetica', 'bold')
            doc.setTextColor(0, 0, 0)
            doc.text(`${index + 1}. ${finding.title}`, margin + 2, y + 2)

            // Severity Badge
            const severityColor =
                finding.severity === 'critical' ? [220, 38, 38] :
                    finding.severity === 'high' ? [234, 88, 12] :
                        finding.severity === 'medium' ? [202, 138, 4] :
                            [22, 163, 74]

            doc.setTextColor(severityColor[0], severityColor[1], severityColor[2])
            doc.text(finding.severity.toUpperCase(), pageWidth - margin - 5, y + 2, { align: 'right' })

            y += 12
            doc.setTextColor(0, 0, 0)
            doc.setFont('helvetica', 'normal')
            doc.setFontSize(11)

            addKeyValue('Type', finding.type)
            addKeyValue('Impact', finding.impact)

            doc.setFont('helvetica', 'bold')
            doc.text('Description:', margin, y)
            y += 5
            doc.setFont('helvetica', 'normal')
            addText(finding.description, 5)

            doc.setFont('helvetica', 'bold')
            doc.text('Recommendation:', margin, y)
            y += 5
            doc.setFont('helvetica', 'normal')
            finding.recommended_fixes.forEach(fix => {
                addText(`• ${fix}`, 5)
            })

            y += 10
        })
    }

    // Recommendations
    if (!Array.isArray(report.recommendations)) {
        addSectionTitle('STRATEGIC RECOMMENDATIONS')

        if (report.recommendations.immediate_actions.length > 0) {
            doc.setFont('helvetica', 'bold')
            doc.setTextColor(220, 38, 38)
            doc.text('Immediate Actions:', margin, y)
            y += 7
            doc.setFont('helvetica', 'normal')
            doc.setTextColor(0, 0, 0)
            report.recommendations.immediate_actions.forEach(rec => addText(`• ${rec}`, 5))
            y += 5
        }

        if (report.recommendations.short_term_fixes.length > 0) {
            if (y > 270) { doc.addPage(); y = 20; }
            doc.setFont('helvetica', 'bold')
            doc.setTextColor(234, 88, 12)
            doc.text('Short-term Fixes:', margin, y)
            y += 7
            doc.setFont('helvetica', 'normal')
            doc.setTextColor(0, 0, 0)
            report.recommendations.short_term_fixes.forEach(rec => addText(`• ${rec}`, 5))
            y += 5
        }

        if (report.recommendations.long_term_improvements.length > 0) {
            if (y > 270) { doc.addPage(); y = 20; }
            doc.setFont('helvetica', 'bold')
            doc.setTextColor(22, 163, 74)
            doc.text('Long-term Improvements:', margin, y)
            y += 7
            doc.setFont('helvetica', 'normal')
            doc.setTextColor(0, 0, 0)
            report.recommendations.long_term_improvements.forEach(rec => addText(`• ${rec}`, 5))
        }
    }

    // Footer
    const totalPages = doc.getNumberOfPages()
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i)
        doc.setFontSize(8)
        doc.setTextColor(150, 150, 150)
        doc.text(`Sentinel Red Security Audit - Page ${i} of ${totalPages}`, pageWidth / 2, doc.internal.pageSize.height - 10, { align: 'center' })
    }

    doc.save(`security-report-${report.scan_id}.pdf`)
}
