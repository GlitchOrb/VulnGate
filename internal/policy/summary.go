package policy

import "fmt"

func SummaryLines(report EvaluationReport) []string {
	lines := []string{
		fmt.Sprintf("policy summary: total_findings=%d considered=%d ignored=%d violations=%d", report.TotalFindings, report.ConsideredFindings, report.IgnoredFindings, report.Violations),
	}
	counts := formatCounts(report.CountsBySeverity)
	for _, line := range counts {
		lines = append(lines, "policy summary: "+line)
	}
	if len(counts) == 0 {
		lines = append(lines, "policy summary: no considered findings")
	}
	return lines
}
