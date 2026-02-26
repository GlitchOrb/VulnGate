package console

import (
	"fmt"
	"io"
	"strings"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

type Renderer struct{}

func New() *Renderer {
	return &Renderer{}
}

func (r *Renderer) Name() string {
	return "console"
}

func (r *Renderer) Render(w io.Writer, report model.Report) error {
	if len(report.Findings) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found.")
		return nil
	}

	fmt.Fprintf(w, "Vulnerability Scan Report for %s\n", report.Project)
	fmt.Fprintf(w, "Generated at: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Total findings: %d\n", len(report.Findings))
	fmt.Fprintln(w, strings.Repeat("=", 80))

	for i, finding := range report.Findings {
		fmt.Fprintf(w, "[%d] %s (%s)\n", i+1, finding.Vulnerability.ID, finding.Vulnerability.Severity)
		
		aliases := finding.Vulnerability.Aliases
		if len(aliases) > 0 {
			fmt.Fprintf(w, "    CVE/Aliases  : %s\n", strings.Join(aliases, ", "))
		} else {
			fmt.Fprintf(w, "    CVE/Aliases  : N/A\n")
		}
		
		fmt.Fprintf(w, "    Location     : %s@%s\n", finding.Dependency.PURL, finding.Dependency.Version)
		fmt.Fprintf(w, "    Reachability : %s\n", finding.Reachability)
		fmt.Fprintf(w, "    Summary      : %s\n", finding.Vulnerability.Summary)
		fmt.Fprintf(w, "    Message      : %s\n", finding.Message)
		fmt.Fprintln(w, strings.Repeat("-", 80))
	}

	if report.PolicyDecision.Fail {
		fmt.Fprintf(w, "POLICY FAILED: %s\n", report.PolicyDecision.Reason)
	} else {
		fmt.Fprintf(w, "POLICY PASSED\n")
	}

	return nil
}
