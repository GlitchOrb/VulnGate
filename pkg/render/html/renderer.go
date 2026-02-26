package html

import (
	"html/template"
	"io"
	"strings"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnGate Report - {{.Project}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* GitHub/Vercel inspired Dark Theme */
            --bg-base: #0a0a0a;
            --bg-surface: #111111;
            --bg-surface-hover: #1a1a1a;
            --border-subtle: #222222;
            --border-strong: #333333;
            --text-primary: #ededed;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            
            --critical-bg: rgba(239, 68, 68, 0.15);
            --critical-color: #ef4444;
            --critical-border: rgba(239, 68, 68, 0.3);
            
            --high-bg: rgba(249, 115, 22, 0.15);
            --high-color: #f97316;
            --high-border: rgba(249, 115, 22, 0.3);
            
            --medium-bg: rgba(234, 179, 8, 0.15);
            --medium-color: #eab308;
            --medium-border: rgba(234, 179, 8, 0.3);
            
            --low-bg: rgba(34, 197, 94, 0.15);
            --low-color: #22c55e;
            --low-border: rgba(34, 197, 94, 0.3);
            
            --unknown-bg: rgba(113, 113, 122, 0.15);
            --unknown-color: #a1a1aa;
            --unknown-border: rgba(113, 113, 122, 0.3);
            
            --accent-primary: #3b82f6;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        .container {
            max-width: 1040px;
            margin: 0 auto;
        }

        /* Header Styles */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 32px;
            margin-bottom: 40px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .header-left {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .header h1 {
            margin: 0;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #ffffff;
        }

        .project-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            background: var(--border-subtle);
            border: 1px solid var(--border-strong);
            border-radius: 999px;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        .project-badge strong {
            color: #ffffff;
            margin-left: 6px;
        }

        .header-meta {
            text-align: right;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .glitchorb-tag {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 6px;
        }
        
        .glitchorb-tag span {
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .timestamp {
            font-size: 13px;
            color: var(--text-muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }

        /* Overview Cards */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .metric-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 24px;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }
        
        .metric-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 2px;
            background: var(--border-subtle);
            transition: background 0.3s ease;
        }
        .metric-card:hover::before {
            background: var(--accent-primary);
        }

        .metric-card.fail::before { background: var(--critical-color); }

        .metric-card h3 {
            margin: 0 0 12px 0;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .metric-value {
            font-size: 40px;
            font-weight: 700;
            line-height: 1;
            color: #ffffff;
            letter-spacing: -0.02em;
        }

        /* Policy Banner */
        .policy-banner {
            padding: 20px 24px;
            border-radius: 12px;
            margin-bottom: 40px;
            display: flex;
            align-items: center;
            gap: 16px;
            font-weight: 500;
            font-size: 15px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }

        .policy-pass {
            background: rgba(34, 197, 94, 0.05);
            border: 1px solid rgba(34, 197, 94, 0.2);
            color: var(--low-color);
        }

        .policy-fail {
            background: rgba(239, 68, 68, 0.05);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--critical-color);
        }

        /* Finding Cards */
        .findings-header {
            font-size: 20px;
            font-weight: 600;
            margin: 0 0 20px 0;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .finding-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            margin-bottom: 20px;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .finding-card:hover {
            border-color: var(--border-strong);
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }

        .finding-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255, 255, 255, 0.02);
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
        }

        .finding-id {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .finding-id svg {
            color: var(--text-muted);
        }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-critical { background: var(--critical-bg); color: var(--critical-color); border: 1px solid var(--critical-border); }
        .severity-high { background: var(--high-bg); color: var(--high-color); border: 1px solid var(--high-border); }
        .severity-medium { background: var(--medium-bg); color: var(--medium-color); border: 1px solid var(--medium-border); }
        .severity-low { background: var(--low-bg); color: var(--low-color); border: 1px solid var(--low-border); }
        .severity-unknown { background: var(--unknown-bg); color: var(--unknown-color); border: 1px solid var(--unknown-border); }

        .finding-body {
            padding: 24px;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 16px;
        }

        @media (min-width: 768px) {
            .detail-grid {
                grid-template-columns: 1fr 1fr;
            }
        }

        .detail-item {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .detail-label {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .detail-value {
            font-size: 14px;
            color: var(--text-primary);
        }

        .code-box {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #000000;
            border: 1px solid var(--border-strong);
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 13px;
            color: #e2e8f0;
            display: inline-block;
            word-break: break-all;
        }

        .finding-summary {
            margin-top: 24px;
            padding-top: 24px;
            border-top: 1px solid var(--border-subtle);
        }

        .finding-summary p {
            margin: 0 0 16px 0;
            font-size: 15px;
            color: var(--text-secondary);
        }

        .message-box {
            background: rgba(59, 130, 246, 0.05);
            border-left: 3px solid var(--accent-primary);
            padding: 16px;
            border-radius: 0 8px 8px 0;
            font-size: 14px;
            color: var(--text-primary);
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }

        .empty-state {
            text-align: center;
            padding: 80px 20px;
            background: var(--bg-surface);
            border: 1px dashed var(--border-strong);
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 16px;
        }
        
        .empty-state h2 {
            margin: 0;
            font-size: 20px;
            color: #ffffff;
        }

        .empty-state p {
            margin: 0;
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-left">
                <h1>
                    <svg height="32" width="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent-primary);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                    VulnGate Report
                </h1>
                <div class="project-badge">
                    Target: <strong>{{.Project}}</strong>
                </div>
            </div>
            <div class="header-meta">
                <div class="glitchorb-tag">
                    <svg height="16" width="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15h2v2h-2v-2zm0-10h2v8h-2V7z"></path></svg>
                    <span>@GlitchOrb</span>
                </div>
                <div class="timestamp">{{.GeneratedAt.Local.Format "2006-01-02 15:04:05 MST"}}</div>
            </div>
        </header>

        {{if .PolicyDecision.Fail}}
        <div class="policy-banner policy-fail">
            <svg height="24" width="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
            <div>
                <strong>Gate Failed:</strong> {{.PolicyDecision.Reason}}
            </div>
        </div>
        {{else}}
        <div class="policy-banner policy-pass">
            <svg height="24" width="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            <div>
                <strong>Gate Passed:</strong> All checks satisfied successfully.
            </div>
        </div>
        {{end}}

        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Vulnerabilities Found</h3>
                <div class="metric-value">{{len .Findings}}</div>
            </div>
            <div class="metric-card {{if gt (len .PolicyDecision.Violations) 0}}fail{{end}}">
                <h3>Policy Violations</h3>
                <div class="metric-value" style="{{if gt (len .PolicyDecision.Violations) 0}}color: var(--critical-color);{{end}}">{{.PolicyDecision.Violations | len}}</div>
            </div>
        </div>

        {{if .Findings}}
            <h2 class="findings-header">Detailed Findings</h2>
            {{range .Findings}}
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-id">
                        <svg height="18" width="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                        {{.Vulnerability.ID}}
                    </div>
                    <div class="severity-badge severity-{{.Vulnerability.Severity}}">{{.Vulnerability.Severity}}</div>
                </div>
                
                <div class="finding-body">
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="detail-label">Aliases / CVE</span>
                            <span class="detail-value">
                                {{if .Vulnerability.Aliases}}
                                    {{join .Vulnerability.Aliases ", "}}
                                {{else}}
                                    <span style="color: var(--text-muted);">Not available</span>
                                {{end}}
                            </span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Reachability</span>
                            <span class="detail-value">
                                {{if eq .Reachability "tier2r"}}
                                    <span style="color: var(--critical-color); font-weight: 500; display:flex; align-items:center; gap:6px;">
                                        <svg height="14" width="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                                        {{.Reachability}} (Runtime Detected)
                                    </span>
                                {{else}}
                                    <span style="color: var(--text-secondary);">{{.Reachability}}</span>
                                {{end}}
                            </span>
                        </div>
                        <div class="detail-item" style="grid-column: 1 / -1;">
                            <span class="detail-label">Affected Dependency</span>
                            <div class="code-box">{{.Dependency.PURL}}@{{.Dependency.Version}}</div>
                        </div>
                    </div>

                    <div class="finding-summary">
                        <p>{{.Vulnerability.Summary}}</p>
                        <div class="message-box">
                            Scanner Output: {{.Message}}
                        </div>
                    </div>
                </div>
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">
                <svg height="48" width="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                <div>
                    <h2>Zero Vulnerabilities Detected</h2>
                    <p>Your dependencies look clean and secure.</p>
                </div>
            </div>
        {{end}}
    </div>
</body>
</html>`

type Renderer struct {
	tmpl *template.Template
}

func New() *Renderer {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(reportTemplate))
	return &Renderer{tmpl: tmpl}
}

func (r *Renderer) Name() string {
	return "html"
}

func (r *Renderer) Render(w io.Writer, report model.Report) error {
	return r.tmpl.Execute(w, report)
}
