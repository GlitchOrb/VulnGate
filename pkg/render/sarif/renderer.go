package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

type logFile struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Results     []result     `json:"results"`
	Invocations []invocation `json:"invocations,omitempty"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []rule `json:"rules,omitempty"`
}

type rule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription shortDescription  `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type shortDescription struct {
	Text string `json:"text"`
}

type result struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    message           `json:"message"`
	Locations  []location        `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type invocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Properties          map[string]any `json:"properties,omitempty"`
}

type Renderer struct{}

func New() *Renderer {
	return &Renderer{}
}

func (r *Renderer) Name() string {
	return "sarif"
}

func (r *Renderer) Render(w io.Writer, report model.Report) error {
	rulesMap := map[string]rule{}
	results := make([]result, 0, len(report.Findings))

	for _, finding := range report.Findings {
		id := finding.Vulnerability.ID
		if _, exists := rulesMap[id]; !exists {
			rulesMap[id] = rule{
				ID:               id,
				Name:             id,
				ShortDescription: shortDescription{Text: finding.Vulnerability.Summary},
				Properties: map[string]string{
					"severity": string(finding.Vulnerability.Severity),
				},
			}
		}

		results = append(results, result{
			RuleID:  id,
			Level:   sarifLevel(finding.Vulnerability.Severity),
			Message: message{Text: finding.Message},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: report.Project},
				},
			}},
			Properties: map[string]string{
				"dependency_purl": finding.Dependency.PURL,
				"reachability":    string(finding.Reachability),
				"scanner":         finding.Scanner,
			},
		})
	}

	rules := make([]rule, 0, len(rulesMap))
	for _, v := range rulesMap {
		rules = append(rules, v)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].Properties["dependency_purl"] < results[j].Properties["dependency_purl"]
	})

	s := logFile{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "VulnGate",
				Version:        report.ToolVersion,
				InformationURI: "https://github.com/GlitchOrb/vulngate",
				Rules:          rules,
			}},
			Results: results,
			Invocations: []invocation{{
				ExecutionSuccessful: !report.PolicyDecision.Fail,
				Properties: map[string]any{
					"policy_fail":   report.PolicyDecision.Fail,
					"policy_reason": report.PolicyDecision.Reason,
				},
			}},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	return nil
}

func sarifLevel(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow:
		return "note"
	default:
		return "none"
	}
}
