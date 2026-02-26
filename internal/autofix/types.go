package autofix

import (
	"context"
	"time"
)

type Candidate struct {
	VulnID       string   `json:"vulnID"`
	PackagePURL  string   `json:"packagePURL"`
	Severity     string   `json:"severity"`
	Reachable    bool     `json:"reachable"`
	FixedVersion string   `json:"fixedVersion,omitempty"`
	Locations    []string `json:"locations,omitempty"`
}

type DetectReport struct {
	TotalFindings     int         `json:"totalFindings"`
	CriticalFindings  int         `json:"criticalFindings"`
	HighFindings      int         `json:"highFindings"`
	ReachableFindings int         `json:"reachableFindings"`
	Candidates        []Candidate `json:"candidates"`
}

type SafetyReport struct {
	Passed       bool     `json:"passed"`
	ChangedFiles int      `json:"changedFiles"`
	AddedLines   int      `json:"addedLines"`
	RemovedLines int      `json:"removedLines"`
	Violations   []string `json:"violations,omitempty"`
}

type ValidationReport struct {
	Passed              bool        `json:"passed"`
	PatchApplied        bool        `json:"patchApplied"`
	TestsRan            bool        `json:"testsRan"`
	TestsPassed         bool        `json:"testsPassed"`
	RescanPassed        bool        `json:"rescanPassed"`
	UnresolvedFindings  []Candidate `json:"unresolvedFindings,omitempty"`
	NewCriticalFindings []Candidate `json:"newCriticalFindings,omitempty"`
	Reasons             []string    `json:"reasons,omitempty"`
	WorktreePath        string      `json:"worktreePath,omitempty"`
	Branch              string      `json:"branch,omitempty"`
	TestOutputPath      string      `json:"testOutputPath,omitempty"`
}

type AuditArtifacts struct {
	Directory       string `json:"directory"`
	PromptPath      string `json:"promptPath"`
	ModelOutputPath string `json:"modelOutputPath"`
	PatchPath       string `json:"patchPath"`
	ReportPath      string `json:"reportPath"`
}

type Status string

const (
	StatusSuccess Status = "success"
	StatusAborted Status = "aborted"
	StatusError   Status = "error"
)

type Report struct {
	StartedAt    time.Time        `json:"startedAt"`
	CompletedAt  time.Time        `json:"completedAt"`
	RepoPath     string           `json:"repoPath"`
	PolicyPath   string           `json:"policyPath,omitempty"`
	Model        string           `json:"model"`
	AutoFix      bool             `json:"autoFix"`
	Status       Status           `json:"status"`
	Detect       DetectReport     `json:"detect"`
	Safety       SafetyReport     `json:"safety"`
	Validation   ValidationReport `json:"validation"`
	Audit        AuditArtifacts   `json:"audit"`
	PatchPreview string           `json:"patchPreview,omitempty"`
	Reason       string           `json:"reason,omitempty"`
	NeverPushed  bool             `json:"neverPushed"`
}

type Options struct {
	RepoPath      string
	PolicyPath    string
	Model         string
	AutoFix       bool
	TestCommand   string
	AuditDir      string
	MaxCandidates int
	LocalLLMCmd   string
	Adapter       Adapter
}

type GenerateRequest struct {
	RepoPath   string
	Prompt     string
	Candidates []Candidate
}

type GenerateResult struct {
	Patch     string
	RawOutput string
	ModelInfo string
}

type Adapter interface {
	Name() string
	GeneratePatch(ctx context.Context, req GenerateRequest) (GenerateResult, error)
}
