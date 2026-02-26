package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultFileName = ".vulngate.yml"

var supportedSeverities = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

var severityOrder = []string{"critical", "high", "medium", "low"}

type LoadOptions struct {
	Path     string
	Required bool
}

type Config struct {
	FailOnSeverities []string          `yaml:"fail_on_severity"`
	Scope            ScopeRules        `yaml:"scope"`
	Reachability     ReachabilityRules `yaml:"reachability"`
	Ignore           []IgnoreRule      `yaml:"ignore"`
}

type ScopeRules struct {
	ProductionMode         bool `yaml:"production_mode"`
	IgnoreDevDependencies  bool `yaml:"ignore_dev_dependencies"`
	IgnoreTestDependencies bool `yaml:"ignore_test_dependencies"`
}

type ReachabilityRules struct {
	RequireReachableForSeverities []string `yaml:"require_reachable_for_severities"`
}

type IgnoreRule struct {
	VulnID  string `yaml:"vuln_id"`
	PURL    string `yaml:"purl"`
	Path    string `yaml:"path"`
	Expires string `yaml:"expires"`
	Reason  string `yaml:"reason"`
}

func DefaultConfig() Config {
	return Config{
		FailOnSeverities: []string{"critical", "high"},
		Scope: ScopeRules{
			ProductionMode:         false,
			IgnoreDevDependencies:  true,
			IgnoreTestDependencies: true,
		},
		Reachability: ReachabilityRules{
			RequireReachableForSeverities: []string{"critical", "high"},
		},
		Ignore: []IgnoreRule{},
	}
}

func Load(opts LoadOptions) (Config, string, error) {
	cfgPath := strings.TrimSpace(opts.Path)
	if cfgPath == "" {
		cfgPath = DefaultFileName
	}

	content, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) && !opts.Required {
			cfg := DefaultConfig()
			return cfg, cfgPath, nil
		}
		return Config{}, cfgPath, fmt.Errorf("read policy config %s: %w", cfgPath, err)
	}

	cfg := DefaultConfig()
	if err := unmarshalConfig(content, &cfg); err != nil {
		return Config{}, cfgPath, fmt.Errorf("parse policy config %s: %w", cfgPath, err)
	}

	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return Config{}, cfgPath, fmt.Errorf("validate policy config %s: %w", cfgPath, err)
	}

	return normalized, cfgPath, nil
}

func ResolveDefaultPath(targetPath string) string {
	trimmed := strings.TrimSpace(targetPath)
	if trimmed == "" {
		return DefaultFileName
	}
	info, err := os.Stat(trimmed)
	if err != nil {
		return filepath.Join(trimmed, DefaultFileName)
	}
	if info.IsDir() {
		return filepath.Join(trimmed, DefaultFileName)
	}
	return filepath.Join(filepath.Dir(trimmed), DefaultFileName)
}

func unmarshalConfig(content []byte, cfg *Config) error {
	root := map[string]any{}
	if err := yaml.Unmarshal(content, &root); err != nil {
		return err
	}

	if _, ok := root["policy"]; ok {
		wrapper := struct {
			Policy Config `yaml:"policy"`
		}{Policy: *cfg}
		if err := yaml.Unmarshal(content, &wrapper); err != nil {
			return err
		}
		*cfg = wrapper.Policy
		return nil
	}

	return yaml.Unmarshal(content, cfg)
}

func normalizeConfig(cfg Config) (Config, error) {
	var err error
	cfg.FailOnSeverities, err = normalizeSeverityList(cfg.FailOnSeverities)
	if err != nil {
		return Config{}, fmt.Errorf("fail_on_severity: %w", err)
	}
	cfg.Reachability.RequireReachableForSeverities, err = normalizeSeverityList(cfg.Reachability.RequireReachableForSeverities)
	if err != nil {
		return Config{}, fmt.Errorf("reachability.require_reachable_for_severities: %w", err)
	}

	normalizedIgnore := make([]IgnoreRule, 0, len(cfg.Ignore))
	for idx, rule := range cfg.Ignore {
		r := IgnoreRule{
			VulnID:  strings.TrimSpace(rule.VulnID),
			PURL:    strings.TrimSpace(rule.PURL),
			Path:    filepath.ToSlash(strings.TrimSpace(rule.Path)),
			Expires: strings.TrimSpace(rule.Expires),
			Reason:  strings.TrimSpace(rule.Reason),
		}

		if r.VulnID == "" && r.PURL == "" && r.Path == "" {
			return Config{}, fmt.Errorf("ignore[%d]: at least one selector is required (vuln_id, purl, path)", idx)
		}
		if r.Expires != "" {
			if _, err := parseExpiry(r.Expires); err != nil {
				return Config{}, fmt.Errorf("ignore[%d].expires: %w", idx, err)
			}
		}
		normalizedIgnore = append(normalizedIgnore, r)
	}

	cfg.Ignore = normalizedIgnore
	return cfg, nil
}

func normalizeSeverityList(values []string) ([]string, error) {
	set := map[string]bool{}
	for _, value := range values {
		severity := strings.ToLower(strings.TrimSpace(value))
		if severity == "" {
			continue
		}
		if _, ok := supportedSeverities[severity]; !ok {
			return nil, fmt.Errorf("unsupported severity %q", value)
		}
		set[severity] = true
	}
	if len(set) == 0 {
		return []string{}, nil
	}

	out := make([]string, 0, len(set))
	for _, severity := range severityOrder {
		if set[severity] {
			out = append(out, severity)
		}
	}
	if len(out) < len(set) {
		extra := make([]string, 0)
		for severity := range set {
			known := false
			for _, ordered := range out {
				if severity == ordered {
					known = true
					break
				}
			}
			if !known {
				extra = append(extra, severity)
			}
		}
		sort.Strings(extra)
		out = append(out, extra...)
	}
	return out, nil
}

func normalizeSeverity(raw string) string {
	severity := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := supportedSeverities[severity]; ok {
		return severity
	}
	return "low"
}

func parseExpiry(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, fmt.Errorf("date is empty")
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unsupported date format %q (use YYYY-MM-DD or RFC3339)", raw)
}
