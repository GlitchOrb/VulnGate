package match

import "strings"

type rangeEvent struct {
	introduced   string
	fixed        string
	lastAffected string
	limit        string
}

func isAffected(rangeType string, version string, events []rangeEvent) (bool, string) {
	switch strings.ToUpper(strings.TrimSpace(rangeType)) {
	case "SEMVER":
		return isSemverAffected(version, events)
	case "GIT":
		return isGitAffected(version, events)
	default:
		return false, ""
	}
}

func isSemverAffected(version string, events []rangeEvent) (bool, string) {
	v := strings.TrimSpace(version)
	if v == "" {
		return false, ""
	}

	affected := false
	fixedVersion := ""
	for _, event := range events {
		if event.introduced != "" {
			if event.introduced == "0" {
				affected = true
			} else if cmp, err := compareSemVersion(v, event.introduced); err == nil && cmp >= 0 {
				affected = true
			}
		}

		if event.fixed != "" {
			if fixedVersion == "" {
				fixedVersion = event.fixed
			}
			if cmp, err := compareSemVersion(v, event.fixed); err == nil && cmp >= 0 {
				affected = false
			}
		}

		if event.lastAffected != "" {
			if cmp, err := compareSemVersion(v, event.lastAffected); err == nil {
				if cmp <= 0 {
					affected = true
				} else {
					affected = false
				}
			}
		}

		if event.limit != "" {
			if cmp, err := compareSemVersion(v, event.limit); err == nil && cmp >= 0 {
				affected = false
			}
		}
	}
	return affected, fixedVersion
}

func isGitAffected(version string, events []rangeEvent) (bool, string) {
	commit := strings.ToLower(strings.TrimSpace(version))
	if commit == "" {
		return false, ""
	}

	affected := false
	fixedVersion := ""
	for _, event := range events {
		intro := strings.ToLower(strings.TrimSpace(event.introduced))
		fix := strings.ToLower(strings.TrimSpace(event.fixed))
		last := strings.ToLower(strings.TrimSpace(event.lastAffected))
		limit := strings.ToLower(strings.TrimSpace(event.limit))

		if intro != "" && (intro == "0" || commitMatch(commit, intro)) {
			affected = true
		}
		if fix != "" {
			if fixedVersion == "" {
				fixedVersion = fix
			}
			if commitMatch(commit, fix) {
				affected = false
			}
		}
		if last != "" && commitMatch(commit, last) {
			affected = true
		}
		if limit != "" && commitMatch(commit, limit) {
			affected = false
		}
	}
	return affected, fixedVersion
}

func commitMatch(commit, candidate string) bool {
	if commit == candidate {
		return true
	}
	if len(candidate) >= 7 && strings.HasPrefix(commit, candidate) {
		return true
	}
	if len(commit) >= 7 && strings.HasPrefix(candidate, commit) {
		return true
	}
	return false
}
