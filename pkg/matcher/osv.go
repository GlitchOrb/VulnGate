package matcher

import (
	"strings"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

func IsAffected(version string, ranges []model.OSVRange) bool {
	for _, r := range ranges {
		switch r.Type {
		case model.OSVRangeSemver:
			if isSemverAffected(version, r.Events) {
				return true
			}
		case model.OSVRangeGit:
			if isGitAffected(version, r.Events) {
				return true
			}
		}
	}
	return false
}

func isSemverAffected(version string, events []model.OSVRangeEvent) bool {
	affected := false
	for _, event := range events {
		if event.Introduced != "" {
			if event.Introduced == "0" {
				affected = true
			} else if cmp, err := compareSemver(version, event.Introduced); err == nil && cmp >= 0 {
				affected = true
			}
		}

		if event.Fixed != "" {
			if cmp, err := compareSemver(version, event.Fixed); err == nil && cmp >= 0 {
				affected = false
			}
		}

		if event.LastAffected != "" {
			if cmp, err := compareSemver(version, event.LastAffected); err == nil && cmp > 0 {
				affected = false
			}
		}

		if event.Limit != "" {
			if cmp, err := compareSemver(version, event.Limit); err == nil && cmp >= 0 {
				affected = false
			}
		}
	}
	return affected
}

func isGitAffected(commit string, events []model.OSVRangeEvent) bool {
	if commit == "" {
		return false
	}
	c := strings.ToLower(commit)
	affected := false
	for _, event := range events {
		if event.Introduced != "" {
			intro := strings.ToLower(event.Introduced)
			if intro == "0" || intro == c {
				affected = true
			}
		}
		if event.Fixed != "" && strings.ToLower(event.Fixed) == c {
			affected = false
		}
		if event.LastAffected != "" && strings.ToLower(event.LastAffected) == c {
			affected = true
		}
		if event.Limit != "" && strings.ToLower(event.Limit) == c {
			affected = false
		}
	}
	return affected
}
