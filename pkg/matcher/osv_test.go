package matcher

import (
	"testing"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

func TestIsAffectedSemverRange(t *testing.T) {
	ranges := []model.OSVRange{{
		Type: model.OSVRangeSemver,
		Events: []model.OSVRangeEvent{
			{Introduced: "0"},
			{Fixed: "1.5.0"},
		},
	}}

	if !IsAffected("1.4.9", ranges) {
		t.Fatalf("expected version 1.4.9 to be affected")
	}
	if IsAffected("1.5.0", ranges) {
		t.Fatalf("expected version 1.5.0 to be fixed")
	}
}

func TestIsAffectedGitEdges(t *testing.T) {
	ranges := []model.OSVRange{{
		Type: model.OSVRangeGit,
		Events: []model.OSVRangeEvent{
			{Introduced: "deadbeef"},
			{Fixed: "cafebabe"},
		},
	}}

	if !IsAffected("deadbeef", ranges) {
		t.Fatalf("introduced commit should be affected")
	}
	if IsAffected("cafebabe", ranges) {
		t.Fatalf("fixed commit should not be affected")
	}
}
