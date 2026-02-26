package matcher

import (
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major int
	minor int
	patch int
	pre   string
}

func parseSemver(raw string) (semver, error) {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return semver{}, fmt.Errorf("empty semver")
	}

	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}

	pre := ""
	if idx := strings.Index(v, "-"); idx >= 0 {
		pre = v[idx+1:]
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return semver{}, fmt.Errorf("invalid semver %q", raw)
	}

	nums := [3]int{}
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			nums[i] = 0
			continue
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return semver{}, fmt.Errorf("invalid semver %q", raw)
		}
		nums[i] = n
	}

	return semver{
		major: nums[0],
		minor: nums[1],
		patch: nums[2],
		pre:   pre,
	}, nil
}

func compareSemver(aRaw, bRaw string) (int, error) {
	a, err := parseSemver(aRaw)
	if err != nil {
		return 0, err
	}
	b, err := parseSemver(bRaw)
	if err != nil {
		return 0, err
	}

	if a.major != b.major {
		if a.major < b.major {
			return -1, nil
		}
		return 1, nil
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1, nil
		}
		return 1, nil
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1, nil
		}
		return 1, nil
	}

	if a.pre == "" && b.pre == "" {
		return 0, nil
	}
	if a.pre == "" {
		return 1, nil
	}
	if b.pre == "" {
		return -1, nil
	}
	if a.pre < b.pre {
		return -1, nil
	}
	if a.pre > b.pre {
		return 1, nil
	}
	return 0, nil
}
