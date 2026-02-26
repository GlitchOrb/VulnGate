package matcher

import "testing"

func TestParsePURL(t *testing.T) {
	p, err := ParsePURL("pkg:golang/github.com/foo/bar@1.2.3?arch=amd64#sub")
	if err != nil {
		t.Fatalf("ParsePURL returned error: %v", err)
	}

	if p.Type != "golang" {
		t.Fatalf("unexpected type: %s", p.Type)
	}
	if p.Namespace != "github.com/foo" {
		t.Fatalf("unexpected namespace: %s", p.Namespace)
	}
	if p.Name != "bar" {
		t.Fatalf("unexpected name: %s", p.Name)
	}
	if p.Version != "1.2.3" {
		t.Fatalf("unexpected version: %s", p.Version)
	}
	if p.Qualifiers["arch"] != "amd64" {
		t.Fatalf("unexpected qualifier arch: %q", p.Qualifiers["arch"])
	}
	if p.Subpath != "sub" {
		t.Fatalf("unexpected subpath: %s", p.Subpath)
	}
	if p.PackageKey() != "golang/github.com/foo/bar" {
		t.Fatalf("unexpected package key: %s", p.PackageKey())
	}
}
