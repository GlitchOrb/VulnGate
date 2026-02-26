package fixture

import "testing"

func TestSum(t *testing.T) {
	if got := Sum(20, 22); got != 42 {
		t.Fatalf("unexpected sum: got=%d want=42", got)
	}
}
