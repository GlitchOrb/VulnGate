package db

import (
	"context"
	"fmt"
)

func (s *Store) PullOCI(_ context.Context, ref string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store is not initialized")
	}
	if ref == "" {
		return fmt.Errorf("oci reference is required")
	}
	return fmt.Errorf("db pull via OCI is not implemented yet")
}
