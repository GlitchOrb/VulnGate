package store

import (
	"context"
	"fmt"
	"strings"
)

type BackendConfig struct {
	Backend string
	Neo4j   Neo4jConfig
}

func Open(ctx context.Context, cfg BackendConfig) (GraphStore, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "memory":
		return NewMemoryStore(), nil
	case "neo4j":
		return NewNeo4jStore(ctx, cfg.Neo4j)
	default:
		return nil, fmt.Errorf("unsupported graph backend %q (expected memory|neo4j)", cfg.Backend)
	}
}
