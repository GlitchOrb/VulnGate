package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GlitchOrb/vulngate/services/graph/api"
	"github.com/GlitchOrb/vulngate/services/graph/store"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		addr      string
		backend   string
		neo4jURI  string
		neo4jUser string
		neo4jPass string
		neo4jDB   string
		readTO    time.Duration
		writeTO   time.Duration
		idleTO    time.Duration
	)

	fs := flag.NewFlagSet("graphd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&addr, "addr", firstNonEmpty(os.Getenv("VULNGATE_GRAPH_ADDR"), ":8090"), "HTTP listen address")
	fs.StringVar(&backend, "backend", firstNonEmpty(os.Getenv("VULNGATE_GRAPH_BACKEND"), "memory"), "Graph backend: memory|neo4j")
	fs.StringVar(&neo4jURI, "neo4j-uri", firstNonEmpty(os.Getenv("VULNGATE_GRAPH_NEO4J_URI"), "bolt://localhost:7687"), "Neo4j URI")
	fs.StringVar(&neo4jUser, "neo4j-user", firstNonEmpty(os.Getenv("VULNGATE_GRAPH_NEO4J_USER"), "neo4j"), "Neo4j username")
	fs.StringVar(&neo4jPass, "neo4j-pass", firstNonEmpty(os.Getenv("VULNGATE_GRAPH_NEO4J_PASS"), "neo4jtest"), "Neo4j password")
	fs.StringVar(&neo4jDB, "neo4j-db", strings.TrimSpace(os.Getenv("VULNGATE_GRAPH_NEO4J_DB")), "Neo4j database name")
	fs.DurationVar(&readTO, "read-timeout", 10*time.Second, "HTTP read timeout")
	fs.DurationVar(&writeTO, "write-timeout", 20*time.Second, "HTTP write timeout")
	fs.DurationVar(&idleTO, "idle-timeout", 60*time.Second, "HTTP idle timeout")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "parse args: %v\n", err)
		return 2
	}

	logger := log.New(os.Stderr, "vulngate-graph: ", log.LstdFlags)
	ctx := context.Background()

	graphStore, err := store.Open(ctx, store.BackendConfig{
		Backend: backend,
		Neo4j: store.Neo4jConfig{
			URI:      neo4jURI,
			Username: neo4jUser,
			Password: neo4jPass,
			Database: neo4jDB,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open graph store: %v\n", err)
		return 2
	}
	defer graphStore.Close()

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      api.NewServer(graphStore, logger).Handler(),
		ReadTimeout:  readTO,
		WriteTimeout: writeTO,
		IdleTimeout:  idleTO,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("graph service listening on %s backend=%s", addr, strings.ToLower(strings.TrimSpace(backend)))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-sigCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "shutdown http server: %v\n", err)
			return 1
		}
		return 0
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "graph server failed: %v\n", err)
			return 1
		}
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
