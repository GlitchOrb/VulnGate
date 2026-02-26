package engine

import (
	"io"
	"log"
	"os"
	"sync"
)

var (
	logMu        sync.RWMutex
	debugLogging bool
	logger       = log.New(os.Stderr, "vulngate: ", log.LstdFlags)
)

func SetDebugLogging(enabled bool) {
	logMu.Lock()
	defer logMu.Unlock()
	debugLogging = enabled
}

func SetLogOutput(w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	logMu.Lock()
	defer logMu.Unlock()
	logger.SetOutput(w)
}

func Debugf(format string, args ...any) {
	logMu.RLock()
	enabled := debugLogging
	l := logger
	logMu.RUnlock()
	if !enabled {
		return
	}
	l.Printf("DEBUG "+format, args...)
}

func Infof(format string, args ...any) {
	logMu.RLock()
	l := logger
	logMu.RUnlock()
	l.Printf("INFO "+format, args...)
}

func Errorf(format string, args ...any) {
	logMu.RLock()
	l := logger
	logMu.RUnlock()
	l.Printf("ERROR "+format, args...)
}
