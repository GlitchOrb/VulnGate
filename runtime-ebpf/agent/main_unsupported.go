//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "vulngate runtime-ebpf agent is supported on linux only")
	os.Exit(1)
}
