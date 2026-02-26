//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	reachruntime "github.com/GlitchOrb/vulngate/internal/reach/runtime"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	modeAttach = "attach"
	modeReplay = "replay"
)

type probeSpec struct {
	ID      uint32 `json:"id"`
	PURL    string `json:"purl"`
	Symbol  string `json:"symbol"`
	Binary  string `json:"binary"`
	Uprobe  string `json:"uprobe,omitempty"`
	Offset  uint64 `json:"offset,omitempty"`
	Address uint64 `json:"address,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

type agentConfig struct {
	Probes              []probeSpec `json:"probes"`
	PollIntervalSeconds int         `json:"pollIntervalSeconds,omitempty"`
	DurationSeconds     int         `json:"durationSeconds,omitempty"`
	ReplayCommand       []string    `json:"replayCommand,omitempty"`
}

type options struct {
	Mode         string
	ConfigPath   string
	OutputPath   string
	PollInterval time.Duration
	Duration     time.Duration
	ReplayCmd    string
	Debug        bool
}

type profileState struct {
	TotalCount uint64
	FirstSeen  time.Time
	LastSeen   time.Time
}

func main() {
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	opts, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "flag error: %v\n", err)
		return 2
	}

	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 2
	}
	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		return 2
	}

	if cfg.PollIntervalSeconds > 0 && opts.PollInterval <= 0 {
		opts.PollInterval = time.Duration(cfg.PollIntervalSeconds) * time.Second
	}
	if cfg.DurationSeconds > 0 && opts.Duration <= 0 {
		opts.Duration = time.Duration(cfg.DurationSeconds) * time.Second
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.Mode == modeReplay && strings.TrimSpace(opts.ReplayCmd) == "" && len(cfg.ReplayCommand) > 0 {
		opts.ReplayCmd = strings.Join(cfg.ReplayCommand, " ")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: adjust memlock rlimit failed: %v\n", err)
	}

	if err := runProfiler(ctx, opts, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "runtime profiler failed: %v\n", err)
		return 1
	}
	return 0
}

func parseFlags() (options, error) {
	fs := flag.NewFlagSet("vulngate-ebpf-agent", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	opts := options{}
	fs.StringVar(&opts.Mode, "mode", modeAttach, "Profiler mode: attach|replay")
	fs.StringVar(&opts.ConfigPath, "config", "", "Path to profiler config JSON")
	fs.StringVar(&opts.OutputPath, "output", "profile.json", "Output profile JSON path")
	fs.DurationVar(&opts.PollInterval, "poll-interval", 5*time.Second, "Polling interval for map snapshots")
	fs.DurationVar(&opts.Duration, "duration", 0, "Maximum profiling duration (0 means until interrupted)")
	fs.StringVar(&opts.ReplayCmd, "replay-cmd", "", "Replay command used in mode=replay")
	fs.BoolVar(&opts.Debug, "debug", false, "Enable debug logs on stderr")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return options{}, err
	}
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return options{}, errors.New("--config is required")
	}
	switch strings.ToLower(strings.TrimSpace(opts.Mode)) {
	case modeAttach, modeReplay:
		opts.Mode = strings.ToLower(strings.TrimSpace(opts.Mode))
	default:
		return options{}, fmt.Errorf("unsupported --mode %q", opts.Mode)
	}
	return opts, nil
}

func loadConfig(path string) (agentConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return agentConfig{}, fmt.Errorf("read config file: %w", err)
	}

	var cfg agentConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return agentConfig{}, fmt.Errorf("decode config json: %w", err)
	}
	return cfg, nil
}

func validateConfig(cfg agentConfig) error {
	if len(cfg.Probes) == 0 {
		return errors.New("at least one probe is required")
	}

	seen := map[uint32]bool{}
	for _, probe := range cfg.Probes {
		if probe.ID == 0 {
			return fmt.Errorf("probe id must be > 0")
		}
		if seen[probe.ID] {
			return fmt.Errorf("duplicate probe id %d", probe.ID)
		}
		seen[probe.ID] = true

		if strings.TrimSpace(probe.PURL) == "" {
			return fmt.Errorf("probe id=%d missing purl", probe.ID)
		}
		if strings.TrimSpace(probe.Symbol) == "" {
			return fmt.Errorf("probe id=%d missing symbol", probe.ID)
		}
		if strings.TrimSpace(probe.Binary) == "" {
			return fmt.Errorf("probe id=%d missing binary", probe.ID)
		}
	}
	return nil
}

func runProfiler(ctx context.Context, opts options, cfg agentConfig) error {
	counts, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "vulngate_counts",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(len(cfg.Probes) * 2),
	})
	if err != nil {
		return fmt.Errorf("create ebpf map: %w", err)
	}
	defer counts.Close()

	for _, probe := range cfg.Probes {
		var initial uint64
		id := probe.ID
		if err := counts.Put(&id, &initial); err != nil {
			return fmt.Errorf("prepopulate map for probe %d: %w", probe.ID, err)
		}
	}

	links := []link.Link{}
	programs := []*ebpf.Program{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
		for _, p := range programs {
			_ = p.Close()
		}
	}()

	for _, probe := range cfg.Probes {
		prog, err := loadCounterProgram(probe.ID, counts)
		if err != nil {
			return fmt.Errorf("load ebpf program for probe id=%d: %w", probe.ID, err)
		}
		programs = append(programs, prog)

		exe, err := link.OpenExecutable(probe.Binary)
		if err != nil {
			return fmt.Errorf("open executable %q for probe id=%d: %w", probe.Binary, probe.ID, err)
		}

		targetSymbol := strings.TrimSpace(probe.Uprobe)
		if targetSymbol == "" {
			targetSymbol = strings.TrimSpace(probe.Symbol)
		}

		up, err := exe.Uprobe(targetSymbol, prog, &link.UprobeOptions{
			Address: probe.Address,
			Offset:  probe.Offset,
			PID:     probe.PID,
		})
		if err != nil {
			return fmt.Errorf("attach uprobe binary=%q symbol=%q id=%d: %w", probe.Binary, targetSymbol, probe.ID, err)
		}
		links = append(links, up)

		if opts.Debug {
			fmt.Fprintf(os.Stderr, "attached probe id=%d purl=%s symbol=%s binary=%s\n", probe.ID, probe.PURL, targetSymbol, probe.Binary)
		}
	}

	state := map[uint32]profileState{}
	prevCounts := map[uint32]uint64{}

	sample := func(now time.Time) error {
		for _, probe := range cfg.Probes {
			id := probe.ID
			var current uint64
			if err := counts.Lookup(&id, &current); err != nil {
				return fmt.Errorf("read ebpf counter id=%d: %w", probe.ID, err)
			}

			prev := prevCounts[id]
			if current > prev {
				st := state[id]
				st.TotalCount = current
				if st.FirstSeen.IsZero() {
					st.FirstSeen = now.UTC()
				}
				st.LastSeen = now.UTC()
				state[id] = st
			}
			prevCounts[id] = current
		}
		return nil
	}

	if err := sample(time.Now().UTC()); err != nil {
		return err
	}

	pollTicker := time.NewTicker(opts.PollInterval)
	defer pollTicker.Stop()

	var deadline <-chan time.Time
	if opts.Duration > 0 {
		timer := time.NewTimer(opts.Duration)
		defer timer.Stop()
		deadline = timer.C
	}

	if opts.Mode == modeReplay {
		if strings.TrimSpace(opts.ReplayCmd) == "" {
			return errors.New("mode replay requires --replay-cmd or replayCommand in config")
		}
		if err := runReplayMode(ctx, opts, pollTicker, deadline, sample); err != nil {
			return err
		}
	} else {
		if err := runAttachMode(ctx, pollTicker, deadline, sample); err != nil {
			return err
		}
	}

	profile := buildRuntimeProfile(cfg.Probes, state)
	if len(profile.Events) == 0 {
		fmt.Fprintln(os.Stderr, "warning: no runtime calls observed in profiling window")
	}

	if err := reachruntime.WriteProfileFile(opts.OutputPath, profile); err != nil {
		return fmt.Errorf("write profile output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "wrote runtime profile: events=%d output=%s\n", len(profile.Events), opts.OutputPath)
	return nil
}

func runAttachMode(ctx context.Context, pollTicker *time.Ticker, deadline <-chan time.Time, sampleFn func(time.Time) error) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline:
			return nil
		case t := <-pollTicker.C:
			if err := sampleFn(t); err != nil {
				return err
			}
		}
	}
}

func runReplayMode(ctx context.Context, opts options, pollTicker *time.Ticker, deadline <-chan time.Time, sampleFn func(time.Time) error) error {
	replayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(replayCtx, "bash", "-lc", opts.ReplayCmd)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start replay command: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			cancel()
			_ = waitReplay(done, 5*time.Second)
			return nil
		case <-deadline:
			cancel()
			_ = waitReplay(done, 5*time.Second)
			return nil
		case t := <-pollTicker.C:
			if err := sampleFn(t); err != nil {
				return err
			}
		case err := <-done:
			if err != nil {
				return fmt.Errorf("replay command failed: %w", err)
			}
			return nil
		}
	}
}

func waitReplay(done <-chan error, timeout time.Duration) error {
	if timeout <= 0 {
		return <-done
	}

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for replay command shutdown")
	}
}

func buildRuntimeProfile(probes []probeSpec, state map[uint32]profileState) reachruntime.Profile {
	events := make([]reachruntime.Event, 0, len(probes))
	for _, probe := range probes {
		st := state[probe.ID]
		if st.TotalCount == 0 {
			continue
		}
		events = append(events, reachruntime.Event{
			PURL:      strings.TrimSpace(probe.PURL),
			Symbol:    strings.TrimSpace(probe.Symbol),
			Count:     st.TotalCount,
			FirstSeen: st.FirstSeen.UTC(),
			LastSeen:  st.LastSeen.UTC(),
		})
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].PURL != events[j].PURL {
			return events[i].PURL < events[j].PURL
		}
		return events[i].Symbol < events[j].Symbol
	})

	return reachruntime.Profile{
		Schema:      reachruntime.ProfileSchema,
		GeneratedAt: time.Now().UTC(),
		Events:      events,
	}
}

func loadCounterProgram(probeID uint32, counts *ebpf.Map) (*ebpf.Program, error) {
	instructions := asm.Instructions{
		asm.StoreImm(asm.R10, -4, int64(probeID), asm.Word),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, counts.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}

	spec := &ebpf.ProgramSpec{
		Name:         fmt.Sprintf("vg_%d", probeID),
		Type:         ebpf.Kprobe,
		Instructions: instructions,
		License:      "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		return nil, fmt.Errorf("new program: %w", err)
	}
	return prog, nil
}
