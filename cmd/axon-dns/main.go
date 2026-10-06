// axon-dns reads registry state and publishes BIND zones. It never signs blockchain transactions.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/authoritative"
)

type config struct {
	RPC             string                     `json:"rpc"`
	Contract        string                     `json:"contract"`
	ChainID         uint64                     `json:"chain_id"`
	MaxNames        int                        `json:"max_names"`
	IntervalSeconds int                        `json:"interval_seconds"`
	TimeoutSeconds  int                        `json:"timeout_seconds"`
	CheckCommand    []string                   `json:"check_command"`
	ReloadCommand   []string                   `json:"reload_command"`
	Zones           []authoritative.ZoneConfig `json:"zones"`
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: axon-dns encode -rr 'owner. TTL IN TYPE RDATA' | publish -config file [-watch]")
	}
	switch os.Args[1] {
	case "encode":
		fs := flag.NewFlagSet("encode", flag.ContinueOnError)
		rr := fs.String("rr", "", "one absolute IN resource record")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		owner, r, err := authoritative.EncodeRR(*rr)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"name": owner, "kind": r.Kind, "ttl": r.TTL, "data": authoritative.PayloadHex(r), "method": "setRecord(string,uint64,uint8,uint32,bytes)", "id": 0})
	case "publish":
		fs := flag.NewFlagSet("publish", flag.ContinueOnError)
		path := fs.String("config", "", "publisher JSON configuration")
		watch := fs.Bool("watch", false, "poll finalized chain state and reload BIND")
		noReload := fs.Bool("no-reload", false, "initial provisioning before BIND starts (one-shot only)")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		f, err := os.Open(*path)
		if err != nil {
			return err
		}
		defer f.Close()
		var cfg config
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields()
		if err = dec.Decode(&cfg); err != nil {
			return err
		}
		if len(cfg.Zones) == 0 || cfg.RPC == "" || cfg.Contract == "" || cfg.ChainID == 0 {
			return errors.New("RPC, contract, expected chain_id and zones required")
		}
		if cfg.IntervalSeconds == 0 {
			cfg.IntervalSeconds = 30
		}
		if cfg.TimeoutSeconds == 0 {
			cfg.TimeoutSeconds = 120
		}
		if cfg.IntervalSeconds < 1 || cfg.TimeoutSeconds < 1 || cfg.MaxNames < 0 {
			return errors.New("invalid publisher bounds")
		}
		files := map[string]bool{}
		origins := map[string]bool{}
		for _, z := range cfg.Zones {
			if err = z.Validate(); err != nil {
				return err
			}
			if files[z.File] || origins[z.Origin] {
				return errors.New("duplicate managed zone/file")
			}
			files[z.File] = true
			origins[z.Origin] = true
		}
		if *noReload {
			if *watch {
				return errors.New("no-reload cannot be used with watch")
			}
			cfg.ReloadCommand = nil
		}
		if *watch && len(cfg.ReloadCommand) == 0 {
			return errors.New("watch mode requires reload_command")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		registry := &authoritative.Registry{RPC: cfg.RPC, Contract: cfg.Contract, ChainID: cfg.ChainID, MaxNames: cfg.MaxNames}
		publisher := authoritative.Publisher{Check: cfg.CheckCommand, Reload: cfg.ReloadCommand}
		sync := func() error {
			var failures []error
			for _, z := range cfg.Zones {
				work, stop := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
				snapshot, err := registry.Snapshot(work, z.Origin)
				if err == nil {
					var changed bool
					changed, err = publisher.Publish(work, z, snapshot)
					if err == nil {
						log.Printf("zone=%s block=%s registered=%t changed=%t", z.Origin, snapshot.BlockHash, snapshot.Registered, changed)
					}
				}
				stop()
				if err != nil {
					log.Printf("zone=%s keeping last validated zone: %v", z.Origin, err)
					failures = append(failures, fmt.Errorf("%s: %w", z.Origin, err))
				}
			}
			return errors.Join(failures...)
		}
		if err = sync(); !*watch {
			return err
		}
		ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				sync()
			}
		}
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
