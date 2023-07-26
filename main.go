// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gops/agent"
	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
)

//go:generate bpf2go -cc clang tp ./ebpf/tp-stuck-it.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

func main() {
	var remote string
	flag.StringVarP(&remote, "remote", "r", "", "remote address")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ip, err := netip.ParseAddr(remote)
	if err != nil {
		log.Fatalf("Invalid remote address: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ping, err := newPinging(remote)
	if err != nil {
		log.Fatalf("Failed to create pinging: %v", err)
	}
	defer ping.close()

	nsStuck1Ino, err := ping.stuck1NetnsIno()
	if err != nil {
		log.Fatalf("Failed to get stuck1 netns inode: %v", err)
	}
	_ = nsStuck1Ino

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	var randData [1 << 18]byte
	_, _ = rand.Read(randData[:])

	spec, err := loadTp()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"RAND":  randData[:],
		"RADDR": ip.As4(),
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	var obj tpObjects
	if err := spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 1000 * ebpf.DefaultVerifierLogSize,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer obj.Close()

	tps := []struct {
		category string
		name     string
		prog     *ebpf.Program
	}{
		// {"qdisc", "qdisc_dequeue", obj.HandleQdiscDequeue},
		{"net", "net_dev_start_xmit", obj.HandleNetDevStartXmit},
		{"net", "net_dev_xmit", obj.HandleNetDevXmit},
	}

	for _, tp := range tps {
		if link, err := link.Tracepoint(tp.category, tp.name, tp.prog, nil); err != nil {
			log.Printf("Failed to attach tracepoint(%s:%s)): %v", tp.category, tp.name, err)
			return
		} else {
			log.Printf("Attached tracepoint(%s:%s))", tp.category, tp.name)
			defer link.Close()
		}
	}

	agent.Listen(agent.Options{
		Addr:            ":6060",
		ShutdownCleanup: true,
	})

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		return ping.run(ctx)
	})

	errg.Go(func() error {
		return handlePerfEvent(ctx, obj.Events)
	})

	if err := errg.Wait(); err != nil {
		log.Printf("Error: %v", err)
	} else {
		log.Printf("Done")
	}
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) error {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader: %v", err)
		return fmt.Errorf("create perf-event reader: %w", err)
	}

	log.Printf("Listening events...")

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev struct {
		Saddr [4]byte
		Daddr [4]byte
		Type  evType
		Rand  uint32
	}
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		// log.Printf("Event: %s, %s -> %s, rand: %d", ev.Type,
		// 	netip.AddrFrom4(ev.Saddr), netip.AddrFrom4(ev.Daddr), ev.Rand)

		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

type evType uint32

const (
	evTypeDefault evType = iota
	evTypeQdiscDequeue
	evTypeNetDevStartXmit
	evTypeNetDevXmit
)

func (t evType) String() string {
	switch t {
	case evTypeDefault:
		return "default"
	case evTypeQdiscDequeue:
		return "qdisc_dequeue"
	case evTypeNetDevStartXmit:
		return "net_dev_start_xmit"
	case evTypeNetDevXmit:
		return "net_dev_xmit"
	default:
		return "unknown"
	}
}
