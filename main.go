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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gops/agent"
	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
)

//go:generate bpf2go -cc clang -no-global-types tp ./ebpf/tp-stuck-it.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

func main() {
	var tsDiff, single bool
	var remote, btfFile string
	flag.StringVarP(&remote, "remote", "r", "192.168.1.2", "remote address")
	flag.StringVarP(&btfFile, "btf", "b", "", "btf file")
	flag.BoolVarP(&tsDiff, "ts-diff", "t", false, "print timestamp diff")
	flag.BoolVarP(&single, "single", "s", false, "send one packet every time; send two packets every time otherwise")
	flag.Parse()

	if tsDiff {
		arg1, arg2 := flag.Args()[0], flag.Args()[1]
		ts1, _ := time.ParseDuration(arg1 + "ns")
		ts2, _ := time.ParseDuration(arg2 + "ns")
		fmt.Printf("%s - %s = %s\n", arg1, arg2, ts1-ts2)
		return
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ip, err := netip.ParseAddr(remote)
	if err != nil {
		log.Fatalf("Invalid remote address: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ping, err := newPinging(remote, single)
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

	var btfSpec *btf.Spec
	if btfFile != "" {
		btfSpec, err = btf.LoadSpec(btfFile)
		if err != nil {
			log.Fatalf("Failed to load btf spec: %v", err)
		}
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
			LogSize:     1000 * ebpf.DefaultVerifierLogSize,
			KernelTypes: btfSpec,
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

	tracings := []struct {
		prog *ebpf.Program
		name string
	}{
		{obj.FentryQdiscRun, "fentry(__qdisc_run)"},
		{obj.FexitQdiscRun, "fexit(__qdisc_run)"},
		{obj.FexitDevQueueXmit, "fexit(__dev_queue_xmit)"},
		{obj.FentryNetifSchedule, "fentry(__netif_schedule)"},
		{obj.FentryPfifoFastDequeue, "fentry(__pfifo_fast_dequeue)"},
		{obj.FexitPfifoFastDequeue, "fexit(__pfifo_fast_dequeue)"},
		{obj.FentryPfifoFastEnqueue, "fentry(__pfifo_fast_enqueue)"},
		{obj.FexitPfifoFastEnqueue, "fexit(__pfifo_fast_enqueue)"},
		{obj.FentryNetTxAction, "fentry(__net_tx_action)"},
		{obj.FexitNetTxAction, "fexit(__net_tx_action)"},
		{obj.FentrySchDirectXmit, "fentry(__sch_direct_xmit)"},
	}

	for _, t := range tracings {
		if link, err := link.AttachTracing(link.TracingOptions{
			Program: t.prog,
		}); err != nil {
			log.Printf("Failed to attach %s: %v", t.name, err)
			return
		} else {
			log.Printf("Attached %s", t.name)
			defer link.Close()
		}
	}

	if tp, err := link.Tracepoint("qdisc", "qdisc_dequeue", obj.HandleQdiscDequeue, nil); err != nil {
		log.Printf("Failed to attach tracepoint(qdisc:qdisc_dequeue): %v", err)
		return
	} else {
		log.Printf("Attached tracepoint(qdisc:qdisc_dequeue)")
		defer tp.Close()
	}

	if tp, err := link.Tracepoint("net", "net_dev_queue", obj.HandleNetDevQueue, nil); err != nil {
		log.Printf("Failed to attach tracepoint(net:net_dev_queue): %v", err)
		return
	} else {
		log.Printf("Attached tracepoint(net:net_dev_queue)")
		defer tp.Close()
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
		return handlePerfEvent(ctx, obj.Events, obj.StackMap)
	})

	if err := errg.Wait(); err != nil {
		log.Printf("Error: %v", err)
	} else {
		log.Printf("Done")
	}
}

func handlePerfEvent(ctx context.Context, events, stackMap *ebpf.Map) error {
	addrs, err := GetAddrs()
	if err != nil {
		log.Printf("Failed to get addrs: %v", err)
		return fmt.Errorf("get addrs: %w", err)
	}

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
		Saddr   [4]byte
		Daddr   [4]byte
		Type    evType
		Rand    uint32
		Seq     uint16
		CPU     uint16
		StackID int64
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

		// log.Printf("Event: %s, %s -> %s, CPU: %d, seq: %d, rand: %d", ev.Type,
		// 	netip.AddrFrom4(ev.Saddr), netip.AddrFrom4(ev.Daddr),
		// 	ev.CPU, ev.Seq, ev.Rand)

		if ev.StackID > 0 {
			const MaxStackDepth = 50
			type StackData struct {
				IPs [MaxStackDepth]uint64
			}

			var stack StackData
			if err := stackMap.Lookup(uint32(ev.StackID), &stack); err == nil {
				for _, ip := range stack.IPs {
					if ip > 0 {
						log.Printf("\t%s", addrs.findNearestSym(ip))
					}
				}
			} else {
				log.Printf("Failed to lookup stack: %v", err)
			}
		}

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
	evTypeNetDevEnqueue
	evTypeQdiscRun
	evTypeQdiscDequeue
	evTypeNetifSchedule
)

func (t evType) String() string {
	switch t {
	case evTypeDefault:
		return "default"
	case evTypeNetDevEnqueue:
		return "net_dev_enqueue"
	case evTypeQdiscRun:
		return "__qdisc_run"
	case evTypeQdiscDequeue:
		return "qdisc_dequeue"
	case evTypeNetifSchedule:
		return "__netif_schedule"
	default:
		return "unknown"
	}
}
