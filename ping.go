// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/samber/lo"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type pinging struct {
	remote string
	conn   *icmp.PacketConn

	ids []int

	smu      sync.Mutex
	sendings map[int]time.Time

	nsMain   netns.NsHandle
	nsStuck1 netns.NsHandle
	nsStuck2 netns.NsHandle
}

func newPinging(remote string) (*pinging, error) {
	var p pinging

	var err error
	p.nsMain, err = netns.Get()
	if err != nil {
		return nil, fmt.Errorf("get current netns: %w", err)
	}

	p.nsStuck1, err = netns.GetFromName("stuck1")
	if err != nil {
		return nil, fmt.Errorf("get stuck1 netns: %w", err)
	}

	p.nsStuck2, err = netns.GetFromName("stuck2")
	if err != nil {
		return nil, fmt.Errorf("get stuck2 netns: %w", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := netns.Set(p.nsStuck1); err != nil {
		return nil, fmt.Errorf("set stuck1 netns: %w", err)
	}
	defer func() {
		if er := netns.Set(p.nsMain); er != nil {
			err = fmt.Errorf("set main netns: %W", er)
		}
	}()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("listen error: %w", err)
	}

	p.remote = remote
	p.conn = conn
	p.sendings = make(map[int]time.Time)

	return &p, nil
}

func (p *pinging) close() error {
	_ = p.nsMain.Close()
	_ = p.nsStuck1.Close()
	_ = p.nsStuck2.Close()
	return p.conn.Close()
}

func (p *pinging) stuck1NetnsIno() (uint32, error) {
	var s unix.Stat_t
	if err := unix.Fstat(int(p.nsStuck1), &s); err != nil {
		return 0, fmt.Errorf("fstat stuck1 netns: %w", err)
	}

	return uint32(s.Ino), nil
}

func (p *pinging) genID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (p *pinging) genData() []byte {
	var b [256]byte
	_, _ = rand.Read(b[:])
	return b[:]
}

func (p *pinging) run(ctx context.Context) error {
	ch1, ch2, ch3 := make(chan int, 1), make(chan int, 1), make(chan int, 1)

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		return p.runSending(ctx, ch1, ch2, ch3)
	})

	errg.Go(func() error {
		return p.recv(ctx)
	})

	errg.Go(func() error {
		p.tick(ctx, ch1, ch3)
		return nil
	})

	return errg.Wait()
}

const tickInterval = 20 * time.Millisecond

func (p *pinging) tick(ctx context.Context, ch1, ch3 chan int) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	log.Printf("Ticking every 10ms to send packets")

	var seq int = 100

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			ch1 <- seq
			seq += 2

		case <-ch3:
		}
	}
}

func (p *pinging) runSending(ctx context.Context, ch1, ch2, ch3 chan int) error {
	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		return p.send(ctx, 1, ch1, ch2)
	})

	errg.Go(func() error {
		return p.send(ctx, 3, ch2, ch3)
	})

	return errg.Wait()
}

func (p *pinging) send(ctx context.Context, cpu int, chIn, chOut chan int) error {
	remote, err := net.ResolveIPAddr("ip", p.remote)
	if err != nil {
		return fmt.Errorf("resolve remote address: %w", err)
	}

	// Ocupy the CPU
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// nsenter the netns
	if err := netns.Set(p.nsStuck1); err != nil {
		return fmt.Errorf("set stuck1 netns: %w", err)
	}
	defer func() {
		if er := netns.Set(p.nsMain); er != nil {
			err = fmt.Errorf("set main netns: %w", er)
		}
	}()

	// Set CPU affinity
	var cpuSet unix.CPUSet
	cpuSet.Set(cpu)
	if err := unix.SchedSetaffinity(0, &cpuSet); err != nil { // bind current thread to the CPU
		return fmt.Errorf("set affinity error: %w", err)
	}

	log.Printf("Sending packets on CPU %d in stuck1 netns", cpu)

	var msg icmp.Message
	msg.Type = ipv4.ICMPTypeEcho
	msg.Code = 0

	var echo icmp.Echo
	echo.ID = int(p.genID())
	echo.Data = p.genData()

	p.ids = append(p.ids, echo.ID)

	for {
		var seq int
		select {
		case <-ctx.Done():
			return nil

		case seq = <-chIn:
			select {
			case <-ctx.Done():
				return nil
			default:
				chOut <- seq + 1
			}
		}

		started := time.Now()

		echo.Seq = int(seq)
		msg.Body = &echo

		b, err := msg.Marshal(nil)
		if err != nil {
			return fmt.Errorf("marshal ICMP echo msg: %w", err)
		}

		p.smu.Lock()
		p.sendings[echo.Seq] = time.Now()
		p.smu.Unlock()

		if _, err := p.conn.WriteTo(b, remote); err != nil {
			return fmt.Errorf("write ICMP echo msg: %w", err)
		}

		log.Printf("Sent packet on CPU %d with seq %d, cost %s", cpu, echo.Seq, time.Since(started))
	}
}

func (p *pinging) recv(ctx context.Context) error {
	var b [1500]byte

	log.Printf("Recving packets")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, peer, err := p.conn.ReadFrom(b[:])
		if err != nil {
			return fmt.Errorf("read ICMP echo reply msg: %w", err)
		}

		if peer.String() != p.remote {
			log.Printf("Dropped by wrong peer")
			continue
		}

		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b[:n])
		if err != nil {
			return fmt.Errorf("parse ICMP echo reply msg: %w", err)
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			log.Printf("Dropped by wrong type")
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			log.Printf("Dropped by wrong body")
			continue
		}

		if !lo.Contains(p.ids, echo.ID) {
			log.Printf("Dropped by missing ID; %d not in %v", echo.ID, p.ids)
			continue
		}

		p.smu.Lock()
		t, ok := p.sendings[echo.Seq]
		delete(p.sendings, echo.Seq)
		p.smu.Unlock()
		if !ok {
			log.Printf("Dropped by missing sending time")
			continue
		}

		cost := time.Since(t)

		if cost > tickInterval {
			fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v (Bingo)\n", n-8, p.remote, echo.Seq, cost)
			return fmt.Errorf("found a packet cost %s", cost)
		}

		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n", n-8, p.remote, echo.Seq, cost)
	}
}
