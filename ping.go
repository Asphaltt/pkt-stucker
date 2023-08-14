// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"syscall"
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
	udpLis *net.UDPConn

	ids []int

	smu      sync.Mutex
	sendings map[int]time.Time

	singleSend bool

	nsMain   netns.NsHandle
	nsStuck1 netns.NsHandle
	nsStuck2 netns.NsHandle
}

func newPinging(remote string, single bool) (*pinging, error) {
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
	if err := netns.Set(p.nsStuck2); err != nil {
		return nil, fmt.Errorf("set stuck1 netns: %w", err)
	}
	defer func() {
		if er := netns.Set(p.nsMain); er != nil {
			err = fmt.Errorf("set main netns: %W", er)
		}
	}()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 2345})
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	p.remote = remote
	p.udpLis = conn
	p.sendings = make(map[int]time.Time)
	p.singleSend = single

	return &p, nil
}

func (p *pinging) close() error {
	_ = p.nsMain.Close()
	_ = p.nsStuck1.Close()
	_ = p.nsStuck2.Close()
	return p.udpLis.Close()
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
		return p.listen(ctx)
	})

	errg.Go(func() error {
		return p.runSending(ctx, ch1, ch2, ch3)
	})

	errg.Go(func() error {
		p.tick(ctx, ch1, ch3)
		return nil
	})

	return errg.Wait()
}

const tickInterval = 1000 * time.Millisecond

func (p *pinging) tick(ctx context.Context, ch1, ch3 chan int) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	log.Printf("Ticking every %s to send packets", tickInterval)

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
		return p.send(ctx, 1, 0, ch1, ch2)
	})

	if p.singleSend {
		errg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ch2:
				}
			}
		})
	} else {
		errg.Go(func() error {
			return p.send(ctx, 3, 1, ch2, ch3)
		})
	}

	return errg.Wait()
}

func (p *pinging) send(ctx context.Context, cpu, tos int, chIn, chOut chan int) error {
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

	dialer := net.Dialer{}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		})
		return err
	}

	c, err := dialer.DialContext(ctx, "udp", fmt.Sprintf("%s:2345", remote.IP.String()))
	if err != nil {
		return fmt.Errorf("dial UDP: %w", err)
	}
	defer c.Close()

	conn := c.(*net.UDPConn)
	go p.recv(ctx, conn)

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

		if cpu == 3 {
			time.Sleep(10 * time.Microsecond)
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

		if _, err := conn.Write(b); err != nil {
			return fmt.Errorf("write ICMP echo msg: %w", err)
		}

		log.Printf("Sent packet on CPU %d with seq %d, cost %s", cpu, echo.Seq, time.Since(started))
	}
}

func (p *pinging) recv(ctx context.Context, conn *net.UDPConn) error {
	var b [1500]byte

	log.Printf("Recving packets")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := conn.Read(b[:])
		if err != nil {
			return fmt.Errorf("read ICMP echo reply msg: %w", err)
		}

		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b[:n])
		if err != nil {
			return fmt.Errorf("parse ICMP echo reply msg: %w", err)
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

func (p *pinging) listen(ctx context.Context) error {
	var buf [1500]byte

	for {
		n, remote, err := p.udpLis.ReadFromUDP(buf[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			log.Printf("Read UDP packet: %v", err)
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_, _ = p.udpLis.WriteToUDP(buf[:n], remote)
	}
}
