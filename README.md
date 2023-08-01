# Make packets stuck in lockless pfifo_fast qdisc

When I read the discussion about [net: sched: fix packet stuck problem for lockless qdisc](https://lore.kernel.org/lkml/1620868260-32984-2-git-send-email-linyunsheng@huawei.com/) on Twitter, an idea lingered in my mind: why not use eBPF to reproduce the issue?

## Read the f\*\*king source code

Above all, I had to read the kernel source code to figure out how does the pfifo_fast qdisc work.

```c
__dev_queue_xmit()    // ${KERNEL}/net/core/dev.c
|-->__dev_xmit_skb() {
    |   if (q->flags & TCQ_F_NOLOCK) {
    |       rc = q->enqueue(skb, q, &to_free) & NET_XMIT_MASK;
    |       qdisc_run(q);
    |       if (unlikely(to_free))
    |           kfree_skb_list(to_free);
    |       return rc;
    |   }
    }
    |-->qdisc_run()   // ${KERNEL}/include/net/pkt_sched.h
        |-->qdisc_run_begin() {
        |       if (qdisc->flags & TCQ_F_NOLOCK) {
        |           if (!spin_trylock(&qdisc->seqlock))
        |               return false;
        |           WRITE_ONCE(qdisc->empty, false);
        |       }
        |   }
        |-->__qdisc_run() {  // ${KERNEL}/net/sched/sch_generic.c
        |   |   int quota = dev_tx_weight;
        |   |   int packets;
        |   |
        |   |   while (qdisc_restart(q, &packets)) {
        |   |       quota -= packets;
        |   |       if (quota <= 0) {
        |   |           __netif_schedule(q);
        |   |           break;
        |   |       }
        |   |   }
        |   }
        |   |-->qdisc_restart()
        |   |   |-->dequeue_skb()
        |   |   |   |-->trace_qdisc_dequeue()
        |   |   |-->sch_direct_xmit()
        |   |-->__netif_schedule()
        |-->qdisc_run_end() {
                if (qdisc->flags & TCQ_F_NOLOCK)
                    spin_unlock(&qdisc->seqlock);
            }
```

With this code snippet, the issue may be a little easy to reproduce by making a packet stuck in `sch_direct_xmit()`.

## Design the experiment

![Patckets stuck in pfifo_fast qdisc](./pkt-stucker.png)

The key is to make packets stuck between `sch_direct_xmit()` and `qdisc_run_end()`.

With eBPF `fexit` on `__qdisc_run`, it’s easy to cost some CPU.

Then, intervally, two `goroutine`s do send ICMP ECHO packets to do ping.

So, as expected, one packet should be stuck in `fexit` on `__qdisc_run`, and the other one should be enqueued and the packet handing should finish at `qdisc_run_begin()` then return early.

> The experiment environment:
>
> It’s a QEMU VM with Debian 11 (bullseye) system with 4 CPU.

```shell
# cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"

# uname -a
Linux hwang 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64 GNU/Linux

# llc --version
Homebrew LLVM version 15.0.7
  Optimized build.
  Default target: x86_64-apple-darwin22.5.0
  Host CPU: skylake

  Registered Targets:
    aarch64    - AArch64 (little endian)
    aarch64_32 - AArch64 (little endian ILP32)
    aarch64_be - AArch64 (big endian)
    amdgcn     - AMD GCN GPUs
    arm        - ARM
    arm64      - ARM64 (little endian)
    arm64_32   - ARM64 (little endian ILP32)
    armeb      - ARM (big endian)
    avr        - Atmel AVR Microcontroller
    bpf        - BPF (host endian)
    bpfeb      - BPF (big endian)
    bpfel      - BPF (little endian)
    hexagon    - Hexagon
    lanai      - Lanai
    mips       - MIPS (32-bit big endian)
    mips64     - MIPS (64-bit big endian)
    mips64el   - MIPS (64-bit little endian)
    mipsel     - MIPS (32-bit little endian)
    msp430     - MSP430 [experimental]
    nvptx      - NVIDIA PTX 32-bit
    nvptx64    - NVIDIA PTX 64-bit
    ppc32      - PowerPC 32
    ppc32le    - PowerPC 32 LE
    ppc64      - PowerPC 64
    ppc64le    - PowerPC 64 LE
    r600       - AMD GPUs HD2XXX-HD6XXX
    riscv32    - 32-bit RISC-V
    riscv64    - 64-bit RISC-V
    sparc      - Sparc
    sparcel    - Sparc LE
    sparcv9    - Sparc V9
    systemz    - SystemZ
    thumb      - Thumb
    thumbeb    - Thumb (big endian)
    ve         - VE
    wasm32     - WebAssembly 32-bit
    wasm64     - WebAssembly 64-bit
    x86        - 32-bit X86: Pentium-Pro and above
    x86-64     - 64-bit X86: EM64T and AMD64
    xcore      - XCore
```

## Expected packets behaviour

By sending two packets at the same time, one should be stuck and the other one
should be enqueued and handled later.

```bash
# ./pkt-stucker
2023/08/02 12:25:36.039502 Attached fentry(__qdisc_run)
2023/08/02 12:25:36.044562 Attached fexit(__qdisc_run)
2023/08/02 12:25:36.046461 Attached fexit(__dev_queue_xmit)
2023/08/02 12:25:36.048453 Attached fentry(__netif_schedule)
2023/08/02 12:25:36.051010 Attached fentry(__pfifo_fast_dequeue)
2023/08/02 12:25:36.053803 Attached fexit(__pfifo_fast_dequeue)
2023/08/02 12:25:36.056199 Attached fentry(__pfifo_fast_enqueue)
2023/08/02 12:25:36.058778 Attached fexit(__pfifo_fast_enqueue)
2023/08/02 12:25:36.061253 Attached fentry(__net_tx_action)
2023/08/02 12:25:36.064454 Attached fexit(__net_tx_action)
2023/08/02 12:25:36.067556 Attached fentry(__sch_direct_xmit)
2023/08/02 12:25:36.068366 Attached tracepoint(qdisc:qdisc_dequeue)
2023/08/02 12:25:36.068704 Attached tracepoint(net:net_dev_queue)
2023/08/02 12:25:36.071864 Ticking every 1s to send packets
2023/08/02 12:25:36.079277 Recving packets
2023/08/02 12:25:36.079529 Sending packets on CPU 3 in stuck1 netns
2023/08/02 12:25:36.080076 Recving packets
2023/08/02 12:25:36.084187 Sending packets on CPU 1 in stuck1 netns
2023/08/02 12:25:36.169146 Listening events...
2023/08/02 12:25:37.074156 Sent packet on CPU 1 with seq 100, cost 802.136µs
256 bytes from 192.168.1.2: icmp_seq=100 time=884.061µs
2023/08/02 12:25:37.074442 Sent packet on CPU 3 with seq 101, cost 456.139µs
256 bytes from 192.168.1.2: icmp_seq=101 time=593.867µs
2023/08/02 12:25:38.074116 Sent packet on CPU 3 with seq 103, cost 143.246µs
2023/08/02 12:25:38.075233 Sent packet on CPU 1 with seq 102, cost 1.558596ms
256 bytes from 192.168.1.2: icmp_seq=103 time=1.398867ms
256 bytes from 192.168.1.2: icmp_seq=102 time=1.719791ms
2023/08/02 12:25:39.073965 Sent packet on CPU 3 with seq 105, cost 106.51µs
2023/08/02 12:25:39.074483 Sent packet on CPU 1 with seq 104, cost 1.15002ms
256 bytes from 192.168.1.2: icmp_seq=104 time=1.332377ms
256 bytes from 192.168.1.2: icmp_seq=105 time=813.38µs
```

As the above log shows, the packets with seq 103 and 105 are stuck in the
`fexit` on `__qdisc_run` and the packets with seq 102 and 104 are enqueued and
handled later.

With the `trace_pipe` in another terminal, the packets behaviour is more clear.

```bash
# cat /sys/kernel/debug/tracing/trace_pipe
pkt-stucker-450580  [001] d... 67082.630302: bpf_trace_printk: handle_net_dev_queue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630499: bpf_trace_printk: fentry_pfifo_fast_enqueue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630502: bpf_trace_printk: fexit_pfifo_fast_enqueue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630505: bpf_trace_printk: fentry__qdisc_run on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630507: bpf_trace_printk: fentry_pfifo_fast_dequeue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630509: bpf_trace_printk: fexit_pfifo_fast_dequeue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630511: bpf_trace_printk: fentry_pfifo_fast_dequeue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630512: bpf_trace_printk: fexit_pfifo_fast_dequeue on CPU 1, seq: 104
pkt-stucker-450580  [001] d... 67082.630517: bpf_trace_printk: handle_qdisc_dequeue on CPU 1, seq: 104, packets: 1
pkt-stucker-450580  [001] d... 67082.630519: bpf_trace_printk: fentry_sch_direct_xmit on CPU 1
pkt-stucker-450580  [001] d... 67082.630525: bpf_trace_printk: fentry__netif_schedule on CPU 1, pid: 450571
pkt-stucker-450580  [001] d... 67082.630816: bpf_trace_printk: fexit__qdisc_run on CPU 1, seq: 104
pkt-stucker-450581  [003] d... 67082.630865: bpf_trace_printk: handle_net_dev_queue on CPU 3, seq: 105
pkt-stucker-450581  [003] d... 67082.630868: bpf_trace_printk: fentry_pfifo_fast_enqueue on CPU 3, seq: 105
pkt-stucker-450581  [003] d... 67082.630869: bpf_trace_printk: fexit_pfifo_fast_enqueue on CPU 3, seq: 105
pkt-stucker-450581  [003] d... 67082.630871: bpf_trace_printk: fexit__dev_queue_xmit on CPU 3, seq: 105
pkt-stucker-450580  [001] dN.. 67082.630885: bpf_trace_printk: fentry__netif_schedule on CPU 1, pid: 450571
pkt-stucker-450580  [001] dNs1 67082.630890: bpf_trace_printk: fentry__qdisc_run on CPU 1, seq: 0, from net_tx_action
pkt-stucker-450580  [001] dNs1 67082.630893: bpf_trace_printk: handle_qdisc_dequeue on CPU 1, seq: 105, packets: 1
pkt-stucker-450580  [001] dNs1 67082.630894: bpf_trace_printk: fentry_sch_direct_xmit on CPU 1
pkt-stucker-450580  [001] dNs1 67082.630896: bpf_trace_printk: fentry__netif_schedule on CPU 1, pid: 450571
pkt-stucker-450580  [001] dNs1 67082.631161: bpf_trace_printk: fexit__qdisc_run on CPU 1, seq: 105
ksoftirqd/1-18      [001] d.s. 67082.631252: bpf_trace_printk: fentry__qdisc_run on CPU 1, seq: 0, from net_tx_action
```

As the above log shows, the packets with seq 104 and 105 are handled by CPU 1.

However, the packet with seq 104 is handled in the context of sending the
packet. And the packet with seq 105 is handled in the context of `ksoftirqd/1`,
which is softirq **NET_TX_SOFTIRQ** context. That's because there is a packet
quota in `__qdisc_run()` to determine whether to schedule the softirq
**NET_TX_SOFTIRQ**, or try to dequeue from the `txq` again.

By imaging a MySQL case, for a packet of the MySQL request:

1. It's enqueued to the `txq`.
2. The quota has been drained.
3. A **NET_TX_SOFTIRQ** is scheduled.
4. But the **NET_TX_SOFTIRQ** is heavy to schedule to handle the packet.

As a result, the MySQL session behaves stuck.

## Run the demo

When the 4-CPUs VM prepares, run the demo:

```shell
# apt install -y git clang-15 llvm-15
# git clone https://github.com/Asphaltt/pkt-stucker.git
# cd pkt-stucker
# go generate
# go build
# bash setup-env.sh
# echo "bash clear-env.sh finally"
# ./pkt-stucker
#
# echo In another terminal
# cat /sys/kernel/debug/tracing/trace_pipe
```

## In conclusion

Wow, congrats, the packet stuck behaviour is reproduced.
