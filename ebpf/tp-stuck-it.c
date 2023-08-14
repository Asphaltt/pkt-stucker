/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bpf_all.h"

#include "jhash.h"

#define TCQ_F_NOLOCK		0x100 /* qdisc does not require locking */

struct random_data {
    char data[1 << 18];
};

static const volatile struct random_data RAND;

static const volatile __be32 RADDR;

// for qdisc:qdisc_dequeue
struct qdisc_dequeue_ctx {
    __u64 unused;

    struct Qdisc * qdisc;
    const struct netdev_queue * txq;
    int packets;
    void * skbaddr;
    int ifindex;
    u32 handle;
    u32 parent;
    unsigned long txq_state;
};

// for net:net_dev_queue
struct net_dev_queue_ctx {
    __u64 unused;

    void * skbaddr;
    __u32 len;
    __u32 name; // __data_loc char[] name;
};

struct pkt_info {
    struct sk_buff *skb;
    __be32 saddr;
    __be32 daddr;
    __u16 seq;
    __u16 pad;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct pkt_info);
    __uint(max_entries, 16);
} curr_pkt SEC(".maps");

enum __tp_type {
    TP_TYPE_DEFAULT = 0,
    TP_TYPE_NET_DEV_ENQUEUE,
    TP_TYPE_QDISC_RUN,
    TP_TYPE_QDISC_DEQUEUE,
    TP_TYPE_NETIF_SCHEDULE,
};

typedef struct event {
    __be32 saddr, daddr;
    __u32 tp_type;
    __u32 rand;
    __u16 seq;
    __u16 cpu;
    __s64 stack_id;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u16);
    __uint(max_entries, 1024);
} pkt_mark SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} net_tx_action_mark SEC(".maps");

#define MAX_STACK_DEPTH 50
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_map SEC(".maps");

static __always_inline u32
__get_stack_id(void *ctx)
{
    return bpf_get_stackid(ctx, &stack_map, BPF_F_FAST_STACK_CMP);
}

static __noinline u32 __compute_hash(u32 initval)
{
    int i = 0;

    for (; i < sizeof(RAND.data) / 12; i += 12)
        initval = jhash((void *)&(RAND.data[i]), 12, initval);

    i -= 12;
    if (i < sizeof(RAND.data))
        initval = jhash((void *)&(RAND.data[i]), sizeof(RAND.data) - i, initval);

    return initval;
}

static const char veth1[] = "vstuck1";

#define IFNAMSIZ 16

static __always_inline bool
__is_veth_veth1(struct net_device *dev)
{
    char name[IFNAMSIZ];
    bpf_probe_read(name, IFNAMSIZ, dev->name);
    return __builtin_memcmp(name, veth1, 8) == 0;
}

static __always_inline bool
__is_stuck_qdisc(struct Qdisc *qdisc)
{
    if (!qdisc)
        return false;

    struct net_device *dev = BPF_CORE_READ(qdisc, dev_queue, dev);
    return __is_veth_veth1(dev);
}

#define __skb_hdr(skb, header)                          \
    ({                                                  \
        unsigned char *head = BPF_CORE_READ(skb, head); \
        u16 offset = BPF_CORE_READ(skb, header);        \
        (head + offset);                                \
    })
#define __skb_l2_hdr(skb) __skb_hdr(skb, mac_header)
#define __skb_l3_hdr(skb) __skb_hdr(skb, network_header)
#define __skb_l4_hdr(skb) __skb_hdr(skb, transport_header)

static __always_inline bool is_ipv4_proto(u16 proto)
{
    return proto == bpf_htons(ETH_P_IP);
}

static __always_inline bool
__is_pkt(struct sk_buff *skb, struct pkt_info *pkt)
{
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    u8 one_byte;

    eth = (typeof(eth))(__skb_l2_hdr(skb));

    if (!is_ipv4_proto(BPF_CORE_READ(eth, h_proto)))
        return false;

    iph = (typeof(iph))(eth + 1);
    bpf_probe_read(&one_byte, 1, iph);
    if ((one_byte >> 4) != 4)
        return false;

    if (BPF_CORE_READ(iph, daddr) != RADDR)
        return false;

    u8 proto = BPF_CORE_READ(iph, protocol);
    if (proto != IPPROTO_UDP) {
        return false;
    }

    udph = (typeof(udph))(iph + 1);
    icmph = (typeof(icmph))(udph + 1);
    if (BPF_CORE_READ(icmph, type) != 8) {
        return false;
    }

    __u16 seq = bpf_ntohs(BPF_CORE_READ(icmph, un.echo.sequence));

    pkt->skb = skb;
    pkt->saddr = BPF_CORE_READ(iph, saddr);
    pkt->daddr = BPF_CORE_READ(iph, daddr);
    pkt->seq = seq;

    return true;
}

static __noinline u32
__consume_cpu(u32 rnd)
{
    rnd = rnd ? : bpf_get_prandom_u32();
    for (int i = 0; i < 5; i++)
        rnd = __compute_hash(rnd);
    return rnd;
}

static __always_inline __u16
__handle_pkt(void *ctx, struct pkt_info *pkt, enum __tp_type type, s64 stack_id)
{
    event_t ev = {};

    ev.saddr = pkt->saddr;
    ev.daddr = pkt->daddr;
    ev.tp_type = (__u32)type;
    ev.seq = pkt->seq;
    ev.stack_id = stack_id;
    ev.cpu = (__u16)bpf_get_smp_processor_id();

    u32 rnd = bpf_get_prandom_u32();
    // if (!stack_id)
    //     rnd = __consume_cpu(rnd);
    ev.rand = rnd;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return pkt->seq;
}

SEC("tp/net/net_dev_queue")
int handle_net_dev_queue(struct net_dev_queue_ctx *ctx)
{
    struct pkt_info pkt = {};
    struct sk_buff *skb = (typeof(skb))ctx->skbaddr;

    if (__is_pkt(skb, &pkt)) {
        u64 ids = bpf_get_current_pid_tgid();
        // u32 thread = (u32) ids;
        u32 pid = (u32) (ids >> 32);
        bpf_printk("handle_net_dev_queue on CPU %d, seq: %d, ts: %llu\n",
            bpf_get_smp_processor_id(), pkt.seq, bpf_ktime_get_ns());

        bpf_map_update_elem(&pkt_mark, &pid, &pkt.seq, BPF_ANY);
    }

    return BPF_OK;
}

SEC("fentry/sch_direct_xmit")
int BPF_PROG(fentry_sch_direct_xmit, struct sk_buff *skb, struct Qdisc *qdisc, struct net_device *dev)
{
    if (!__is_veth_veth1(dev))
        return BPF_OK;

    struct pkt_info *pkt = (typeof(pkt))bpf_map_lookup_elem(&curr_pkt, (const void *) &qdisc);
    u16 seq = pkt ? pkt->seq : 0;
    bpf_printk("fentry_sch_direct_xmit on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), seq);

    return BPF_OK;
}

SEC("fexit/__dev_queue_xmit")
int BPF_PROG(fexit__dev_queue_xmit, struct sk_buff *skb, struct net_device *sb_dev)
{
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!__is_veth_veth1(dev))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    // u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u16 *seq = bpf_map_lookup_and_delete(&pkt_mark, &pid);

    u16 _seq = seq ? *seq : 0;
    bpf_printk("fexit__dev_queue_xmit on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), _seq);

    return BPF_OK;
}

SEC("tp/qdisc/qdisc_dequeue")
int handle_qdisc_dequeue(struct qdisc_dequeue_ctx *ctx)
{
    struct pkt_info pkt = {};
    struct sk_buff *skb = (typeof(skb))ctx->skbaddr;

    if (__is_pkt(skb, &pkt)) {
        struct Qdisc *qdisc = ctx->qdisc;
        bpf_map_update_elem(&curr_pkt, &qdisc, &pkt, BPF_ANY);

        bpf_printk("handle_qdisc_dequeue on CPU %d, seq: %d, packets: %d\n",
            bpf_get_smp_processor_id(), pkt.seq, ctx->packets);
    }

    return BPF_OK;
}

SEC("fentry/__qdisc_run")
int BPF_PROG(fentry__qdisc_run, struct Qdisc *qdisc)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u32 cpu = bpf_get_smp_processor_id();

    u32 *val = bpf_map_lookup_elem(&net_tx_action_mark, &thread);
    bool is_net_tx_action = val && *val == 0;

    u16 *seq = bpf_map_lookup_elem(&pkt_mark, &pid);
    u16 _seq = seq ? *seq : 0;
    if (is_net_tx_action)
        bpf_printk("fentry__qdisc_run on CPU %d, seq: %d, next sched: %d, from net_tx_action\n",
            cpu, _seq, __is_stuck_qdisc(BPF_CORE_READ(qdisc, next_sched)));
    else
        bpf_printk("fentry__qdisc_run on CPU %d, seq: %d\n",
            cpu, _seq);

    return BPF_OK;
}

static const u8 __ksoftirqd_prefix[] = "ksoftirqd/";

static __always_inline bool
__is_ksoftirqd(void)
{
    u8 comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    return __builtin_memcmp(comm, __ksoftirqd_prefix, sizeof(__ksoftirqd_prefix) - 1) == 0;
}

SEC("fexit/__qdisc_run")
int BPF_PROG(fexit__qdisc_run, struct Qdisc *qdisc, int retval)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 volatile key = (u64)qdisc;
    struct pkt_info *pkt = (typeof(pkt))bpf_map_lookup_and_delete(&curr_pkt, (const void *) &key);
    u16 seq = pkt ? __handle_pkt(ctx, pkt, TP_TYPE_QDISC_RUN, 0) : 0;

    u64 ids = bpf_get_current_pid_tgid();
    u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    bpf_map_delete_elem(&pkt_mark, &pid);

    u32 *val = bpf_map_lookup_and_delete(&net_tx_action_mark, &thread);
    bool is_net_tx_action = val && *val == 0;

    u32 cpu = bpf_get_smp_processor_id();

    if (is_net_tx_action) {
        bool is_ksoftirqd = __is_ksoftirqd();
        if (is_ksoftirqd) {
            bpf_printk("fexit__qdisc_run on CPU %d, ts: %llu, from ksoftirqd\n",
                cpu, bpf_ktime_get_ns());
            // u32 rnd = __consume_cpu(0);
            u32 rnd = bpf_get_prandom_u32();
            bpf_printk("fexit__qdisc_run on CPU %d, ts: %llu, rnd: %lu, from ksoftirqd\n",
                cpu, bpf_ktime_get_ns(), rnd);
        } else {
            bpf_printk("fexit__qdisc_run on CPU %d, ts: %llu, from net_tx_action\n",
                cpu, bpf_ktime_get_ns());
            u32 rnd = __consume_cpu(0);
            bpf_printk("fexit__qdisc_run on CPU %d, ts: %llu, rnd: %lu, from net_tx_action\n",
                cpu, bpf_ktime_get_ns(), rnd);
        }
    } else
        bpf_printk("fexit__qdisc_run on CPU %d, seq: %d\n",
            cpu, seq);

    return BPF_OK;
}

SEC("fentry/__netif_schedule")
int BPF_PROG(fentry__netif_schedule, struct Qdisc *qdisc)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    // u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u16 *seq = bpf_map_lookup_elem(&pkt_mark, &pid);

    u16 _seq = seq ? *seq : 0;
    bpf_printk("fentry__netif_schedule on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), _seq);

    // struct pkt_info pkt = {};
    // pkt.seq = _seq;
    // u32 stack_id = __get_stack_id(ctx);
    // __handle_pkt(ctx, &pkt, TP_TYPE_NETIF_SCHEDULE, stack_id);

    return BPF_OK;
}

SEC("fentry/pfifo_fast_dequeue")
int BPF_PROG(fentry_pfifo_fast_dequeue, struct Qdisc *qdisc)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    // u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u16 *seq = bpf_map_lookup_elem(&pkt_mark, &pid);

    u16 _seq = seq ? *seq : 0;
    bpf_printk("fentry_pfifo_fast_dequeue on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), _seq);

    return BPF_OK;
}

SEC("fexit/pfifo_fast_dequeue")
int BPF_PROG(fexit_pfifo_fast_dequeue, struct Qdisc *qdisc)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    // u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u16 *seq = bpf_map_lookup_elem(&pkt_mark, &pid);

    u16 _seq = seq ? *seq : 0;
    bpf_printk("fexit_pfifo_fast_dequeue on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), _seq);

    return BPF_OK;
}

SEC("fentry/pfifo_fast_enqueue")
int BPF_PROG(fentry_pfifo_fast_enqueue, struct sk_buff *skb, struct Qdisc *qdisc)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    // u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u16 *seq = bpf_map_lookup_elem(&pkt_mark, &pid);

    u16 _seq = seq ? *seq : 0;
    bpf_printk("fentry_pfifo_fast_enqueue on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), _seq);

    return BPF_OK;
}

SEC("fexit/pfifo_fast_enqueue")
int BPF_PROG(fexit_pfifo_fast_enqueue, struct sk_buff *skb, struct Qdisc *qdisc)
{
    if (!__is_stuck_qdisc(qdisc))
        return BPF_OK;

    u64 ids = bpf_get_current_pid_tgid();
    // u32 thread = (u32) ids;
    u32 pid = (u32) (ids >> 32);
    u16 *seq = bpf_map_lookup_elem(&pkt_mark, &pid);

    u16 _seq = seq ? *seq : 0;
    bpf_printk("fexit_pfifo_fast_enqueue on CPU %d, seq: %d\n",
        bpf_get_smp_processor_id(), _seq);

    return BPF_OK;
}

SEC("fentry/net_tx_action")
int BPF_PROG(fentry_net_tx_action)
{
    u64 ids = bpf_get_current_pid_tgid();
    u32 thread = (u32) ids;
    u32 val = 0;
    bpf_map_update_elem(&net_tx_action_mark, &thread, &val, BPF_ANY);

    return BPF_OK;
}

SEC("fexit/net_tx_action")
int BPF_PROG(fexit_net_tx_action)
{
    u64 ids = bpf_get_current_pid_tgid();
    u32 thread = (u32) ids;
    bpf_map_delete_elem(&net_tx_action_mark, &thread);

    return BPF_OK;
}