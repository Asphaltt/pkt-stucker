/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */


#include "bpf_all.h"

#include "jhash.h"

struct random_data {
    char data[1<<18];
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

// for net:net_dev_start_xmit
struct net_dev_start_xmit_ctx {
    __u64 unused;

    u32 name; // __data_loc char[] name;
    u16 queue_mapping;
    const void * skbaddr;
    bool vlan_tagged;
    u16 vlan_proto;
    u16 vlan_tci;
    u16 protocol;
    u8 ip_summed;
    unsigned int len;
    unsigned int data_len;
    int network_offset;
    bool transport_offset_valid;
    int transport_offset;
    u8 tx_flags;
    u16 gso_size;
    u16 gso_segs;
    u16 gso_type;
};

// for net:net_dev_xmit
struct net_dev_xmit_ctx {
    __u64 unused;

    void * skbaddr;
    unsigned int len;
    int rc;
    u32 name; //__data_loc char[] name;
};

enum __tp_type {
    TP_TYPE_DEFAULT = 0,
    TP_TYPE_QDISC_DEQUEUE,
    TP_TYPE_NET_DEV_START_XMIT,
    TP_TYPE_NET_DEV_XMIT,
};

typedef struct event {
    __be32 saddr, daddr;
    __u32 tp_type;
    __u32 rand;
} __attribute__((packed)) event_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, 4);
} events SEC(".maps");

static __noinline u32
__compute_hash(u32 initval)
{
    int i = 0;

    for (; i < sizeof(RAND.data)/12; i += 12)
        initval = jhash((void *)&(RAND.data[i]), 12, initval);

    i -= 12;
    if (i < sizeof(RAND.data))
        initval = jhash((void *)&(RAND.data[i]), sizeof(RAND.data) - i, initval);

    return initval;
}

// static __always_inline u32
// get_netns(struct sk_buff *skb) {
// 	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

// 	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
// 	if (netns == 0)	{
// 		struct sock *sk = BPF_CORE_READ(skb, sk);
// 		if (sk != NULL)	{
// 			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
// 		}
// 	}

// 	return netns;
// }

#define __skb_hdr(skb, header)                          \
    ({                                                  \
        unsigned char *head = BPF_CORE_READ(skb, head); \
        u16 offset = BPF_CORE_READ(skb, header);        \
        (head + offset);                                \
    })
#define __skb_l2_hdr(skb) __skb_hdr(skb, mac_header)
#define __skb_l3_hdr(skb) __skb_hdr(skb, network_header)
#define __skb_l4_hdr(skb) __skb_hdr(skb, transport_header)

static __always_inline bool
is_ipv4_proto(u16 proto)
{
    return proto == bpf_htons(ETH_P_IP);
}

static __always_inline __u16
__handle_pkt(void *ctx, struct sk_buff *skb, enum __tp_type type)
{
    struct ethhdr *eth;
    struct iphdr *iph;
    struct icmphdr *icmph;
    u8 one_byte;

    eth = (typeof(eth))(__skb_l2_hdr(skb));

    if (!is_ipv4_proto(BPF_CORE_READ(eth, h_proto)))
        return 0;

    iph = (typeof(iph))(eth + 1);
    bpf_probe_read(&one_byte, 1, iph);
    if ((one_byte >> 4) != 4)
        return 0;

    if (BPF_CORE_READ(iph, daddr) != RADDR)
        return 0;

    u8 proto = BPF_CORE_READ(iph, protocol);
    if (proto != IPPROTO_ICMP) {
        return 0;
    }

    icmph = (typeof(icmph)) (iph + 1);
    if (BPF_CORE_READ(icmph, type) != 8) {
        return 0;
    }

    __u16 seq = bpf_ntohs(BPF_CORE_READ(icmph, un.echo.sequence));

    event_t ev = {};

    ev.saddr = BPF_CORE_READ(iph, saddr);
    ev.daddr = BPF_CORE_READ(iph, daddr);
    ev.tp_type = (__u32)type;

    u32 rnd = bpf_get_prandom_u32();
    for (int i = 0; i < 5; i++)
        rnd = __compute_hash(rnd);
    ev.rand = rnd;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return seq;
}

SEC("tp/qdisc/qdisc_dequeue")
int handle_qdisc_dequeue(struct qdisc_dequeue_ctx *ctx)
{
    struct sk_buff *skb = (typeof(skb))ctx->skbaddr;

    u16 seq = __handle_pkt(ctx, skb, TP_TYPE_QDISC_DEQUEUE);

    if (seq)
        bpf_printk("qdisc_dequeue on CPU %u, seq: %d\n", bpf_get_smp_processor_id(), seq);

    return BPF_OK;
}

SEC("tp/net/net_dev_start_xmit")
int handle_net_dev_start_xmit(struct net_dev_start_xmit_ctx *ctx)
{
    struct sk_buff *skb = (typeof(skb))ctx->skbaddr;

    u16 seq = __handle_pkt(ctx, skb, TP_TYPE_NET_DEV_START_XMIT);

    if (seq)
        bpf_printk("net_dev_start_xmit on CPU %u, seq: %d, ts: %llu\n", bpf_get_smp_processor_id(), seq, bpf_ktime_get_ns());

    return BPF_OK;
}

SEC("tp/net/net_dev_xmit")
int handle_net_dev_xmit(struct net_dev_xmit_ctx *ctx)
{
    struct sk_buff *skb = (typeof(skb))ctx->skbaddr;

    u16 seq = __handle_pkt(ctx, skb, TP_TYPE_NET_DEV_XMIT);

    if (seq)
        bpf_printk("net_dev_xmit on CPU %u, seq: %d, ts: %llu\n", bpf_get_smp_processor_id(), seq, bpf_ktime_get_ns());

    return BPF_OK;
}