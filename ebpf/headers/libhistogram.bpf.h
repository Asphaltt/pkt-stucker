// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

#ifndef __LIBHISTOGRAM_BPF_H_
#define __LIBHISTOGRAM_BPF_H_

#include "bits.bpf.h"
#include "maps.bpf.h"

static __always_inline void
update_hist_map(int index, __u64 delta);

#define MAX_SLOTS 36

struct hist {
    __u64 slots[MAX_SLOTS];
};

#define def_hist(name, capacity)                                                    \
    struct {                                                                        \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                           \
        __type(key, __u32);                                                         \
        __type(value, struct hist);                                                 \
        __uint(max_entries, capacity);                                              \
    } name SEC(".maps");                                                            \
                                                                                    \
    static __always_inline void                                                     \
    update_hist_map(int index, __u64 delta)                                         \
    {                                                                               \
        struct hist initial_hist = {};                                              \
        struct hist *hp = bpf_map_lookup_or_try_init(&name, &index, &initial_hist); \
        if (!hp)                                                                    \
            return;                                                                 \
                                                                                    \
        __u64 slot = log2l(delta);                                                  \
        if (slot >= MAX_SLOTS)                                                      \
            slot = MAX_SLOTS - 1;                                                   \
        __sync_fetch_and_add(&hp->slots[slot], 1);                                  \
    }

#endif // __LIBHISTOGRAM_BPF_H_
