#!/bin/bash
# Copyright 2023 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0


set -e

NS_STUCK1="stuck1"
NS_STUCK2="stuck2"

VETH_STUCK1="vstuck1"
VETH_STUCK2="vstuck2"

IP_STUCK1="192.168.1.1"
IP_STUCK2="192.168.1.2"

MAC_STUCK1="0a:0d:53:74:aa:11"
MAC_STUCK2="0a:0d:53:74:aa:12"

ip netns add $NS_STUCK1
ip netns add $NS_STUCK2

ip link add $VETH_STUCK1 numtxqueue 2 numrxqueue 2 type veth peer name $VETH_STUCK2 numtxqueue 2 numrxqueue 2

ip link set dev $VETH_STUCK1 netns $NS_STUCK1
ip netns exec $NS_STUCK1 bash -c "
ip link set dev $VETH_STUCK1 up
ip addr add $IP_STUCK1/24 dev $VETH_STUCK1
ip link set dev $VETH_STUCK1 address $MAC_STUCK1
ip neigh add dev ${VETH_STUCK1} ${IP_STUCK2} lladdr ${MAC_STUCK2} nud permanent
ip route add dev ${VETH_STUCK1} default via ${IP_STUCK2}
tc qdisc add dev ${VETH_STUCK1} root pfifo_fast
"

ip link set dev $VETH_STUCK2 netns $NS_STUCK2
ip netns exec $NS_STUCK2 bash -c "
ip link set dev $VETH_STUCK2 up
ip addr add $IP_STUCK2/24 dev $VETH_STUCK2
ip link set dev $VETH_STUCK2 address $MAC_STUCK2
ip neigh add dev ${VETH_STUCK2} ${IP_STUCK1} lladdr ${MAC_STUCK1} nud permanent
ip route add dev ${VETH_STUCK2} default via ${IP_STUCK1}
"

echo "To destroy the netns evn:"
echo "ip netns del $NS_STUCK1"
echo "ip netns del $NS_STUCK2"
echo "Done"
