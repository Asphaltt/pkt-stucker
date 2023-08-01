# Copyright 2023 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0


set -e

NS_STUCK1="stuck1"
NS_STUCK2="stuck2"

ip netns del $NS_STUCK1
ip netns del $NS_STUCK2

sysctl -w net.core.dev_weight=64
