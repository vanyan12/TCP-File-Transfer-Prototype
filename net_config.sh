#!/bin/bash
set -e

echo "=== 1. Creating Network Namespaces ==="
ip netns add pc1
ip netns add encoder
ip netns add decoder
ip netns add pc2

echo "=== 2. Creating Veth Pairs (Virtual Cables) ==="
ip link add veth-pc1 type veth peer name veth-enc1
ip link add veth-enc2 type veth peer name veth-dec1
ip link add veth-dec2 type veth peer name veth-pc2

echo "=== 3. Moving Interfaces into Respective Namespaces ==="
ip link set veth-pc1 netns pc1
ip link set veth-enc1 netns encoder
ip link set veth-enc2 netns encoder
ip link set veth-dec1 netns decoder
ip link set veth-dec2 netns decoder
ip link set veth-pc2 netns pc2

echo "=== 4. Assigning IP Addresses ==="
ip netns exec pc1 ip addr add 10.0.1.1/24 dev veth-pc1
ip netns exec encoder ip addr add 10.0.1.2/24 dev veth-enc1
ip netns exec encoder ip addr add 10.0.2.2/24 dev veth-enc2
ip netns exec decoder ip addr add 10.0.2.1/24 dev veth-dec1
ip netns exec decoder ip addr add 10.0.3.1/24 dev veth-dec2
ip netns exec pc2 ip addr add 10.0.3.2/24 dev veth-pc2

echo "=== 5. Bringing All Interfaces UP ==="
for ns in pc1 encoder decoder pc2; do
    ip netns exec $ns ip link set lo up
done

ip netns exec pc1 ip link set veth-pc1 up
ip netns exec encoder ip link set veth-enc1 up
ip netns exec encoder ip link set veth-enc2 up
ip netns exec decoder ip link set veth-dec1 up
ip netns exec decoder ip link set veth-dec2 up
ip netns exec pc2 ip link set veth-pc2 up

echo "=== 6. Configuring Routing Tables for Packet Forwarding ==="
ip netns exec encoder sysctl -w net.ipv4.ip_forward=1 > /dev/null
ip netns exec decoder sysctl -w net.ipv4.ip_forward=1 > /dev/null

ip netns exec pc1 ip route add default via 10.0.1.2
ip netns exec pc2 ip route add default via 10.0.3.1

ip netns exec encoder ip route add 10.0.3.0/24 via 10.0.2.1 dev veth-enc2
ip netns exec decoder ip route add 10.0.1.0/24 via 10.0.2.2 dev veth-dec1

echo "Setup Complete! Network topology is ready."