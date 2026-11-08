# 🔒 TCP File Transfer & Transparent Encryption Pipeline

[![C Standard](https://img.shields.io/badge/C-C11%2FC17-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20DH%202048-orange.svg)](https://www.openssl.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20NFQUEUE-red.svg)](https://netfilter.org/projects/libnetfilter_queue/)

A high-performance, transparent in-line encryption and file transfer security system built in C. The project leverages **Linux Netfilter Queues (NFQUEUE)** and **OpenSSL** to intercept, encrypt, decrypt, and re-checksum TCP network payloads on the fly between network namespaces without requiring modification to endpoint applications.

---

## 📸 Architecture & Network Topology

The lab setup operates inside isolated Linux network namespaces, mimicking an intermediate bump-in-the-wire encryption pipeline:

```
+----------------+          +-------------------+          +-------------------+          +----------------+
|   Host PC1     |          |  Encoder Device   |          |  Decoder Device   |          |   Host PC2     |
|  (10.0.1.1)    | <======> |  (10.0.1.2/2.2)   | <======> |  (10.0.2.1/3.1)   | <======> |  (10.0.3.2)    |
|  Cleartext     |          |  Encrypted Channel|          |  Decrypted Channel|          |  Cleartext     |
+----------------+          +-------------------+          +-------------------+          +----------------+
                             [ NFQUEUE Intercept ]          [ NFQUEUE Intercept ]
```

### Key Workflow Overview
1. **Packet Capture:** `PC1` sends TCP packets intended for `PC2`.
2. **Inline Encryption:** The **Encoder** intercepts TCP traffic via `NFQUEUE`, encrypts the payload using **AES-256-GCM**, appends an authentication tag (+16 bytes), adjusts IP/TCP headers, recalculates the RFC 1071 checksums, and forwards the packet.
3. **Inline Decryption:** The **Decoder** receives the encrypted packet via `NFQUEUE`, verifies the GCM authentication tag, decrypts the payload (-16 bytes), recalculates header lengths & checksums, and delivers cleartext to `PC2`.

---

## ✨ Features

* **Transparent Packet Inspection & Modification:** Intercepts traffic at Layer 3/4 using Linux `libnetfilter_queue`.
* **Authenticated Encryption:** AES-256-GCM authenticated payload protection with replay protection windows.
* **Secure Key Exchange:** Authenticated Diffie-Hellman 2048-bit (Group 14) exchange with HKDF-SHA256 key derivation.
* **On-the-Fly Checksum Calculation:** Full zero-copy RFC 1071 IP and TCP header checksum recalculation logic in raw C.
* **Automated Network Virtualization:** Complete virtual network infrastructure setup using standard Linux `ip netns` bash scripts.

---

## 🛠️ Project Structure

| File | Description |
| :--- | :--- |
| `src/secure_device.c` | Main application entry point managing control connections, NFQUEUE processing, and state machine. |
| `src/crypto.c` / `include/crypto.h` | OpenSSL integration for AES-256-GCM, DH key exchange, and HKDF key derivation. |
| `src/packet.c` / `include/packet.h` | TCP packet parsing, AAD extraction, and payload transformation engine. |
| `src/checksum.c` / `include/checksum.h` | IP/TCP packet validation and RFC 1071 checksum repair library. |
| `tests/test_packet.c` | Unit and integration test suite validating payload round-trip crypto and checksum integrity. |
| `scripts/net_config.sh` | Bash script setting up 4 namespaces, veth pairs, routing tables, and IP addresses. |
| `scripts/net_cleanup.sh` | Teardown script removing all created network namespaces. |
| `Makefile` | Build configuration file for compilation and testing. |

---

## 🚀 Quick Start Guide

### 1. Prerequisites

Ensure you have the required development packages installed (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libnetfilter-queue-dev iptables
```

### 2. Compilation

Build both the executable and test binaries using `make`:

```bash
make
```

To run internal unit tests and verify crypto round-tripping:

```bash
make test
```

---

## 🧪 Running the Network Lab Environment

### Step 1: Initialize the Virtual Network Infrastructure

Execute the setup script with root privileges to configure the network namespaces (`pc1`, `encoder`, `decoder`, `pc2`):

```bash
sudo ./scripts/net_config.sh
```

### Step 2: Configure NFQUEUE Rules

Reroute outgoing TCP packets inside the `encoder` and incoming TCP packets inside the `decoder` to `NFQUEUE`:

```bash
# Intercept traffic on Encoder (Queue 0)
sudo ip netns exec encoder iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0

# Intercept traffic on Decoder (Queue 0)
sudo ip netns exec decoder iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0
```

### Step 3: Run the In-line Secure Devices

Set a shared Pre-Shared Key (PSK) and start the secure device services inside their respective namespaces:

```bash
# Terminal 1: Start Decoder (device2) first to listen for control connections
sudo SECURE_DEVICE_PSK="SecretKey123" ip netns exec decoder ./secure_device device2 - 8080 0

# Terminal 2: Start Encoder (device1) to initiate handshake with Decoder
sudo SECURE_DEVICE_PSK="SecretKey123" ip netns exec encoder ./secure_device device1 10.0.2.1 8080 0
```

### Step 4: Verify File Transfer & Communication

Open a receiver on `PC2` and transmit data from `PC1`:

```bash
# Terminal 3: Listen on PC2
sudo ip netns exec pc2 nc -l -p 9000

# Terminal 4: Send file or text from PC1
sudo ip netns exec pc1 sh -c 'echo "Hello Secure World!" | nc 10.0.3.2 9000'
```

---

## 🧹 Cleanup

To safely tear down the virtual interfaces and network namespaces:

```bash
sudo ./scripts/net_cleanup.sh
make clean
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.