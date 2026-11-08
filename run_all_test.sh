#!/bin/bash
# run_all_test.sh - sets up the lab and opens one terminal per role.
#   ./run_all_test.sh        run the whole test   (run as your normal user, NOT with sudo)
#   ./run_all_test.sh stop   kill devices and remove the lab
# Needs: a graphical session (gnome-terminal / xterm / konsole / x-terminal-emulator) or tmux.

DIR="$(cd "$(dirname "$0")" && pwd)"
PSK='long-random-secret'
MSG='hello secure world'

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this as your normal user (it calls sudo itself)." >&2; exit 1
fi

if [ "${1:-}" = "stop" ]; then
    sudo pkill secure_device 2>/dev/null
    sudo pkill tcpdump 2>/dev/null
    sudo pkill nc 2>/dev/null
    sudo "$DIR/net_cleanup.sh"
    command -v tmux >/dev/null && tmux kill-session -t securetest 2>/dev/null
    exit 0
fi

# ---------- pick a way to open terminals ----------
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v gnome-terminal >/dev/null; then MODE=gnome
elif [ -n "${DISPLAY:-}" ] && command -v konsole >/dev/null; then MODE=konsole
elif [ -n "${DISPLAY:-}" ] && command -v xterm >/dev/null; then MODE=xterm
elif [ -n "${DISPLAY:-}" ] && command -v x-terminal-emulator >/dev/null; then MODE=xte
elif command -v tmux >/dev/null; then MODE=tmux
else echo "No terminal emulator or tmux found. Install one: sudo apt install xterm  (or tmux)"; exit 1; fi
echo "Terminal mode: $MODE"

open_term() {   # open_term "title" "command"
    local title="$1" cmd="cd '$DIR'; export SECURE_DEVICE_PSK='$PSK'; $2; echo; echo '[done - press Enter to close]'; read _"
    case $MODE in
        gnome)   gnome-terminal --title="$title" -- bash -c "$cmd" ;;
        konsole) konsole --new-tab -p tabtitle="$title" -e bash -c "$cmd" & ;;
        xterm)   xterm -T "$title" -e bash -c "$cmd" & ;;
        xte)     x-terminal-emulator -T "$title" -e bash -c "$cmd" & ;;
        tmux)
            if ! tmux has-session -t securetest 2>/dev/null; then
                tmux new-session -d -s securetest -n "$title" "bash -c \"$cmd\""
            else
                tmux new-window -t securetest -n "$title" "bash -c \"$cmd\""
            fi ;;
    esac
    sleep 0.5
}

sudo -v || exit 1

# ---------- 1. build ----------
cd "$DIR" || exit 1
rm -f test_packet secure_device
echo "=== Building and running unit test ==="
make test || { echo "Unit test failed"; exit 1; }
make device || { echo "Device build failed (install libnetfilter-queue-dev pkg-config)"; exit 1; }

# ---------- 2. lab ----------
echo "=== Creating lab ==="
sudo "$DIR/net_cleanup.sh" >/dev/null 2>&1
sudo "$DIR/net_config.sh" || { echo "net_config.sh failed"; exit 1; }

sudo ip netns exec pc1 ip link set veth-pc1 mtu 1400
sudo ip netns exec pc2 ip link set veth-pc2 mtu 1400
for i in "pc1 veth-pc1" "encoder veth-enc1" "encoder veth-enc2" "decoder veth-dec1" "decoder veth-dec2" "pc2 veth-pc2"; do
    set -- $i
    sudo ip netns exec "$1" ethtool -K "$2" tso off gso off gro off tx off rx off >/dev/null 2>&1
done
sudo modprobe nfnetlink_queue 2>/dev/null
sudo ip netns exec encoder iptables -A FORWARD -i veth-enc1 -o veth-enc2 -p tcp -j NFQUEUE --queue-num 10
sudo ip netns exec decoder iptables -A FORWARD -i veth-dec1 -o veth-dec2 -p tcp -j NFQUEUE --queue-num 20

echo "=== Ping check PC1 -> PC2 ==="
sudo ip netns exec pc1 ping -c 2 -W 2 10.0.3.2 || { echo "Ping failed - lab broken"; exit 1; }

# ---------- 3. terminals ----------
echo "=== Opening terminals ==="
open_term "T2 Device2 (decoder)" \
  "sudo -E ip netns exec decoder ./secure_device device2 - 40000 20"
sleep 2
open_term "T3 Device1 (encoder)" \
  "sudo -E ip netns exec encoder ./secure_device device1 10.0.2.1 40000 10"
sleep 3

open_term "T6 capture: PC1 side (plain)" \
  "sudo ip netns exec encoder tcpdump -ni veth-enc1 -v -A 'tcp port 5000'"
open_term "T7 capture: encoder->decoder (ENCRYPTED, +16 bytes)" \
  "sudo ip netns exec encoder tcpdump -ni veth-enc2 -v -A 'tcp port 5000'"
open_term "T8 capture: PC2 side (plain again)" \
  "sudo ip netns exec pc2 tcpdump -ni veth-pc2 -v -A 'tcp port 5000'"
sleep 2

open_term "T4 PC2 listener" \
  "rm -f /tmp/out.txt; echo 'Waiting for text on port 5000...'; sudo ip netns exec pc2 sh -c 'nc -l 5000 > /tmp/out.txt'; echo; echo '--- Received by PC2 ---'; cat /tmp/out.txt"
sleep 3

open_term "T5 PC1 sender" \
  "{ echo '$MSG'; for i in 1 2 3 4 5; do echo \"line \$i: the quick brown fox jumps over the lazy dog\"; done; head -c 3000 /dev/zero | tr '\\0' 'A'; echo; } > /tmp/in.txt;
   echo '--- Sending from PC1 ---'; cat /tmp/in.txt | cut -c1-80;
   sudo ip netns exec pc1 sh -c 'nc -q1 10.0.3.2 5000 < /tmp/in.txt'; sleep 2;
   echo; echo 'Hashes (must match):'; sha256sum /tmp/in.txt /tmp/out.txt;
   if cmp -s /tmp/in.txt /tmp/out.txt; then echo 'PASS: text identical'; else echo 'FAIL: text differs'; fi"

[ "$MODE" = tmux ] && echo "tmux session started: attach with 'tmux attach -t securetest' (Ctrl+b n = next window)"
echo
echo "All terminals launched. Check: T4 shows the message, T7 shows unreadable payload 16 bytes longer, T5 prints PASS."
echo "When done: ./run_all_test.sh stop"
