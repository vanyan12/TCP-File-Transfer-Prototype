#!/bin/bash
set -u

for ns in pc1 encoder decoder pc2; do
	ip netns del "$ns" 2>/dev/null || true
done

echo "Lab environment cleaned up successfully."