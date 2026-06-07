#!/usr/bin/env bash
#
# chaos_test.sh - inject latency, partitions, and crashes while clients submit
# transactions. Demonstrates Task 5 (Docker networking & chaos testing).
#
# Prereqs:  docker compose up -d --build     (cluster already running)
# Usage:    ./tests/chaos_test.sh
#
set -u
API="http://localhost:8474"            # Toxiproxy HTTP API
PROXY="cluster_ingress"

hr() { printf '\n=== %s ===\n' "$1"; }
submit() { docker compose run --rm client; }

hr "0. Baseline: submit transactions through a healthy network"
submit

hr "1. LATENCY: inject 1500ms +/-300ms on the client ingress (Toxiproxy)"
curl -s -XPOST "$API/proxies/$PROXY/toxics" \
  -d '{"type":"latency","attributes":{"latency":1500,"jitter":300}}' >/dev/null
echo "latency toxic added; submitting under degraded network..."
submit
echo "removing latency toxic..."
curl -s -XDELETE "$API/proxies/$PROXY/toxics/latency_downstream" >/dev/null 2>&1 || true

hr "2. PARTITION (node crash): stop node3 + node4 -> 2 of 5 down"
docker compose stop node3 node4
sleep 3
echo "submitting during partition (majority node0/1/2 must still commit)..."
submit

hr "3. RECOVERY: restart node3 + node4"
docker compose start node3 node4
sleep 4
echo "submitting after recovery..."
submit

hr "4. INGRESS PARTITION via Toxiproxy: disable, then re-enable the proxy"
curl -s -XPOST "$API/proxies/$PROXY" -d '{"enabled":false}' >/dev/null
echo "ingress proxy DISABLED (client cut off from node0)"; sleep 2
curl -s -XPOST "$API/proxies/$PROXY" -d '{"enabled":true}'  >/dev/null
echo "ingress proxy RE-ENABLED"

hr "DONE"
echo "Inspect committed ledger entries with:"
echo "  docker compose logs node0 | grep COMMIT"
echo "  docker compose logs node0 | grep DROPPED      # (PBFT mode: adversary caught)"
