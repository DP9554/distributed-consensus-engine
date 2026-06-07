"""
client.py
---------
Submits client transactions to the consensus cluster.

Each transaction is a fire-and-forget framed JSON message:
    {"type": "client", "txn": "<transaction string>"}

A node that is not the leader forwards the request to the current leader, so
the client may target ANY node (default: node 0). With --concurrent, all
transactions are sent at once across the cluster round-robin, exercising the
leader's slot-serialization (linearizability) under concurrent load.

Examples:
  python client.py --peers 0:127.0.0.1:9000,1:127.0.0.1:9001 --txn "SET x=42"
  python client.py --peers <map> --count 10 --concurrent
"""

import argparse
import asyncio
import json
import random


def parse_peers(spec):
    peers = {}
    for part in spec.split(","):
        pid, host, port = part.split(":")
        peers[int(pid)] = (host, int(port))
    return peers


async def submit(addr, txn):
    host, port = addr
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2.0
        )
        msg = json.dumps({"type": "client", "txn": txn}).encode()
        writer.write(len(msg).to_bytes(4, "big") + msg)
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        print(f"submitted '{txn}' -> {host}:{port}")
    except Exception as e:
        print(f"FAILED  '{txn}' -> {host}:{port} ({e})")


async def main():
    ap = argparse.ArgumentParser(description="Consensus client.")
    ap.add_argument("--peers", required=True, help="id:host:port,...")
    ap.add_argument("--node", type=int, default=0, help="target node id (default 0)")
    ap.add_argument("--txn", help="a single transaction to submit")
    ap.add_argument("--count", type=int, default=0, help="submit N generated transactions")
    ap.add_argument("--concurrent", action="store_true",
                    help="send all generated transactions at once (round-robin across nodes)")
    args = ap.parse_args()
    peers = parse_peers(args.peers)

    if args.txn:
        await submit(peers[args.node], args.txn)
        return

    txns = [f"txn-{i}-{random.randint(1000, 9999)}" for i in range(args.count or 5)]
    ids = sorted(peers)

    if args.concurrent:
        # Spread across nodes to exercise forwarding + leader serialization.
        tasks = [submit(peers[ids[i % len(ids)]], t) for i, t in enumerate(txns)]
        await asyncio.gather(*tasks)
    else:
        for t in txns:
            await submit(peers[args.node], t)
            await asyncio.sleep(0.2)


if __name__ == "__main__":
    asyncio.run(main())
