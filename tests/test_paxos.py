"""
test_paxos.py
-------------
Unit tests for Basic Paxos (Task 2), driven by an in-memory message bus.
Verifies: a full Prepare/Promise/Accept/Accepted round commits; all replicas
agree on slot->value and ordering; the on-disk ledger is written only on commit;
and consensus still succeeds with 2 of 5 nodes crashed (3/5 quorum).

Run:  python tests/test_paxos.py
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from node import Node, Role  # noqa: E402


def build_cluster(tmp, n=5):
    nodes, down = {}, set()
    for i in range(n):
        d = os.path.join(tmp, f"n{i}")
        nodes[i] = Node(i, {j: ("mem", j) for j in range(n)}, mode="paxos", data_dir=d)

    def patch(node):
        async def send(target_id, message, _n=node):
            if _n.id in down or target_id in down:
                return
            message.setdefault("sender", _n.id)
            await nodes[target_id].dispatch(dict(message))
        node.send = send

    for node in nodes.values():
        patch(node)
    # Pretend N0 won the election for term 1.
    for n_ in nodes.values():
        n_.current_term = 1
        n_.leader_id = 0
    nodes[0].role = Role.LEADER
    return nodes, down


def read_ledger(node):
    path = os.path.join(node.data_dir, f"ledger_N{node.id}.log")
    if not os.path.exists(path):
        return []
    return [json.loads(line) for line in open(path)]


async def main():
    tmp = tempfile.mkdtemp()
    try:
        nodes, down = build_cluster(tmp)

        # 1) Three transactions through the leader --------------------------
        for txn in ["SET x=10", "SET y=20", "DEL x"]:
            await nodes[0].on_client_request({"txn": txn})

        expected = {0: "SET x=10", 1: "SET y=20", 2: "DEL x"}
        for i, n in nodes.items():
            assert n.committed == expected, f"N{i} committed {n.committed}"
        print("PASS 1: all 5 replicas agree on slot->value")

        # 2) On-disk ledger written, in slot order, only committed entries ---
        for i, n in nodes.items():
            entries = read_ledger(n)
            slots = [e["slot"] for e in entries]
            assert slots == [0, 1, 2], f"N{i} disk ledger slots = {slots}"
        print("PASS 2: on-disk ledger written in order on every node")

        # 3) Forwarding: a follower forwards a client txn to the leader ------
        await nodes[3].on_client_request({"txn": "SET z=99"})
        assert all(n.committed.get(3) == "SET z=99" for n in nodes.values())
        print("PASS 3: follower forwards client request to leader")

        # 4) Tolerate 2 crashes (N3, N4 down) -> still commits via 3/5 -------
        down.update({3, 4})
        await nodes[0].on_client_request({"txn": "SET w=1"})
        survivors = [0, 1, 2]
        assert all(nodes[i].committed.get(4) == "SET w=1" for i in survivors)
        print("PASS 4: consensus survives 2 simultaneous crashes (3/5 quorum)")

        print("\nALL PAXOS TESTS PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
