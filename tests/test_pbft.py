"""
test_pbft.py
------------
Unit tests for PBFT (Task 3), driven by an in-memory message bus with REAL
Ed25519 signatures. Verifies: an honest 5-node run drives a request through
Pre-prepare -> Prepare -> Commit and commits with a 2f+1=3 quorum on every
node; and that a message with a bad/forged signature is rejected.

Run:  python tests/test_pbft.py
"""

import asyncio
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_utils as cu          # noqa: E402
from node import Node, Role        # noqa: E402


def build_cluster(tmp, n=5):
    nodes, down = {}, set()
    keys = {i: cu.generate_keypair() for i in range(n)}
    manifest = {i: keys[i][1] for i in range(n)}
    for i in range(n):
        d = os.path.join(tmp, f"n{i}")
        node = Node(i, {j: ("mem", j) for j in range(n)}, mode="pbft", data_dir=d)
        node.private_key = keys[i][0]
        node.public_keys = manifest
        node.current_term = 1
        node.leader_id = 0
        nodes[i] = node

    def patch(node):
        async def send(target_id, message, _n=node):
            if _n.id in down or target_id in down:
                return
            message.setdefault("sender", _n.id)
            await nodes[target_id].dispatch(dict(message))
        node.send = send

    for node in nodes.values():
        patch(node)
    nodes[0].role = Role.LEADER
    return nodes, down


async def main():
    tmp = tempfile.mkdtemp()
    try:
        nodes, down = build_cluster(tmp)

        # 1) Honest run: one request through all three phases ---------------
        await nodes[0].on_client_request({"txn": "SET balance=500"})
        for i, n in nodes.items():
            assert n.committed.get(0) == "SET balance=500", f"N{i} did not commit"
        print(f"PASS 1: all 5 nodes committed via PBFT (quorum 2f+1 = {nodes[0]._quorum()})")

        # 2) Every committed node holds a 2f+1 commit certificate -----------
        for i, n in nodes.items():
            key = (1, 0, n._digest("SET balance=500"))
            assert len(n.pbft_commits[key]) >= n._quorum()
        print("PASS 2: each node holds a >=2f+1 signed commit certificate")

        # 3) Forged message rejected ----------------------------------------
        victim = nodes[2]
        before = len(victim.pbft_prepares.get((1, 99, victim._digest("HACK")), set()))
        forged = {"type": "pbft", "phase": "prepare", "view": 1, "seq": 99,
                  "digest": victim._digest("HACK"), "sender": 1,
                  "signature": "00" * 64}  # invalid signature
        await victim.dispatch(forged)
        after = len(victim.pbft_prepares.get((1, 99, victim._digest("HACK")), set()))
        assert after == before, "forged message must not be counted"
        print("PASS 3: message with invalid signature is dropped (no spoofing)")

        # 4) Tampered (post-signing) message rejected -----------------------
        good = nodes[1]._sign({"type": "pbft", "phase": "prepare", "view": 1,
                               "seq": 0, "digest": nodes[1]._digest("SET balance=500"),
                               "sender": 1})
        good["digest"] = "tampered_digest"   # break integrity after signing
        assert victim._verify(good) is False
        print("PASS 4: tampering invalidates the signature")

        print("\nALL PBFT TESTS PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
