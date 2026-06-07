"""
test_adversary.py
-----------------
Task 4: run PBFT with a real Byzantine node (N4) and confirm the 4 honest
nodes still reach consensus on the CORRECT value -- under all three attacks.

Run:  python tests/test_adversary.py
"""

import asyncio
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_utils as cu              # noqa: E402
from node import Node, Role            # noqa: E402
from adversary import ByzantineNode    # noqa: E402

HONEST = [0, 1, 2, 3]
ADVERSARY = 4


def build_cluster(tmp, adversary_mode, n=5):
    keys = {i: cu.generate_keypair() for i in range(n)}
    manifest = {i: keys[i][1] for i in range(n)}
    nodes, down = {}, set()
    for i in range(n):
        d = os.path.join(tmp, f"n{i}")
        if i == ADVERSARY:
            node = ByzantineNode(i, {j: ("mem", j) for j in range(n)}, mode="pbft",
                                 data_dir=d, adversary_mode=adversary_mode)
        else:
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
    return nodes


async def run_attack(mode):
    tmp = tempfile.mkdtemp()
    try:
        nodes = build_cluster(tmp, mode)
        txn = "TRANSFER 100 A->B"
        await nodes[0].on_client_request({"txn": txn})
        # All honest nodes must commit the correct value.
        for i in HONEST:
            assert nodes[i].committed.get(0) == txn, \
                f"[{mode}] honest N{i} committed {nodes[i].committed.get(0)!r}"
        # No honest node ever commits the fake/malicious value.
        fake = nodes[ADVERSARY]._digest(f"MALICIOUS-{txn}")
        for i in HONEST:
            bad = [k for k in nodes[i].pbft_committed if k[2] == fake]
            assert not bad, f"[{mode}] honest N{i} committed a malicious value!"
        print(f"PASS [{mode}]: 4 honest nodes committed correct value; adversary contained")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def main():
    print("=== Byzantine adversary (N4) vs 4 honest nodes, PBFT n=5 f=1 ===\n")
    for mode in ["equivocate", "suppress", "forge"]:
        await run_attack(mode)
    print("\nALL ADVERSARY TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
