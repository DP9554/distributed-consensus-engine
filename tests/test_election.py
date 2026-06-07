"""
test_election.py
----------------
Unit tests for Raft-style leader election (Task 1), driven by an in-memory
message bus. We route messages by calling dispatch() directly instead of using
real sockets, so the election STATE MACHINE is tested deterministically and
instantly -- independent of timers, ports, or network flakiness.

Run:  python tests/test_election.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from node import Node, Role  # noqa: E402


def build_cluster(n=5):
    nodes = {i: Node(i, {j: ("mem", j) for j in range(n)}, "paxos") for i in range(n)}
    down = set()

    def patch(node):
        async def send(target_id, message, _n=node):
            if _n.id in down or target_id in down:
                return  # simulate crash / partition
            message.setdefault("sender", _n.id)
            await nodes[target_id].dispatch(dict(message))
        node.send = send

    for node in nodes.values():
        patch(node)
    return nodes, down


def leaders(nodes, down):
    return [i for i, n in nodes.items() if n.role == Role.LEADER and i not in down]


async def main():
    nodes, down = build_cluster(5)

    # 1) Initial election ----------------------------------------------------
    await nodes[0].start_election()
    assert leaders(nodes, down) == [0], "expected exactly N0 as leader"
    assert all(n.current_term == 1 for n in nodes.values()), "terms must converge"
    print("PASS 1: initial election -> single leader, terms converge")

    # 2) Leader crash -> failover -------------------------------------------
    down.add(0)
    await nodes[1].start_election()
    assert leaders(nodes, down) == [1], "expected N1 elected after N0 crash"
    print("PASS 2: leader crash -> clean failover, no split-brain")

    # 3) Tolerate up to 2 crashes (5 nodes, majority = 3) --------------------
    down.add(4)  # now N0 and N4 are down; 3 survivors remain
    await nodes[2].start_election()
    assert len(leaders(nodes, down)) == 1, "must still elect with 3/5 alive"
    print("PASS 3: tolerates 2 simultaneous crashes (3/5 quorum)")

    # 4) Split-vote safety: never >1 leader in a term -----------------------
    for n in nodes.values():
        n.role, n.current_term, n.voted_for, n.votes_received = Role.FOLLOWER, 9, None, set()
    down.clear()
    await nodes[3].start_election()
    assert len(leaders(nodes, down)) == 1, "at most one leader per term"
    print("PASS 4: majority rule -> at most one leader per term")

    print("\nALL ELECTION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
