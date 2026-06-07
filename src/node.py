"""
node.py
-------
Main consensus node daemon.

Implemented so far:
  * Async length-prefixed JSON/TCP transport (fire-and-forget messaging).
  * Task 1 - Raft-style leader election (terms, randomized timeouts,
    majority voting, heartbeats). The elected leader is the Paxos Proposer
    (Mode A) / PBFT Primary (Mode B). The monotonic `term` is also the
    PBFT `view` number.
  * Task 2 - Basic Paxos (Mode A): per-slot Prepare/Promise/Accept/Accepted,
    committing to an on-disk append-only ledger only once a majority accepts.

Hooks left for later steps:
  * Mode B: PBFT (Pre-prepare/Prepare/Commit) + signature verification.

The Node class is structured for subclassing: adversary.py overrides handlers
to inject Byzantine behaviour.
"""

import argparse
import asyncio
import hashlib
import json
import os
import random
import time
from enum import Enum

import crypto_utils as cu


class Role(Enum):
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


def now() -> float:
    return time.monotonic()


class Node:
    HEARTBEAT_INTERVAL = 0.5
    ELECTION_MIN = 1.5
    ELECTION_MAX = 3.0

    def __init__(self, node_id, peers, mode="paxos", data_dir="./data"):
        self.id = node_id
        self.peers = peers                 # {id: (host, port)} including self
        self.mode = mode
        self.data_dir = data_dir

        # --- Raft election state ---
        self.role = Role.FOLLOWER
        self.current_term = 0
        self.voted_for = None
        self.leader_id = None
        self.votes_received = set()
        self.last_heartbeat = now()
        self.election_timeout = self._rand_timeout()

        # --- Paxos state ---
        # committed ledger (the chosen value for each slot)
        self.committed = {}                # slot -> value
        self.next_slot = 0                 # leader's slot allocator
        # acceptor state (per slot)
        self.promised = {}                 # slot -> ballot  (highest promised)
        self.accepted = {}                 # slot -> (ballot, value)
        # proposer state (per slot)
        self.proposals = {}                # slot -> bookkeeping dict

        # --- PBFT state (Mode B) ---
        self.private_key = None            # our Ed25519 signing key
        self.public_keys = {}              # {id: public_key} manifest for verification
        self.pbft_seq = 0                  # primary's sequence allocator
        self.pbft_log = {}                 # (view, seq) -> {"digest", "txn"}
        self.pbft_prepares = {}            # (view, seq, digest) -> set(senders)
        self.pbft_commits = {}             # (view, seq, digest) -> set(senders)
        self.pbft_prepared = set()         # keys that reached the prepared certificate
        self.pbft_committed = set()        # keys that reached committed-local

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _rand_timeout(self):
        return random.uniform(self.ELECTION_MIN, self.ELECTION_MAX)

    def majority(self):
        return len(self.peers) // 2 + 1

    def is_leader(self):
        return self.role == Role.LEADER

    def _ballot(self):
        # Unique, monotonic per leader: (term, node_id). The term's leader is
        # unique, so no two proposers ever share a ballot. Compared as a list
        # lexicographically: [term, id] > [term', id'].
        return [self.current_term, self.id]

    # --- PBFT helpers ---
    def _f(self):
        """Max Byzantine faults tolerated: floor((n-1)/3). n=5 -> f=1."""
        return (len(self.peers) - 1) // 3

    def _quorum(self):
        """Prepared/commit certificate size: 2f+1. n=5 -> 3."""
        return 2 * self._f() + 1

    def _digest(self, txn):
        return hashlib.sha256(str(txn).encode()).hexdigest()[:16]

    def load_crypto(self, keys_dir):
        """Load our private key + everyone's public keys from a keys directory."""
        with open(os.path.join(keys_dir, "keys.json")) as f:
            allk = json.load(f)
        self.private_key = cu.load_private(allk[str(self.id)]["private"])
        self.public_keys = cu.load_manifest(os.path.join(keys_dir, "manifest.json"))

    def _sign(self, message):
        """Attach an Ed25519 signature (no-op if crypto disabled)."""
        if self.private_key is None:
            return message
        message = dict(message)
        message["signature"] = cu.sign_message(self.private_key, message)
        return message

    def _verify(self, message):
        """Verify a message's signature against the sender's public key."""
        if not self.public_keys:
            return True  # crypto disabled (e.g., Paxos mode)
        pub = self.public_keys.get(message.get("sender"))
        return pub is not None and cu.verify_message(pub, message)

    async def _pbft_broadcast(self, message):
        """Stamp sender, sign, and broadcast a PBFT message."""
        message["sender"] = self.id
        await self.broadcast(self._sign(message))

    def log_event(self, msg):
        print(
            f"[term={self.current_term:>2}] [N{self.id}] [{self.role.value:<9}] {msg}",
            flush=True,
        )

    # ------------------------------------------------------------------ #
    # Transport: fire-and-forget, one connection per message
    # ------------------------------------------------------------------ #
    async def send(self, target_id, message):
        message.setdefault("sender", self.id)
        host, port = self.peers[target_id]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            data = json.dumps(message).encode()
            writer.write(len(data).to_bytes(4, "big") + data)
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass  # peer crashed / partitioned -> drop. Consensus tolerates it.

    async def broadcast(self, message):
        await asyncio.gather(
            *[self.send(pid, dict(message)) for pid in self.peers if pid != self.id]
        )

    async def handle_conn(self, reader, writer):
        try:
            header = await reader.readexactly(4)
            length = int.from_bytes(header, "big")
            data = await reader.readexactly(length)
            await self.dispatch(json.loads(data.decode()))
        except Exception:
            pass
        finally:
            writer.close()

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #
    async def dispatch(self, msg):
        term = msg.get("term", 0)
        if term > self.current_term:          # universal Raft step-down rule
            if self.role != Role.FOLLOWER:
                self.log_event(f"saw higher term {term}, stepping down to follower")
            self.current_term = term
            self.voted_for = None
            self.role = Role.FOLLOWER

        handler = {
            "request_vote": self.on_request_vote,
            "vote": self.on_vote,
            "heartbeat": self.on_heartbeat,
            "paxos": self.on_paxos,
            "pbft": self.on_pbft,
            "client": self.on_client_request,
        }.get(msg.get("type"))
        if handler:
            await handler(msg)

    # ================================================================== #
    # TASK 1: Leader election (Raft-style)
    # ================================================================== #
    async def on_request_vote(self, msg):
        cand, term = msg["sender"], msg["term"]
        grant = False
        if term == self.current_term and self.voted_for in (None, cand):
            self.voted_for = cand
            grant = True
            self.last_heartbeat = now()
        await self.send(cand, {"type": "vote", "term": self.current_term, "granted": grant})
        self.log_event(f"vote {'GRANTED' if grant else 'denied '} -> N{cand} (term {term})")

    async def on_vote(self, msg):
        if self.role != Role.CANDIDATE or msg["term"] != self.current_term:
            return
        if msg.get("granted"):
            self.votes_received.add(msg["sender"])
            if len(self.votes_received) >= self.majority():
                await self.become_leader()

    async def start_election(self):
        self.role = Role.CANDIDATE
        self.current_term += 1
        self.voted_for = self.id
        self.votes_received = {self.id}
        self.last_heartbeat = now()
        self.election_timeout = self._rand_timeout()
        self.log_event(f"election timeout -> starting election for term {self.current_term}")
        await self.broadcast({"type": "request_vote", "term": self.current_term})

    async def become_leader(self):
        if self.role == Role.LEADER:
            return
        self.role = Role.LEADER
        self.leader_id = self.id
        self.log_event(
            f"*** ELECTED LEADER for term {self.current_term} (votes={sorted(self.votes_received)}) ***"
        )
        await self.send_heartbeats()

    async def on_heartbeat(self, msg):
        self.last_heartbeat = now()
        self.election_timeout = self._rand_timeout()
        self.leader_id = msg["sender"]
        if self.role != Role.FOLLOWER:
            self.log_event(f"recognizing N{msg['sender']} as leader, becoming follower")
            self.role = Role.FOLLOWER

    async def send_heartbeats(self):
        await self.broadcast({"type": "heartbeat", "term": self.current_term, "leader": self.id})

    # ================================================================== #
    # TASK 2: Basic Paxos (Mode A)
    # ================================================================== #
    async def on_client_request(self, msg):
        """Client transaction entry point."""
        txn = msg.get("txn")
        if self.mode == "pbft":
            if not self.is_leader():  # the elected leader is the PBFT primary
                if self.leader_id is not None and self.leader_id != self.id:
                    await self.send(self.leader_id, {"type": "client", "txn": txn})
                return
            await self._pbft_preprepare(txn)
            return
        # --- Paxos path (Mode A) ---
        if not self.is_leader():
            # Forward to the leader if we know who it is.
            if self.leader_id is not None and self.leader_id != self.id:
                await self.send(self.leader_id, {"type": "client", "txn": txn})
            return
        slot = self.next_slot
        self.next_slot += 1
        self.log_event(f"client txn '{txn}' -> Paxos round for slot {slot}")
        await self._propose(slot, txn)

    async def on_paxos(self, msg):
        if self.mode != "paxos":
            return
        handler = {
            "prepare": self._on_prepare,
            "promise": self._on_promise,
            "accept": self._on_accept,
            "accepted": self._on_accepted,
            "commit": self._on_commit,
        }.get(msg.get("phase"))
        if handler:
            await handler(msg)

    # ---- Proposer: Phase 1 (Prepare) ---------------------------------- #
    async def _propose(self, slot, value):
        b = self._ballot()
        self.proposals[slot] = {
            "ballot": b, "value": value,
            "promises": set(), "promise_data": [],
            "accepts": set(), "accept_sent": False, "done": False,
        }
        # The proposer is also an acceptor: count its own promise.
        ok, ab, av = self._acceptor_promise(slot, b)
        if ok:
            self._record_promise(slot, self.id, ab, av)
        self.log_event(f"PAXOS slot {slot}: PREPARE ballot={b}")
        await self.broadcast({"type": "paxos", "phase": "prepare", "slot": slot, "ballot": b})

    # ---- Acceptor: respond to Prepare with a Promise ------------------ #
    def _acceptor_promise(self, slot, ballot):
        cur = self.promised.get(slot)
        if cur is None or ballot > cur:
            self.promised[slot] = ballot
            ab, av = self.accepted.get(slot, (None, None))
            return True, ab, av
        return False, None, None

    async def _on_prepare(self, msg):
        slot, b = msg["slot"], msg["ballot"]
        ok, ab, av = self._acceptor_promise(slot, b)
        if ok:
            await self.send(msg["sender"], {
                "type": "paxos", "phase": "promise", "slot": slot,
                "ballot": b, "acc_ballot": ab, "acc_value": av,
            })

    # ---- Proposer: collect Promises, then Phase 2 (Accept) ------------ #
    def _record_promise(self, slot, sender, acc_ballot, acc_value):
        p = self.proposals.get(slot)
        if not p or p["done"] or sender in p["promises"]:
            return
        p["promises"].add(sender)
        p["promise_data"].append((acc_ballot, acc_value))

    async def _on_promise(self, msg):
        slot = msg["slot"]
        p = self.proposals.get(slot)
        if not p or p["done"] or msg["ballot"] != p["ballot"]:
            return
        self._record_promise(slot, msg["sender"], msg["acc_ballot"], msg["acc_value"])
        if len(p["promises"]) >= self.majority() and not p["accept_sent"]:
            p["accept_sent"] = True
            # Paxos safety: if any acceptor already accepted a value, we MUST
            # re-propose the one with the highest accepted ballot.
            chosen, best = p["value"], None
            for ab, av in p["promise_data"]:
                if ab is not None and (best is None or ab > best):
                    best, chosen = ab, av
            p["value"] = chosen
            self.log_event(f"PAXOS slot {slot}: majority promised -> ACCEPT value='{chosen}'")
            if self._acceptor_accept(slot, p["ballot"], chosen):
                p["accepts"].add(self.id)
            await self.broadcast({
                "type": "paxos", "phase": "accept", "slot": slot,
                "ballot": p["ballot"], "value": chosen,
            })
            await self._maybe_commit(slot)

    # ---- Acceptor: respond to Accept with Accepted -------------------- #
    def _acceptor_accept(self, slot, ballot, value):
        cur = self.promised.get(slot)
        if cur is None or ballot >= cur:
            self.promised[slot] = ballot
            self.accepted[slot] = (ballot, value)
            return True
        return False

    async def _on_accept(self, msg):
        slot, b, v = msg["slot"], msg["ballot"], msg["value"]
        if self._acceptor_accept(slot, b, v):
            await self.send(msg["sender"], {
                "type": "paxos", "phase": "accepted", "slot": slot, "ballot": b, "value": v,
            })

    # ---- Proposer: collect Accepted, then commit ---------------------- #
    async def _on_accepted(self, msg):
        slot = msg["slot"]
        p = self.proposals.get(slot)
        if not p or p["done"] or msg["ballot"] != p["ballot"]:
            return
        p["accepts"].add(msg["sender"])
        await self._maybe_commit(slot)

    async def _maybe_commit(self, slot):
        p = self.proposals.get(slot)
        if not p or p["done"]:
            return
        if len(p["accepts"]) >= self.majority():
            p["done"] = True
            self._commit(slot, p["value"])
            # Tell everyone the value is chosen so all replicas log it.
            await self.broadcast({"type": "paxos", "phase": "commit",
                                  "slot": slot, "value": p["value"]})

    # ---- Learner: commit to the on-disk ledger ------------------------ #
    async def _on_commit(self, msg):
        self._commit(msg["slot"], msg["value"])

    def _commit(self, slot, value):
        """Append to the on-disk ledger -- ONLY called once consensus is reached."""
        if slot in self.committed:
            return
        self.committed[slot] = value
        os.makedirs(self.data_dir, exist_ok=True)
        path = os.path.join(self.data_dir, f"ledger_N{self.id}.log")
        with open(path, "a") as f:
            f.write(json.dumps({"slot": slot, "value": value}) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.log_event(f"COMMIT slot {slot} = '{value}'  (consensus reached -> written to disk)")

    # ================================================================== #
    # TASK 3: PBFT (Mode B)
    # ================================================================== #
    # n = 3f+1 nodes tolerate f Byzantine faults. With n=5, f=1, and both the
    # prepared and commit certificates require a quorum of 2f+1 = 3 matching,
    # signed messages. Every message is Ed25519-signed; a message whose
    # signature does not verify against the sender's public key is dropped,
    # so a malicious node cannot forge or impersonate another replica.

    async def on_pbft(self, msg):
        if self.mode != "pbft":
            return
        if not self._verify(msg):
            self.log_event(f"DROPPED forged/unsigned {msg.get('phase')} from N{msg.get('sender')}")
            return
        handler = {
            "pre-prepare": self._on_preprepare,
            "prepare": self._on_prepare_pbft,
            "commit": self._on_commit_pbft,
        }.get(msg.get("phase"))
        if handler:
            await handler(msg)

    # ---- Phase 1: Pre-prepare (primary assigns a sequence number) ----- #
    async def _pbft_preprepare(self, txn):
        v, seq = self.current_term, self.pbft_seq
        self.pbft_seq += 1
        d = self._digest(txn)
        self.pbft_log[(v, seq)] = {"digest": d, "txn": txn}
        self.pbft_prepares.setdefault((v, seq, d), set()).add(self.id)  # pre-prepare = primary's vote
        self.log_event(f"PBFT PRE-PREPARE seq={seq} digest={d} txn='{txn}'")
        await self._pbft_broadcast({
            "type": "pbft", "phase": "pre-prepare",
            "view": v, "seq": seq, "digest": d, "txn": txn,
        })

    async def _on_preprepare(self, msg):
        v, seq, d, txn, sender = msg["view"], msg["seq"], msg["digest"], msg["txn"], msg["sender"]
        # Accept only from the expected primary, and only if the digest is honest.
        if sender != self.leader_id:
            self.log_event(f"DROPPED pre-prepare from non-primary N{sender}")
            return
        if self._digest(txn) != d:
            self.log_event(f"DROPPED pre-prepare seq={seq}: digest does not match txn (lying primary)")
            return
        key = (v, seq)
        if key in self.pbft_log and self.pbft_log[key]["digest"] != d:
            self.log_event(f"DROPPED conflicting pre-prepare for seq={seq} (equivocation)")
            return
        self.pbft_log[key] = {"digest": d, "txn": txn}
        pk = (v, seq, d)
        self.pbft_prepares.setdefault(pk, set()).update({sender, self.id})
        await self._pbft_broadcast({"type": "pbft", "phase": "prepare", "view": v, "seq": seq, "digest": d})
        await self._check_prepared(v, seq, d)

    # ---- Phase 2: Prepare (agree on ordering) ------------------------- #
    async def _on_prepare_pbft(self, msg):
        v, seq, d, sender = msg["view"], msg["seq"], msg["digest"], msg["sender"]
        self.pbft_prepares.setdefault((v, seq, d), set()).add(sender)
        await self._check_prepared(v, seq, d)

    async def _check_prepared(self, v, seq, d):
        key = (v, seq, d)
        if key in self.pbft_prepared:
            return
        if len(self.pbft_prepares.get(key, set())) >= self._quorum():
            self.pbft_prepared.add(key)
            self.pbft_commits.setdefault(key, set()).add(self.id)
            self.log_event(f"PBFT PREPARED seq={seq} ({self._quorum()} matching) -> broadcasting COMMIT")
            await self._pbft_broadcast({"type": "pbft", "phase": "commit", "view": v, "seq": seq, "digest": d})
            await self._check_committed(v, seq, d)

    # ---- Phase 3: Commit (agree to execute) --------------------------- #
    async def _on_commit_pbft(self, msg):
        v, seq, d, sender = msg["view"], msg["seq"], msg["digest"], msg["sender"]
        self.pbft_commits.setdefault((v, seq, d), set()).add(sender)
        await self._check_committed(v, seq, d)

    async def _check_committed(self, v, seq, d):
        key = (v, seq, d)
        if key in self.pbft_committed:
            return
        if len(self.pbft_commits.get(key, set())) >= self._quorum():
            self.pbft_committed.add(key)
            txn = self.pbft_log.get((v, seq), {}).get("txn")
            self.log_event(f"PBFT COMMITTED-LOCAL seq={seq} ({self._quorum()} matching) -> execute")
            self._commit(seq, txn)  # write to the same on-disk ledger, keyed by seq

    # ------------------------------------------------------------------ #
    # Background timers + server
    # ------------------------------------------------------------------ #
    async def election_timer(self):
        while True:
            await asyncio.sleep(0.1)
            if self.role != Role.LEADER and now() - self.last_heartbeat > self.election_timeout:
                await self.start_election()

    async def heartbeat_timer(self):
        while True:
            await asyncio.sleep(self.HEARTBEAT_INTERVAL)
            if self.role == Role.LEADER:
                await self.send_heartbeats()

    async def run(self):
        _, port = self.peers[self.id]
        server = await asyncio.start_server(self.handle_conn, "0.0.0.0", port)
        self.log_event(f"listening on 0.0.0.0:{port} | mode={self.mode} | cluster={sorted(self.peers)}")
        async with server:
            await asyncio.gather(
                server.serve_forever(),
                self.election_timer(),
                self.heartbeat_timer(),
            )


def parse_peers(spec):
    peers = {}
    for part in spec.split(","):
        pid, host, port = part.split(":")
        peers[int(pid)] = (host, int(port))
    return peers


def main():
    ap = argparse.ArgumentParser(description="Consensus node daemon.")
    ap.add_argument("--id", type=int, required=True)
    ap.add_argument("--peers", required=True, help="id:host:port,id:host:port,...")
    ap.add_argument("--mode", choices=["paxos", "pbft"], default="paxos")
    ap.add_argument("--data-dir", default="./data")
    ap.add_argument("--keys-dir", default="./keys", help="dir with keys.json + manifest.json (PBFT)")
    args = ap.parse_args()

    node = Node(args.id, parse_peers(args.peers), mode=args.mode, data_dir=args.data_dir)
    if args.mode == "pbft":
        node.load_crypto(args.keys_dir)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
