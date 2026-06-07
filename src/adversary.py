"""
adversary.py
------------
A Byzantine (malicious) node for Mode B testing (Task 4).

ByzantineNode subclasses the honest Node and overrides its PBFT behaviour to
break protocol in one of three ways (selected by --adversary-mode / env
ADVERSARY_MODE):

  * equivocate : during PREPARE, send CONFLICTING digests to different peers
                 (tell some peers value X, others value Y). This is the attack
                 plain signatures cannot stop -- the 2f+1 quorum rule must.
  * suppress   : stay completely silent (never send prepare/commit), like a
                 stealthy crash that still "exists".
  * forge      : try to impersonate another replica by stamping a different
                 sender id. Honest nodes verify the signature against THAT
                 node's public key, so the forgery is rejected.

In every case the 4 honest nodes (n=5, f=1) still reach the 2f+1=3 quorum on
the correct value, so the adversary cannot corrupt or stall consensus.
"""

import argparse
import asyncio
import os

import crypto_utils as cu
from node import Node, Role, parse_peers


class ByzantineNode(Node):
    def __init__(self, *args, adversary_mode="equivocate", **kwargs):
        super().__init__(*args, **kwargs)
        self.adversary_mode = adversary_mode

    async def _on_preprepare(self, msg):
        # We received a (valid, signed) pre-prepare from the honest primary.
        # Instead of behaving, we misbehave according to our mode.
        v, seq, d, txn = msg["view"], msg["seq"], msg["digest"], msg["txn"]

        if self.adversary_mode == "suppress":
            self.log_event(f"BYZANTINE[suppress]: going silent on seq={seq} (no prepare/commit)")
            return

        if self.adversary_mode == "forge":
            victim = (self.id + 1) % len(self.peers)
            forged = {"type": "pbft", "phase": "prepare", "view": v, "seq": seq,
                      "digest": d, "sender": victim}
            forged["signature"] = cu.sign_message(self.private_key, forged)  # our key, wrong identity
            self.log_event(f"BYZANTINE[forge]: sending PREPARE impersonating N{victim}")
            await self.broadcast(forged)
            return

        # default: equivocate -- conflicting digests to different peers
        fake_d = self._digest(f"MALICIOUS-{txn}")
        backups = [p for p in self.peers if p != self.id]
        for i, pid in enumerate(backups):
            chosen = d if (i % 2 == 0) else fake_d   # alternate real / fake
            m = {"type": "pbft", "phase": "prepare", "view": v, "seq": seq,
                 "digest": chosen, "sender": self.id}
            await self.send(pid, self._sign(m))
        self.log_event(f"BYZANTINE[equivocate]: seq={seq} real={d[:8]} vs fake={fake_d[:8]} to different peers")

    async def _check_prepared(self, v, seq, d):
        # Even if we somehow get "prepared" locally, suppress the commit.
        if self.adversary_mode == "suppress":
            return
        await super()._check_prepared(v, seq, d)


def main():
    ap = argparse.ArgumentParser(description="Byzantine adversary node.")
    ap.add_argument("--id", type=int, required=True)
    ap.add_argument("--peers", required=True)
    ap.add_argument("--data-dir", default="./data")
    ap.add_argument("--keys-dir", default="./keys")
    ap.add_argument("--adversary-mode",
                    default=os.environ.get("ADVERSARY_MODE", "equivocate"),
                    choices=["equivocate", "suppress", "forge"])
    args = ap.parse_args()

    node = ByzantineNode(args.id, parse_peers(args.peers), mode="pbft",
                         data_dir=args.data_dir, adversary_mode=args.adversary_mode)
    node.load_crypto(args.keys_dir)
    print(f"[N{args.id}] starting as BYZANTINE adversary (mode={args.adversary_mode})", flush=True)
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
