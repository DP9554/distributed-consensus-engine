"""
crypto_utils.py
---------------
Cryptographic primitives for the consensus engine.

We use Ed25519 (fast, small 32-byte keys, deterministic signatures) to sign
inter-node messages in PBFT. This is what lets honest nodes detect a Byzantine
peer that tries to forge a request or impersonate the primary: a message is
only accepted if its signature verifies against the *sender's* public key, and
only that node holds the matching private key.

Key distribution model (answer this in the report):
  - Keys are generated ONCE, ahead of time, by `generate_cluster_keys`.
  - Each node is given its own private key plus a manifest of ALL nodes'
    public keys (a trusted PKI bootstrap, mounted into each container).
  - Private keys never travel over the network; only signatures do.
"""

import json
import os
import argparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# --------------------------------------------------------------------------- #
# Key (de)serialization
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return a fresh (private_key, public_key) Ed25519 pair."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def serialize_private(priv) -> str:
    raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return raw.hex()


def serialize_public(pub) -> str:
    raw = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return raw.hex()


def load_private(hexstr: str):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hexstr))


def load_public(hexstr: str):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexstr))


# --------------------------------------------------------------------------- #
# Message signing / verification
# --------------------------------------------------------------------------- #
def _canonical(message: dict) -> bytes:
    """
    Deterministic byte encoding of a message, EXCLUDING the signature field.
    Both signer and verifier must agree byte-for-byte, so we sort keys and use
    compact separators.
    """
    payload = {k: v for k, v in message.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_message(priv, message: dict) -> str:
    """Return a hex signature over the canonical form of `message`."""
    return priv.sign(_canonical(message)).hex()


def verify_message(pub, message: dict) -> bool:
    """True iff message['signature'] is a valid signature by `pub`."""
    sig = message.get("signature")
    if not sig:
        return False
    try:
        pub.verify(bytes.fromhex(sig), _canonical(message))
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Cluster key bootstrap (PKI)
# --------------------------------------------------------------------------- #
def generate_cluster_keys(node_ids, out_dir):
    """
    Generate a keypair per node and write:
      - <out_dir>/keys.json   : {id: {"private": ..., "public": ...}}  (full)
      - <out_dir>/manifest.json: {id: public_hex}                      (public only)
    In Docker, mount keys.json read-only and have each node read only its own
    private key, while everyone shares manifest.json for verification.
    """
    os.makedirs(out_dir, exist_ok=True)
    keys = {}
    manifest = {}
    for nid in node_ids:
        priv, pub = generate_keypair()
        keys[str(nid)] = {
            "private": serialize_private(priv),
            "public": serialize_public(pub),
        }
        manifest[str(nid)] = serialize_public(pub)

    with open(os.path.join(out_dir, "keys.json"), "w") as f:
        json.dump(keys, f, indent=2)
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return keys, manifest


def load_manifest(path):
    """Load {id(int): public_key_object} from a manifest.json."""
    with open(path) as f:
        raw = json.load(f)
    return {int(k): load_public(v) for k, v in raw.items()}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate cluster keys for PBFT.")
    ap.add_argument("--nodes", type=int, default=5, help="number of nodes")
    ap.add_argument("--out", default="./keys", help="output directory")
    args = ap.parse_args()
    generate_cluster_keys(range(args.nodes), args.out)
    print(f"Wrote keys + manifest for {args.nodes} nodes to {args.out}/")
