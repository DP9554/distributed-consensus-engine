# Distributed Consensus Engine

**Roll Number:** G25AI1018

A 5-node replicated ledger with two consensus modes, a Byzantine adversary, and chaos testing via Toxiproxy.

## Quick Start

```bash
# Run unit tests
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 tests/test_election.py
python3 tests/test_paxos.py
python3 tests/test_pbft.py
python3 tests/test_adversary.py

# Start cluster (PBFT mode)
docker compose up --build -d
docker compose run --rm client
docker compose logs | grep -E "COMMITTED-LOCAL|DROPPED|BYZANTINE"

# Chaos test
./tests/chaos_test.sh

# Cleanup
docker compose down -v
```

## Structure

- `src/node.py` — transport, leader election, Paxos, PBFT
- `src/adversary.py` — Byzantine node (equivocate/suppress/forge)
- `src/client.py` — concurrent transaction submitter
- `src/crypto_utils.py` — Ed25519 keygen, sign, verify
- `tests/` — election, Paxos, PBFT, adversary, chaos tests
- `docker-compose.yml` — 5 nodes + Toxiproxy + client
