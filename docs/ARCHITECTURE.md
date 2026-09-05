# Architecture

## Design Goals
- **Performance**: C11, minimal allocations, lock-free structures where possible.
- **Memory footprint**: < 10MB base per federated node; no heap leaks.
- **Federation**: Custom peer-to-peer protocol over TCP; nodes appear as homogeneous connection service.
- **Load balancing / HA**: Automatic peer discovery; nodes share user/channel state; clients reconnect to any available node.
- **Auto-scaling**: Nodes can spawn/shutdown based on connection load; federation protocol propagates state.

## Spec Targets
- RFC 1459 (base) — MUST
- Modern IRC (IRCv3) — tags, SASL, multi-prefix, message-id — SHOULD
- Federation handshake: `FEDERATE`, `SYNC`, `HEARTBEAT`

## CI / TDD
- `tests/` — unit tests (planned; will be wired up with CTest)
- `tests/benchmark/` — memory footprint + throughput (planned)
- CI runs on push/PR to `main` and feature branches
- `main` protected; merge via PR with passing CI workflow
