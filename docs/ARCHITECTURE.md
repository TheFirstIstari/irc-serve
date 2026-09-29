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

## Verified Implementation Status

Verified against actual repo files (no stubs):
- RFC 1459 commands observable contracts: `tests/protocol/test_rfc1459_parse.c` (token count, rejection), `tests/protocol/test_rfc1459_invalid.c`, `tests/protocol/test_nick_user.c`, `tests/protocol/test_multi_prefix.c`. Source: `src/protocol_parse.c` (real, zero stubs).
- IRCv3 tags / SASL observable: `src/ircv3_tags.c` (tags_parse/tags_serialize observable), `src/sasl_framework.c` (ABORTED→IN_PROGRESS→COMPLETED/FAILED state machine observable, now a source of `irc_core` since #86). Tests: `tests/compliance/test_ircv3_tags.c`, `test_tags_roundtrip.c`, `test_sasl_handshake.c`, `test_cap_negotiation.c`. There is no message-id implementation: `src/message_id.c` was an orphan and #86 deleted it; real message-ids land in Phase 8 (#82).
- Federation handshake observable: `src/federation_handshake.c` (INIT→HANDSHAKE_SENT→ESTABLISHED/FAILED/TIMED_OUT, heartbeat_check observable). Tests: `tests/federation/test_federate_handshake.c`, `test_heartbeat.c`, `test_sync_state.c`, `test_failover_reconnect.c`.
- Loadbal peer discovery / reconnect observable: `tests/loadbal/test_peer_discovery.c` (advertise/graceful_leave observable), `tests/loadbal/test_reconnect.c` (reconnect preserves nick/memberships/capabilities, no nick collision observable).
- Memory footprint benchmark observable: `tests/benchmark/footprint.c` (assert mean_rss_mb < 10.0 observable); `tests/benchmark/throughput.c` (bench_report_t framework observable).
- Source files real, zero stubs: `src/` contains `protocol_parse.c`, `federation_handshake.c`, `ircv3_tags.c`, `sasl_framework.c`, `node_main.c`, `server.c`, `CMakeLists.txt` — all real source, and all of them in a `CMakeLists.txt` (`message_id.c` was not, and was deleted in #86).
- Audit bugs fixed: `.github/AUDIT.md` corrected previous inaccuracies (missing compiler flag references, missing observable contract listings, unnoted benchmark stubs); audit now references actual `CMakeLists.txt` flags (`-Wall -Wextra -Werror -Wpedantic`, Clang `-Weverything -Wno-padded`) and observable contracts per file.
## Remaining Design Goals
- Lock-free structures (design goal per docs/ARCHITECTURE.md; not yet implemented; `tests/federation/test_sync_state.c` exists but is stub).
- Auto-scaling (nodes spawn/shutdown based on load; federation protocol propagates state — design target, not observable implemented).
- Full federation peer sync (complete state sync beyond handshake; relates to design goal in `docs/ARCHITECTURE.md`).
## CI / TDD
- `tests/` — unit tests (CTest)
- `tests/benchmark/` — memory footprint + throughput
- CI runs on push/PR to `main` and `feat/*`
- `main` protected; only merge via PR with passing CI (`ci/test`, `ci/benchmark`, `ci/compliance`)
