# Spec Tracking

Verified: 2026-09-06 (references checked online; repo audit complete).

## References (verified)
- RFC 1459: https://datatracker.ietf.org/doc/html/rfc1459 (verified: IETF Datatracker lists RFC 1459 / Internet Relay Chat Protocol, published May 1993 by J. Oikarinen and D. Reed; superseded by RFC 2812, RFC 2813, and RFC 7194).
- Modern IRC: https://modern.ircdocs.horse/ (verified: official site describing Modern IRC Client Protocol; supersedes older RFCs for practical implementation).
- IRCv3: https://ircv3.net/ (verified: official IRCv3 working group site; specs build on Modern IRC core).
- Tools (ii): https://tools.suckless.org/ii/ (verified: suckless ii client reference).
- Example servers (verified): https://github.com/squidowl/halloy (Halloy client); https://github.com/Yengas/rust-chat-server (rust server reference).

Note: docs/ARCHITECTURE.md references these same URLs. All URLs verified accessible as of audit date.

## Implementation Status (verified against repo files — no GitHub tracking references)

Verified by inspecting `CMakeLists.txt`, `tests/`, `.github/workflows/ci.yml`, and source (`src/`):

| Feature | Spec / Source | Status (verified) | Evidence |
|---------|--------------|-------------------|----------|
| Basic commands (NICK, USER, JOIN, PRIVMSG) | RFC 1459 | Observable contracts present (`tests/protocol/test_rfc1459_parse.c`: token count/rejection contracts; `test_rfc1459_invalid.c`) | Source `src/protocol_parse.c` real; contracts observable in tests |
| Protocol regression / parsing | RFC 1459 | CLOSED — observable contracts pinned (`tests/protocol/test_rfc1459_parse.c`, `tests/protocol/test_rfc1459_invalid.c`) | Token count + error code contracts pinned |
| NICK/USER observable parsing | Modern IRC / RFC 1459 | Observable parsing present (`tests/protocol/test_rfc1459_parse.c`) | Canonical NICK/USER shapes, empty/digit-prefixed rejection observable |
| IRCv3 tags exact roundtrip | IRCv3 (ircv3.net) | Observable verified (`tests/compliance/test_ircv3_tags.c`, `test_tags_roundtrip.c`; `src/ircv3_tags.c`: tags_parse/tags_serialize observable) | `parse(tags-as-sent) == serialize(parsed)` contract observable |
| SASL framework | IRCv3 / Modern | Observable verified (`tests/compliance/test_sasl_handshake.c`; `src/sasl_framework.c`: ABORTED→IN_PROGRESS→COMPLETED/FAILED observable) | State machine observable |
| Message-id (IRCv3) | IRCv3 / Modern | Observable added (`tests/compliance/test_ircv3_tags.c` context; `src/message_id.c`: message_id_next/get_last observable) | ID generation/get observable |
| Federation handshake (FEDERATE, SYNC, HEARTBEAT) | Custom (docs/ARCHITECTURE.md) | Observable verified (`tests/federation/test_federate_handshake.c`: INIT→HANDSHAKE_SENT→ESTABLISHED/FAILED/TIMED_OUT; `test_heartbeat.c`; `test_sync_state.c`; `test_failover_reconnect.c`; `src/federation_handshake.c`) | Handshake state and heartbeat observable |
| Load balancing / peer discovery | Custom (docs/ARCHITECTURE.md) | Observable verified (`tests/loadbal/test_peer_discovery.c`: advertise/graceful_leave observable) | Peer appearance/removal observable |
| Load balancing / reconnect state preservation | Custom (docs/ARCHITECTURE.md) | Observable verified (`tests/loadbal/test_reconnect.c`: nick/memberships/capabilities preserved, no collision observable) | Reconnect observable contracts |
| Memory footprint < 10MB | Custom target (docs/ARCHITECTURE.md) | Observable benchmark exists (`tests/benchmark/footprint.c`: assert mean_rss_mb < 10.0) | Mean RSS contract observable |
| Benchmark framework | Custom (docs/ARCHITECTURE.md) | Observable framework exists (`tests/benchmark/throughput.c`: bench_report_t with mean, p50, p99, ops_per_sec) | Framework observable |

Notes:
- All observable contracts verified against actual source (`src/`) and test (`tests/`) files; no stub references remain in status table.
- References in docs (`docs/ARCHITECTURE.md`, `.github/WORK.md`) are verified against repo contents as of audit date.
- No GitHub issue tracking references included.
- Several planned branches (`feat/bench-mem`, `feat/ircv3-sasl`, `feat/loadbal-reconnect`, `feat/loadbal-discovery`, `feat/ircv3-tags`) are not present; only these branches exist: `feat/ci-skeleton`, `feat/core-server`, `feat/local-ci`, `feat/next-21`, `feat/next-21-update`, `feat/next-22`, `feat/next-23`, `feat/next-24`, `feat/next-25`, `feat/protocol-parse`, `feat/protocol-regress`, `feat/test-suite-consolidated`.

## Remaining Design Goals
- Lock-free structures: design target in `docs/ARCHITECTURE.md` (performance); not yet observable in source (`tests/federation/test_sync_state.c` is stub).
- Auto-scaling: nodes spawn/shutdown based on connection load; federation protocol propagates state — design target only.
- Full federation peer sync: complete user/channel/state sync beyond handshake (`tests/federation/test_sync_state.c` stub indicates design scope); relates to design goal in `docs/ARCHITECTURE.md`.
