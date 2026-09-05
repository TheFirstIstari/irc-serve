# Spec Tracking

Verified: 2026-09-06 (references checked online; repo audit complete).

## References (verified)
- RFC 1459: https://datatracker.ietf.org/doc/html/rfc1459 (verified: IETF Datatracker lists RFC 1459 / Internet Relay Chat Protocol, published May 1993 by J. Oikarinen and D. Reed; superseded by RFC 2812, RFC 2813, and RFC 7194).
- Modern IRC: https://modern.ircdocs.horse/ (verified: official site describing Modern IRC Client Protocol; supersedes older RFCs for practical implementation).
- IRCv3: https://ircv3.net/ (verified: official IRCv3 working group site; specs build on Modern IRC core).
- Tools (ii): https://tools.suckless.org/ii/ (verified: suckless ii client reference).
- Example servers (verified): https://github.com/squidowl/halloy (Halloy client); https://github.com/Yengas/rust-chat-server (rust server reference).

Note: docs/ARCHITECTURE.md references these same URLs. All URLs verified accessible as of audit date.

## Implementation Status (verified against repo files)

Verified by inspecting `CMakeLists.txt`, `tests/`, `.github/workflows/ci.yml`, and source (`src/`):

| Feature | Spec / Source | Status (actual) | Issue / Evidence |
|---------|--------------|-----------------|------------------|
| Basic commands (NICK, USER, JOIN, PRIVMSG) | RFC 1459 | Skeleton (stub in `tests/protocol/test_rfc1459_parse.c`) | Issue #2 (open: Implement basic IRC commands) |
| IRCv3 message tags | IRCv3 (ircv3.net) | Planned / stub (`tests/compliance/test_ircv3_tags.c`, `test_tags_roundtrip.c`) | Issue #20 (open: Spec compliance: IRCv3 tags exact roundtrip) |
| Federation handshake | Custom (docs/ARCHITECTURE.md) | Design / stub (`tests/federation/test_federate_handshake.c`, `test_heartbeat.c`, `test_sync_state.c`) | Issue #3 (open: Federation handshake and peer sync protocol); #11 (CLOSED: SYNC state hash equality); #12 (OPEN: FEDERATE handshake timeout/state) |
| Load balancing / HA / peer discovery | Custom (docs/ARCHITECTURE.md) | Design / stub (`tests/loadbal/test_peer_discovery.c`, `test_reconnect.c`) | Issue #4 (open: Memory footprint benchmark and compliance checks — note: title references memory, but content relates to load balance/benchmark tracking); #19 (open: Load balance: peer discovery); #18 (open: Load balance: reconnect state preservation) |
| Memory footprint < 10MB | Custom target (docs/ARCHITECTURE.md) | Observable benchmark exists (`tests/benchmark/footprint.c`: assert(mean_rss_mb < 10.0)) | Issue #13 (open: Benchmark: memory footprint mean RSS <10MB) |
| Benchmark framework | Custom (docs/ARCHITECTURE.md) | Observable framework exists (`tests/benchmark/throughput.c`: defines `bench_report_t` with mean, p50, p99, ops_per_sec) | Issue #17 (open: Benchmark: throughput measurement framework) |
| SASL framework | IRCv3 / Modern | Placeholder stub (`tests/compliance/test_sasl_handshake.c`) | Issue #16 (open: Spec compliance: SASL placeholder framework observable contract) |
| Protocol regression / parsing | RFC 1459 | Observable contracts pinned (`tests/protocol/test_rfc1459_parse.c`, `test_rfc1459_invalid.c`) | Issue #10 (CLOSED: Protocol parsing: RFC 1459 observable token count contract) |
| NICK/USER observable parsing | Modern IRC / RFC 1459 | Observable parsing referenced (`tests/protocol/test_rfc1459_parse.c`) | Issue #14 (open: Protocol regression: NICK/USER observable parsing contract) |

Notes:
- Issue #1 does not exist; the closest open issue is #2.
- Issue #3 exists (Federation handshake) and aligns with federation work.
- Issue #4's title references memory footprint/benchmark; the content relates to federation/load balance tracking per .github/WORK.md. The title is slightly mismatched with the issue number reference in docs.
- Issue #5 (Sub-issue tracker: federation state sync) and #6 (Sub-issue tracker: protocol test categories) are sub-trackers, not feature contracts.
- Issue #7 (Benchmark: memory footprint per node) relates to #13 but is a separate granular contract.
- Issue #8 (Test framework: protocol parsing regression tests) and #9 (Test framework: federation handshake and sync) relate to test framework work, not direct feature contracts.
- Issue #11 (CLOSED: SYNC state hash equality) and #10 (CLOSED: Protocol parsing) confirm completed contracts.
- Several branches referenced in older docs (`feat/bench-mem`, `feat/ircv3-sasl`, `feat/loadbal-reconnect`, `feat/loadbal-discovery`, `feat/ircv3-tags`) do not exist in the repository. Only these branches exist: `feat/ci-skeleton`, `feat/core-server`, `feat/local-ci`, `feat/next-21`, `feat/next-21-update`, `feat/next-22`, `feat/next-23`, `feat/next-24`, `feat/next-25`, `feat/protocol-parse`, `feat/protocol-regress`, `feat/test-suite-consolidated`.
