# irc-serve — Work Tracker

Mapping: issue → branch → PR → test file → observable contract.

This file is the source of truth for which branch owns each granular contract and which PR closes it. Update when branches or PRs change.

## Master table

| Issue | Title | Branch | PR | Test file | Observable contract |
|------:|-------|--------|----|-----------|---------------------|
| #10 | RFC 1459 observable token count | `feat/protocol-parse` | #23 | `tests/protocol/test_rfc1459_parse.c` | Parser returns exact token count + error code for NICK/USER/JOIN/PRIVMSG/PING/PONG/QUIT and malformed input |
| #11 | SYNC state hash equality | `feat/federation-handshake` | #22 | `tests/federation/test_sync_state.c` | Identical channel/user state → identical hash; divergence observable as mismatch state |
| #12 | FEDERATE handshake timeout/state | `feat/federation-handshake` | #22 | `tests/federation/test_federate_handshake.c` | INIT → HANDSHAKE_SENT → ESTABLISHED \| FAILED \| TIMED_OUT; slot released on failure |
| #13 | Memory footprint <10MB mean RSS | `feat/bench-mem` | — | `tests/benchmark/mem_footprint.c` | Mean RSS < 10 MiB with one federated peer, zero clients |
| #14 | NICK/USER observable parsing | `feat/protocol-regress` | #22 | `tests/protocol/test_nick_user.c` | Canonical NICK/USER shapes (nick ≤ 9, realname trailing); rejection of empty/digit-prefixed/forbidden-char nicks |
| #15 | HEARTBEAT interval observable | `feat/federation-handshake` | — | `tests/federation/test_heartbeat.c` | Single documented constant `IRC_FED_HEARTBEAT_MS`; silent peer → STALE/DOWN within N×interval |
| #16 | SASL placeholder framework | `feat/ircv3-sasl` | — | `tests/compliance/test_sasl_framework.c` | State machine ABORTED → IN_PROGRESS → COMPLETED \| FAILED; defined error on unregistered mechanism |
| #17 | Throughput measurement framework | `feat/bench-throughput` | — | `tests/benchmark/throughput.c` | `bench_report_t { mean, p50, p99, ops_per_sec }`; baseline recorded, no hard target |
| #18 | Reconnect state preservation | `feat/loadbal-reconnect` | — | `tests/loadbal/test_reconnect_state.c` | Client reconnects to node B with same nick/channel memberships/capabilities; no nick collision observable |
| #19 | Peer discovery observable | `feat/loadbal-discovery` | — | `tests/loadbal/test_peer_discovery.c` | `advertise()` → existing peers observe newcomer within bounded window; graceful leave observable as removal |
| #20 | IRCv3 tags exact roundtrip | `feat/ircv3-tags` | — | `tests/compliance/test_ircv3_tags.c` | `parse(tags-as-sent) == serialize(parsed)`; trailing tag-free body preserved; parse errors observable |

## PR index

| PR | Title | Branch | State | Closes |
|----|-------|--------|-------|--------|
| #1 | feat(ci-skeleton) | `feat/ci-skeleton` | MERGED | Related #10–#20 (gates the workflow) |
| #21 | feat(tests): consolidate full test suite | `feat/test-suite-consolidated` | OPEN | Aggregates all #10–#20 test files |
| #22 | test(protocol): pin NICK/USER observable parsing contract | `feat/protocol-regress` | CLOSED | #14 (also #11, #12 via shared `feat/federation-handshake` work) |
| #23 | feat(protocol): RFC 1459 observable token count contract | `feat/protocol-parse` | OPEN | #10 |

## CI label → issues

- **benchmark** (off by default): #13, #17
- **compliance**: #10, #14, #16, #20
- **federation**: #11, #12, #15
- **loadbal**: #18, #19
- **protocol**: #10, #14

## Conventions

- Every contract test pins observable behavior (return values, state transitions, byte counts), not internal storage layout, struct fields, or wire formats.
- Each test executable is its own `add_executable` target — no OBJECT bundles (avoids duplicate `main()`).
- Tests must fail red before the implementation lands and pass once the contract is honored.
- Tests are deterministic, isolated, and full-suite-safe.
- No test exists solely so a change "has tests"; throwaway scripts are preferred for one-off proof.

## How to use this file

1. Pick an issue from the table.
2. Check out the listed branch (or create it from `main` if not yet pushed).
3. Implement the listed test file to pin the observable contract.
4. Open (or update) the PR; reference the issue with `Closes #N`.
5. After merge, mark the row `Closes` if not already, and add any new PRs to the PR index.