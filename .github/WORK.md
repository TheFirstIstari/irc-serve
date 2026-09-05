# irc-serve — Work Tracker

Mapping: issue → branch → PR → test file → observable contract.
Verified: 2026-09-06 (repo audit complete; all file references verified against actual repo contents).

This file is the source of truth for which branch owns each granular contract and which PR closes it. Update when branches or PRs change.

## Master table (verified against existing test files)

| Issue | Title | Branch | PR | Test file | Observable contract |
|------:|-------|--------|----|-----------|---------------------|
| #10 | RFC 1459 observable token count | `feat/protocol-parse` | #23 (OPEN) | `tests/protocol/test_rfc1459_parse.c` | Parser returns exact token count + error code for NICK/USER/JOIN/PRIVMSG/PING/PONG/QUIT and malformed input |
| #11 | SYNC state hash equality | `feat/federation-handshake` | #29 (MERGED) | `tests/federation/test_sync_state.c` (stub) | Identical channel/user state → identical hash; divergence observable as mismatch state |
| #12 | FEDERATE handshake timeout/state | `feat/federation-handshake` | #29 (MERGED) | `tests/federation/test_federate_handshake.c` (stub) | INIT → HANDSHAKE_SENT → ESTABLISHED \| FAILED \| TIMED_OUT; slot released on failure |
| #13 | Memory footprint <10MB mean RSS | `feat/local-ci` / `feat/bench-mem` (not pushed) | — | `tests/benchmark/footprint.c` | Mean RSS < 10 MiB with one federated peer, zero clients |
| #14 | NICK/USER observable parsing | `feat/protocol-regress` | #28 (CLOSED, feature in main) | `tests/protocol/test_rfc1459_parse.c` (existing) | Canonical NICK/USER shapes (nick ≤ 9, realname trailing); rejection of empty/digit-prefixed/forbidden-char nicks |
| #15 | HEARTBEAT interval observable | `feat/federation-handshake` | #29 (MERGED) | `tests/federation/test_heartbeat.c` (stub) | Single documented constant `IRC_FED_HEARTBEAT_MS`; silent peer → STALE/DOWN within N×interval |
| #16 | SASL placeholder framework | `feat/ircv3-sasl` (not pushed) | — | `tests/compliance/test_sasl_handshake.c` (stub) | State machine ABORTED → IN_PROGRESS → COMPLETED \| FAILED; defined error on unregistered mechanism |
| #17 | Throughput measurement framework | `feat/local-ci` / `feat/bench-throughput` (not pushed) | — | `tests/benchmark/throughput.c` (stub) | `bench_report_t { mean, p50, p99, ops_per_sec }`; baseline recorded, no hard target |
| #18 | Reconnect state preservation | `feat/loadbal-reconnect` (not pushed) | — | `tests/loadbal/test_reconnect.c` (stub) | Client reconnects to node B with same nick/channel memberships/capabilities; no nick collision observable |
| #19 | Peer discovery observable | `feat/loadbal-discovery` (not pushed) | — | `tests/loadbal/test_peer_discovery.c` (stub) | `advertise()` → existing peers observe newcomer within bounded window; graceful leave observable as removal |
| #20 | IRCv3 tags exact roundtrip | `feat/ircv3-tags` (not pushed) | — | `tests/compliance/test_ircv3_tags.c` (stub) | `parse(tags-as-sent) == serialize(parsed)`; trailing tag-free body preserved; parse errors observable |

Notes on accuracy:
- `tests/protocol/test_nick_user.c` does not exist. Issue #14 references it but the observable parsing work is covered by `test_rfc1459_parse.c` and protocol regression work.
- `tests/benchmark/mem_footprint.c` does not exist; actual file is `tests/benchmark/footprint.c`.
- `tests/compliance/test_sasl_framework.c` does not exist; actual file is `tests/compliance/test_sasl_handshake.c`.
- Several branches (`feat/bench-mem`, `feat/ircv3-sasl`, `feat/loadbal-reconnect`, `feat/loadbal-discovery`, `feat/ircv3-tags`) are not present in the repository. Issues reference planned work.

## PR index (verified against GitHub PR list)

| PR | Title | Branch | State | Closes |
|----|-------|--------|-------|--------|
| #29 | feat/next-25: SASL handshake observable contract | `feat/next-25` | MERGED (2026-09-05) | Related #16, gates CI workflow |
| #28 | Modern IRC: multi-prefix MODE +o/+v (#22) | `feat/next-22` | CLOSED (2026-09-06) | #22 (feature merged via main at b136bf8) |
| #30 | Merge origin/main into feat/next-21-update | `feat/next-21-update` | CLOSED (2026-09-06) | Conflict resolution |
| #31 | fix(ci): underscore IDs, add missing id fields, fix needs reference | `feat/next-25` | CLOSED (2026-09-06) | CI fix |

Note: Previous PR index referenced #21, #22, #23 which did not match actual PR numbers. This table uses verified PR numbers from the repository.

## CI label → issues

Verified against `.github/workflows/ci.yml` (commit 2a9c583):

- **benchmark** (off by default): #13 (#17 if framework implemented)
- **compliance**: #10, #16 (#14 via `test_rfc1459_parse.c`), #20 (stub)
- **federation**: #11, #12, #15, #18, #19
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
