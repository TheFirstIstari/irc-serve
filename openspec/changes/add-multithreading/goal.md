# Goal: multithreading waves (issues #235–#244)

## Objective

Implement OpenSpec change `add-multithreading` (loop + writer threads) across
10 GitHub issues, one PR per issue, merged only after CI is green. Then return
to the user for audit instructions.

## Issue map

| Wave | Issues | Why grouped |
|------|--------|-------------|
| 1 (parallel-safe) | #235 atomics, #236 Threads linkage, #237 TSan cell, #238 file_secret, #239 stop flag | Disjoint files/regions; no shared interfaces |
| 2a | #240 per-conn mutex + `--writers` flag | Defines the mutex/flag interface wave 2b builds on |
| 2b (parallel after 2a merges) | #241 pump move, #244 SSL serialization | Different files, both consume #240's interface |
| 2c | #242 close handoff, #243 wakeup | Touch reap/wakeup; rebase onto 2b |
| 3 | #246–#251 (tests, bench, rollout) | After writers land |

Out of scope this goal: #245 (covered by #244's test), flipping the
`--writers` default (needs soak data), archiving the OpenSpec change.

## Rules for every PR

1. One issue → one branch `mt/<n>-<slug>` → one PR. No unrelated changes.
2. Conventions hold: strict C11, `-Weverything` clean on all 3 compilers,
   ASan/UBSan clean, fail-closed behavior unchanged.
3. `--writers 0` (default) is byte-identical to today; prove with full suite.
4. Agent owns its files/regions only (see wave plan); shared interfaces are
   dictated in the wave context, never invented.
5. PR merges **only** when `gh pr checks` is fully green. Agent fixes CI
   failures in its own PR. Merge order follows the wave table (rebase onto
   new main when a predecessor merges).
6. Report back: PR URL + CI status + files changed. Never merge another
   agent's PR; the orchestrator merges in dependency order.

## Shared interface contract (wave 2+)

- `conn_t`: `_Atomic int state, want_read, want_write;` + `pthread_mutex_t
  wq_lock;` (`connection.h`; `<stdatomic.h>`, `<pthread.h>`).
- Publish release / consume acquire. Writers own `conn_pump` when
  `s->writer_threads > 0`; loop never sends then.
- `server.h`: `int writer_threads;` + `server_set_writer_threads(s,0)` seam.
- `node_main.c`: `--writers N` → seam. Default 0.

## Done when

All 10 PRs merged green, `openspec validate` still passes, working tree clean,
user recalled for audit instructions.
