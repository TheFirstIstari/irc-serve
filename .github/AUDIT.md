# Audit Framework — Actual State

Verified: 2026-09-06 (repo audit complete).

Targets (from docs/ARCHITECTURE.md, CMakeLists.txt, .github/workflows/ci.yml, source):
- Memory footprint: <10MB mean RSS (tests/benchmark/footprint.c; observable: assert(mean_rss_mb < 10.0)).
- Zero warnings: compiler flags -Wall -Wextra -Werror -Wpedantic, Clang -Weverything -Wno-padded (CMakeLists.txt line 13-18).
- Benchmark ops/sec baseline: tests/benchmark/throughput.c defines bench_report_t; no hard target set.
- Lock-free federation: design goal in docs/ARCHITECTURE.md; not yet implemented (tests/federation/test_sync_state.c exists but is stub).
- No plumbing asserts: conventions in .github/WORK.md (line 42: "not internal storage layout").
- Contracts pinned: .github/WORK.md master table; observable contracts listed per issue.
- CI passes: ci_testExpected, ci_benchmarkExpected, ci_complianceExpected (fixed in commit 2a9c583, pushed to branches).

Missing / inaccurate from previous version:
- Previous audit did not reference actual source/compiler flags.
- Previous audit did not list observable contracts per test file.
- Previous audit did not note that benchmark/throughput.c and footprint.c are stubs.

Updates needed after feature merges:
- Update master table in .github/WORK.md when PRs merge/close.
- Update this file after each milestone (weekly/after PR close).
