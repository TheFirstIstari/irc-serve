# Contributing

## Licensing

By opening a pull request you agree that your contribution is licensed under the
project's terms: the **GNU Affero General Public License v3.0 or later**. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

If your contribution is derived from code under a different licence, say so in
the PR description — that needs settling before it can be merged, not after.

The AGPL was chosen specifically because this is a federated network service:
section 13 means a modified node offered over a network must offer its source.
Some organisations cannot deploy the AGPL. That is a real constraint rather than
a detail, and it is the licence the project has chosen.

Participation is also governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Branching and review

`main` is protected. Work on a branch and open a pull request.

- Phase work: `phase/N-short-description`
- Fixes: `fix/short-description`
- Everything else: `feat/`, `docs/`, `ci/`

Every PR must pass three required checks — `ci_test`, `ci_benchmark` and
`ci_compliance`. Those are the exact job ids in `.github/workflows/ci.yml`; if
they drift from the names branch protection requires, every PR sits `BLOCKED`
with no obvious cause. That happened here in September 2026 for three weeks.

Not required, but please read the result: `ci_macos`, `build_arch` (gcc and
clang, Release and Debug), and `build_cachyos` (self-hosted, push to main only).

## Before you open a PR

```sh
./local-ci.sh          # or: make local-ci
```

This mirrors CI: strict C11, `-Wall -Wextra -Werror -Wpedantic -O2`, and the
full test suite. If your change passes locally it will almost certainly pass in
CI, and the reverse is not true.

## Testing conventions

These are the rules this project holds itself to, and they exist because the
opposite is what it was built out of.

- **Assert on observable behaviour** — return values, state transitions, and
  bytes on the wire. Never on struct fields or internal layout. Tests that read
  `chan_t` break on any restructuring while proving nothing about the server.
- **A test that cannot fail is not a test.** When you add one, break the
  implementation and watch it go red. If it stays green, the test is wrong.
  Note that a *build* failure leaves the old binary in place, so a fault you
  injected can appear to "pass" — check the build succeeded before believing a
  teeth result.
- **If a feature is absent, say so.** Return CTest's skip code (`77`) with a
  message naming what is missing. Do not write a test that asserts behaviour
  nothing implements. CI does not yet fail on skips; that gate is Phase 7.
- **No `sleep()` in tests.** Use a `select()`-driven deadline loop. A fixed
  sleep is the leading cause of CI flake, and `tc_expect()` is there so you do
  not need one.
- **Do not write platform-specific assertions.** Linux returns a different
  value from `getsockopt(SO_SNDBUF)` than macOS does. Assert on wire bytes.

## Portability

The project builds as **strict C11** (`CMAKE_C_EXTENSIONS OFF`). That defines
`__STRICT_ANSI__`, which hides POSIX declarations on glibc, so the root
`CMakeLists.txt` opts in with explicit feature-test macros. Read the comment
block there before changing it: switching to `gnu11` will silence the Linux
build break by giving up the portability guarantee, which is a trade, not a
fix.

If your change touches platform headers, check it on both Linux and macOS. Two
of the three build breaks fixed in this project were invisible on the machine
they were written on.

## Style

Match the surrounding code. Comments should explain **why**, not restate what
the line does. If a claim in a comment is later found to be wrong, retract it
everywhere it was repeated — including in tests and other files.

## Documentation

`docs/SERVER_DESIGN.md` is authoritative for anything structural. If your change
contradicts it, the design is what needs updating, and the PR should say how.

`docs/SPEC_TRACKING.md` records actual state with checkable evidence. It is
regenerated in part by `.github/workflows/stats.yml`. Do not hand-edit numbers
into it.

## Reporting bugs

Open an issue with the version, your platform, and how to reproduce. If you have
already found that the tracked behaviour is wrong rather than the code, say so
— that has happened repeatedly here and is worth knowing about.
