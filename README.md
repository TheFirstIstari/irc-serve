# irc-serve

A federated IRC server in C11, built so that federation is a property of the
core data model rather than a retrofit. Performance- and memory-conscious;
single-threaded `poll()` event loop; no third-party runtime dependencies.

> **Status: in development.** Phases 1-3 of 9 are complete. The node can bind,
> accept a TCP connection, register a client, and emit its `001`-`005` welcome
> numerics. Channels, messaging and federation are not implemented yet — see
> [`docs/STATS.md`](https://github.com/TheFirstIstari/irc-serve/blob/docs/stats/docs/STATS.md)
> and [`docs/SERVER_DESIGN.md`](docs/SERVER_DESIGN.md) for exactly what works.

[![CI](https://github.com/TheFirstIstari/irc-serve/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheFirstIstari/irc-serve/actions/workflows/ci.yml)
[![Language](https://img.shields.io/badge/C-C11-00599B?logo=c)](https://en.cppreference.com/w/c)
[![Spec](https://img.shields.io/badge/spec-RFC%201459%20%2F%20IRCv3-blueviolet)](docs/SPEC_TRACKING.md)
[![Stats](https://img.shields.io/badge/project%20status-auto--generated-3fb950)](https://github.com/TheFirstIstari/irc-serve/blob/docs/stats/docs/STATS.md)

<!--
No test-count or phase-progress badge here on purpose. shields.io has no
endpoint that reads a milestone's progress, and a hardcoded count goes stale the
moment a phase lands -- which is the same failure mode as the documentation
this repo spent September 2026 correcting. The numbers live in STATS.md, which
is measured rather than typed.
-->

<!--
About "analytics": GitHub strips <script> from READMEs, so Google Analytics,
Plausible and every other JS-based tracker are impossible here. What actually
works without JavaScript is badges and a generated status document, plus
GitHub's own Insights -> Traffic for real visitor data. See "Analytics" below.
-->

## What works today

Verified against the shipped binary, not a test double:

```
:irc.test 001 alice :Welcome to the irc-serve network alice!alice@127.0.0.1
:irc.test 005 alice NETWORK=irc-serve CHANTYPES=#& PREFIX=(ov)@+ CASEMAPPING=ascii NICKLEN=63
```

- Full RFC 1459 / IRCv3 line parsing: `@tags`, `:prefix`, 15-parameter cap,
  trailing-parameter absorption, the 8192-byte limit
- A real `poll()` event loop: nonblocking accept, bounded write queues, a single
  close site behind a reaper, and a tick hook for timeouts
- Registration: `PASS` `NICK` `USER` `MOTD` `PING` `PONG` `QUIT`, with numerics
  `001`-`005`, `372`/`375`/`376`, `421`, `432`, `433`, `451`, `461`
- `reply()` as the only outbound path to a client, which refuses a peer-link
  target — the invariant that keeps numerics from being parsed as commands by a
  peer

## Not yet implemented

Stated plainly rather than implied. 8 tests are CTest skips naming these:

| Missing | Phase |
|---|---|
| Channels — `JOIN` `PART` `TOPIC` `NAMES` `KICK` `MODE` | 4 |
| Messaging — `PRIVMSG` `NOTICE` `WHO` `WHOIS` `ISON` | 5 |
| Federation — peer links, `SBURST` resync, loop prevention | 6 |
| Remaining command surface | 7 |
| IRCv3 — CAP negotiation, SASL PLAIN, real tag escaping | 8 |
| Multi-prefix, topic persistence, auto-scaling | 4-9 |

`PASS` records a password and does **not** authenticate it. SASL is Phase 8.

## Building

Requires CMake 3.20+ and a C11 compiler. No external libraries.

```sh
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure --timeout 60
```

Or with the bundled driver, which mirrors CI:

```sh
make local-ci     # or: ./local-ci.sh
```

### Platform support

| Platform | Status |
|---|---|
| Linux (gcc, clang) | Tested in CI, Release and Debug |
| macOS | Tested in CI and in development |

The project builds as **strict C11** (`CMAKE_C_EXTENSIONS OFF`) and opts into
POSIX explicitly with feature-test macros rather than relaxing to `gnu11`. See
the comment block in `CMakeLists.txt` before changing that — switching to
`gnu11` would silence the Linux build break by giving up the portability
guarantee.

## Architecture

Read [`docs/SERVER_DESIGN.md`](docs/SERVER_DESIGN.md) before changing anything
structural. Three decisions carry the federation design:

- **Nicks are scoped per server** (`nick@server`), so collision resolution is a
  peer's problem rather than a global lock
- **Channels are origin-owned** and store only local members, so a join on a
  remote channel costs one message rather than a roster sync
- **Clients and peers share one dispatch path**, distinguished only by
  `conn_t.kind`

The highest-leverage rule in the design: *a node never applies a channel state
change it cannot route to the channel's origin; it refuses the action (`437`)*
rather than queueing it. That is what turns permanent divergence into
self-healing divergence.

## Analytics

**For repository traffic** — GitHub's built-in, nothing to configure:
[Insights → Traffic](https://github.com/TheFirstIstari/irc-serve/graphs/traffic)
for views, clones, unique visitors and referrers;
[Insights → Code frequency](https://github.com/TheFirstIstari/irc-serve/graphs/code-frequency)
for commit history.

**For project health** — the badges above, plus
[`docs/STATS.md`](https://github.com/TheFirstIstari/irc-serve/blob/docs/stats/docs/STATS.md),
regenerated by [`stats.yml`](.github/workflows/stats.yml) on a schedule and on
relevant pushes. Every number in it is measured at generation time: test counts
come from running `ctest`, phase progress from the milestone API. It is
mechanically unable to claim a feature exists when it does not.

**A note on what is not here.** Google Analytics, Plausible and similar tools
require JavaScript, and GitHub strips `<script>` from READMEs, so they cannot be
added. A tracking pixel in an `<img>` tag would register a request through
GitHub's image proxy but yields no usable per-visitor data and adds a third
party as a dependency, so it is deliberately not used.

## Development

- `main` is protected. **Work on a `phase/*` branch and open a PR.** Branch
  protection requires `ci_test`, `ci_benchmark` and `ci_compliance`, and those
  job ids must match `.github/workflows/ci.yml` exactly or the PR stays
  `BLOCKED` — a mismatch here is exactly what stalled this repo for three weeks
  in September 2026.
- One issue per phase, tracked in the
  [`Federated IRC Server v1.0`](https://github.com/TheFirstIstari/irc-serve/milestone/5)
  milestone.
- CI runs gcc and clang, Release and Debug, on Linux and macOS.
- The suite is `assert()`-based; `-UNDEBUG` in `tests/CMakeLists.txt` is
  load-bearing. Do not remove it.

### Known gaps in the toolchain

- `-Weverything` only runs for upstream Clang, not AppleClang
  ([#85](https://github.com/TheFirstIstari/irc-serve/issues/85)), so the macOS
  CI job does not exercise the full warning set
- No sanitizer build yet ([#92](https://github.com/TheFirstIstari/irc-serve/issues/92)),
  so the allocation-hygiene criteria are asserted rather than verified

## Further reading

- [`docs/SERVER_DESIGN.md`](docs/SERVER_DESIGN.md) — the authoritative design
  and phased plan
- [`docs/SPEC_TRACKING.md`](docs/SPEC_TRACKING.md) — per-feature status against
  the spec, with checkable evidence
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — background
