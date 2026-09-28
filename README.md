<p align="center">
  <code>irc-serve</code>
</p>

<p align="center">
  <em>A federated IRC server in C11, written so federation is a property of the
  core data model rather than a retrofit.</em>
</p>

<p align="center">
  <a href="https://github.com/TheFirstIstari/irc-serve/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/TheFirstIstari/irc-serve/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/TheFirstIstari/irc-serve/blob/docs/stats/docs/STATS.md"><img alt="Project status" src="https://img.shields.io/badge/project%20status-auto--generated-3fb950"></a>
  <img alt="Language" src="https://img.shields.io/badge/C-C11-00599B">
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#what-works-today">What works</a> •
  <a href="#not-yet-implemented">Not yet</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#security">Security</a> •
  <a href="#license">License</a>
</p>

---

> **Development milestone.** 3 of 9 phases are merged; Phase 4 is in review. The node binds, accepts,
> registers a client and speaks the channel and messaging verbs — but there is
> no authentication, no TLS, and no federation between nodes yet. Numbers below
> are measured, not typed: see
> [project status](https://github.com/TheFirstIstari/irc-serve/blob/main/docs/STATS.md),
> regenerated from a live test run.

## Overview

Two IRC clients that want to talk need a server in the middle. That part is
ordinary. The hard part is what happens when you want **more than one** of those
servers — a network — and the usual way that goes wrong is by deciding early
that the second one is a special case.

`irc-serve` takes the opposite position: the data model is built for multiple
nodes from the first commit, so adding a second one is a transport problem
rather than a rewrite. Three decisions carry that:

- **Nicks are scoped per server** (`nick@server`). Uniqueness is a peer's
  business, so there is no global lock to take and no cluster-wide lock to
  maintain.
- **Channels are origin-owned** and store only their local members. A join on
  someone else's channel costs one message instead of a roster synchronisation,
  and no node ever holds the full membership of a channel it does not own.
- **Clients and peers share one dispatch path.** A command arriving from a
  socket and a command arriving from a peer are handled by the same code; the
  only difference is a field on the connection.

The rule that makes those work is small and worth stating here, because it is
the one most federation designs leave out:

> A node never applies a channel state change it cannot route to the channel's
> origin. It refuses the action.

Refusing rather than queueing is what turns a permanent disagreement between
two nodes into a temporary one that heals on the next resync.

## What works today

Verified against the shipped binary over a real socket, not a test double:

```
:irc.test 001 alice :Welcome to the irc-serve network alice!alice@127.0.0.1
:irc.test 005 alice NETWORK=irc-serve CHANTYPES=#& PREFIX=(ov)@+ CASEMAPPING=ascii NICKLEN=63
:irc.test 353 alice = #t :alice @bob
```

- **Parsing** — `@tags`, `:prefix`, the 15-parameter cap, trailing-parameter
  absorption, an 8192-byte limit, and IRCv3 escaping in both directions
- **Event loop** — single-threaded `poll()`, nonblocking accept, bounded write
  queues that refuse rather than buffer, and a single close site behind a reaper
- **Registration** — `PASS` `NICK` `USER` `MOTD` `PING` `PONG` `QUIT`, with
  numerics `001`–`005`, `372`/`375`/`376`, `421`, `432`, `433`, `451`, `461`
- **Channels** — `JOIN` `PART` `TOPIC` `NAMES` `LIST` `KICK` `MODE`, per-member
  `+o`/`+v`, and the origin-ownership and single-writer rules above. *Landing now
  in #95, not yet on `main`.*
- **Test suite** — 39 wire-level integration tests that spawn the real binary
  and speak to it over loopback. No `sleep()` anywhere; every wait is a deadline

## Not yet implemented

Named rather than implied. Each is a tracked phase, not a maybe.

| Missing | Phase | Issue |
|---|---|---|
| Messaging — `PRIVMSG` `NOTICE` `WHO` `WHOIS` `ISON` | 5 | [#79](https://github.com/TheFirstIstari/irc-serve/issues/79) |
| Federation — peer links, `SBURST` resync, loop prevention | 6 | [#80](https://github.com/TheFirstIstari/irc-serve/issues/80) |
| Remaining command surface | 7 | [#81](https://github.com/TheFirstIstari/irc-serve/issues/81) |
| IRCv3 — CAP negotiation, SASL PLAIN, real tag escaping | 8 | [#82](https://github.com/TheFirstIstari/irc-serve/issues/82) |
| Multi-prefix, topic persistence, auto-scaling | 4–9 | — |

Phase 4 (channels) is complete on its branch and in review; the table reflects
what is on `main`.

`PASS` **records** a password and does not check it. SASL is Phase 8. There is
no TLS, so everything on the wire is plaintext.

## Quickstart

Requires CMake 3.20+ and a C11 compiler. No third-party libraries.

```sh
git clone https://github.com/TheFirstIstari/irc-serve.git
cd irc-serve
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure --timeout 60
```

Then run the node — it takes an optional port, and `0` means "any free port":

```sh
./build/src/irc-serve 6667
```

Connect with any IRC client on `127.0.0.1:6667`. Registration is
`NICK` then `USER`; `JOIN #anything` afterwards.

To reproduce the CI pipeline locally, including the strict warning flags:

```sh
make local-ci      # or: ./local-ci.sh
```

### Platform support

| Platform | Status |
|---|---|
| Linux — gcc, clang | Release + Debug in CI |
| macOS | Release + Debug in CI |
| Arch Linux, CachyOS | self-hosted smoke job, push to `main` only |

Builds as **strict C11** with POSIX opted into explicitly via feature-test
macros, rather than relaxing to `gnu11`. That matters: relaxing would silence
the Linux build break by giving up the portability guarantee. See the comment
block in `CMakeLists.txt` before changing it.

## Architecture

[`docs/SERVER_DESIGN.md`](docs/SERVER_DESIGN.md) is the authoritative design and
the phased plan. Read it before changing anything structural — it explains why
the message path is shaped the way it is, and several of those shapes are load-
bearing for a phase that has not been written yet.

Source layout:

```
src/core/     message, connection, server, poll_loop, reply, channel, commands
src/          protocol_parse, ircv3_tags, federation_handshake   (older modules)
tests/        unit, contract, benchmark, integration, harness
docs/         SERVER_DESIGN, SPEC_TRACKING, ARCHITECTURE, STATS (generated)
```

## Documentation

| Document | What it is |
|---|---|
| [`docs/SERVER_DESIGN.md`](docs/SERVER_DESIGN.md) | Architecture and the 9-phase plan. Authoritative. |
| [`docs/SPEC_TRACKING.md`](docs/SPEC_TRACKING.md) | Per-feature status against RFC 1459 / RFC 2812 / IRCv3, with checkable evidence. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Background and original design goals. |
| [Project status](https://github.com/TheFirstIstari/irc-serve/blob/main/docs/STATS.md) | Generated test counts and phase progress. |
| [Milestone](https://github.com/TheFirstIstari/irc-serve/milestone/5) | One issue per phase. |

### About project analytics

GitHub strips `<script>` from READMEs, so Google Analytics, Plausible and every
other JavaScript-based tracker are impossible here. What is used instead:

- **Badges** above, for live health
- **Generated status** for measured numbers, from
  [`stats.yml`](.github/workflows/stats.yml) — it reads a live `ctest` result
  and the milestone API, so it cannot report a feature that is not there
- **GitHub's own [Insights → Traffic](https://github.com/TheFirstIstari/irc-serve/graphs/traffic)**
  for actual visitor data — no setup required

A tracking pixel in an `<img>` tag would register a request through GitHub's
image proxy but yield no usable per-visitor data and add a third party as a
dependency, so it is deliberately not used.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: branch from `main`, keep the
suite green, and make sure your test can actually fail.

The conventions that matter most here, because this project spent three months
with a green suite for a server that could not talk IRC:

- Assert on **observable behaviour** — return values, state transitions, and
  bytes on the wire. Never on struct fields.
- A test you cannot make go red by breaking the code is not a test. Note that a
  *build* failure leaves the old binary in place, so an injected fault can look
  like a pass.
- If a feature is absent, return CTest's skip code with a message naming it.
  Do not write a test asserting behaviour nothing implements.
- No `sleep()` in tests. Use the `select()`-driven helpers in `tests/harness`.
- Do not write platform-specific assertions; Linux and macOS disagree about
  `SO_SNDBUF`, among other things.

## Release Cycle

Currently pre-1.0 and moving toward [Semantic Versioning](https://semver.org/).

Phases merge to `main` in order, each one leaving the node in a working state.
The milestones that matter:

- **Phase 5** — messaging. This is the point at which a standard client can
  join a channel and talk to another user. It is the "does it work" line.
- **Phase 6** — federation. Two nodes, convergence, exactly-once delivery.
- **Phase 7** — the skip gate closes: CI starts failing if any test is skipped.

There is no 1.0 until 5 and 6 are done and the definition of done in
`docs/SERVER_DESIGN.md` is met in full.

## Security

Please read [SECURITY.md](SECURITY.md) before reporting anything. It states the
threat model, including what is **not** defended yet — there is no
authentication, no TLS, and no rate limiting in the current build, and this
should not be exposed to the internet as it stands.

To report a vulnerability, use
[private vulnerability reporting](https://github.com/TheFirstIstari/irc-serve/security/advisories/new)
rather than a public issue.

## License

**No license has been chosen yet.** Until one is, default copyright applies:
the code is not open source in the OSI sense, and nobody may lawfully reuse it.
This is the one thing standing between this repository and being a conventional
open-source project, and it needs a maintainer decision rather than a default
guess. See the tracking issue.

## Credits

- [RFC 1459](https://datatracker.ietf.org/doc/html/rfc1459) and
  [RFC 2812](https://datatracker.ietf.org/doc/html/rfc2812) — the protocol
- [modern.ircdocs.horse](https://modern.ircdocs.horse/) and
  [IRCv3](https://ircv3.net/) — the current specification
