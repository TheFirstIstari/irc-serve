# irc-serve

Federated modern-spec IRC server in C. Performance-first, minimal memory footprint.

## Specs
- RFC 1459 (base)
- Modern IRC / IRCv3 (tags, SASL, multi-prefix)
- Federation: custom peer-to-peer protocol for homogeneous nodes

## Development
- `main` is protected. Work on `feat/*` branches.
- PRs must pass `ci/test`, `ci/benchmark`, `ci/compliance`.
- See `docs/ARCHITECTURE.md` and `docs/SPEC_TRACKING.md`.

## CI / Benchmark
Runs on GCC and Clang (Release + Debug). Memory footprint and spec compliance verified automatically.

## Tracking
Issues and milestones track work. See GitHub Issues tab.
