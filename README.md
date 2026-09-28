# irc-serve

Federated modern-spec IRC server in C. Performance-first, minimal memory footprint.

## Specs
- RFC 1459 (base)
- Modern IRC / IRCv3 (tags, SASL, multi-prefix)
- Federation: custom peer-to-peer protocol for homogeneous nodes

## Development
- `main` is protected. Work on `feat/*` branches.
- PRs must pass `ci_test`, `ci_benchmark` and `ci_compliance` — these are the
  check names branch protection on `main` requires, and they must match the
  job ids in `.github/workflows/ci.yml` exactly or the PR stays BLOCKED.
- See `docs/ARCHITECTURE.md` and `docs/SPEC_TRACKING.md`.

## CI / Benchmark
Runs on GCC and Clang (Release + Debug). Memory footprint and spec compliance verified automatically.

## Tracking
Issues and milestones track work. See GitHub Issues tab.
