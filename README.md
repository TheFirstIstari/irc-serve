# irc-serve

Federated modern-spec IRC server in C. Performance-first, minimal memory footprint.

## Specs
- RFC 1459 (base)
- Modern IRC / IRCv3 (tags, SASL, multi-prefix)
- Federation: custom peer-to-peer protocol for homogeneous nodes

## Development
- `main` is protected. Work on `feat/*` branches.
- PRs must pass the GitHub Actions CI workflow.
- See `docs/ARCHITECTURE.md` and `docs/SPEC_TRACKING.md`.

## CI / Benchmark
Runs on GCC and Clang (Release + Debug). Benchmark/spec-compliance automation is currently a placeholder.

## Tracking
Issues and milestones track work. See GitHub Issues tab.
