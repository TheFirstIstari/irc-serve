# Local CI — running the GitHub Actions pipeline on your machine

`make local-ci` is the local mirror of `.github/workflows/ci.yml`. It exists so
contributors can exercise the same gates CI runs *before* pushing, regardless
of which `feat/*` or `fix/*` branch they have checked out.

## Quick start

```bash
# Install pinned toolchain (gcc, clang, cmake >= 3.20, make)
mise install

# Run the local CI script
make local-ci
```

The script the Makefile invokes is `local-ci.sh` at the repo root. It calls plain
`cmake` / `ctest`; if you have mise installed, the tool versions in `mise.toml`
apply via mise shims on your `PATH`. Running it without mise installed requires
the Debian/Arch packages listed in `mise.toml` (build-essential + cmake + make on
Debian, base-devel + cmake on Arch).

## CI job mapping

The local script is intentionally small — it covers the **primary test path**
that every PR must pass. The full CI workflow (`.github/workflows/ci.yml`)
adds the cross-compiler matrix and compliance checks; see the table below.

| GitHub Actions job                  | Workflow steps                                                                   | Covered by `make local-ci`? | Equivalent `make` target      |
| ----------------------------------- | -------------------------------------------------------------------------------- | --------------------------- | ----------------------------- |
| `ci_testExpected`                      | Configure (Release, BUILD_TESTING=ON) → Build → `ctest --output-on-failure`       | **Yes**                     | `make test` (after `build`)   |
| `ci_benchmarkExpected`                  | Configure with BUILD_BENCHMARK=ON → Build → `ctest -L Benchmark`                  | Optional (run on demand)    | `make benchmark`              |
| `ci_complianceExpected`                 | Echo target platforms + memory footprint statement                                 | Echo only — no script step   | n/a                           |

`ci_testExpected` is the *primary* path: every PR must pass it before merge
(`docs/ARCHITECTURE.md` → CI / TDD). The matrix and compliance jobs are
intended to run in parallel across GitHub-hosted runners and are not
reproduced locally by default.

## Feature-branch safety

These files contain no branch-specific state:

- `mise.toml` — pins tool versions, no git refs.
- `Makefile` — drives CMake directly, no git refs.
- `local-ci.sh` — reads `git rev-parse --abbrev-ref HEAD` only to *print*
  the current branch; it never checks the branch name.

Switching between `feat/*` branches is safe: re-run `make local-ci` after
each `git checkout`.

## Troubleshooting

| Symptom                                            | Fix                                                                  |
| -------------------------------------------------- | -------------------------------------------------------------------- |
| `cmake: command not found`                         | `mise install` or `apt install cmake` / `pacman -S cmake`           |
| `nproc: command not found` (macOS)                 | Makefile falls back to `4` cores automatically                      |
| `local-ci.sh: Permission denied`                   | `chmod +x local-ci.sh`                                              |
| `docs/SPEC_TRACKING.md: No such file`              | `make docs-check` will tell you the same thing — create the file    |
| `local-ci` script missing                          | Makefile prints a warning and falls back to `make build && make test` |

## Adding a new CI job

When `.github/workflows/ci.yml` gains a step that contributors should
run locally too:

1. Add the command under a new target in `Makefile` (keep target names
   aligned with the CI job id where possible).
2. Add the same step to `local-ci.sh` so `make local-ci` keeps the
   "single command, mirrors CI" promise.
3. Update the **CI job mapping** table above.
