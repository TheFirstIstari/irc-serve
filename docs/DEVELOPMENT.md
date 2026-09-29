# Development workflow

## Branching

`main` is protected. Nothing lands on it except by merging a pull request.

- Phase work: `phase/N-short-description`
- Features: `feat/short-description`
- Fixes: `fix/short-description`
- Docs and CI: `docs/`, `ci/`

Branches are deleted after merge, so the branch list is either `main` or work in
progress. That is the invariant worth keeping: a branch that survived a merge is
a branch nobody cleaned up, and after a few months nobody can tell which are
abandoned experiments and which are live.

## What `main` enforces

| Check | Runs on | Required |
|---|---|---|
| `ci_test` | `ubuntu-22.04` (hosted) | yes |
| `ci_macos` Release / Debug | `macos-latest` (hosted) | yes |
| `ci_benchmark` | `ubuntu-22.04` (hosted) | no |
| `ci_compliance` | `ubuntu-22.04` (hosted) | no |
| `ci_linux` | `cachyos-x8664` (self-hosted) | no, push-to-main only |

Plus: `strict` (results from a stale commit cannot satisfy a merge), linear
history, force push and deletion disabled, admins enforced.

### Why the split is this way

The self-hosted CachyOS runner is where most Linux work happens, for three
reasons that each rule out the obvious alternative:

**One runner process runs one job at a time.** A single self-hosted runner
therefore serialises a 4-way matrix into four sequential builds. The fix is not
one job that loops internally — that trades the parallelism away — it is **more
runner processes**.

`cachyos-x8664` is a 32-core / 29 GB box, so it runs **six instances** from a
templated systemd unit, each in its own directory and each registered
separately. `ci_linux` is a real 4-way matrix again, and the four jobs land on
four different runners at once. Measured: `gcc Release` and `clang Debug` each
completed in 19 s, concurrently, on the same box.

**macOS cannot run there.** `ci_macos` stays hosted. That is the platform, not a
preference.

**The merge gate must not depend on a machine that can be switched off.**
`ci_test` is deliberately small and deliberately hosted. It is the check that
keeps a merge possible when `cachyos-x8664` is unavailable. If every required
check lived on a personal machine, powering it off would be a development
freeze, and turning it off would be the fastest way to break the project.

The consequence worth stating plainly: the required set is smaller than it was.
Nine checks became three. That is a real reduction in what gates a merge, made
deliberately in exchange for speed and independence from hosted capacity. What
survives is a hosted Linux test run and both macOS configurations, so no required
check is produced solely by the maintainer's own machine.

### Installing or repairing the runner

The runner runs as a **system** unit, not a user unit. The original
`~/.config/systemd/user` installation only started while that user had an active
login session, so it died at every reboot and reported nothing wrong; that is
what "runner is offline" meant here. `multi-user.target.wants` symlinks are what
make it survive a reboot, and they are installed by the script.

```sh
# needs sudo: it writes /etc/systemd/system and enables units at boot
GH_RUNNER_TOKEN=$(gh api -X POST repos/TheFirstIstari/irc-serve/actions/runners/registration-token --jq .token) \
sudo -E ./scripts/setup-self-hosted-runner.sh          # add INSTANCES=N to change the count
```

Then check it:

```sh
systemctl list-units 'actions-runner@*'                              # all should be active
gh api repos/TheFirstIstari/irc-serve/actions/runners --jq '.runners[] | "\(.name) \(.status)"'
sudo systemctl restart actions-runner@3                              # one instance, not all
journalctl -u actions-runner@1 -f
```

Two behaviours are worth knowing, both found on the live machine rather than by
reading the unit:

- **A crash is reported as success.** `run.sh` does not propagate one: killing
  `Runner.Listener` makes it log `Exiting with unknown error code: 137` and then
  exit **0**, so `Restart=on-failure` never fires and the runner just stays dead.
  The unit uses `Restart=always`. A genuinely broken config still surfaces
  visibly: `StartLimitBurst=10` within `StartLimitIntervalSec=600` trips and the
  unit goes to `failed`.
- **A hard kill leaves a stale session.** GitHub then answers
  `A session for this runner already exists` and the runner retries the conflict
  in a loop, appearing `active` to systemd but `offline` to GitHub. It clears
  itself in about 90 s. If it does not, delete the stale registration and
  re-run `config.sh` for that instance.

**Removing an instance** — `sudo systemctl disable --now actions-runner@4`, then
delete it from GitHub's runner list, or it lingers as a ghost.

### Exposure from the self-hosted runner

`ci_linux` runs on `cachyos-x8664`, so anything reaching it executes code there.
It is gated three ways:

- push to `main` only, so a pull request from anyone — including a public fork —
  never reaches the machine
- the `self-hosted` environment, whose only required reviewer is the owner
- the owner's own pushes bypass that review by design, via
  `self-hosted-auto`

The third is the deliberate trade: **anything able to authenticate as
`TheFirstIstari` runs there unattended** — including a stolen token or a leaked
SSH key. Everyone else waits for approval. If that trade stops being worth
making, drop the `environment:` line from `ci_linux` and every run requires
approval again.

### Why there is no required review

`required_pull_request_reviews` is off, and that is a deliberate decision rather
than an oversight.

GitHub does not let you approve your own pull request, and a required review must
come from an account with write access. This repository has exactly one such
account. **Enabling required reviews would make it impossible to merge anything,
ever** — a repository that is permanently stuck, not a weak policy.

The nine status checks, linear history and the self-hosted gates stop a broken
commit landing and stop history being rewritten. They do not stop an unreviewed
but *working* commit landing, and it is worth being honest that this is the
weaker guarantee.

If a second maintainer is added, turn it on:

```sh
gh api -X PATCH repos/TheFirstIstari/irc-serve/branches/main/protection \
  -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -F 'required_pull_request_reviews[dismiss_stale_reviews]=true'
```

## Rollback

Tags mark every phase boundary, so "go back to the last working state" is a
lookup rather than an archaeology exercise.

```
v0.1.0-preserved     738f254  preserved work, corrected docs, federation design
v0.2.0-tokenizer     8d8c416  Phase 1: tokenizer, tag format, nick charset
v0.3.0-core          e958ea9  Phase 2: poll loop, conn_t, registries
v0.4.0-registration  cbb1d16  Phase 3: registration, 001-005, reply() invariant
v0.5.0-channels      7d0fe4b  Phase 4: channels, final struct shapes
v0.6.0-docs          5291c85  macOS CI, self-hosted runner, generated stats
```

### Finding the last good state

```sh
git log --oneline --decorate main        # tags show the rollback points
git describe --tags --abbrev=0 main     # nearest tag to a commit
```

### Three ways back, and when to use each

**Revert one commit — the default.** Keeps history, so the mistake stays visible
and the revert is reviewable.

```sh
git revert <sha>
```

**Revert a whole phase.** Reverting a squash merge is a single commit:

```sh
git revert -m 1 <phase-sha>
```

**Reset to a tag — only when history must be rewritten.** Discards everything
after the tag. Correct for a leaked secret, and *only* for that.

```sh
git reset --hard v0.5.0-channels
git push --force-with-lease origin main   # blocked by branch protection
```

Note that last line will be **rejected**: force push is disabled on `main`, and
that is intentional. To rewrite history you must first lift the protection, and
lifting it is a deliberate, visible act. This is a feature — the normal way back
is `revert`, and rewriting `main` should never be something a tired person does
at 2am.

## Local verification

```sh
./local-ci.sh      # or: make local-ci
```

Mirrors CI: strict C11, `-Wall -Wextra -Werror -Wpedantic -O2`, full suite.
Green locally is necessary but not sufficient — two of the three build breaks
fixed in this project were invisible on the machine they were written on, so let
CI have the final word.
