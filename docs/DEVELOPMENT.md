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
v0.1.0-preserved     1e0bbe4  Preserve prior work, correct docs, adopt federation
v0.2.0-tokenizer     4e01501  Phase 1: message tokenizer, tag format, nick charset
v0.3.0-core          d33bbf0  Phase 2: server core - poll loop, conn_t, framing
v0.4.0-registration  dc871d3  registration, 001-005 numerics, reply() invariant
v0.5.0-channels      cbf1eeb  Phase 4: channels, final struct shapes, single-writer
v0.6.0-docs          7166382  macOS CI, self-hosted runner, generated stats
v0.7.0-messaging     6757d4e  PRIVMSG, NOTICE, WHO, WHOIS, ISON, away-notify
```

Every one of those SHAs was WRONG until now, and the table was also missing a tag
— which is the same failure the README's version number was, in a file whose whole
purpose is to tell you where to roll back to. The history was rewritten once
(there are `backup-before-*-rewrite` tags recording it), the phase tags were
re-created against the rewritten commits, and this table kept naming the pre-rewrite
objects. They are still in the object store, so `git show 738f254` succeeds and
returns a commit that is not what `v0.1.0-preserved` resolves to — which is worse
than a missing SHA, because it looks right.

**AND THE TAGS ARE NOT RELEASES.** `v0.7.0-messaging` is the newest one and the
project is at a much later phase; the number in a tag names the *phase*, which is
also why the version in `src/core/server.h` and the number in these tags are two
different series that will not track each other. There is no `v0.8.0` because
nothing after Phase 5 was tagged, and there is no `v1.0.0` because there has been no
release.

**TO CHECK THIS TABLE RATHER THAN TRUST IT:**

```sh
git tag -l --sort=creatordate --format='%(refname:short)  %(objectname:short)  %(subject)'
git for-each-ref --format='%(refname:short)  %(objectname:short)' refs/tags | \
  while read -r tag _; do printf '%-24s %s\n' "$tag" "$(git rev-list -n1 "$tag" | cut -c1-7)"; done
```

**AND IF YOU ADD A TAG, ADD IT HERE.** A rollback table that describes a repository
which no longer exists is worse than no rollback table.

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

Mirrors CI: strict C11, `-Wall -Wextra -Werror -Wpedantic -O2`, full suite, and
the skip gate below. Green locally is necessary but not sufficient — two of the
three build breaks fixed in this project were invisible on the machine they were
written on, so let CI have the final word.

## The skip gate is a ratchet

`tests/known_skips.txt` is the single authoritative list of tests that are allowed
to skip. One line per skip, naming the CTest test, the phase that owns it and the
issue that closes it. `scripts/check-skips.sh` compares that list with the set
CTest actually reports as skipped and **fails in both directions**:

| | |
|---|---|
| a test skips and is not on the list | **FAIL** — a new skip |
| a test on the list no longer skips | **FAIL** — a retired skip whose line was not retired |
| a listed name is not a registered test | **FAIL** — a typo, or a deleted test |
| the output has no skip block to read | **FAIL** — "could not tell" is not "there are none" |

The second row is the one that makes it a ratchet rather than an allowlist. An
allowlist that only fails on a *new* skip is a permanent permission: a test
implemented in 2026 and left on the list goes on authorising a skip for ever and
the count stops meaning anything.

### The list is EMPTY, and the file is not deleted

Phase 9 closed the last five, so `tests/known_skips.txt` has no lines in it — comments
only — and the gate is now simply **"no test may skip"**, which is the phrase §6.4
always said the goal was.

Two consequences worth knowing before you touch either:

- **The first row is now total.** With no permitted lines, *every* test that skips
  lands in it. The other three rows have nothing to check and pass vacuously — which
  is said plainly here so nobody reads a green gate as a four-way check still running.
- **Do not delete the file.** `check-skips.sh` fails on a **MISSING** list by design:
  a test that skipped with no list would otherwise be permitted by the accident of the
  file's own absence. An empty file is the finished state; an absent one is a broken
  gate, and the two look identical from a passing run.

Adding a line back needs no change to the script. A developer who genuinely cannot
implement something writes the line and the skip is red until they do — which is still
the whole point of the file.

It runs in `ci_test` (the required merge gate), in `local-ci.sh`, and in
`make test`. CTest's own exit code cannot express "a test skipped" — it excludes
skips from the pass rate and from the status — which is why the gate is a
separate step reading a saved log rather than part of the `ctest` invocation.

### Why it is a ratchet and not "zero skips"

`docs/SERVER_DESIGN.md` §6.4 used to say the list *"must reach empty by Phase 7"*
and claimed a `KNOWN_SKIPS` list existed. Neither was true: no list existed, and
zero is unreachable before Phase 9. The phase allocation is the reason — CAP and
multi-prefix are §7/Phase 8, and peer discovery, auto-scale, reconnect and
failover are §7/Phase 9, with §2.3 saying "Peer discovery and auto-scale stay
Phase 9" in as many words. Those skips are not unfinished Phase 7 work. A gate
demanding zero would demand a feature Phase 7 must not build, and the only ways
out would be to delete the tests — the exact failure the gate prevents — or to
build two phases inside one.

Seven skips were permitted when this gate landed, and the list was the account of
all seven. Phase 8 closed `CapNegotiation` and `MultiPrefix`. **Phase 9 closed the
remaining five** — `SyncState`, `FailoverReconnect`, `Reconnect`, `PeerDiscovery` and
`AutoScale` — and each moved to `tests/integration/` with its **CTest name unchanged**,
which is why the gate has nothing left to check.

A moved test keeps its name for a mechanical reason: the ratchet names tests by that
name, so renaming a test to suit a build system is how a line goes stale without
anybody noticing. `tests/CMakeLists.txt`'s `irc_ctest_name()` shim is where the name
survives a move.

### Adding a skip

`CONTRIBUTING.md` already requires a test for an absent feature to return CTest's
skip code with a message naming what is missing. That rule is unchanged. On top of
it, **a skip is only permitted with a line in `tests/known_skips.txt`** — a new
skip without one is red in CI, which is the point.

Before you add one, check that the feature is not already allocated to this phase.
Most of what was skipped when this gate landed belonged to a later one; the list
exists so that a skip in the wrong phase is visible rather than plausible.

### Closing a skip

Implement the feature, remove the `return 77` and the `SKIP_RETURN_CODE` from the
test's CMakeLists, and **delete the line from `tests/known_skips.txt` in the same
change**. Leaving the line is a CI failure by design. `test_topic_persist` is the
worked example: it skipped from Phase 1, Phase 7 implemented topic persistence
across a reconnect, and the line is gone.

**If the test moves directories, keep the CTest name.** `AutoScale` is the worked
example: the implementation needed real sockets between real processes, which a target
in `tests/loadbal/` cannot do (it links `irc_core` and nothing else), so the file moved
to `tests/integration/` and the *target* was renamed while `irc_ctest_name()` kept the
CTest name. Renaming both is how a name on the list goes stale, and `check-skips.sh`'s
third row is what catches it.
