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

| Control | Setting |
|---|---|
| Direct pushes | Blocked — a push that does not satisfy every required check is rejected with `GH006` |
| Required checks | 9: `ci_test`, `ci_benchmark`, `ci_compliance`, `ci_macos` ×2, `build_arch` ×4 |
| Checks must be current | `strict` — you cannot merge on results from an older commit |
| Linear history | Merge commits rejected; squash only |
| Force push | Disabled |
| Deletion | Disabled |
| Admins | Subject to all of the above |

`build_cachyos` is deliberately **not** a required check. It runs on a
self-hosted machine, and requiring it would mean the project cannot merge
anything while that machine is off.

### Why there is no required review

`required_pull_request_reviews` is off, and that is a deliberate decision rather
than an oversight.

GitHub does not let you approve your own pull request, and a required review must
come from an account with write access. This repository currently has exactly
one such account. **Enabling required reviews would therefore make it impossible
to merge anything, ever** — not a policy that is merely unenforced, a repository
that is permanently stuck.

If a second maintainer is added, turn it on:

```sh
gh api -X PATCH repos/TheFirstIstari/irc-serve/branches/main/protection \
  -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -F 'required_pull_request_reviews[dismiss_stale_reviews]=true'
```

Until then, the required checks plus linear history are what actually hold. They
stop a broken commit landing and stop history being rewritten; they do not stop
an unreviewed but *working* commit landing, and it is worth being honest that
this is the weaker guarantee.

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
