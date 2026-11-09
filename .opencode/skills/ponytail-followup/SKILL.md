---
name: ponytail-followup
description: >
  After a ponytail-audit report: verify each finding against the source, fix
  each real one on its own branch with its own pull request, then land the
  stack with scripts/merge-train.sh. Use when the user says "fix the audit",
  "fix all findings", "open PRs for these", or "merge the train".
---

Turn a `ponytail-audit` report into merged fixes, one PR per finding. PONYTAIL
MODE rules still apply: smallest diff that works, delete over add, no layers.

## 1. Verify before you touch

Re-read every finding's file:lines. Drop with a stated reason, do not fix:

- No concrete case (input -> wrong result) you can reproduce by reading.
- A marked deliberate trade (`shortcut:` comment, or a comment arguing both
  sides) that the expected load does not cross.
- Lean-only churn with a wide blast radius and zero behaviour gain.
- A claim the source contradicts (read the caller, not just the function).

Report what you dropped and why. That is the review, not cowardice.

## 2. One branch and one PR per finding

Branch from `main`: `fix/short-name`. Keep the diff to the finding; if two
findings share a file, keep hunks disjoint so merges stay clean. Build and run
the relevant tests per PR (full suite at least once before merging anything).
Commit message: `fix: <what>`, body naming the case. Push, `gh pr create`
with the finding number in the body.

If a PR's own tests catch a deeper problem (e.g. a fix deadlocks a case the
suite covers), fix the branch — the suite is right until proven otherwise.

## 3. Land with the train

`main` is protected and strict: merging one PR flips the rest to BEHIND, each
needing a full CI rerun. Never `--admin` (admins are enforced too).

```sh
./scripts/merge-train.sh PR PR PR   # updates all branches, merges each as green
```

Conflicting hunks in one file: resolve by keeping both changes, rebuild that
configuration, push to the branch. After the train: full suite on `main`,
delete the branches. End with what you skipped and the risk, in plain English.
