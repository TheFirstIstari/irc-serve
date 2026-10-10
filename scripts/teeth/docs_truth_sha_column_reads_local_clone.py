#!/usr/bin/env python3
"""teeth/docs_truth_sha_column_reads_local_clone.py -- the COMMIT column, read from
this clone, and the tooth the existing one could not be.

THE FAULT
---------
One argument. `rows()` in `scripts/gen-rollback-table.py` resolved the commit with

    sha = git("rev-list", "-n1", <BARE TAG NAME>)

A bare name is what git resolves against the repository's ORDINARY refs -- this clone's
`refs/tags` -- and not against `refs/ircserve-docstruth/tags`, which is where the remote's
tag objects are actually fetched. Every other value in the row (the name from
`ls-remote`, the order from `creatordate`, the kind from the peeled line) came from the
remote; the SHA came from the clone. So the same remote published two different SHAs for
the same tag depending on which clone ran `make docs`, and the table that was COMMITTED
was whichever clone that was.

Measured on the two machines this was fixed on, one remote, nine tags: eight of the nine
SHAs differed, and one of the two machines was a CLEAN clone of exactly the remote's nine
tags. The defect did not need a local-only tag to happen -- it needed a clone whose
`refs/tags` had been moved by the history rewrite.

WHY THIS IS A SEPARATE TOOTH AND NOT A WIDENING OF THE EXISTING ONE
-------------------------------------------------------------------
`scripts/teeth/docs_truth_reads_local_clone.py` faults `DEFAULT_DOCS_REMOTE` from
`origin` to `.`, and it goes red for the RIGHT reason -- a tag the local repository has
and the committed table does not. That is the tag LIST. It stayed GREEN for the whole
life of the SHA defect, because the list half had been fixed and the column half had not,
and a check that covers the list and not the column is a check that reports CLEAN while
the defect it is named for is present. Two instruments are needed because they are two
columns.

WHY THE DIVERGENCE IS MANUFACTURED HERE RATHER THAN HOPED FOR
--------------------------------------------------------------
The existing tooth's docstring says the machine "carries tags `origin` does not -- measured
at the time of writing: the clone held 11 and `origin` held 9". That is a property of ONE
developer's checkout. On a clean clone the bare-name fault is INVISIBLE: `refs/tags/<tag>`
and `refs/ircserve-docstruth/tags/<tag>` name the same commit, so the faulted generator
regenerates the committed table byte for byte and the check is green. A tooth that only
bites on one machine is a tooth that silently stops biting on CI and on the Linux gate box
-- which is the same failure the last pass collected, in a different instrument.

So this fault builds its own divergence, and it does it with a DECOY rather than by moving
a tag. Git's ref resolution tries `refs/<name>` BEFORE `refs/tags/<name>`, so a ref at
`refs/<tag>` shadows the clone's tag of that name for bare-name resolution while leaving
`refs/tags/` itself completely untouched:

  * `git rev-list -n1 <tag>`                      -> the decoy   (what the fault reads)
  * `git rev-list -n1 refs/tags/<tag>`            -> unchanged    (nothing else moved)
  * `git rev-list -n1 refs/ircserve-docstruth/tags/<tag>` -> the remote's answer

WHAT IS AND IS NOT REPRODUCED, stated so nobody over-claims this tooth. The mechanism is
the real one -- a bare name resolved against the clone's refs instead of the fetched
namespace -- and the ref it resolves to is planted at `refs/<tag>` rather than by editing
`refs/tags/<tag>`, because planting a new ref cannot leave a developer's checkout in a
different state if this process is killed between the two lines below. It does NOT
reproduce the history-rewrite sequence that moved the tag in the first place; that is a
provenance question and not the property under test.

THE NEEDLE CANNOT BE SATISFIED BY A COMMENT, and that is enforced rather than asserted
---------------------------------------------------------------------------------------
`ORIGINAL` below is the whole fixed line, `sha = git("rev-list", "-n1", full)...`. The
production file's own comments quote the old call in prose, and a fault script that
replaces the first textual match would rewrite a COMMENT -- leaving the code intact, the
fault "applied", and the tooth reporting coverage it does not have. That is not
hypothetical: this project shipped a `--asan-selftest` grep in a workflow that stayed
green against a fault that had deleted the assertion the grep exists to check, because
the assertion had been satisfied by prose.

So `_find_in_code` accepts a match only on a line whose stripped text does not begin with
`#`, it requires EXACTLY ONE such line, and it refuses to apply if there is not exactly
one. A needle a comment can satisfy is not a needle, and this one is built so that it
cannot be.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TARGET = "scripts/gen-rollback-table.py"

# The FIXED line: the full refname the namespace gave us. Indented, because a match at
# column 0 would be a different statement and this file has no such statement.
ORIGINAL = '        sha = git("rev-list", "-n1", full).strip()[:7]'

# The FAULTED line: a bare tag name, which git resolves against refs/tags. This is the
# defect verbatim -- it is what the code said before this pass and what it must never say
# again.
FAULTED = '        sha = git("rev-list", "-n1", name).strip()[:7]'

DECOY_RECORD = "decoy.ref"


def die(msg):
    sys.stderr.write("teeth fault: %s\n" % msg)
    sys.exit(1)


def git(*args):
    out = subprocess.run(["git", "-C", ROOT] + list(args),
                         capture_output=True, text=True)
    if out.returncode != 0:
        die("git %s failed: %s" % (" ".join(args), out.stderr.strip()))
    return out.stdout


def _find_in_code(text, needle):
    """The line numbers where `needle` appears on a line that is CODE.

    A COMMENT IS NOT A MATCH, and that is the whole point of this function. Both
    needles are whole statements, so a line carrying one is the statement and not a
    sentence about it -- but "so" is an argument, and the argument is only as good as the
    code that enforces it, so the check is here rather than in a docstring. A line whose
    stripped form starts with `#` is a comment; a `#` further along the line is not
    treated as one, because this file's needles contain no `#`.
    """
    hits = []
    for n, line in enumerate(text.split("\n"), 1):
        if needle in line and line.strip().startswith("#"):
            continue
        if needle in line:
            hits.append(n)
    return hits


def remote_tag(remote):
    """One tag name the REMOTE has, chosen deterministically.

    It must be a tag the remote has, because the row this fault corrupts is a row the
    table has: a tag only the clone had is filtered out before `rev-list` is ever
    reached, so decoying one of those would plant a ref that the faulted line never
    reads and the tooth would pass for the wrong reason.
    """
    names = []
    for line in git("ls-remote", "--tags", remote).splitlines():
        if "\t" not in line:
            continue
        _, ref = line.split("\t", 1)
        if ref.startswith("refs/tags/") and not ref.endswith("^{}"):
            names.append(ref[len("refs/tags/"):])
    if not names:
        die("remote '%s' named no tags, so this fault has no row to corrupt." % remote)
    return sorted(names)[0]


def distinct_commit(tag):
    """A commit that is NOT what the clone's tag of that name peels to.

    Candidates are tried in order and each is checked, rather than taking `HEAD` and
    hoping: if the decoy happened to point at the same commit the real tag points at,
    bare-name resolution and the correct answer would coincide, the faulted generator
    would regenerate the committed table exactly, and the tooth would report GREEN on a
    fault it had failed to make visible. That is the "fault applied but proves nothing"
    outcome, and it is worth three lines to be sure it cannot happen.
    """
    tag_ref = "refs/tags/%s" % tag
    have = git("rev-parse", "--verify", "--quiet", tag_ref)
    have = have.strip() if have.strip() else None
    ns_ref = "refs/ircserve-docstruth/tags/%s" % tag
    have_ns = git("rev-parse", "--verify", "--quiet", ns_ref)
    have_ns = have_ns.strip() if have_ns.strip() else None

    # Peeled, because that is what the faulted line asks for: a tag OBJECT and the
    # commit under it are different values and comparing them would be comparing the
    # wrong pair.
    def peel(ref):
        out = subprocess.run(["git", "-C", ROOT, "rev-list", "-n1", ref],
                             capture_output=True, text=True)
        return out.stdout.strip() if out.returncode == 0 else None

    for cand in ("HEAD", "HEAD~1", "origin/main", "origin/main~1"):
        sha = git("rev-parse", "--verify", "--quiet", cand).strip()
        if not sha:
            continue
        peeled = peel(cand)
        if peeled is None:
            continue
        if have is not None and peel(tag_ref) == peeled:
            continue
        if have_ns is not None and peel(ns_ref) == peeled:
            continue
        return sha
    die("no commit could be found that differs from every ref named %s; refusing to "
        "plant a decoy that would not change the answer." % tag)


def main():
    path = os.path.join(ROOT, TARGET)
    if not os.path.isfile(path):
        die("%s not found" % TARGET)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    hits = _find_in_code(text, ORIGINAL)
    if len(hits) != 1:
        die("%s must contain the FIXED rev-list line on exactly one non-comment line; "
            "found %d. Refusing to apply rather than reporting a fault that was not."
            % (TARGET, len(hits)))

    if _find_in_code(text, FAULTED):
        die("%s already resolves the commit from a BARE tag name. This fault is already "
            "applied; applying it again would look like coverage and prove nothing."
            % TARGET)

    text = text.replace(ORIGINAL, FAULTED, 1)

    # The same guard AFTER the write. A replacement that landed on a comment would leave
    # a file that still compiles, still runs, and still publishes the clone's SHA to
    # nobody -- so the fault has to be verified where it happened, not assumed.
    landed = _find_in_code(text, FAULTED)
    if landed != hits:
        die("the replacement did not land on the line it was aimed at (%s vs %s); the "
            "fault would be a no-op." % (landed, hits))

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)

    # --- the divergence, built so the tooth does not depend on whose checkout this is ---
    tag = remote_tag("origin")
    sha = distinct_commit(tag)
    decoy = "refs/%s" % tag
    git("update-ref", decoy, sha)

    # PROVEN, not assumed: the decoy must actually be what a bare name resolves to, or
    # the fault reads the correct answer and the tooth passes for the wrong reason.
    bare = git("rev-list", "-n1", tag).strip()
    if bare != sha:
        die("a bare name resolved to %s rather than to the decoy %s; this git does not "
            "resolve refs/<name> ahead of refs/tags/<name>, so the decoy would be "
            "inert." % (bare[:7], sha[:7]))

    state = os.environ.get("TEETH_STATE_DIR")
    if state:
        with open(os.path.join(state, DECOY_RECORD), "w", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (decoy, sha))

    sys.stderr.write("teeth fault: commit column resolves the bare tag name, and "
                     "refs/%s is planted locally so bare-name resolution has something "
                     "local to find.\n" % tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())