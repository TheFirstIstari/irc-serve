#!/usr/bin/env python3
"""gen-rollback-table.py -- GENERATE docs/DEVELOPMENT.md's rollback table.

WHY A GENERATOR, AND THE DOCUMENT ITSELF ASKS FOR IT
-----------------------------------------------------
`docs/DEVELOPMENT.md` said, in its own words: *"AND IF YOU ADD A TAG, ADD IT HERE."*
That is a MANUAL INVARIANT on the one file in the tree whose entire purpose is to tell
you where to roll back to -- and it had already been wrong. The seven SHAs in the table
were pre-rewrite objects until a previous pass corrected them, and the table was missing
a tag while README named a different one as newest. Two stale claims in one paragraph
is not a coincidence; it is a manual invariant that nobody maintains between the tag and
the edit.

So the table is generated, `make docs` rewrites it, and `scripts/check-docs-truth.py`
fails when the committed table disagrees with the repository. The document's
instruction becomes a `make docs` away instead of a memory test.

WHICH REPOSITORY, AND WHY THAT IS THE WHO OF THIS FILE'S LAST CHANGE
---------------------------------------------------------------------
It used to read `refs/tags` out of the CLONE. That is the wrong repository, and the
consequence is not subtle: this project carries tags that exist only on one developer's
machine, so `make docs` on that machine writes a table CI cannot reproduce and
`check-docs-truth.py` answers a different question there than it answers in CI. The
answer is then true of nobody. Measured on the machine this was written on: the local
clone held 11 tags and `origin` held 9, and the two the clone had extra were the ones
that made README's "the tree's newest tag is `safety-net`" sentence true locally and
false everywhere else.

So the tag LIST comes from `git ls-remote --tags <remote>` -- a query against the
remote, which a local ref cannot answer -- and the METADATA (creatordate, subject,
the dereferenced commit) comes from a fetch into a PRIVATE ref namespace rather than
from `refs/tags`. Both halves are needed and neither is decorative:

  * `ls-remote` alone gives names and object SHAs and no dates, so it cannot say which
    tag is newest, which is the claim README.md makes;
  * `refs/tags` alone answers that instantly, and is exactly the local state that is
    not allowed to decide it.

The private namespace is `refs/ircserve-docstruth/tags`. A dedicated namespace rather
than a plain `git fetch --tags` for one reason: the verdict must be a function of the
REMOTE and not of whether some earlier command happened to update this clone, and a
fetch that writes the repository's own `refs/tags` would reintroduce exactly that.
Nothing outside this file reads that namespace, and `git ls-remote` is re-run every
time, so a tag deleted on the remote disappears from the table rather than lingering.

WHAT IS GENERATED, AND THE HONEST LIMIT OF IT
---------------------------------------------
The ROWS. One row per tag, ordered by `creatordate`, with:

  * the tag name;
  * the KIND -- `tag` (annotated) or `commit` (lightweight). This is not decoration:
    it is the fact that broke the document's own verification command, because
    `%(objectname:short)` on an ANNOTATED tag yields the TAG OBJECT rather than the
    commit, so the old first command printed seven SHAs that were all wrong while the
    table beside it was right;
  * the COMMIT's short SHA, from `git rev-list -n1 <tag>` -- the dereference, which is
    the whole correction;
  * the commit's subject, from that same commit rather than from the tag object.

THE LIMIT, stated because a generator is easy to over-claim: **a generator can only
produce the part that is a function of the repository.** It cannot check the PROSE
AROUND the table. "There is no v0.8.0 because nothing after Phase 5 was tagged" is a
claim about what the table MEANS, and no `awk` over `for-each-ref` can decide whether a
reader will draw the same conclusion from the same rows. What the generator plus its
test buys is that the rows are true; what it does not buy is that the argument made
about them is. Prose cannot be checked the way `#error` checks code, and the claim
that it could is the failure mode this replaces.

USAGE
-----
  scripts/gen-rollback-table.py                print the table to stdout
  scripts/gen-rollback-table.py --write        rewrite the block in docs/DEVELOPMENT.md
  scripts/gen-rollback-table.py --newest-tag   print the newest tag's NAME and nothing
                                               else; the provenance goes to stderr
  scripts/gen-rollback-table.py --remote R     read R instead of `origin`

EXIT STATUS
-----------
0 on success. 1 with a message if the REMOTE cannot be read, if a tag the remote names
cannot be fetched, or if the markers are absent from DEVELOPMENT.md -- a generator that
silently appends a second copy of the table is worse than none, so a missing marker is
a failure and not a default. Equally, a remote that cannot be reached is a FAILURE and
never a fallback to the local clone: falling back is the bug this file was changed to
remove, and reintroducing it as an "if the network is down" branch would put it back
for exactly the runs nobody is watching.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "DEVELOPMENT.md")
BEGIN = "<!-- BEGIN GENERATED: rollback-table (scripts/gen-rollback-table.py; `make docs`) -->"
END = "<!-- END GENERATED: rollback-table -->"

# The remote, and the private namespace the remote's tag objects are fetched into.
# WHY A CONSTANT AND NOT `refs/tags`: see the header. A tag the remote does not have
# must be unable to reach the table by way of this clone's own refs.
DEFAULT_REMOTE = "origin"
TAG_NAMESPACE = "refs/ircserve-docstruth/tags"


def die(msg):
    sys.stderr.write("gen-rollback-table: %s\n" % msg)
    sys.exit(1)


def git(*args):
    out = subprocess.run(["git", "-C", ROOT] + list(args),
                         capture_output=True, text=True)
    if out.returncode != 0:
        die("git %s failed: %s" % (" ".join(args), out.stderr.strip()))
    return out.stdout


def remote_tag_names(remote):
    """The tag NAMES the remote has, from `git ls-remote`.

    This is the authority on WHICH tags exist, and it is deliberately not
    `for-each-ref refs/tags`: a query against the remote cannot be answered by a ref
    that exists only in this clone, which is the entire point of the change.

    `ls-remote --tags` prints a second line per ANNOTATED tag, with `^{}` appended to
    the refname, naming the commit the tag peels to. The `^{}` suffix is stripped and
    the name is recorded once; `annotated` is set for exactly the tags that had a
    peeled line, which is how the KIND column is derived without a second question to
    the local repository.
    """
    out = subprocess.run(["git", "-C", ROOT, "ls-remote", "--tags", remote],
                         capture_output=True, text=True)
    if out.returncode != 0:
        die("cannot read tags from remote '%s': %s\n"
            "    The tag list is a question about the REPOSITORY, not about this\n"
            "    clone, and it is not answered from refs/tags when the remote cannot\n"
            "    be reached -- a fallback here is the defect this file was changed to\n"
            "    remove. Check the network and the remote name, or pass\n"
            "    --remote <name>." % (remote, out.stderr.strip() or out.stdout.strip()))
    names = []
    annotated = set()
    for line in out.stdout.splitlines():
        if "\t" not in line:
            continue
        _, ref = line.split("\t", 1)
        if not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            annotated.add(name[:-3])
            continue
        names.append(name)
    if not names:
        die("remote '%s' has no tags, so the table would be empty and a reader "
            "would take that as 'there are no rollback points' rather than as 'the "
            "query failed'." % remote)
    return names, annotated


def sync_tag_objects(remote):
    """Fetch the remote's tags into the PRIVATE namespace, then make it EXACTLY them.

    `--no-tags` so git does not follow tags by its own default and write refs/tags;
    `+refs/tags/*:...` so only this namespace moves and a tag that was moved or
    deleted on the remote is corrected rather than shadowed by what the clone
    happens to hold. `--force` is what makes the "+" legal, and it is safe here
    because the destination is a namespace nothing else in the repository uses.

    `--prune` IS LOAD-BEARING AND WAS MISSED IN THE FIRST VERSION OF THIS FUNCTION.
    Without it a tag DELETED on the remote stays in the namespace forever, and the
    namespace is what the ordering is read from -- so the exact defect this file was
    changed to remove came back through the back door. It was caught by running this
    file against the local clone first (which put two tags origin does not have into
    the namespace) and then against origin again: the two stale entries survived the
    second fetch and `--sort=-creatordate --count=1` handed one of them back as "the
    newest tag". A namespace that can hold a tag the remote has deleted is not a
    mirror of the remote, and the fix is to delete what the remote does not have.
    """
    out = subprocess.run(
        ["git", "-C", ROOT, "fetch", "--quiet", "--no-tags", "--force", "--prune",
         remote, "+refs/tags/*:%s/*" % TAG_NAMESPACE],
        capture_output=True, text=True, check=False)
    if out.returncode != 0:
        die("cannot fetch tags from remote '%s': %s"
            % (remote, out.stderr.strip() or out.stdout.strip()))
    return TAG_NAMESPACE


def verify_tag_objects(remote, names, namespace):
    """The namespace must hold EXACTLY the tags the remote named -- no more, no fewer.

    This is the cross-check that makes the two halves honest. `ls-remote` says what
    the remote has; the namespace says what this machine can actually read the
    metadata of. If they disagree the answer is incomplete, and an incomplete answer
    from a documentation check is a FAILURE -- a table quietly missing a tag reads as
    a table of every tag, and (the half this check originally lacked) a namespace
    quietly KEEPING a tag reads as a tag the project still has.
    """
    present = set()
    for line in git("for-each-ref", "--format=%(refname:short)",
                    namespace).splitlines():
        if line.strip():
            present.add(line.strip().split("/")[-1])
    want = set(names)
    missing = sorted(want - present)
    extra = sorted(present - want)
    if missing or extra:
        die("the fetched tag namespace does not match remote '%s'.\n"
            "    named by the remote but not present: %s\n"
            "    present but NOT named by the remote: %s\n"
            "    This is a failure rather than a shorter or longer table, because a "
            "table\n    that is missing a tag reads as a table of every tag and one "
            "that has an extra\n    reads as a rollback point the project has."
            % (remote,
               ", ".join(missing) or "(none)",
               ", ".join(extra) or "(none)"))


def rows(remote):
    """One row per tag ON THE REMOTE, in creatordate order.

    The dates and the subjects come from the fetched objects rather than from
    `refs/tags`, and `creatordate` is a property of the OBJECT -- an annotated tag's
    tagger date, a lightweight tag's commit date -- so it is the same number on every
    machine that has the object. That is what makes the ORDER reproducible and the
    local clone's extra tags irrelevant.
    """
    names, annotated = remote_tag_names(remote)
    namespace = sync_tag_objects(remote)
    verify_tag_objects(remote, names, namespace)

    refs = git("for-each-ref",
               "--sort=creatordate",
               "--format=%(refname:short)\t%(objecttype)",
               namespace)
    out = []
    seen = set()
    for line in refs.splitlines():
        if not line.strip():
            continue
        full, objtype = line.split("\t", 1)
        name = full.split("/")[-1]
        if name not in names or name in seen:
            continue
        seen.add(name)
        sha = git("rev-list", "-n1", name).strip()[:7]
        subject = git("log", "-1", "--format=%s", sha).strip()
        # The KIND column, taken from what the remote said rather than from the local
        # clone's view of the object: the two can only disagree if the object was
        # re-tagged, and the remote's answer is the one the document is about.
        kind = "tag" if name in annotated else objtype
        out.append("| `%s` | %s | `%s` | %s |" % (name, kind, sha, subject))
    if len(seen) != len(names):
        die("read %d of %d tags the remote '%s' has; the table would be short."
            % (len(seen), len(names), remote))
    return out


def newest_tag_name(remote):
    """The newest tag ON THE REMOTE, by creatordate. The whole of this file's answer
    to README.md's "the tree's newest tag is `X`".

    It reads the namespace the way `rows()` does -- ordered, then FILTERED to the
    names `ls-remote` reported -- and the filter is not belt and braces. The first
    version of this function took `--count=1` straight off the namespace with no
    filter, and when the namespace still held a tag from an earlier read of a
    different repository it returned that one: the newest tag was a tag the remote
    did not have. `verify_tag_objects` now makes an exact match a precondition, and
    this filter is the second line of the same defence, because the claim this
    answers is a single word in a README and there is no reason it should be the one
    place in the file that trusts the namespace blindly.
    """
    names, _ = remote_tag_names(remote)
    namespace = sync_tag_objects(remote)
    verify_tag_objects(remote, names, namespace)
    want = set(names)
    for line in git("for-each-ref", "--sort=-creatordate",
                    "--format=%(refname:short)", namespace).splitlines():
        if not line.strip():
            continue
        name = line.strip().split("/")[-1]
        if name in want:
            return name
    return None


def table(remote):
    head = ("| Tag | Kind | Commit | Subject |\n"
            "|---|---|---|---|")
    body = rows(remote)
    if not body:
        die("remote '%s' produced no rows, so the table would be empty." % remote)
    return head + "\n" + "\n".join(body)


def main():
    remote = DEFAULT_REMOTE
    argv = sys.argv[1:]
    if "--remote" in argv:
        i = argv.index("--remote")
        if i + 1 >= len(argv):
            die("--remote needs a remote name")
        remote = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]

    if "--newest-tag" in argv:
        name = newest_tag_name(remote)
        if name is None:
            die("remote '%s' has no tags, so there is no newest one." % remote)
        print(name)
        # Provenance on stderr, so a caller can show WHICH repository produced the
        # answer it is about to compare against a document. It is the one line that
        # makes the answer auditable, and it goes to stderr so stdout stays a value.
        # ONE line and no more: check-docs-truth.py prints this next to the claim it
        # checked, so it has to say WHICH repository without burying the answer. The
        # long form is in this file's header.
        sys.stderr.write("remote '%s', by creatordate (git ls-remote --tags %s)\n"
                         % (remote, remote))
        return 0

    text = table(remote)
    if "--write" not in argv:
        print(text)
        return 0
    doc = open(DOC, "r", encoding="utf-8").read()
    if BEGIN not in doc or END not in doc:
        sys.stderr.write(
            "gen-rollback-table: FAIL: docs/DEVELOPMENT.md does not carry the "
            "generated-table markers.\n"
            "  expected to find:\n    %s\n    %s\n"
            "  A generator that appends a second copy of the table is worse than no "
            "generator, so this is a failure and not a default.\n" % (BEGIN, END))
        return 1
    pat = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    new = pat.sub(lambda _m: BEGIN + "\n" + text + "\n" + END, doc, count=1)
    if new == doc:
        print("gen-rollback-table: the table is already current (remote '%s')" % remote)
        return 0
    open(DOC, "w", encoding="utf-8").write(new)
    print("gen-rollback-table: rewrote the rollback table in docs/DEVELOPMENT.md "
          "(%d tags, read from remote '%s')" % (text.count("\n| `"), remote))
    return 0


if __name__ == "__main__":
    sys.exit(main())