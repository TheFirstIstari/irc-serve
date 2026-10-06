#!/usr/bin/env python3
"""gen-rollback-table.py -- GENERATE docs/DEVELOPMENT.md's rollback table.

WHY A GENERATOR, AND THE DOCUMENT ITSELF ASKS FOR IT
-----------------------------------------------------
`docs/DEVELOPMENT.md` said, in its own words: *"AND IF YOU ADD A TAG, ADD IT HERE."*
That is a MANUAL INVARIANT on the one file in the tree whose entire purpose is to tell
you where to roll back to -- and it had already been wrong. The seven SHAs in the table
were pre-rewrite objects until a previous pass corrected them, and the table was missing
a tag while README named a different one as newest. Two stale claims in one paragraph
is not a coincidence; it is a manual invariant that nobody maintains between the tag
and the edit.

So the table is generated, `make docs` rewrites it, and `scripts/check-docs-truth.py`
fails when the committed table disagrees with the repository. The document's
instruction becomes a `make docs` away instead of a memory test.

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
  scripts/gen-rollback-table.py            print the table to stdout
  scripts/gen-rollback-table.py --write    rewrite the block in docs/DEVELOPMENT.md

EXIT STATUS
-----------
0 on success. 1 with a message if the repository cannot be read, or if the markers are
absent from DEVELOPMENT.md -- a generator that silently appends a second copy of the
table is worse than none, so a missing marker is a failure and not a default.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "DEVELOPMENT.md")
BEGIN = "<!-- BEGIN GENERATED: rollback-table (scripts/gen-rollback-table.py; `make docs`) -->"
END = "<!-- END GENERATED: rollback-table -->"


def git(*args):
    out = subprocess.run(["git", "-C", ROOT] + list(args),
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.stderr.write("gen-rollback-table: git %s failed: %s\n"
                         % (" ".join(args), out.stderr.strip()))
        sys.exit(1)
    return out.stdout


def rows():
    """One row per tag, in creatordate order.

    `%(objecttype)` and `%(creatordate:short)` come from `for-each-ref`; the COMMIT sha
    and subject come from `rev-list -n1`, which is the dereference that makes the
    annotated/lightweight distinction matter.
    """
    refs = git("for-each-ref",
               "--sort=creatordate",
               "--format=%(refname:short)%09%(objecttype)",
               "refs/tags")
    out = []
    for line in refs.splitlines():
        if not line.strip():
            continue
        name, objtype = line.split("\t", 1)
        sha = git("rev-list", "-n1", name).strip()[:7]
        subject = git("log", "-1", "--format=%s", sha).strip()
        out.append("| `%s` | %s | `%s` | %s |"
                   % (name, objtype, sha, subject))
    return out


def table():
    head = ("| Tag | Kind | Commit | Subject |\n"
            "|---|---|---|---|")
    body = rows()
    if not body:
        sys.stderr.write("gen-rollback-table: FAIL: the repository has no tags, so "
                         "the table would be empty and a reader would take that as "
                         "'there are no rollback points' rather than as 'the query "
                         "failed'.\n")
        sys.exit(1)
    return head + "\n" + "\n".join(body)


def main():
    text = table()
    if "--write" not in sys.argv:
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
        print("gen-rollback-table: the table is already current")
        return 0
    open(DOC, "w", encoding="utf-8").write(new)
    print("gen-rollback-table: rewrote the rollback table in docs/DEVELOPMENT.md "
          "(%d tags)" % text.count("\n| `"))
    return 0


if __name__ == "__main__":
    sys.exit(main())