#!/usr/bin/env python3
"""FAULT: packaging/debian/source/format opens with a comment block above the value.

THIS IS THE FAULT THAT WAS FOUND AND FIXED IN THIS PASS, and it is here for that
reason rather than for symmetry with the others.

WHAT IT IS
----------
`debian/source/format` is read by `Dpkg::Source::Format::parse()`, which is:

    my $format = <$fh>;
    chomp $format if defined $format;
    error(g_('%s is empty'), $desc)
        unless defined $format and length $format;
    $self->set($format);

and `set()` accepts the string only if it matches

    ^(\\d+)(?:\\.(\\d+))?(?:\\s+\\(([a-z0-9]+)\\))?$

ONE `<$fh>` read, one anchored regex, and NO comment handling. So a file that opens
with a comment block -- which is what a maintainer writes when they want to explain
themselves, and which dpkg's OWN man pages invite, because they document `#` comments
in `debian/source/include-binaries`, `debian/source/options` and
`debian/patches/series` and say nothing about this file -- is a HARD ERROR:

    dpkg-source: error: source package format '# debian/source/format -- 3.0
    (quilt)' is invalid

An earlier draft of `packaging/debian/source/format` in this repository was 30 lines
of explanation followed by the value. It was correct as prose and it would have broken
`dpkg-source` on the first real Debian build -- which is issue #48's build, and the one
nobody here can run. The reasoning it carried now lives in `packaging/README.md`,
which dpkg does not parse.

WHY THIS FAULT IS WORTH A SEPARATE FILE
---------------------------------------
The three-document trap is that every available description of this file says
"comments are skipped": dpkg's three sibling files all say so in as many words, and
`debian/patches/series` in THIS repository carries a comment block that is genuinely
fine. A check that took "comments are skipped" as a general property of `debian/`
would pass this fault and pass the real bug. So this fault is here to keep the
check-packaging.py check pinned to dpkg's actual parser rather than to a habit
learned from its neighbours.

NO sleep, NO PORT, NO TIMER: this rewrites one line of a text file.
"""

import os
import sys

FORMAT = os.path.join("packaging", "debian", "source", "format")

with open(FORMAT, "r", encoding="utf-8") as fh:
    before = fh.read()

if not before.strip().startswith("3.0"):
    sys.stderr.write("source_format_leading_comment: FAULT NOT APPLIED: %s does not "
                     "contain a 3.0 format.\n" % FORMAT)
    sys.exit(1)

with open(FORMAT, "w", encoding="utf-8") as fh:
    fh.write("# debian/source/format -- 3.0 (quilt), because the changelog carries a\n"
             "# Debian revision and a native package may not have one.\n"
             "#\n"
             "# The reasoning continues in packaging/README.md.\n"
             "3.0 (quilt)\n")