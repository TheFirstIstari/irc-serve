#!/usr/bin/env python3
"""check-peer-log-sites.py -- every peer-path `[observable]` printf, accounted for.

WHY THIS EXISTS, AND IT IS NOT "TO FIND THE ONES I MISSED"
-----------------------------------------------------------
Issue #135 said the fix shape already existed in the file it was filed against, and
that this was "less a design question and more a coverage gap". PR #140 converted 56
sites in `src/federation/verbs.c` to `fed_obs()` and left the other four files alone,
because `fed_obs()` was `static` and the other files could not reach it. So at the
time this was written the node had:

    src/federation/verbs.c     0  raw `[observable]` printf sites   (fully covered)
    src/federation/burst.c    27  raw sites
    src/federation/link.c     34  raw sites
    src/federation/nickreg.c   6  raw sites
    src/federation/dedup.c     1  raw site

and `fed_obs()` is now exported precisely so burst.c can use it. A one-time sweep of
those 68 sites found FOUR that print a value the peer chose and that no predicate has
touched; the rest print a validated server name, a validated channel or nickname, this
node's own counters, a fixed literal, or a length. That is a good ratio and it is also
a ratio a reader cannot check, which is the problem: "I looked and there were four" is
a claim with no standing once the file is edited.

WHAT THIS CHECKS, AND WHY IT IS ABOUT `%s` AND NOT ABOUT ARGUMENTS
------------------------------------------------------------------
For every `[observable]` `printf(` statement in `src/federation/*.c`, this parses the
statement's own FORMAT STRING, takes the ordered list of conversions, and checks only
the arguments that a `%s` actually consumes.

That restriction is the difference between a check and noise. The first version of this
file flagged every argument, which meant it flagged `link->fd`, `m->nparams` and
`g_shadow.nnicks` beside every finding and produced 163 lines for a file with four
problems. A check that reports 163 things to say four is a check whose output gets
skimmed, and a skimmed check is a check that has stopped working while still being
green. A `%d` argument cannot put a control byte on a terminal whatever it holds.

So, for each `%s` argument:

  1. IT MAY NOT BE `m->params[...]` OR `m->command`. Those are the parse tree's own
     array and the command word off the wire, with no predicate between them and the
     log. This is the #134 rule generalised from one file to the peer path.
  2. IT MUST BE IN AN ALLOWLIST of expressions this tree asserts are printable BY
     CONSTRUCTION, each with the predicate named beside it.

WHAT IT DOES NOT CHECK, and the limits are the point of stating them
--------------------------------------------------------------------
  - It does not check that an allowlisted expression really is validated at the site
    that prints it. That is a dataflow question needing a C parser; a regex checker
    that pretended to answer it would be the decorative-assertion failure this
    project keeps paying for. What it DOES guarantee is the decidable half: no peer
    string reaches a peer log through `m->` unmeasured. The rest belongs to the
    predicate, and every predicate named below has its own test.
  - REACHABILITY IS NOT CHECKED AND CANNOT BE. A site printing an allowlisted
    expression is reported as OK whether or not a peer can get there, because that is
    not decidable from the text of a line. The four sites this found WERE reachable;
    the other 64 were assessed reachable-with-nothing-the-peer-chose by reading each
    handler, and this file does not pretend it decided that.

EXIT STATUS
-----------
0 when clean. 1 with a per-site report otherwise, naming the file, the line, the
argument and WHY -- because "not allowed" is not an actionable review comment and
"this prints the peer's <nick> on the branch where valid_nick() has not run" is.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FED = os.path.join(ROOT, "src", "federation")

# The expressions a peer CANNOT choose freely, each with the predicate that makes it
# printable. Kept next to the reason so that adding an entry means writing the reason
# too -- which is the only way this list stays short.
ALLOWED = {
    "link->name": "2.3 server name; irc_serve_server_name_valid() at every set site",
    "s->name": "this node's own name; server_init() refuses anything else",
    "s->links[i].name": "2.3 server name, as above",
    "ch->name": "chan_name_valid()",
    "ch->origin": "2.3 server name, as above",
    "sc->name": "the canonical name chan_name_upper() wrote from a validated one",
    "sc->origin": "2.3 server name; burst_copy() of an irc_serve_server_name_valid()",
    "tags.origin": "2.4 tag value; irc_serve_tags_parse() validated it",
    "key.origin": "2.4 tag value, as above",
    "c->nick": "valid_nick() at registration",
    "nick": "valid_nick(); nickreg_learn() applies it again",
    "oldnick": "valid_nick(); this node renamed the holder",
    "fresh": "built by fed_nickreg_next_name() from the old nick and a suffix",
    "peer": "a configured peer name from fed_link_configure()",
    "claim": "the claim from a FEDERATE this node validated against its own config",
    "fed_state_name": "a fixed table key",
    "fed_queue_why_name": "a fixed table key",
    "fed_federate_reason": "a fixed table key",
    "reason": "a fixed literal at every call site",
    "why": "a fixed literal at every call site (a shadow_discard() or report reason)",
    "which": "this node's own enum index",
    "verb": "a table lookup, never the wire's command word",
    "origin": "a local copy of link->name, or of g_shadow.origin which is one",
    "g_shadow.origin": "burst_copy() of link->name",
    # NOT this node's own name in general. `params[0]` is the SQUIT `<server>` there,
    # which fed_in_squit() builds from `s->name`, so it cannot carry a peer-chosen
    # byte -- and it is ALSO SKICK's `<member>` and SMODES' `<server>`, which are
    # whatever the peer put in that slot. Both of those now print through
    # `conn_text_logsafe()` with the count beside them; this entry is the SQUIT site,
    # and it was being read as a blanket exemption for the other two until #141 made
    # one of them a value an operator reads on a refusal line.
    "params[0]": "fed_in_squit()'s <server>, built from this node's own name; the "
                 "SKICK and SMODES uses of params[0] go through conn_text_logsafe()",
    "holder": "the best remote holder from fed_nickreg_best_holder(): a copy of "
              "fed_rnick::server, which is written only from g_shadow.origin (a "
              "burst_copy of link->name) or from an irc_serve_server_name_valid()",
}

# The expressions the rule is about. PATTERNS rather than literal text, so that
# `m->params[3]` and `m->params[12]` are both caught.
BANNED = re.compile(r"\bm->params\[|\bm->command\b")


def strip_comments(src):
    """Blank comments, keeping every byte offset and every string literal.

    Two reasons, both load-bearing:

      * this check's own argument list and docstring name `m->params[...]` and
        `m->command` many times, and a checker that matched itself would be a checker
        that could only ever fail -- the reason check-portability.py strips first;
      * a `[observable]` LINE is recognised by its string literal, so the literals
        cannot be blanked. Comments are replaced by spaces rather than removed so
        that every offset -- and therefore every reported line number -- still
        refers to the real file.
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def read_string_literal(clean, i):
    """The C string literal starting at `i`, or None. Handles `\\` and `\\\"`."""
    q = clean[i]
    if q not in "\"'":
        return None
    j = i + 1
    buf = []
    while j < len(clean):
        if clean[j] == "\\" and j + 1 < len(clean):
            buf.append(clean[j + 1])
            j += 2
            continue
        if clean[j] == q:
            return ("".join(buf), j + 1)
        buf.append(clean[j])
        j += 1
    return None


def read_printf(clean, start):
    """(format_string, [args], end_offset) for the printf at `start`, or None.

    The format string is the concatenation of ADJACENT literals, which is how a long
    `[observable]` line is written in every file here -- `printf("[observable] "
    "fed_x: a=%s\\n", ...)`. Reading only the first literal would leave the `%s`
    conversions of the later ones invisible, and the check would then pass on a
    statement whose peer string is in the third fragment.
    """
    open_paren = clean.index("(", start)
    i = open_paren + 1
    fmt = ""
    while True:
        while i < len(clean) and clean[i] in " \t\n\r":
            i += 1
        lit = read_string_literal(clean, i) if i < len(clean) else None
        if lit is None:
            break
        fmt += lit[0]
        i = lit[1]
    # Skip the comma that separates the format from the first argument. Without this
    # the format string itself is taken as argument 0 and every statement reports one
    # conversion too many -- which is exactly what the first version of this parser
    # did, on all 64 sites.
    while i < len(clean) and clean[i] in " \t\n\r":
        i += 1
    if i >= len(clean) or clean[i] == ")":
        return fmt, [], i + 1
    if clean[i] != ",":
        return None
    i += 1
    # The argument list, split on top-level commas.
    depth = 0
    args = []
    cur = []
    while i < len(clean):
        c = clean[i]
        if c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            if depth == 0:
                tail = "".join(cur).strip()
                if tail:
                    args.append(tail)
                return fmt, args, i + 1
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    return None


def split_ternary(arg):
    """(condition, true_branch, false_branch) if `arg` is a ternary, else None.

    The ternary is the third shape a `%s` argument takes in this tree, and it is the
    one an allowlist keyed on a bare expression cannot see:

        printf("... %s ...", (why != NULL) ? why : "?")
        printf("... %s ...", (link != NULL) ? link->name : claim)
        printf("... %s ...", (open != 0) ? "OPEN" : "NONE")

    In the third of those the argument is a compile-time CONSTANT -- both branches are
    literals -- and flagging it would be noise. In the first two, each branch is an
    ordinary allowlisted expression. So a ternary is checked BRANCH BY BRANCH, which
    makes the constant case fall out as "a literal is printable" rather than needing
    its own exemption list. This is what turned 23 findings into the real ones; the
    version before it flagged all three shapes with one rule and a reader would have
    learned to skip the output.

    `?` inside a nested `(` is not the operator, so the split is depth-aware. There is
    no ternary nested inside a ternary in these files; a reader who adds one will find
    this returns something slightly wrong rather than silently accepting it, which is
    the direction to be wrong in.
    """
    depth = 0
    for i, ch in enumerate(arg):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "?" and depth == 0:
            rest = arg[i + 1:]
            j = 0
            d2 = 0
            while j < len(rest):
                if rest[j] == "(":
                    d2 += 1
                elif rest[j] == ")":
                    d2 -= 1
                elif rest[j] == ":" and d2 == 0:
                    return arg[:i], rest[:j], rest[j + 1:]
                j += 1
            return None
    return None


def is_literal_only(arg):
    """True when `arg` is a string literal, possibly parenthesised."""
    a = arg.strip().strip("()").strip()
    return len(a) >= 2 and a[0] == '"' and a[-1] == '"'


def check_string_arg(arg, rel, lineno, findings, seen):
    """The rule, applied to one `%s` argument.

    `seen` dedupes an expression already reported, so one expression used at twenty
    sites is twenty lines of nothing but one finding.
    """
    if arg in seen:
        return
    seen.add(arg)
    if BANNED.search(arg):
        findings.append(
            (rel, lineno, arg,
             "a parse-tree value (`m->params[...]` / `m->command`) reaching a peer log "
             "as a `%s` argument. Render it with `fed_obs()`, or measure it with "
             "`strlen()` / `conn_text_bad_count()` and print the measurement -- "
             "connection.h's Rule 1."))
        return
    if is_literal_only(arg):
        return
    tri = split_ternary(arg)
    if tri is not None:
        _, t, f = tri
        check_string_arg(t, rel, lineno, findings, seen)
        check_string_arg(f, rel, lineno, findings, seen)
        return
    base = arg.split("(")[0].strip()
    if base not in ALLOWED:
        findings.append(
            (rel, lineno, arg,
             "not on the allowlist. Every allowlisted expression is there because a "
             "named predicate makes it printable by construction; this one needs that "
             "predicate stated here or the value routed through `fed_obs()`."))


CONV = re.compile(r"%[-+ #0123456789.*hlLqjzt]*([a-zA-Z%])")


def conversions(fmt):
    """The conversion letters of `fmt`, in order, with `%%` removed."""
    out = []
    for m in CONV.finditer(fmt):
        if m.group(1) == "%":
            continue
        out.append(m.group(1))
    return out


def check_file(path, findings, stats):
    src = open(path, "r", encoding="utf-8", errors="replace").read()
    clean = strip_comments(src)
    rel = os.path.relpath(path, ROOT)
    for m in re.finditer(r"(?<![A-Za-z0-9_])printf\(", clean):
        parsed = read_printf(clean, m.start())
        if parsed is None:
            continue
        fmt, args, end = parsed
        if "[observable]" not in fmt:
            continue
        stats["sites"] += 1
        convs = conversions(fmt)
        if len(convs) != len(args):
            # A mismatch means the parse is wrong, not the code. Say so rather than
            # checking a prefix of the arguments, because a partial check is a check
            # that reports clean on the part it did not read.
            findings.append(
                (rel, clean[:m.start()].count("\n") + 1, fmt[:60],
                 "this check could not line the format string up with the argument "
                 "list (%d conversions, %d arguments), so it checked NOTHING on this "
                 "line. That is a defect in the check and is reported as a failure, "
                 "because a check that silently skips a site is worse than no check."
                 % (len(convs), len(args))))
            continue
        seen = set()
        for conv, arg in zip(convs, args):
            if conv != "s":
                continue
            stats["strings"] += 1
            check_string_arg(arg, rel, clean[:m.start()].count("\n") + 1, findings,
                             seen)


def main():
    findings = []
    stats = {"sites": 0, "strings": 0}
    if not os.path.isdir(FED):
        sys.stderr.write("check-peer-log-sites: FAIL: %s does not exist, so this "
                         "check would pass vacuously.\n" % FED)
        return 1
    files = sorted(os.path.join(FED, f) for f in os.listdir(FED) if f.endswith(".c"))
    if not files:
        sys.stderr.write("check-peer-log-sites: FAIL: no sources under "
                         "src/federation/, so this check would pass vacuously.\n")
        return 1
    for path in files:
        check_file(path, findings, stats)

    if findings:
        sys.stderr.write("check-peer-log-sites: FAIL: %d of %d `%%s` argument(s) "
                         "across %d `[observable]` site(s) in src/federation/ print a "
                         "value with no predicate between it and the operator's "
                         "terminal:\n"
                         % (len(findings), stats["strings"], stats["sites"]))
        for rel, lineno, arg, why in findings:
            sys.stderr.write("    %s:%d: %s\n" % (rel, lineno, arg))
            sys.stderr.write("        %s\n" % why)
        sys.stderr.write(
            "\n    Two ways out, and which one is right depends on what the\n"
            "    expression is: `fed_obs()` if it is a peer string, or an entry in\n"
            "    ALLOWED above WITH THE PREDICATE THAT MAKES IT PRINTABLE if it is a\n"
            "    value this tree already validated.\n")
        return 1
    print("check-peer-log-sites: OK: %d `[observable]` site(s) and %d `%%s` argument(s) "
          "in src/federation/; every `%%s` prints either an allowlisted expression "
          "with its predicate named or a value routed through fed_obs()."
          % (stats["sites"], stats["strings"]))
    print("    This says nothing about REACHABILITY -- see the file's header. It says "
          "no peer string reaches a peer log unmeasured, which is the narrower claim "
          "that is decidable from the text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())