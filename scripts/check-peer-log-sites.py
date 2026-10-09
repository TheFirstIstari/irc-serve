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

WHAT CHANGED IN THIS PASS, AND IT IS WHY THE CHECK WAS GREEN ON A FAULT
------------------------------------------------------------------------
The previous version of this file swept `printf(` sites only -- there are 64 of them
against 68 `fed_obs(` ones -- so it enforced every rule about peer strings on the RAW
path and none on the FILTERED one. A bare `%s` fed_obs site was green because
`fed_obs()` satisfies the routing advice a finding gives, and because the allowlist was
keyed on expression TEXT: one site's recorded justification for `link->name` was a blank
cheque for every other site's.

Three things changed:

  1. IT READS `fed_obs(` TOO. 132 sites rather than 64, 220 `%s` arguments rather than
     82. The measurement assertion only means anything on the filtered path, because
     fed_obs() is the thing that WITHHOLDS a value as `-`.
  2. IT ASSERTS THE MEASUREMENT. A value fed_obs may withhold must carry a
     `<field>_len=` and a `<field>_bad_bytes=` beside it, or have a named predicate
     recorded in ALLOWED_SITES FOR THAT CALL SITE. Neither was checked before, which is
     the whole of the reported gap.
  3. ALLOWED_SITES IS KEYED ON CALL SITE, so one site's justification stops blanketing
     the same expression everywhere else.

Two of the fixes were WRONG before they were right, and both are recorded at the site
rather than here, because a site is where the next person looks: `shown_by` is a
RENDERED buffer, so measuring it reported the length of `-` and not of what the peer
sent; and `loadbuf` is a 16-byte COPY, so it reported 15 for an input of 200. A
measurement of the wrong string is worse than no measurement, because it is a number
that looks like an answer.

WHAT IT DOES NOT CHECK, and the limits are the point of stating them
----------------------------------------------------------------------
  - It does not check that an allowlisted expression really is validated at the site
    that prints it. That is a dataflow question needing a C parser; a regex checker
    that pretended to answer it would be the decorative-assertion failure this
    project keeps paying for. What it DOES guarantee is the decidable half: no peer
    string reaches a peer log unmeasured. The rest belongs to the
    predicate, and every predicate named below has its own test.
  - THE MEASUREMENT IS PAIRED BY NAME. `subject=%s` beside `subject_len=%zu` is
    accepted; a `subject=%s` whose length is really some other field's would also be
    accepted. It cannot tell whether the length is the length OF that argument -- only
    whether the name matches. This is a name-discipline check, not a dataflow one, and
    saying so is more useful than pretending otherwise.
  - REACHABILITY IS NOT CHECKED AND CANNOT BE. A site printing an allowlisted
    expression is reported as OK whether or not a peer can get there, because that is
    not decidable from the text of a line. The four sites this found WERE reachable;
    the other 64 were assessed reachable-with-nothing-the-peer-chose by reading each
    handler, and this file does not pretend it decided that. The same limit applies to
    all 132 sites now in scope.

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
    "field": "which of two named fields a refusal is about -- \"user\" or \"host\", "
             "a fixed literal at both call sites (nickreg_ident_refused)",
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

# ---------------------------------------------------------------------------
# MEASUREMENT: the assertion this check was missing, and what it is NOT
# ---------------------------------------------------------------------------
# The problem, stated as the pass found it. This check was GREEN on a bare-`%s` of a
# peer-chosen value, because fed_obs() satisfies the routing rule -- every `%s` that
# goes through fed_obs() is "safe" by definition, and a site that adds one with no
# measurement beside it is still routed through fed_obs(). It went red only on the
# PRE-#135 shape, a raw `printf`. So the check enforced a rule the project had already
# finished migrating away from, and the migration's own requirement -- that a WITHHELD
# peer value be MEASURED, so `len=` and `bad_bytes=` sit beside it -- was not checked
# at all.
#
# Why the requirement exists, from connection.h: `conn_text_logsafe()` renders a peer
# string as `-` when any byte is not printable ASCII. An operator reading
# `fault_bare: target=-` learns that something was withheld and nothing else: not how
# long it was, not how bad. `len=` and `bad_bytes=` are what turn "the peer sent
# something I am not showing you" into a diagnosable statement. So the assertion is not
# "the value was filtered" -- fed_obs does that -- it is "the line says how much it
# withheld and how much of it was unprintable".
#
# WHAT IT DOES NOT CLAIM. It cannot tell whether the len= beside a field is the len OF
# that field: `subject_len=` beside `subject=` is checked by name-pairing, and a field
# named `foo=` with `bar_len=` beside it is not caught. That is a name-discipline
# check, not a dataflow check, and saying so here is more useful than pretending
# otherwise. What it DOES guarantee is that a site printing a peer value through
# fed_obs() prints a measurement SOMEWHERE on the same line, which is the property that
# was entirely unchecked.

# The measurement keywords, as they appear in a format string.
#
# THE PREFIX IS PART OF THE PATTERN, and getting this wrong was the first version's
# only bug and it is worth recording because the symptom was a false PASS on nine
# sites that DO measure. These lines write `nick_len=` beside `nick=`, `subject_len=`
# beside `subject=`, `mask_len=` beside `mask=` -- the length field is named after the
# field it measures. A pattern anchored on `\blen=` does not match `nick_len=`: `\b`
# is a boundary between a word character and a non-word character, and the character
# before `len` in `nick_len` is `_`, which IS a word character, so there is no boundary
# there and the alternation never fires. Nine measured sites were therefore reported as
# unmeasured, and the fix that was about to be applied -- adding a second measurement to
# nine correct lines -- would have been damage done in the name of a check.
#
# So the field-name prefix is part of the keyword. `(?:\w+_)?len=` matches `len=` and
# `nick_len=`; `\w` cannot match a space, so it cannot run across two fields.
MEASURE_LEN = re.compile(r"(?:\w+_)?(?:len|length|size|bytes)=")
MEASURE_BAD = re.compile(r"(?:\w+_)?(?:bad_bytes|bad|nonprintable|ctl_bytes)=")

# ---------------------------------------------------------------------------
# THE ALLOWLIST IS NOW KEYED ON CALL SITE, AND HERE IS WHY THAT IS A DIFFERENT CHECK
# ---------------------------------------------------------------------------
# The defect, as measured: ALLOWED is keyed on EXPRESSION TEXT. `fed_obs()` and
# `printf()` are both named in the routing advice, so adding a new `fed_obs()` site
# printing `link->name` -- an expression with a named predicate -- passes for the same
# reason a new `printf()` site printing `link->name` would, which is right. But the
# inverse also passes: the justification for ONE site's `link->name` is a blank cheque
# for EVERY site's `link->name`, including a site added next year in a function whose
# `link->name` has not been through irc_serve_server_name_valid(). The allowlist cannot
# see that, because it does not know which line is which.
#
# So there are now TWO allowlists and they answer different questions:
#   ALLOWED          -- is this EXPRESSION printable by construction? (text, global)
#   ALLOWED_SITES    -- is THIS LINE's justification recorded? (file+line+expression)
# A site that is not in ALLOWED_SITES is reported even when its expression is on the
# global list. That is the whole of the change, and it is the reason a line is a key:
# the global list is a predicate claim that travels, and the site list is a promise
# about a specific line, made by the person who wrote that line.
#
# THE COST, WHICH IS REAL AND IS NOT SMALL. Adding a new `[observable]` site now
# REQUIRES an entry here, with a reason. That is friction, and friction is why the
# previous version was written: 68 sites with one allowlist was maintainable, and 68
# entries with reasons is a list that rots. So:
#   * ALLOWED_SITES is generated from the tree by `python3
#     scripts/check-peer-log-sites.py --dump-sites`, which prints one entry per site
#     with its expression and line, ready to paste. A missing entry is therefore a
#     five-second fix, not a judgement call;
#   * and the entries may name a SHARED justification by SITE GROUP rather than
#     repeating it, because most of the 68 sites in one file share one reason.
#
# The alternative -- keep one list -- leaves the check unable to catch a new site
# printing an expression that happens to be spelled the same way as an allowlisted one
# in a function that never validated it. That is the defect this section fixes.

# ---------------------------------------------------------------------------
# ALLOWED_SITES: THE ALLOWLIST, KEYED ON CALL SITE
# ---------------------------------------------------------------------------
# The problem this fixes, as measured: ALLOWED is keyed on EXPRESSION TEXT, so the
# justification recorded for one site is a blank cheque for every other site that spells
# its argument the same way. `shown_by` is printable at fed_in_smodes()'s refusal lines
# because a named predicate ran there; a new site next year that prints a `shown_by`
# whose predicate never ran is green, because the checker cannot tell which is which.
#
# So there are now two lists answering two different questions:
#   ALLOWED        is this EXPRESSION printable by construction, anywhere? (text)
#   ALLOWED_SITES  is THIS CALL SITE's use of it justified, and why?  (file+function)
#
# A site is clean if it is allowlisted, OR measured, OR its (file, function, expression)
# is recorded below WITH A REASON. The reason is not optional and not free text: it is
# the whole content of the entry, and an entry without one does not parse, because a
# suppression nobody can explain is a suppression nobody will review.
#
# THE KEY IS THE FUNCTION, NOT THE LINE, and that is a real trade rather than a
# convenience. A line number breaks on every unrelated edit above it -- adding a comment
# to verbs.c would move sixty-eight entries and the honest response to sixty-eight red
# lines is to regenerate them, which is a diff nobody reads. A function name survives
# every edit that does not change what the function is, which is the only edit that
# should re-open the question: MOVING a site to a different function is a change of
# justification, and this key makes that a red line.
#
# THE COST, STATED: adding a `[observable]` site to a function already recorded here is
# covered by that function's entry. That is coarser than a line and it is the price of
# ten entries instead of sixty-eight. The narrower key was measured and rejected: it
# needs a maintenance loop to stay valid, and a list that needs a loop is a list that
# goes stale.
ALLOWED_SITES = {
    ("verbs.c", "fed_in_smodes"): {
        # `applied` and `refused` are BUILT HERE, from this node's own decisions.
        # `applied` accumulates one byte per mode letter that chan_mode_implemented()
        # accepted, and `refused` one per letter it did not; both are written by this
        # loop and by nothing else, so a peer cannot put a byte in either. They are
        # listed here rather than measured because measuring a two-byte string this node
        # wrote would put `applied_len=2 applied_bad_bytes=0` on a line that can only
        # ever say 2 and 0.
        "applied": "built by fed_in_smodes()'s own loop from mode letters "
                   "chan_mode_implemented() accepted; not a peer string",
        "refused": "built by the same loop from the letters it refused; not a peer string",
    },
}


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


def strip_outer_parens(arg):
    """`arg` with one layer of enclosing parentheses removed, or `arg` itself.

    A PARENTHESIS IS NOT PART OF THE EXPRESSION and leaving it on changes what the
    next two helpers can see. `fed_preauth_drop:`'s `state=` argument reaches
    split_ternary() as

        ((link->state == (int)ESTABLISHED) ? "ESTABLISHED" : "PENDING")

    -- the true branch of the outer ternary, still wrapped -- and the `?` inside it is
    at paren depth 1, so the splitter reports "not a ternary" and the constant branches
    are never examined. The argument is then treated as an ordinary expression, is not
    allowlisted, and is reported. That is a finding against a line whose every possible
    value is the word ESTABLISHED, PENDING or NONE.

    Stripping the parens is what makes the recursion in check_string_arg() terminate
    on the actual shape rather than on how it happens to be parenthesised.
    """
    a = arg.strip()
    while len(a) >= 2 and a[0] == "(" and a[-1] == ")":
        depth = 0
        balanced = True
        for i, ch in enumerate(a):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(a) - 1:
                    # The closing paren is not the outermost one, so the leading `(` is
                    # not the one this string wraps in and removing it would change the
                    # expression.
                    balanced = False
                    break
        if not balanced:
            break
        a = a[1:-1].strip()
    return a


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
    arg = strip_outer_parens(arg)
    depth = 0
    for i, ch in enumerate(arg):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "?" and depth == 0:
            rest = arg[i + 1:]
            # NESTED TERNARIES ARE COUNTED, and the old comment that said there were
            # none is what made this a live bug. `fed_preauth_drop:` carries
            #
            #     (link != NULL) ? ((link->state == ESTABLISHED) ? "ESTABLISHED"
            #                                                          : "PENDING")
            #                       : "NONE"
            #
            # and a splitter that stops at the first `:` at paren-depth 0 cuts it
            # INSIDE the inner ternary: the true branch comes back as
            # `((link->state == ...) ? "ESTABLISHED"` -- not a literal, not allowlisted,
            # and therefore a finding against a line whose every branch IS a constant.
            # The cost of getting it wrong is a false positive, which is the direction
            # this project would rather err in for a PARSER and not for a gate.
            #
            # `?` increments and `:` decrements, so only the `:` that matches THIS `?`
            # returns -- which is what makes the recursion below see a well-formed
            # argument each time.
            j = 0
            d2 = 0
            pending = 1
            while j < len(rest):
                if rest[j] == "(":
                    d2 += 1
                elif rest[j] == ")":
                    d2 -= 1
                elif d2 == 0 and rest[j] == "?":
                    pending += 1
                elif d2 == 0 and rest[j] == ":":
                    pending -= 1
                    if pending == 0:
                        return arg[:i], rest[:j], rest[j + 1:]
                j += 1
            return None
    return None


# ---------------------------------------------------------------------------
# WHICH FUNCTION IS THIS SITE IN, AND WHY A LINE NUMBER IS NOT THE KEY
# ---------------------------------------------------------------------------
# Column 0, the same boundary rule scripts/audit-teardown.py uses and for the same
# reason: in this tree every nested brace is indented, so a `{` at the start of a line
# is a function body's. The signature matched is the line-initial `name(...)` that
# precedes it, so a multi-line parameter list does not defeat it.
#
# WHY THE KEY IS THE FUNCTION AND NOT THE LINE. A line number is a key that breaks on
# every unrelated edit above it: adding a comment to verbs.c would move 63 entries and
# the honest response to 63 red lines is to regenerate them, which is a diff nobody
# reads and a review that stops looking. A function name survives every edit that does
# not change what the function is, which is the edit that actually matters here: moving
# a log site from one function to another is a change of justification and SHOULD be
# re-asked for.
#
# THE LIMIT, which is real and is stated rather than discovered: two sites in the same
# function share one entry, so a site added to an already-allowed function is covered
# by that function's justification. That is a coarser key than a line and it is the
# trade: function granularity keeps the list at five entries and makes an edit cost one
# line, where line granularity costs 68 and makes an edit cost 68. The alternative --
# a line number plus a tolerance -- is a key that is wrong on purpose some of the time.
# The signature's NAME, not its first word. Every function in this tree is written
# `static void f(...)`, `int server_init(...)`, `const char *fed_federate_reason(...)`
# and so on, so the name is the LAST identifier before the parameter list's `(`. Matching
# the first word instead -- which a first version did -- finds the storage class
# (`static`, `int`, `const`) and calls every function `static`.
FUNC_SIG = re.compile(
    r"(?m)^(?:[A-Za-z_]\w*[ \t*]+)*([A-Za-z_]\w*)[ \t]*\(")


def enclosing_function(clean, offset):
    """The name of the function whose body contains `offset`, or "<toplevel>"."""
    prefix = clean[:offset]
    best = "<toplevel>"
    best_pos = -1
    for m in FUNC_SIG.finditer(prefix):
        # A signature is only a signature if its body opens before the site. The `{`
        # check is what stops a CALL's argument list at column 0 from being read as a
        # function declaration, which this tree does write (`fed_obs("...", x);` at the
        # start of a wrapped line is the common case).
        tail = prefix[m.end():m.end() + 400]
        brace = tail.find("{")
        semi = tail.find(";")
        if brace == -1 or (semi != -1 and semi < brace):
            continue
        if m.start() > best_pos:
            best_pos = m.start()
            best = m.group(1)
    return best


def is_literal_only(arg):
    """True when `arg` is a string literal, possibly parenthesised."""
    a = arg.strip().strip("()").strip()
    return len(a) >= 2 and a[0] == '"' and a[-1] == '"'


def check_string_arg(arg, rel, lineno, findings, seen, field=None, measured=False,
                     is_fed_obs=False, site=None, used=None):
    """The rule, applied to one `%s` argument.

    `seen` dedupes an expression already reported, so one expression used at twenty
    sites is twenty lines of nothing but one finding.

    `field` is the format string's OWN name for this argument -- the `foo` in
    `foo=%s` -- and it is what the measurement assertion is keyed on. It is passed in
    rather than re-derived because the association between a conversion and its field
    name is only available where the format string is walked, and re-deriving it here
    would be a second parser with its own bugs.

    `measured` says whether this site's format string already carries a
    `*_len=`/`*_bad_bytes=` pair. The rule is PER FIELD, not per line: a line with
    `channel=%s subject=%s subject_len=%zu` measures the subject and says nothing
    about the channel, and a line-level check would call that measured.
    """
    if arg in seen:
        return
    seen.add(arg)
    # BANNED IS ABOUT THE RAW `printf` PATH ONLY, and scoping it that way is a fix
    # rather than a clarification. This sweep previously looked only at `printf(` sites,
    # so rule 1 was only ever reached through `printf(` and the scoping was implicit.
    # Now that it reads `fed_obs(` too, the rule as written would fire on every
    # `fed_obs("... command=%s", m->command)` -- which is the CORRECT shape, because
    # fed_obs() is the function that renders a peer string through
    # conn_text_logsafe(). It reported 18 such sites as findings when the sweep was
    # extended, and every one of them is a site that does the right thing.
    if BANNED.search(arg) and not is_fed_obs:
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
        check_string_arg(t, rel, lineno, findings, seen, field, measured, is_fed_obs,
                         site, used)
        check_string_arg(f, rel, lineno, findings, seen, field, measured, is_fed_obs,
                         site, used)
        return
    base = strip_outer_parens(arg).split("(")[0].strip()

    # ---------------------------------------------------------------------------
    # MEASUREMENT IS AN ALTERNATIVE TO THE ALLOWLIST, NOT AN EXTRA CONDITION ON TOP
    # ---------------------------------------------------------------------------
    # The order here is the whole design, so it is worth stating plainly:
    #
    #   * ALLOWLISTED means a NAMED PREDICATE validated the value. Nothing is withheld,
    #     so there is nothing to measure and nothing for an operator to be missing.
    #   * MEASURED means nothing validated the value, but the line says how long it was
    #     and how much of it was unprintable. That is a DIFFERENT and sufficient answer:
    #     `nick=- nick_len=1 nick_bad_bytes=1` tells an operator the peer sent a
    #     nickname whose one byte was a control character, which is a finding. Without
    #     the measurement the same line says `nick=-` and nothing else.
    #
    # Requiring BOTH would be wrong in the other direction: it would force a measurement
    # onto every `link->name` in the tree, which irc_serve_server_name_valid() has
    # already made printable, and the extra `link_name_len=7 link_name_bad_bytes=0` on
    # forty lines would be noise that trains people to skip the log.
    #
    # THE LIMIT, and it is a real one: measurement is paired by NAME. `subject=%s` beside
    # `subject_len=%zu` is accepted; so would a `subject=%s` whose length is really some
    # other field's. It cannot tell whether the length is the length OF that argument --
    # only whether the name matches. Saying so is more useful than pretending a regex is
    # a dataflow analysis.
    if base in ALLOWED:
        return
    if is_fed_obs and measured:
        return
    # ALLOWED_SITES, consulted AFTER the two above and before the measurement
    # assertion, so an entry is only ever needed for a value that is neither globally
    # allowlisted nor measured. That is what keeps the list at ten entries rather than
    # sixty-eight: it records JUDGEMENTS, not the absence of measurement everywhere.
    if site is not None:
        reason = ALLOWED_SITES.get(site, {}).get(base)
        if reason is not None:
            # Counted HERE rather than at the call site, because the count has to be
            if used is not None:
                used[site] = used.get(site, 0) + 1
            # "arguments this entry actually justified" and a ternary's branches are
            # counted one level down in the recursion. Counting at the call site would
            # miss every wrapped use: `applied` reaches the check as
            # `(applied[0] != '\0') ? applied : "-"`, whose stripped text is the whole
            # ternary and whose base is the ternary, not `applied`.
            return
    if is_fed_obs and field is not None:
        findings.append(
            (rel, lineno, arg,
             "printed as `%s=%%s` with no `%s_len=` and no `%s_bad_bytes=` beside it. "
             "fed_obs() WITHHOLDS a value whose bytes are not printable ASCII and "
             "renders it as `-`, so an operator reading `%s=-` learns that something "
             "was withheld and nothing else: not how long it was, not how much of it "
             "was unprintable. Either add `strlen(...)` and `conn_text_bad_count(...)` "
             "under names ending `_len=` and `_bad_bytes=`, or state in ALLOWED_SITES "
             "which predicate makes this particular value printable. Measured from the "
             "PEER'S OWN string, not from a rendered copy: a 16-byte buffer holding a "
             "copy of a 200-byte field reports 15 for an input of 200."
             % (field, field, field, field)))
        return
    findings.append(
        (rel, lineno, arg,
         "not on the allowlist, and this is a raw `printf` site so there is no "
         "`fed_obs()` to route it through. Every allowlisted expression is there "
         "because a named predicate makes it printable by construction; this one needs "
         "that predicate stated here."))


# The FIELD NAME of each conversion: the last `word=` written before it in the format
# string. `channel=%s reason=X channel_len=%zu` gives ("s", "channel") then
# ("z", "channel"), and the second `channel=` is the field's own name again -- which is
# harmless here because only `%s` arguments are looked up.
#
# A conversion with NO preceding `name=` gets None, and a None field is not checked for
# measurement: there is no name to pair a measurement with, and inventing one from the
# expression would make the assertion's key a guess.
FIELD_TOKEN = re.compile(r"(\w+)=|%[-+ #0123456789.*hlLqjzt]*([a-zA-Z%])")


def fields_of(fmt):
    """[(conversion_letter, field_name_or_None)] in format-string order."""
    out = []
    last = None
    for m in FIELD_TOKEN.finditer(fmt):
        if m.group(1) is not None:
            last = m.group(1)
            continue
        if m.group(2) == "%":
            continue
        out.append((m.group(2), last))
    return out


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
    # The key ALLOWED_SITES is looked up under: the BARE FILE NAME, not the path
    # relative to the root. A key that spells out `src/federation/verbs.c` is a key that
    # breaks if the module moves, and a key that breaks when the code moves is a key
    # that gets deleted rather than updated.
    rel_name = os.path.basename(path)
    # BOTH `printf(` AND `fed_obs(`, and that is the whole of what this pass changed.
    # The sweep found 64 printf sites and 68 fed_obs sites; it checked only the first
    # 64, which is why a bare-`%s` fed_obs fault was green. `fed_obs()` is the FILTERED
    # writer, so the values it prints are the ones this check most needed to look at,
    # and it was looking at none of them.
    for m in re.finditer(r"(?<![A-Za-z0-9_])(printf|fed_obs)\(", clean):
        parsed = read_printf(clean, m.start())
        if parsed is None:
            continue
        fmt, args, end = parsed
        if "[observable]" not in fmt:
            continue
        is_fed_obs = m.group(1) == "fed_obs"
        stats["sites"] += 1
        convs = conversions(fmt)
        flds = fields_of(fmt)
        # The field list must line up with the conversion list or the measurement
        # pairing is meaningless. A mismatch is REPORTED rather than tolerated, for the
        # same reason an arity mismatch is: a check that pairs a measurement with the
        # wrong field is worse than a check that does not run.
        if len(flds) != len(convs):
            findings.append(
                (rel, clean[:m.start()].count("\n") + 1, fmt[:60],
                 "this check read %d conversions but %d field name(s), so it could not "
                 "pair a measurement with its argument and checked NOTHING on this "
                 "line. That is a defect in the check, and it is reported as a "
                 "failure rather than skipped: a check that silently skips a site is "
                 "worse than no check." % (len(convs), len(flds))))
            continue
        measured_fields = set()
        for mm in re.finditer(r"(\w+?)_len=", fmt):
            measured_fields.add(mm.group(1))
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
        site_key = (rel_name, enclosing_function(clean, m.start()))
        for (conv, field), arg in zip(flds, args):
            if conv != "s":
                continue
            stats["strings"] += 1
            check_string_arg(arg, rel, clean[:m.start()].count("\n") + 1, findings,
                             seen, field=field,
                             measured=(field in measured_fields),
                             is_fed_obs=is_fed_obs,
                             site=site_key, used=stats["sites_used"])


def main():
    findings = []
    stats = {"sites": 0, "strings": 0, "sites_used": {}}
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
            "\n    Three ways out, and which one is right depends on the site:\n"
            "      * MEASURE it -- add `strlen(<the peer's own string>)` and\n"
            "        `conn_text_bad_count(<the peer's own string>)` under names\n"
            "        ending `_len=` and `_bad_bytes=`. Not the rendered buffer: a\n"
            "        16-byte copy of a 200-byte field reports 15 for an input of 200.\n"
            "      * ALLOWLIST the EXPRESSION in ALLOWED above, when a named predicate\n"
            "        makes it printable by construction wherever it appears.\n"
            "      * RECORD the CALL SITE in ALLOWED_SITES, when the justification is\n"
            "        true of this function only. That is the narrower key and it is\n"
            "        the one to reach for when the global claim would be a lie.\n")
        return 1
    print("check-peer-log-sites: OK: %d `[observable]` site(s) and %d `%%s` argument(s) "
          "in src/federation/, over BOTH `printf(` and `fed_obs(`; every `%%s` prints "
          "either an allowlisted expression with its predicate named, a value measured "
          "by a `<field>_len=`/`<field>_bad_bytes=` pair beside it, or a call site "
          "recorded in ALLOWED_SITES with its reason."
          % (stats["sites"], stats["strings"]))
    for (fname, func), n in sorted(stats["sites_used"].items()):
        # THE COUNT IS PRINTED BECAUSE THE KEY IS COARSE, and the coarseness is the
        # honest limit of this design: an ALLOWED_SITES entry covers its whole FUNCTION,
        # so a site added to that function tomorrow is covered by an entry written
        # today. Printing how many sites each entry actually covers is what makes that
        # visible instead of leaving it as something a reader has to discover. MEASURED:
        # a `fed_obs("[observable] fault_reuse: applied=%s\n", applied)` added to
        # fed_in_smodes() passes this check, because that function's entry covers
        # `applied`. Function granularity is the price of a list that stays valid; the
        # alternative -- line numbers -- needs a maintenance loop and rots. Stating the
        # count is cheaper than pretending the key is finer than it is.
        print("    ALLOWED_SITES %s/%s covers %d `%%s` argument(s) in that function."
              % (fname, func, n))
    print("    This says nothing about REACHABILITY -- see the file's header. It says "
          "no peer string reaches a peer log unmeasured, which is the narrower claim "
          "that is decidable from the text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())