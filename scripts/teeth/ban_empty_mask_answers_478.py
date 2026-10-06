"""FAULT: #133's empty-mask case answered with 478 again.

`ban_refusal()` has four arms and the empty-mask one is 461. Collapsing it back
onto the capacity numeric is the defect the issue filed: a client that sent
`MODE #chan +b :<ESC>` -- a parameter that is present and is one control byte --
was told its ban list was full, and the recovery that implies is to remove a ban
it never added.

It goes through a WRONG NUMERIC rather than deleting an arm so that the arm stays
live and the build stays clean: a fault that does not compile proves nothing, and
a fault that removes code would also be satisfied by a tree that had never had
the arm.

The test that must catch it is `test_banlist`, whose section 6a asserts the exact
rendered 461 line AND the absence of 478 in the same window.
"""
p = "src/core/chan_verbs.c"
s = open(p).read()
old = '''        (void)reply_refused(s, c, "MODE", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] chan_ban_refused: channel=%s by=%s reason=empty_mask "'''
new = '''        /* FAULT: the capacity numeric, which is what this path answered before. */
        (void)reply(s, c, "478", (const char *const[]){ ch->name, "b" }, 2,
                    "Channel list is full");
        printf("[observable] chan_ban_refused: channel=%s by=%s reason=empty_mask "'''
assert old in s, "the empty-mask refusal arm not found"
open(p, "w").write(s.replace(old, new))