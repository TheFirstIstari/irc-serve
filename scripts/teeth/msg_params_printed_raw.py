"""FAULT: #134's log line printing a client `<msgtarget>` raw again.

`test_hostmask_reachability.c` establishes the three premises that make
`conn_hostmask() == 0` unreachable (the width is derived, the fields are arrays,
the format is `"%s!%s@%s"`) AND states the rule that makes dead code safe to
leave: no `printf` in `msg_verbs.c` may pass `m->params[...]` as an argument in its
own right.

This fault reverts the injection fix and exercises the second half, because the
first half is a claim about reachability and this one is a claim about safety. A
test that only proved deadness would pass against this: the branch is still
unreachable, the width is still derived, and the line is still a log-injection
site the day somebody makes it reachable.

The needle is the ORIGINAL statement, verbatim, so the fault is the one #134 filed
rather than a paraphrase of it.
"""
p = "src/core/msg_verbs.c"
s = open(p).read()
old = '''        (void)conn_text_logsafe(shown, sizeof shown, m->params[0]);
        printf("[observable] msg_refused: verb=%s nick=%s target=%s "
               "target_len=%zu target_bad_bytes=%zu reason=unrenderable_source\\n",
               verb, c->nick, shown, strlen(m->params[0]),
               conn_text_bad_count(m->params[0]));'''
new = '''        /* FAULT: the client's <msgtarget> into printf("%s") with no filter. */
        (void)shown;
        printf("[observable] msg_refused: verb=%s nick=%s target=%s "
               "reason=unrenderable_source\\n",
               verb, c->nick, m->params[0]);'''
assert old in s, "the filtered msg_refused line not found"
open(p, "w").write(s.replace(old, new))