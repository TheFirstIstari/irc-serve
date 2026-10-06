"""FAULT: #132's authority check reading the LINK rather than the LINE.

`fed_in_stopic()` used to compare `link->name` against `ch->origin`: the server
this node is SPEAKING TO, rather than the server whose opinion the line carries.
Those two are the same name in exactly one topology -- the origin's own direct
peer -- and the fix reads 2.4's `irc-serve-origin` tag instead, with the member
set in `servers[]` as the second term.

Both arms of the new test depend on the change, and they fail for OPPOSITE
reasons, which is what makes this fault worth having:

  * `test_fed_topic_authority` case 1 needs the second term: the line arrives at
    the ORIGIN on a link named the member-server, so the link-name rule refuses a
    topic the origin is supposed to evaluate.
  * case 2 needs the first term: the line arrives at a SECOND-HOP relay on a link
    named the middle node while the subject is the origin, so the link-name rule
    refuses a topic the origin already published.

It goes through a wrong-name rather than removing the call so that the function
stays used and the build stays clean; a fault that does not compile proves
nothing.
"""
p = "src/federation/verbs.c"
s = open(p).read()
old = """    if (!chan_same_name(tags->origin, ch->origin) &&
        !chan_server_has(ch, tags->origin)) {"""
new = """    /* FAULT: the transport rather than the line, which is the rule as it was. */
    if (!chan_same_name(link->name, ch->origin)) {"""
assert old in s, "the topic authority check not found"
open(p, "w").write(s.replace(old, new))