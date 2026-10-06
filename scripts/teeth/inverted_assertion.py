"""FAULT: the inverted-assertion check, checked against ITSELF.

A standing check that cannot fail is not a check. This fault flips one assertion in
the peer sweep so its CONDITION says absent and its MESSAGE describes the absent case
as though it were the failure -- the inverted shape `ps_assert_no_inverted_assertions()`
looks for -- and the requirement is that the check catches it.

Only the condition is touched. Flipping the message instead would test the word list,
which is a weaker claim; flipping the condition is the claim that matters, because an
inverted assertion is one whose logic is backwards, not one whose prose is.
"""
p = "tests/integration/test_peer_terminal_sweep.c"
s = open(p).read()
old = """        TF_CHECK_MSG(k_shapes[i].needle[0] != '\\0',"""
new = """        TF_CHECK_MSG(k_shapes[i].needle[0] == '\\0',"""
assert old in s, "the needle-emptiness assertion not found"
open(p, "w").write(s.replace(old, new, 1))
