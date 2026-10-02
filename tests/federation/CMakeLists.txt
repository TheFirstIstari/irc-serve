# These are UNIT tests: they exercise a function directly, need no sockets, no
# children and no loop, and link the library and nothing else. Two of them exercise
# federation_handshake.c with a caller-owned context; the third exercises 2.1's
# rename-the-loser comparison.
add_executable(test_federate_handshake test_federate_handshake.c)
add_executable(test_heartbeat test_heartbeat.c)
# Phase 9: 2.1's rename-the-loser DECISION, as the total order it has to be for
# the mesh to converge. It belongs HERE and not with the integration test because
# the claim is a property of a comparison function -- antisymmetric, transitive,
# case-blind, and defined on the prefix pairs of two legal 2.4 server names -- and
# an integration test cannot build a node named `irc.b1` next to `irc.b` without
# configuring two peers that differ only in length. The integration test
# (tests/integration/test_nick_duplicate.c) asserts the mesh; this asserts the
# arithmetic the mesh's convergence rests on.
add_executable(test_nick_policy test_nick_policy.c)

target_link_libraries(test_federate_handshake PRIVATE irc_core)
target_link_libraries(test_heartbeat PRIVATE irc_core)
target_link_libraries(test_nick_policy PRIVATE irc_core)

add_test(NAME FederateHandshake COMMAND test_federate_handshake)
add_test(NAME Heartbeat COMMAND test_heartbeat)
add_test(NAME NickPolicy COMMAND test_nick_policy)

set_tests_properties(FederateHandshake PROPERTIES LABELS Federation)
set_tests_properties(Heartbeat PROPERTIES LABELS Federation)
set_tests_properties(NickPolicy PROPERTIES LABELS Federation)

# ---------------------------------------------------------------------------
# The two that were SKIPS and are now REAL tests, and WHY THEY MOVED
# ---------------------------------------------------------------------------
# Both used to be 10-line placeholders that returned CTest's skip code, and both
# are now two-node integration tests: the reconnect policy is only observable
# through a real link that really went dead, so a unit test could only have
# asserted the policy's arithmetic, which is not the claim.
#
# They live in tests/integration/ and are registered with irc_add_integration_test
# because that brings the HARNESS (test_harness: node_fixture + irc_client), and
# these tests fork real child nodes and freeze them. tests/federation/ links
# irc_core alone, so a test here has no way to spawn a node.
#
# The CTest NAMES are unchanged (FailoverReconnect), and that is the reason
# irc_ctest_name() exists on the integration side: renaming a test to suit a
# build system is how a line in tests/known_skips.txt goes stale without anyone
# noticing. The name is being RETIRED from that list in this phase, but keeping
# it means a CI link to a past run still names the same test.
#
# NO SKIP_RETURN_CODE ANYWHERE IN THIS FILE, and that is the ratchet's other
# direction: a test that used to skip and no longer does must have its line
# deleted in the same change, and SKIP_RETURN_CODE left behind would be a
# property of a test that can no longer return 77.