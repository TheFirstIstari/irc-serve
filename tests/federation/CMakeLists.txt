# These two are UNIT tests: they exercise federation_handshake.c with a
# caller-owned context and need no sockets, no children and no loop, so they
# link the library and nothing else.
add_executable(test_federate_handshake test_federate_handshake.c)
add_executable(test_heartbeat test_heartbeat.c)

target_link_libraries(test_federate_handshake PRIVATE irc_core)
target_link_libraries(test_heartbeat PRIVATE irc_core)

add_test(NAME FederateHandshake COMMAND test_federate_handshake)
add_test(NAME Heartbeat COMMAND test_heartbeat)

set_tests_properties(FederateHandshake PROPERTIES LABELS Federation)
set_tests_properties(Heartbeat PROPERTIES LABELS Federation)

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