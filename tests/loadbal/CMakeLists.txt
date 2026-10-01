add_executable(test_peer_discovery test_peer_discovery.c)
add_executable(test_autoscale test_autoscale.c)

target_link_libraries(test_peer_discovery PRIVATE irc_core)
target_link_libraries(test_autoscale PRIVATE irc_core)

add_test(NAME PeerDiscovery COMMAND test_peer_discovery)
add_test(NAME AutoScale COMMAND test_autoscale)

set_tests_properties(PeerDiscovery PROPERTIES LABELS LoadBal)
set_tests_properties(AutoScale PROPERTIES LABELS LoadBal)

# Absent features register an honest skip (return 77) rather than fabricated
# passing assertions.
#
# ONE OF THE THREE IS GONE, and where it went is the point of this file being
# worth reading. `Reconnect` was here because the phase table put it here, next
# to peer discovery and auto-scale -- three of the five skips 7/Phase 9 owned.
# Two of those three are orchestration features about a mesh. Reconnect is not:
# a client dropping its TCP session and coming back is a SINGLE node's business,
# and its claim is only observable over a socket, by a client that really
# connects and really disconnects. A target in this directory links irc_core and
# nothing else, so it has no way to spawn a node, no way to drop a socket and no
# way to read a 366 -- which is why the file was a placeholder and why
# implementing the feature in place was not possible.
#
# IT IS NOW tests/integration/test_reconnect.c, and the CTest NAME is unchanged
# (`Reconnect`) because tests/known_skips.txt names the test and
# scripts/check-skips.sh checks that name against the registered set in BOTH
# directions. `set_tests_properties(Reconnect PROPERTIES SKIP_RETURN_CODE 77)` is
# gone rather than edited: leaving it would make CTest treat a FAILURE as a skip,
# and the name is being retired from the list in the same change -- which is the
# ratchet's other direction, the one that catches a skip that was implemented but
# not retired.
set_tests_properties(PeerDiscovery PROPERTIES SKIP_RETURN_CODE 77)
set_tests_properties(AutoScale PROPERTIES SKIP_RETURN_CODE 77)