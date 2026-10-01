add_executable(test_autoscale test_autoscale.c)

target_link_libraries(test_autoscale PRIVATE irc_core)

add_test(NAME AutoScale COMMAND test_autoscale)

set_tests_properties(AutoScale PROPERTIES LABELS LoadBal)
set_tests_properties(AutoScale PROPERTIES SKIP_RETURN_CODE 77)

# Absent features register an honest skip (return 77) rather than fabricated
# passing assertions.
#
# ONE IS LEFT, and which one is the point of this file being worth reading.
# `Reconnect` and `PeerDiscovery` were both here because the phase table put them
# here, alongside auto-scale -- three of the five skips 7/Phase 9 owned. None of
# the three is a property of a SINGLE node: a client whose TCP session drops and
# comes back is observable only over a socket, by a client that really connects
# and really disconnects; and a peer that advertises a dial hint, or says it is
# leaving, is observable only across a mesh. A target in this directory links
# irc_core and nothing else, so it has no way to spawn a node, no way to own one
# end of a link, no way to drop a socket and no way to read a 366 -- which is why
# both files were placeholders and why implementing the features in place was not
# possible.
#
# THEY ARE NOW tests/integration/test_reconnect.c and
# tests/integration/test_peer_discovery.c, and the CTest NAMES are unchanged
# (`Reconnect` and `PeerDiscovery`) because tests/known_skips.txt names the tests
# and scripts/check-skips.sh checks those names against the registered set in
# BOTH directions. `set_tests_properties(PeerDiscovery PROPERTIES
# SKIP_RETURN_CODE 77)` is gone rather than edited: leaving it would make CTest
# treat a FAILURE as a skip, and each name is retired from the list in the same
# change -- which is the ratchet's other direction, the one that catches a skip
# that was implemented but not retired.
set_tests_properties(AutoScale PROPERTIES SKIP_RETURN_CODE 77)
