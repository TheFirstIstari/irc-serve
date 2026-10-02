# THIS DIRECTORY IS EMPTY OF TESTS, and that is the state rather than a leftover.
#
# It held five of the skips 7/Phase 9 owned, and all five have now been retired. The
# classification those five were filed under was a classification BY THE SKIP'S NAME
# rather than by the feature, and it was wrong in the same way for all of them:
#
#   Reconnect          a client whose TCP session drops and comes back gets its
#                      channel set back. Observable only over a socket, by a client
#                      that really connects and really disconnects.
#   PeerDiscovery      a peer advertises a dial hint and this node records it and
#                      NEVER dials it. Needs a mesh, and a third node for the hint
#                      to point at.
#   AutoScale          a node announces its departure and its peers treat it as
#                      terminal. Observable only across real links between real
#                      processes.
#
# NONE OF THEM IS A PROPERTY OF A SINGLE NODE, and a target in this directory links
# irc_core and nothing else: it cannot spawn a node, cannot own one end of a link,
# cannot drop a socket and cannot read a 366. That is why all three files here were
# ten-line placeholders returning 77, and why implementing the features in place was
# not possible.
#
# THEY ARE NOW tests/integration/test_reconnect.c,
# tests/integration/test_peer_discovery.c and
# tests/integration/test_autoscale.c, and their CTest NAMES are unchanged
# (`Reconnect`, `PeerDiscovery`, `AutoScale`) because tests/known_skips.txt names the
# tests and scripts/check-skips.sh checks those names against the registered set in
# BOTH directions. Renaming a test to suit a build system is how a skip line goes
# stale without anybody noticing; renaming the TARGET and keeping the CTest name is
# the move that keeps the ratchet honest.
#
# The `set_tests_properties(... SKIP_RETURN_CODE 77)` lines are GONE rather than
# edited, and that is deliberate: leaving one would make CTest treat a FAILURE as a
# skip, which is the same accident in the other direction. Each name is retired from
# tests/known_skips.txt in the same change that retires the skip, which is the
# ratchet's other half -- the one that catches a skip that was implemented but whose
# line nobody deleted.
#
# The file is KEPT rather than deleted, and `add_subdirectory(loadbal)` in
# tests/CMakeLists.txt is kept with it. A missing directory would be a smaller diff
# and a worse record: this paragraph is where a reader looking for "where did
# auto-scale's test go, and why is it not here" finds the answer, and the skip
# ratchet's history is worth more than the tidiness of an absent folder. The
# `AutoScale` name still resolves through irc_ctest_name() in
# tests/integration/CMakeLists.txt, which is the whole reason a moved test is allowed
# to keep its name.
