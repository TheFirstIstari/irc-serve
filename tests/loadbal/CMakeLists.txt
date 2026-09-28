add_executable(test_peer_discovery test_peer_discovery.c)
add_executable(test_reconnect test_reconnect.c)
add_executable(test_autoscale test_autoscale.c)

target_link_libraries(test_peer_discovery PRIVATE irc_core test_contracts)
target_link_libraries(test_reconnect PRIVATE irc_core test_contracts)
target_link_libraries(test_autoscale PRIVATE irc_core test_contracts)

add_test(NAME PeerDiscovery COMMAND test_peer_discovery)
add_test(NAME Reconnect COMMAND test_reconnect)
add_test(NAME AutoScale COMMAND test_autoscale)

set_tests_properties(PeerDiscovery PROPERTIES LABELS LoadBal)
set_tests_properties(Reconnect PROPERTIES LABELS LoadBal)
set_tests_properties(AutoScale PROPERTIES LABELS LoadBal)

# Absent features register an honest skip (return 77) rather than fabricated
# passing assertions.
set_tests_properties(PeerDiscovery PROPERTIES SKIP_RETURN_CODE 77)
set_tests_properties(Reconnect PROPERTIES SKIP_RETURN_CODE 77)
set_tests_properties(AutoScale PROPERTIES SKIP_RETURN_CODE 77)