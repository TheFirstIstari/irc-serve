add_executable(test_peer_discovery test_peer_discovery.c)
add_executable(test_reconnect test_reconnect.c)

target_link_libraries(test_peer_discovery PRIVATE irc_core test_contracts)
target_link_libraries(test_reconnect PRIVATE irc_core test_contracts)

add_test(NAME PeerDiscovery COMMAND test_peer_discovery)
add_test(NAME Reconnect COMMAND test_reconnect)

set_tests_properties(PeerDiscovery PROPERTIES LABELS LoadBal)
set_tests_properties(Reconnect PROPERTIES LABELS LoadBal)