# Protocol tests
add_executable(test_rfc1459_parse test_rfc1459_parse.c)
add_executable(test_rfc1459_invalid test_rfc1459_invalid.c)
add_executable(test_nick_user test_nick_user.c)
add_executable(test_message_parse test_message_parse.c)
add_executable(test_message_format test_message_format.c)
add_executable(test_valid_nick test_valid_nick.c)
add_executable(test_cap_bounds test_cap_bounds.c)

target_link_libraries(test_rfc1459_parse PRIVATE irc_core)
target_link_libraries(test_rfc1459_invalid PRIVATE irc_core)
target_link_libraries(test_nick_user PRIVATE irc_core)
target_link_libraries(test_message_parse PRIVATE irc_core)
target_link_libraries(test_message_format PRIVATE irc_core)
target_link_libraries(test_valid_nick PRIVATE irc_core)
# irc_core only, and NOT the integration harness: tests/protocol/ does not link
# test_harness and test_cap_bounds does not need it -- it is a unit sweep over one
# function, with its own failure reporting in the assert(3) style the rest of this
# directory uses. See the file header for why that is the shape here.
target_link_libraries(test_cap_bounds PRIVATE irc_core)

add_test(NAME Rfc1459Parse COMMAND test_rfc1459_parse)
add_test(NAME Rfc1459Invalid COMMAND test_rfc1459_invalid)
add_test(NAME NickUser COMMAND test_nick_user)
add_test(NAME MessageParse COMMAND test_message_parse)
add_test(NAME MessageFormat COMMAND test_message_format)
add_test(NAME ValidNick COMMAND test_valid_nick)
add_test(NAME CapBounds COMMAND test_cap_bounds)

set_tests_properties(Rfc1459Parse PROPERTIES LABELS Protocol)
set_tests_properties(Rfc1459Invalid PROPERTIES LABELS Protocol)
set_tests_properties(NickUser PROPERTIES LABELS Protocol)
set_tests_properties(MessageParse PROPERTIES LABELS Protocol)
set_tests_properties(MessageFormat PROPERTIES LABELS Protocol)
set_tests_properties(ValidNick PROPERTIES LABELS Protocol)
set_tests_properties(CapBounds PROPERTIES LABELS Protocol)

# test_multi_prefix MOVED to tests/integration/ for the reason
# test_cap_negotiation did: a `353` roster is produced by a server over a socket,
# and a test that cannot reach one cannot tell "one prefix per member" from "this
# node has no multi-prefix capability at all". The CTest NAME is unchanged, so
# tests/known_skips.txt's line for it matched a test that still existed while it
# moved.
