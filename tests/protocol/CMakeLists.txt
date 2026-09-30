# Protocol tests
add_executable(test_rfc1459_parse test_rfc1459_parse.c)
add_executable(test_rfc1459_invalid test_rfc1459_invalid.c)
add_executable(test_multi_prefix test_multi_prefix.c)
add_executable(test_nick_user test_nick_user.c)
add_executable(test_message_parse test_message_parse.c)
add_executable(test_message_format test_message_format.c)
add_executable(test_valid_nick test_valid_nick.c)

target_link_libraries(test_rfc1459_parse PRIVATE irc_core)
target_link_libraries(test_rfc1459_invalid PRIVATE irc_core)
target_link_libraries(test_multi_prefix PRIVATE irc_core)
target_link_libraries(test_nick_user PRIVATE irc_core)
target_link_libraries(test_message_parse PRIVATE irc_core)
target_link_libraries(test_message_format PRIVATE irc_core)
target_link_libraries(test_valid_nick PRIVATE irc_core)

add_test(NAME Rfc1459Parse COMMAND test_rfc1459_parse)
add_test(NAME Rfc1459Invalid COMMAND test_rfc1459_invalid)
add_test(NAME MultiPrefix COMMAND test_multi_prefix)
add_test(NAME NickUser COMMAND test_nick_user)
add_test(NAME MessageParse COMMAND test_message_parse)
add_test(NAME MessageFormat COMMAND test_message_format)
add_test(NAME ValidNick COMMAND test_valid_nick)

set_tests_properties(Rfc1459Parse PROPERTIES LABELS Protocol)
set_tests_properties(Rfc1459Invalid PROPERTIES LABELS Protocol)
set_tests_properties(MultiPrefix PROPERTIES LABELS Protocol)
set_tests_properties(NickUser PROPERTIES LABELS Protocol)
set_tests_properties(MessageParse PROPERTIES LABELS Protocol)
set_tests_properties(MessageFormat PROPERTIES LABELS Protocol)
set_tests_properties(ValidNick PROPERTIES LABELS Protocol)

# Absent features register an honest skip (return 77) rather than fabricated
# passing assertions. The skip is only permitted with a line in
# tests/known_skips.txt -- see docs/DEVELOPMENT.md's "The skip gate is a ratchet"
# and docs/SERVER_DESIGN.md 6.4, and scripts/check-skips.sh, which fails if this
# set and that list disagree in EITHER direction.
#
# test_topic_persist used to be one of these. 7/Phase 7 implemented the feature it
# was named for -- a channel's topic survives the channel being disposed -- and
# the test is now a wire-level integration test under tests/integration/, because
# a test that cannot reach a node cannot test that. The CTest name is unchanged.
set_tests_properties(MultiPrefix PROPERTIES SKIP_RETURN_CODE 77)
