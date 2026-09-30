add_executable(test_ircv3_tags test_ircv3_tags.c)
add_executable(test_tags_roundtrip test_tags_roundtrip.c)
# 7/Phase 8: the escape-table round-trip PROPERTY, over a corpus of hostile
# values. Separate from test_tags_roundtrip because that one calls the same two
# functions and cannot fail: they used to be one function.
add_executable(test_tag_roundtrip_hostile test_tag_roundtrip_hostile.c)
# SASL is part of irc_core now (#86), so this links the library rather than
# compiling src/sasl_framework.c as a source of its own. Linking the library is
# the point: a test target that compiles the file itself passes whether or not
# SASL is in the shipped node.
add_executable(test_sasl_handshake test_sasl_handshake.c)
add_executable(test_cap_negotiation test_cap_negotiation.c)

target_link_libraries(test_ircv3_tags PRIVATE irc_core)
target_link_libraries(test_tags_roundtrip PRIVATE irc_core)
target_link_libraries(test_tag_roundtrip_hostile PRIVATE irc_core)
target_link_libraries(test_sasl_handshake PRIVATE irc_core)
target_link_libraries(test_cap_negotiation PRIVATE irc_core)

add_test(NAME Ircv3Tags COMMAND test_ircv3_tags)
add_test(NAME TagsRoundtrip COMMAND test_tags_roundtrip)
add_test(NAME TagRoundtripHostile COMMAND test_tag_roundtrip_hostile)
add_test(NAME SaslHandshake COMMAND test_sasl_handshake)
add_test(NAME CapNegotiation COMMAND test_cap_negotiation)

set_tests_properties(Ircv3Tags PROPERTIES LABELS Compliance)
set_tests_properties(TagsRoundtrip PROPERTIES LABELS Compliance)
set_tests_properties(TagRoundtripHostile PROPERTIES LABELS Compliance)
set_tests_properties(SaslHandshake PROPERTIES LABELS Compliance)
set_tests_properties(CapNegotiation PROPERTIES LABELS Compliance)

# Absent feature: CAP negotiation registers an honest skip (return 77).
set_tests_properties(CapNegotiation PROPERTIES SKIP_RETURN_CODE 77)