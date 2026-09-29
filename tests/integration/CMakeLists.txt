# Integration tests -- the wire-level suite that 6.1 makes mandatory from
# Phase 2 on ("every test skipped or faked is what let a green suite coexist
# with a non-functional server").
#
# Convention, same as the other test directories: one add_executable per test.
# No OBJECT library and no bundled sources, because that is how two mains end
# up in one binary.
#
# The harness is a library, not a test: it holds no main() and is linked into
# each test. It is not a "bundle" of tests, so it does not conflict with the
# one-executable-per-test rule.

add_library(test_harness STATIC
  ../harness/irc_client.c
  ../harness/node_fixture.c
  ../harness/test_util.c
)
target_link_libraries(test_harness PUBLIC irc_core)
target_include_directories(test_harness PUBLIC ${PROJECT_SOURCE_DIR}/tests)

# PUBLIC, so both the harness and every test that links it see them. The binary
# path is needed inside the harness (it is what forks and execs), and the source
# root is needed by the tests that inspect sources.
#
# $<TARGET_FILE:...> creates the build dependency, so the binary exists before
# any test that execs it.
target_compile_definitions(test_harness PUBLIC
  NF_SERVER_BIN="$<TARGET_FILE:irc-serve>"
  IRCSERVE_SRC_DIR="${PROJECT_SOURCE_DIR}")

function(irc_add_integration_test name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE test_harness)
  # Spelled out rather than relying on the generator expression's side effect:
  # an ordering guarantee worth having should not be implicit.
  add_dependencies(${name} irc-serve)
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES LABELS Integration)
endfunction()

# 7/Phase 2: "a client connects and is closed cleanly (assert accept -> EOF)".
# Runs the SHIPPED BINARY over real TCP.
irc_add_integration_test(test_conn_lifecycle test_conn_lifecycle.c)

# 3.3: partial writes, drained across poll iterations, byte for byte.
irc_add_integration_test(test_partial_write test_partial_write.c)

# 3.4: bounded write queues; a saturated link is dropped and nobody else is.
irc_add_integration_test(test_writeq_overflow test_writeq_overflow.c)

# 3.4: explicit fd >= FD_SETSIZE rejection at the accept site.
irc_add_integration_test(test_fdsize_reject test_fdsize_reject.c)

# 3.4: the loop is EINTR-safe.
irc_add_integration_test(test_eintr test_eintr.c)

# 3.4: the reaper is the only close site, and a closed slot leaves nothing
# behind. The structural half is the test below.
irc_add_integration_test(test_reaper_close test_reaper_close.c)

# 3.4: no other file closes a connection descriptor. Source inspection, and
# labelled as such in the test.
irc_add_integration_test(test_close_sites test_close_sites.c)

# 3.3: RFC 1459 2.3 line framing at the cap boundary.
irc_add_integration_test(test_framing test_framing.c)

# 2.1 / 2.2 / 2.4: the nick registry, the channel registry, the fd-indexed
# connection registry, and the per-SERVER message id.
irc_add_integration_test(test_registries test_registries.c)

# 3.4: the nonblocking dial state machine.
irc_add_integration_test(test_dial_fsm test_dial_fsm.c)

# 7/Phase 3: "integration test registers and receives 001 and 005; duplicate
# nick -> 433". The first phase in which the node answers a client at all.
irc_add_integration_test(test_registration test_registration.c)

# 2.1 / 5: valid_nick() enforced at runtime. Phase 1 shipped the predicate with
# no caller in src/, so this is the test that makes it load-bearing. Asserts the
# RESPONSE, never that the function was called.
irc_add_integration_test(test_nick_rule test_nick_rule.c)

# 7/Phase 3: duplicate nick -> 433, and the incumbent keeps it.
irc_add_integration_test(test_dup_nick test_dup_nick.c)

# 2.1 / RFC 2812 2.3.1: nicknames are case-INsensitive. One name is held at a
# time whichever way it is spelled -- `BOB` is refused while `bob` is held, and
# `bob` is refused while `BOB` is -- and the case the user CHOSE is what appears
# in 353, in a message prefix, in 352 and in 311. Separate from test_dup_nick
# because that file asserts the claim rule for one spelling and this one asserts
# it across spellings; folding the stored nickname would satisfy test_dup_nick
# and break every display assertion here.
irc_add_integration_test(test_nick_case test_nick_case.c)

# 4.4: 451 before registration, 421 for a verb this build does not have. Nothing
# falls through in silence.
irc_add_integration_test(test_pre_register test_pre_register.c)

# 4.1: PING/PONG, including the trailing-colon cases a client's own liveness
# check depends on.
irc_add_integration_test(test_ping_pong test_ping_pong.c)

# 3.4 + Phase 3: QUIT closes through the reaper, and the nickname is released.
irc_add_integration_test(test_quit test_quit.c)

# 3: numerics are never written to a peer link. Source inspection, and labelled
# as such; Phase 6 adds the end-to-end version once a peer exists.
irc_add_integration_test(test_reply_guard test_reply_guard.c)

# 7/Phase 4: JOIN/PART/TOPIC/NAMES/LIST/KICK/MODE on the wire, the fixed 353
# order, 332/333, non-op KICK -> 482, and the single-writer rule (437, with the
# channel state asserted unchanged afterwards). The last group runs against an
# INLINE child because 2.2's rule needs a channel whose origin is not this node,
# and the only way to produce one without a peer socket is to re-key a channel
# the node created -- which is 2.2's own creation-race path, driven from the
# tick hook rather than simulated around.
irc_add_integration_test(test_channels test_channels.c)

# 7/Phase 5: "two clients exchange a PRIVMSG; NOTICE not echoed to sender" --
# the "working server" line, so the acceptance criterion is the centre of the
# test rather than one case among many. Runs against the SHIPPED BINARY, like
# every other integration test.
irc_add_integration_test(test_messaging test_messaging.c)

# 7/Phase 5: WHO/WHOIS/ISON/AWAY, and the away field 4.3's SBURST will have to
# carry. Separate from test_messaging because the AWAY state is what WHO and
# WHOIS report on, so the three cannot be separated by a file boundary without
# the file testing itself.
irc_add_integration_test(test_queries test_queries.c)
