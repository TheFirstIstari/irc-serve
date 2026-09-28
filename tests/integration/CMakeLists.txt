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
