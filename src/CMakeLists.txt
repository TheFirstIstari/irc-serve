# CMake for src
#
# sasl_framework.c is here because it was NOT, and that was the defect (#86): it
# was compiled as a source of the test_sasl_handshake executable from
# tests/compliance/CMakeLists.txt, so SASL was absent from the shipped library
# entirely -- a Phase-8 feature with no place in irc_core to grow into. It is
# still the Phase-8 placeholder implementation (see docs/SERVER_DESIGN.md and
# #82), and being in the library now means the code that replaces it has a target
# to live in and a header (src/sasl_framework.h) that is on the include path for
# everything linking irc_core, rather than a test-local extern declaration.
add_library(irc_core STATIC
  protocol_parse.c
  ircv3_tags.c
  federation_handshake.c
  sasl_framework.c
  core/message.c
  core/connection.c
  core/server.c
  core/channel.c
  core/poll_loop.c
  core/reply.c
  core/fanout.c
  core/commands.c
  core/chan_verbs.c
  core/msg_verbs.c
  # Phase 6. federation/ is a DIRECTORY of its own rather than more core/*.c,
  # because the split that matters in this phase is not "core versus
  # federation" but "encode versus decode": verbs.c is the outbound half of
  # 4.3's wire and dedup.c is 2.4's loop guard, and neither is reachable from
  # the message path yet. Putting them beside core/ would imply they are part of
  # the always-on path, and a reader would expect to find them in fanout.c.
  federation/verbs.c
  federation/dedup.c
  # The peer link: the table, the FEDERATE exchange and the tick. It is listed
  # after the two above because it uses both -- dedup for T5 and verbs.c for
  # the outbound side of the wire -- which is the first time anything in this
  # tree has had a reason to depend on more than one module under federation/.
  federation/link.c
)

target_link_libraries(irc_core PRIVATE pthread)

# Expose src/ headers to anything linking irc_core (tests, benchmarks).
target_include_directories(irc_core PUBLIC ${PROJECT_SOURCE_DIR}/src)

# Executable for federated node
add_executable(irc-serve node_main.c)
target_link_libraries(irc-serve PRIVATE irc_core)

install(TARGETS irc-serve RUNTIME DESTINATION bin)
