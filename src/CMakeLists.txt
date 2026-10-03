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
  # Phase 10.1: the ACCOUNT REGISTRY. It sits beside sasl_framework.c and NOT
  # inside core/ for the same reason sasl_framework.c is at this level: it is a
  # file-backed secret store whose layout and bounds belong to one module, and
  # both that module and the credential store it is deliberately separate from
  # are loaded from main() before the loop is armed. See account_store.h for the
  # argument that they are two files rather than one.
  account_store.c
  core/message.c
  core/connection.c
  core/server.c
  core/channel.c
  core/poll_loop.c
  core/reply.c
  core/resume.c
  core/fanout.c
  core/commands.c
  # Phase 10.1: the account IDENTITY on a connection. It is a module of its own
  # for the reason core/cap.c is -- the predicate every consumer asks must have
  # one home, or two callers will each write `c->logged_in && c->account[0]` and
  # the pair will be read apart somewhere.
  core/account.c
  # Phase 8: the IRCv3 capability negotiation. It is a module of its own rather
  # than part of commands.c because the TABLE of what this node implements is
  # the part that has to be read in one place -- a capability advertised by a
  # literal at a call site is a claim with no owner.
  core/cap.c
  core/chan_verbs.c
  core/msg_verbs.c
  # Phase 10.12: IRCv3 `batch`, the client-facing half -- the BATCH verb and the
  # `@`/`+` reference tags. It is a module of its own for the reason cap.c is: the
  # per-connection batch state is read in THREE places that must agree
  # (commands.c's dispatch, reply.c's single queueing site, and the verb table),
  # and a decision any two of them have to reach into separately is a decision they
  # will eventually disagree about.
  core/batch.c
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
  # The resync: 4.3's SBURST, the wire format it froze, and the transaction that
  # replaces rather than merges. It is listed LAST because it is the one module
  # here that depends on both of the others -- link.c calls federation_resync()
  # at establishment and fed_burst_abandon() on link-down, and burst.c reaches the
  # guard chain's vocabulary through federation/verbs.h. A shadow is a
  # transaction the size of a channel list, which is the reason it is a file and
  # not a function in the module that decides which sockets are up.
  federation/burst.c
  # Phase 9's remote-nick registry: 2.1's "which server holds the user called
  # X", which is what makes 3.1's `nick@server` row resolvable rather than merely
  # routable, and the rename-the-loser decision that goes with it. It is listed
  # LAST because it is the only module here that depends on TWO others -- it
  # includes federation/link.h for the liveness constant its TTL is derived from,
  # and core/channel.h for valid_nick() and the remote-host width, which is a
  # wider dependency surface than anything else under federation/ has. The table
  # itself is a vector on server_t rather than a module global, so it has a home
  # the shutdown can reach -- the difference between it and the burst shadow,
  # which is a file-scope static and needs fed_burst_close() to be released.
  federation/nickreg.c
)

target_link_libraries(irc_core PRIVATE pthread)

# Expose src/ headers to anything linking irc_core (tests, benchmarks).
target_include_directories(irc_core PUBLIC ${PROJECT_SOURCE_DIR}/src)

# Executable for federated node
add_executable(irc-serve node_main.c)
target_link_libraries(irc-serve PRIVATE irc_core)

install(TARGETS irc-serve RUNTIME DESTINATION bin)
