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
  ../harness/peer_fixture.c
  ../harness/test_util.c
  # Phase 12: the TLS client and the certificate generator. Compiled ONLY when
  # WITH_TLS is ON, because it includes <openssl/ssl.h> and there is no point (and
  # no header path) in the default build. The tests that use it ask
  # tf_tls_available() at runtime and assert the PLAINTEXT consequences instead, so
  # no test is skipped in the default build and none is skipped in the TLS build --
  # they assert different things about the build they are in.
  $<$<BOOL:${WITH_TLS}>:../harness/tls_fixture.c>
  $<$<NOT:$<BOOL:${WITH_TLS}>>:../harness/tls_fixture_none.c>
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
  IRCSERVE_SRC_DIR="${PROJECT_SOURCE_DIR}"
  # WHAT CMAKE PARSED OUT OF src/core/server.h, as a string. It is here so a test can
  # compare it against IRC_SERVE_VERSION from the same translation unit and say so at
  # RUNTIME: if the regex in the top-level CMakeLists stops matching, or someone puts a
  # literal back into project(), this definition disagrees with the header and a test
  # fails. A definition nobody compares is a comment.
  IRC_SERVE_CMAKE_VERSION="${IRC_SERVE_VERSION}"
  # Where the TLS fixture writes its generated certificates. A build directory
  # rather than /tmp, and per-process rather than shared, so two runs of this test
  # -- which a developer does while bisecting -- cannot collide over a directory
  # full of private keys.
  IRCSERVE_BUILD_DIR="${PROJECT_BINARY_DIR}")

# `ctest_name` is optional and defaults to `name`. It exists for exactly one
# caller: a test that MOVED out of tests/compliance/ or tests/protocol/ and whose
# CTest name must not change, because tests/known_skips.txt names it and
# scripts/check-skips.sh checks every listed name against the registered set.
# Renaming a test to satisfy a build system is how a skip line goes stale without
# anybody noticing; renaming the TARGET and keeping the CTest name is the move
# that keeps the ratchet honest.
# A map from target name to CTest name, for the tests that MOVED here with a CTest
# name they are not allowed to change. tests/known_skips.txt names the moved
# tests, and scripts/check-skips.sh cross-checks every listed name against the
# registered set -- so renaming a test to suit a build system is how a skip line
# goes stale without anybody noticing. Renaming the TARGET and keeping the CTest
# name is the move that keeps the ratchet honest.
function(irc_ctest_name name out)
  if(${name} STREQUAL "test_cap_negotiation")
    set(${out} "CapNegotiation" PARENT_SCOPE)
  elseif(${name} STREQUAL "test_multi_prefix")
    set(${out} "MultiPrefix" PARENT_SCOPE)
  elseif(${name} STREQUAL "test_failover_reconnect")
    set(${out} "FailoverReconnect" PARENT_SCOPE)
  elseif(${name} STREQUAL "test_sync_state")
    set(${out} "SyncState" PARENT_SCOPE)
  elseif(${name} STREQUAL "test_peer_discovery")
    set(${out} "PeerDiscovery" PARENT_SCOPE)
  elseif(${name} STREQUAL "test_reconnect")
    set(${out} "Reconnect" PARENT_SCOPE)
  elseif(${name} STREQUAL "test_autoscale")
    set(${out} "AutoScale" PARENT_SCOPE)
  else()
    set(${out} "${name}" PARENT_SCOPE)
  endif()
endfunction()

function(irc_add_integration_test name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE test_harness)
  # Spelled out rather than relying on the generator expression's side effect:
  # an ordering guarantee worth having should not be implicit.
  add_dependencies(${name} irc-serve)
  irc_ctest_name(${name} _ctest_name)
  add_test(NAME ${_ctest_name} COMMAND ${name})
  set_tests_properties(${_ctest_name} PROPERTIES LABELS Integration)
  # TIMEOUT is looked up by TARGET name, and only if it was set. Keeping it a
  # per-test opt-in variable rather than a default applied to all 60-odd tests is
  # the point: the suite-wide 60s default stays the thing that catches a wedge,
  # and a test earns an override by having a measurement.
  if(DEFINED irc_timeout_${name})
    set_tests_properties(${_ctest_name} PROPERTIES TIMEOUT ${irc_timeout_${name}})
  endif()
endfunction()

# ---------------------------------------------------------------------------
# PER-TEST TIMEOUTS: WHY THEY EXIST, AND WHY THEY ARE NOT `--timeout 400`
# ---------------------------------------------------------------------------
# Every CI job runs `ctest --timeout 60`, and three tests in this suite are
# legitimately slower than that. The obvious fix -- raising the global -- is the
# wrong one: 60s is what turns a WEDGED run red in a minute instead of an hour,
# and raising it to accommodate three slow tests spends that detection on the
# other eighty-two, which finish in under three seconds and would then hang
# unnoticed for as long as the new limit allows. So the global default stays
# 60 and only the tests with a measured reason get an override.
#
# The rule is one rule, applied to the measured maximum rather than chosen by
# feel: SIX TIMES THE OBSERVED MAXIMUM, rounded up to the next 30 seconds, and
# never below the global 60. Six because the fastest machine here is not the
# machine CI runs on: a hosted runner is slower, it shares cores with whatever
# else the account is running, and `-j2` means this test is competing with
# another test for them.
#
# MEASURED, on this machine, Debug with WITH_TLS=ON (the slow configuration --
# Debug is unsstripped and TLS adds a real handshake to every case), at -j2,
# as the maximum over three runs and three compilers (gcc-16, upstream Clang 23,
# Apple clang 21), all reporting 85/85:
#
#   test_peer_tls         28.75s   -> 180   (6.3x)
#   test_topic_persist    22.81s   -> 150   (6.6x)
#   FailoverReconnect     11.24s   ->  90   (8.0x)
#
# NOTHING ELSE GETS ONE, and that is a result rather than an omission: the fourth
# slowest test is CapNegotiation at 4.53s, which is 13x inside 60, and every
# other test in the suite is faster still. The rule produces three overrides and
# stops; a fourth would be a number without a measurement behind it.
#
# THE COST, stated rather than discovered later. These three tests accumulate
# MANY deadline-bounded waits rather than one long one -- test_peer_tls has 20
# wait sites at 4s-20s each, test_topic_persist 20 at 15s, FailoverReconnect 13
# at up to 20s -- so a run in which EVERY wait fully expires reaches roughly
# 200s, 300s and 160s respectively. That is a failing run, not a hanging one,
# and because these values sit below those structural worst cases, such a run
# can surface as a ctest Timeout rather than as a named failed assertion. The
# trade is deliberate: a 4-5 minute budget for a wedge is cheaper than the
# alternative, which is a red CI run whose log says "timeout" where it could
# have said which assertion gave up. `--output-on-failure` still prints
# everything the test managed to print before it was killed, so the diagnosis is
# degraded rather than lost.
function(irc_test_timeout ctest_name seconds)
  if(seconds GREATER 0)
    set_tests_properties(${ctest_name} PROPERTIES TIMEOUT ${seconds})
  endif()
endfunction()

# ---------------------------------------------------------------------------
# The three overrides. Each is set immediately before the add_test() for the
# test it is about, so the number and the test it belongs to are read together
# rather than from a list somewhere else in the file.
#
# irc_timeout_test_peer_tls = 180
#   Two nodes, a real mutual-TLS mesh, real OpenSSL handshakes. 20 bounded
#   waits at 4s-20s. Measured 28.75s -- this is the test that made the global
#   60 unsafe, at 2.1x headroom on a fast machine with nothing else running.
# irc_timeout_test_topic_persist = 150
#   20 bounded waits at T_IO_MS/T_READY_MS = 15s each. Measured 22.81s.
# irc_timeout_test_failover_reconnect = 90
#   13 bounded waits, 8 of them at T_IO_MS = 20s. Measured 11.24s -- the
#   mildest of the three, and it still gets an override because a failover
#   test's wall clock is dominated by deliberate backoff waits, which is the
#   shape that degrades worst when the machine is busy.
# ---------------------------------------------------------------------------

# 7/Phase 2: "a client connects and is closed cleanly (assert accept -> EOF)".
# Runs the SHIPPED BINARY over real TCP.
irc_add_integration_test(test_conn_lifecycle test_conn_lifecycle.c)

# 3.3: partial writes, drained across poll iterations, byte for byte.
irc_add_integration_test(test_partial_write test_partial_write.c)

# Phase 12, the STRUCTURAL commit: poll() reads a readiness INTENT off the
# connection instead of deriving the event mask from data, because a nonblocking
# TLS handshake parks waiting to WRITE with an empty write queue and poll()'s
# revents cannot report that. Its own file, and it is the only test that asserts
# on conn_t fields, because the invariant it asserts IS a field invariant --
# "on a plaintext connection want_read is always 1 and want_write is exactly
# 'there are unsent bytes'" is what makes the plaintext poll set byte-identical,
# and no wire line can check it. The wire case is here too, though, and it is the
 # one that carries the claim: a connection whose intent says "do not read me" is
# never read while a second client on the same node is served normally, so a loop
# that mentions want_read and ignores it cannot pass.
irc_add_integration_test(test_readiness_intent test_readiness_intent.c)

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

# 7/Phase 8: IRCv3 CAP negotiation and SASL PLAIN. The CTest name is unchanged
# (CapNegotiation) and only the TARGET is spelled differently -- see the
# ctest_name shim in irc_add_integration_test below. It moved here from
# tests/compliance/ because CAP is answered by a server over a socket, and a test
# that cannot reach a server cannot tell a working CAP END gate from a server
# that never implemented CAP.
irc_add_integration_test(test_cap_negotiation test_cap_negotiation.c)

# 7/Phase 8: the IRCv3 `msgid`. Its own file because it is the only capability
# whose whole property is a value INVARIANT across a hop, so three of its four
# cases need clients that negotiated the capability and one of them needs two
# nodes: the advertised table agrees with what is written, the gate is both
# capabilities or neither, the value is 2.4's own (origin, epoch, id) rendered
# rather than a second counter, and the two clients on two processes see the SAME
# string. The last of those fails with either of the two mints broken and passes
# with both correct, which is what makes it the case worth having.
irc_add_integration_test(test_ircv3_msgid test_ircv3_msgid.c)

# test_multi_prefix, here because a `353` roster and a `352` flags field are
# produced by a server over a socket -- which is why it left tests/protocol/ -- and
# no longer a skip: Phase 8 implemented `multi-prefix`, so the test asserts the
# capability rather than the absence of it. The CTest NAME is unchanged, which is
# why the SKIP_RETURN_CODE line that used to follow this one is GONE rather than
# edited: leaving it would make ctest treat a failure as a skip. Its line in
# tests/known_skips.txt went in the same change, which is the other half of what
# the ratchet asks.
irc_add_integration_test(test_multi_prefix test_multi_prefix.c)

# userhost-in-names (Phase 10.5), here beside test_multi_prefix for one reason:
# both are about what a `353` roster LOOKS LIKE per destination, and both are the
# kind of test that passes with one client and fails with two. A separate file, not
# a second case in test_multi_prefix.c, because this one is a privacy assertion --
# it checks that a hostmask is disclosed to the client that asked and ONLY to that
# client -- and burying it beside a sigil-ordering case would make the disclosure
# easy to skim past.
irc_add_integration_test(test_userhost_in_names test_userhost_in_names.c)

# setname (Phase 10.6), its own file for one reason: almost everything the
# specification says about it is a REFUSAL -- before registration, without the
# capability, over-long, hostile -- and a file whose cases are mostly "nothing
# arrived, and the field did not change" reads very differently beside one whose
# cases are all "this line is on the wire".
irc_add_integration_test(test_setname test_setname.c)

# echo-message (Phase 10.7). Its own file because its assertions are COUNTS and no
# other capability here has that shape: the defect it invites is two identical
# deliveries, and a substring search for either one reports success. Every case
# below is tf_count over a marked region.
irc_add_integration_test(test_echo_message test_echo_message.c)

# 2.1 / 5: valid_nick() enforced at runtime. Phase 1 shipped the predicate with
# no caller in src/, so this is the test that makes it load-bearing. Asserts the
# RESPONSE, never that the function was called.
irc_add_integration_test(test_nick_rule test_nick_rule.c)

# The nickname grammar is UTF-8-AWARE: `ā` (C4 81), `café`, `日本` register and
# appear in the prefix a SECOND client receives, while a bare 0x80-0x9F, the
# encoded 0xC2 0x80-0x9F pair, and a lead byte with no continuations are refused
# with 432 and leave no byte on the wire. test_valid_nick.c proves the predicate;
# this proves what the other client SEES, which the predicate cannot.
irc_add_integration_test(test_nick_utf8 test_nick_utf8.c)

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

# Issue #102: a client that disconnects WITHOUT QUIT -- the ordinary end of a
# connection, and the path QUIT's test cannot reach -- must leave nothing behind
# in the nick index. Separate from test_quit.c because QUIT is a line the node
# gets to interpret and a dropped TCP connection is not: this is the one where
# the teardown was doing half the work. Under -DIRC_SANITIZE=ON the WHO in here
# is the statement that reads the freed conn_t.
irc_add_integration_test(test_disconnect_nick test_disconnect_nick.c)

# Issue #103, and the ownership guard the #102 fix rests on: one connection is in
# the enumeration at most once however many names it claims, a teardown retires
# every name it holds, and a connection that was DENIED a name cannot evict the
# holder's. In process against server_t, because no command sequence reaches
# these states -- which is the reason they were not caught.
irc_add_integration_test(test_nick_index test_nick_index.c)

# 2.1 / 2.2: the open-addressed table both registries are served by, and the
# probe chains deletion used to break (issue #107). A release that left a hole
# rather than shifting the chain back made every nickname that probed past it
# unreachable -- 401 for a connected user, and claimable by a second client --
# while WHO kept listing it, because WHO walks the enumeration. Collision-
# dependent, so it is not reachable from a one-name wire test; the two hand-
# picked cases assert their own hash premise, and the bulk sweeps need no
# particular pair to collide.
irc_add_integration_test(test_strtab_probe test_strtab_probe.c)

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

# 7/Phase 7, 4.2's INVITE. Its own file because the command's shape is "two
# replies to two DIFFERENT clients", which is the property most of the test is
# about: a 341 on the invitee's socket, or an INVITE on a third party's, would
# pass any check that only looked at the inviter.
irc_add_integration_test(test_invite test_invite.c)

# 7/Phase 7, 4.2's USERHOST. Its own file because the numeric is a per-name
# answer rather than a single reply, and the count of replies is the property
# most of the test is about -- a node that answered a four-name query with one
# 302 carrying everybody would satisfy every individual line assertion.
irc_add_integration_test(test_userhost test_userhost.c)

# 7/Phase 7, 4.2's KNOCK. Its own file because the command's ENTIRE behaviour is
# one numeric, and the only thing that distinguishes an honest refusal from a
# stub is which of the other numerics does NOT come back for each input.
irc_add_integration_test(test_knock test_knock.c)

# 7/Phase 7, 4.2's LUSERS, ADMIN and INFO. One file rather than three because
# they are one family with one fixture, and because the file's central assertion
# is that INFO's list of claims about the node is TRUE -- which is checked by
# sending what INFO says this node answers and reading the numerics back.
irc_add_integration_test(test_serverinfo test_serverinfo.c)

# 7/Phase 7, 4.2's CHOPER, and with it the refusal policy for operator commands.
# Its own file because the property most of the test is about is what the node
# does NOT say: 381 must never appear, and the password must never reach the log.
irc_add_integration_test(test_choper test_choper.c)

# Channel topic persistence across a reconnect. This was a CTest skip
# (return 77) from Phase 1 and Phase 7 implemented the feature it was named for:
# a channel's topic now survives the channel being DISPOSED, which 2.2 requires
# once every member has left. Moved here from tests/protocol because the feature
# is only observable on the wire -- a test that cannot reach a node cannot assert
# it -- and because the harness that reaches one is built by this file. The CTest
# name TopicPersistence is unchanged, so nothing that has ever seen the test sees
# a different thing.
set(irc_timeout_test_topic_persist 150)
irc_add_integration_test(test_topic_persist test_topic_persist.c)

# 2.4 / 3.2 / 4.3: the internal tag block the relay path budgets against, from
# the side that is not Phase 1's. test_message_format.c pins the 179 overhead as
# a LENGTH; this one pins the block as BYTES (a length cannot tell origin from
# epoch, so a serialiser emitting the four tags in the wrong order has exactly
# the right length) and then measures the overhead from two real renders, and
# asserts that the largest body the node will relay, stamped with the largest
# legal stamp, still fits IRC_MAX_LINE while one byte more is refused.
irc_add_integration_test(test_fed_tags test_fed_tags.c)

# 4.3 / 2.4: the S-verb wire, byte for byte, toward a listener THIS test owns.
# Every client verb with an S-verb is compared against a written-out literal --
# the four tag names in the frozen order, hops=0, the S-verb, the target, the
# text -- and the whole peer buffer is then asserted equal to exactly those
# lines, so a line that was not asked for fails as surely as one that was
# missing. The end-to-end half of test_reply_guard.c is here: real numerics
# driven through a real peer link, with each one checked to have reached the
# CLIENT first so that "the peer link is empty" is not satisfied by a link that
# never worked. No sleep anywhere; waiting is a deadline loop over the node's
# own poll step, and the negatives close their window with a PING/PONG.
irc_add_integration_test(test_fed_wire test_fed_wire.c)

# 2.4: the (origin, epoch, id) duplicate store and the loop guard that reads it.
# The store is asserted on RETURN VALUES -- first arrival new, second seen, the
# three key fields independent, the origin folded ASCII, an illegal key not new
# -- plus the TTL on BOTH sides of its boundary, the sweep throttle, and the
# capacity eviction (the store must not grow, must take the least recently seen
# entry, and must still answer correctly afterwards, which is what catches a
# back-shift repair that broke a probe chain). The guard is asserted on the WIRE:
# a link that is not ESTABLISHED is not a route, a relay carries its
# origin/epoch/id through untouched with only hops incremented (the id counter is
# pinned and required not to move), hops one short of the ceiling is refused,
# and a message whose origin is this node is refused in either case spelling --
# each beside a positive control, and each with a different-case name so the
# fold is load-bearing.
irc_add_integration_test(test_fed_dedup test_fed_dedup.c)

# 2.3 / 4.3 / 8: the FEDERATE exchange, end to end, over real TCP between real
# child processes. Every case is a REJECTION or the happy path, and each is
# asserted on the child's own observable output rather than on a struct field:
# two nodes claiming one name (SELF_NAME, and neither reaches ESTABLISHED), a
# wrong secret (BAD_SECRET, with the two secrets differing only in their LAST
# byte so a prefix compare would pass), a second claim on a name that is
# already ESTABLISHED (DUPLICATE_LINK), a handshake nobody answers, a link that
# goes silent, and the happy path -- which runs the SHIPPED BINARY on a command
# line, so --name/--secret/--peer and main()'s getaddrinfo are covered by
# something that can fail rather than by code nothing reaches. The handshake
# timeout and the liveness threshold are set per process in the child, so no
# case waits the shipped five or ninety seconds, and there is no sleep anywhere:
# every wait is a deadline over select() (6.3).
irc_add_integration_test(test_fed_handshake test_fed_handshake.c)

# 7/Phase 6: a user on A JOINs a channel and a user on B JOINs the same one, and
# the FULL 353 contents on each node are asserted in the Phase 4 order. Two child
# processes over real TCP, per 6.2.
irc_add_integration_test(test_fed_roster test_fed_roster.c)

# 7/Phase 6: a PRIVMSG from A reaches B exactly once, the two-node ping-pong
# settles, and 2.4's own-origin rule is the counter that proves it.
irc_add_integration_test(test_fed_loop test_fed_loop.c)

# 7/Phase 6: a node with ZERO local members in the channel still relays that
# channel's SPRIVMSG to the owner.
irc_add_integration_test(test_fed_relay test_fed_relay.c)

# #135: the peer-path log sites the burst family REFUSES. The other peer sweep
# cannot reach these by construction -- it drives shapes this node acts on, and
# these are the shapes it reports on while refusing -- so they need a fixture of
# their own or they are unchecked.
irc_add_integration_test(test_burst_malformed_log test_burst_malformed_log.c)

# #134: the "documented unreachable" claim in msg_verbs.c, CHECKED. A source
# inspection with no skip and no build-configuration dependence, because the thing
# it retires is a COMMENT -- and a comment cannot fail.
irc_add_integration_test(test_hostmask_reachability test_hostmask_reachability.c)

# #132: WHO IS ALLOWED TO SET A CHANNEL'S TOPIC. Three cases and a third node
# between them, because the rule has three arms and the one that needed three
# nodes is the one whose absence let the defect survive a suite that already had
# two-node federation in it.
irc_add_integration_test(test_fed_topic_authority test_fed_topic_authority.c)

# #141: #132's sibling, in the other verb. WHO IS ALLOWED TO EVALUATE A CHANNEL MODE.
# `MODE #chan +b` is one of 2.2's three origin-only fields, and the entitlement test
# read `params[0] <server>` -- which carries the authority -- as though it were the
# whole of it, so a ban set by an operator on any node but the origin's never took
# effect anywhere. Four cases: the origin applies a non-owner's +b and its ban list
# changes ON THE WIRE, a third server's claim is still refused, the origin's own mode
# change survives one relay hop (which needs the third node, because a refusal sits
# ABOVE the forward and suppresses it too), and a cache records the letter without
# enforcing it.
irc_add_integration_test(test_fed_mode_authority test_fed_mode_authority.c)

# 4.3 / 7/Phase 6 acceptance criterion 2: the FULL 353 CONTENTS on BOTH nodes
# after a resync, in the Phase 4 order and terminated by a 366 -- and the
# replace-never-merge property the resync exists for, which needs three bursts
# over one established link because "replaces" is three different claims. The
# middle one (an origin de-privileging a member) has teeth with no fixture poke
# anywhere in it; the third (a member the origin lost) cannot be produced by
# client commands on a two-node mesh at all, because the SPART would have
# removed the member first, and the test says so and pokes deliberately.
irc_add_integration_test(test_fed_burst test_fed_burst.c)

# 2.4: the inbound guard chain, driven by a peer that is trying to get past it.
# Every guard is a refusal of a line a well-behaved node would never send, so the
# far end of the link has to be a raw socket rather than a second node.
irc_add_integration_test(test_fed_guards test_fed_guards.c)

# 2.5.7 / 4.3.1: the <account> field of SJOIN and SBURSTM, and the bound it
# needs. A peer is the only thing that can produce an account name wider than the
# field -- account_store_add() will not store one -- so this owns one end of a
# link like test_fed_guards.c does, and asserts the refusal on the node's own
# output and the resulting roster on a client's socket.
irc_add_integration_test(test_fed_account test_fed_account.c)

# 2.2 / 4.3: what a node does when a peer goes away and when one comes back.
# 437 naming the origin on a channel this node cannot route to, NAMES still
# answered after the drop, NO auto-redial, re-linking a server of the SAME name
# resurrecting the channel (asserted as a round trip on the far side, not as an
# absence of 437), the SQUIT a dying node sends its remaining peers and the
# PER-ORIGIN purge that follows -- including an unrelated origin's roster
# surviving, which is the assertion with teeth -- and a peer claiming THIS node
# is gone being refused without costing the link. Three of the four cases need a
# node with more than one peer, so the fixture is four nodes: a two-node mesh
# cannot produce a link-down announcement at all, because the link that died was
# the only link. The last case owns one end of a link, like test_fed_guards.c,
# because no second node built from this code will send the line.
irc_add_integration_test(test_fed_resync test_fed_resync.c)

# 7/Phase 9: the reconnect POLICY -- exponential backoff, a cap, and a retry
# budget that is SPENT and reported rather than retried for ever. Two nodes, a
# frozen peer (SIGSTOP, not a kill: a killed peer sends a FIN and the survivor
# would observe a closed connection rather than the silence T4 exists to
# notice), and the ladder read out of the node's own delay_ms= reports. The
# ladder is scaled down per process through fed_set_retry(), because the shipped
# base is 90 s and a test that waited out even the first rung would be a slow
# test rather than a test.
set(irc_timeout_test_failover_reconnect 90)
irc_add_integration_test(test_failover_reconnect test_failover_reconnect.c)

# 7/Phase 9: the 4.3 resync being DRIVEN by a reconnect, which is 8's
# "Link loss and reconnect re-syncs channel state via SBURST". Phase 6 proved
# both halves either side of this and explicitly declined the middle: nothing in
# the node decided to reconnect, so a test's own signal was doing it. This case
# asserts the node recovers on its own AND that the resync it drives REPLACES
# rather than merges -- checked on the wire, with a member who parts and one who
# joins WHILE the link is down, which is the only way to produce state the mesh
# cannot have seen. The retry scale is shortened per process; the policy's shape
# is test_failover_reconnect's claim, not this one's.
irc_add_integration_test(test_sync_state test_sync_state.c)

# 2.1: the remote-nick registry, the scoped `nick@server` being ROUTED rather
# than recognised, and rename-the-loser. Its own file because it is the only
# feature whose claim is visible in FOUR places at once -- the renamed client's
# own NICK line, the other members of its channels, the peer's rekeyed roster,
# and the winner's non-rename -- and a test that checked one of them would pass
# against a mesh that had resolved the duplicate in only one.
irc_add_integration_test(test_nick_duplicate test_nick_duplicate.c)

# 2.1/2.2/8: a client whose TCP session is LOST and who comes back gets its
# channel set, with the per-channel prefix flags re-derived rather than copied.
# Its own file because the claim is a SEQUENCE over a real socket -- register,
# join, become op, CLOSE THE SOCKET, wait for the node to reap it, connect a
# second real socket -- and every step of that sequence is a place a test can
# stop being real. A unit test could assert that a window was recorded and
# nothing else, and the placeholder this file replaced said exactly why that was
# not enough: "honest CTest skip rather than SIMULATED RECONNECT STATE".
#
# IT MOVED HERE FROM tests/loadbal/, where the phase table put it because it was
# one of five skips 7/Phase 9 owned. That was a classification by the skip's name
# rather than by the feature: peer discovery and auto-scale are about a mesh, and
# a client reconnecting is a single node's business with no peer in the file.
# The CTest NAME is unchanged (Reconnect) -- see irc_ctest_name() for why, and
# tests/loadbal/CMakeLists.txt for what is left of the three.
irc_add_integration_test(test_reconnect test_reconnect.c)

# 7/Phase 9: 2.3's peer discovery -- ADVERTISE (a load figure, and a dial hint
# this node records and NEVER dials) and SHUTDOWN (a goodbye that must not spend
# a retry budget). Its own file because the SSRF claim is not observable on the
# node that holds the hint: the placeholder this file replaced could only have
# asserted that the node said `dialed=NO`, and a guard that prints its own
# verdict and then dials anyway passes that. So it needs a THIRD node for the
# hint to point at -- the same shape test_nick_duplicate.c documents, and the same
# trap.
#
# IT MOVED HERE FROM tests/loadbal/, where the phase table put it because it was
# one of five skips 7/Phase 9 owned. That was a classification by the skip's name
# rather than by the feature: peer discovery and auto-scale are about a mesh over
# real sockets, and a target in that directory links irc_core and nothing else --
# it cannot spawn a node, cannot own one end of a link and cannot read a dial it
# did not make. The CTest NAME is unchanged (PeerDiscovery) -- see
# irc_ctest_name() above for why, and tests/loadbal/CMakeLists.txt for what is
# left of the five.
irc_add_integration_test(test_peer_discovery test_peer_discovery.c)

# 7/Phase 9: 2.3's auto-scale, SCOPED TO WHAT A NODE CAN HONESTLY DO. Its own file
# and its own CTest name because the scoping decision is the deliverable as much as
# the code is: a node does NOT spawn or stop nodes (that is a supervisor's job, and
# a node that cannot measure its own load has nothing honest to decide a spawn on),
# so the placeholder this file replaced asserted nothing. What it asserts instead is
# the half that IS a node's business -- a node announces its own departure on the
# wire before it goes, its peers treat that as terminal rather than as a failure, and
# a peer that advertises itself as busy is reported to whoever can act on it without
# anything being moved.
#
# IT IS A SEPARATE FILE FROM test_peer_discovery.c AND NOT AN EXTENSION OF IT,
# because the two assert opposite halves of the same verbs. That file writes its own
# SHUTDOWN and its own ADVERTISE onto a socket, because at the time no node in this
# build ORIGINATED either. This one uses two real forked nodes, because
# fed_send_shutdown() now has a caller (server_shutdown()) and a departure that can
# only be produced by writing the line by hand proves nothing about whether a node
# produces one. Same reasoning the SSRF claim forced a third node there, applied to
# the origination question here.
#
# IT MOVED HERE FROM tests/loadbal/, where the phase table put it because it was one
# of five skips 7/Phase 9 owned -- a classification by the skip's NAME rather than by
# the feature, since auto-scale as this codebase implements it is a property of a mesh
# over real sockets. The CTest NAME is unchanged (AutoScale) -- see irc_ctest_name()
# above for why, and tests/loadbal/CMakeLists.txt for what is left of the five.
irc_add_integration_test(test_autoscale test_autoscale.c)

# 7/Phase 10.1: the ACCOUNT subsystem -- an identity that outlives a socket,
# which is the thing seven IRCv3 specs were blocked on because src/ had no
# account concept at all. In tests/integration/ and not tests/protocol/ for the
# same reason test_cap_negotiation.c is: the properties are all about what a
# CLIENT sees and what a node says at start-up and teardown, so they need a real
# socket, a real forked node, and the node's own stdout.
#
# Its own file because the claims are asymmetric and cannot be split by a file
# boundary without the file's testing itself: a registry that LOADS and a registry
# that does not must produce the SAME observable behaviour for a client that is
# not identified (that is the "account == \"\" is indistinguishable from no
# account system" invariant), and the only way to assert that is to run one set of
# assertions over both configurations.
irc_add_integration_test(test_account test_account.c)

# 7/Phase 10.8a: the fanout contract's THIRD outcome. `fanout_form_t` chose
# between two wire SHAPES per destination, which cannot express "send this member
# nothing" -- and `setname`, `chghost` and `away-notify` all need to publish to a
# SUBSET of a channel's members. So the routing module grew a per-destination
# GATE rather than three handlers growing three member walks.
#
# Its own file because nothing on the wire produces a gated emission until
# away-notify lands, and the contract is load-bearing for three specifications
# that do: the assertion has to be against the API, which is the same argument
# test_nick_index.c makes for the nick enumeration. Phase 10.8b then adds the
# wire-level case on top of it.
irc_add_integration_test(test_fanout_gate test_fanout_gate.c)

# 7/Phase 10.9: `standard-replies`, and the KICK reason bound `KICKLEN` was
# waiting for. One file because the two halves of the commit are the same claim
# about the same thing -- a refusal this node cannot represent must be REFUSED at
# the boundary with a numeric a client already understands, and only four of this
# node's numerics are ambiguous enough to be worth rendering as a `FAIL` for a
# client that negotiated the capability.
irc_add_integration_test(test_standard_replies test_standard_replies.c)

# 7/Phase 10.8: `chghost`, and the finding that is its deliverable. There is no
# CHGHOST verb on this node and no CHGHOST emitter, so the capability is ABSENT
# and the file's job is to make the absence provable and the reason precise: a
# HOST cannot move after accept(), but an IDENT CAN -- `USER` is a pre-registration
# verb the dispatch table still routes for a registered connection -- and nothing
# tells anybody when it does.
irc_add_integration_test(test_chghost test_chghost.c)

# 7/Phase 10.8b: `away-notify`, the `AWAY` notification on BOTH edges of the
# change. Its own file because the cleared edge is the half that is usually
# missing and it needs the same case as the set edge to be visible at all: a
# node that notified only on the way out leaves every member believing their
# friend is still at lunch for ever.
irc_add_integration_test(test_away_notify test_away_notify.c)

# IRCv3 `batch`, the client-facing half (Phase 10.12). Its own file because the whole
# capability's visible behaviour is a TAG on somebody else's line, so every assertion
# in it is either a count of tagged lines or a count of their absence -- and a
# substring search reports success for both. It is also the only place the `@`/`+`
# reference tags are tested at all.
irc_add_integration_test(test_batch test_batch.c)

# IRCv3 `labeled-response` (Phase 10.13). Its own file because the specification's
# central requirement -- "the tag in EXACTLY ONE LOGICAL MESSAGE" -- is a claim about a
# MULTI-LINE response, so every assertion in it is a count over a window rather than a
# substring, and because it is the only place the `labeled-response` grouping batch and
# the `ACK` are tested at all.
irc_add_integration_test(test_labeled_response test_labeled_response.c)

# IRCv3 `invite-notify` (Phase 10.14). Its own file because the specification's AUDIENCE
# is the thing being asserted -- the members of one channel, not the invitee's other
# connections and not the node -- and because `test_invite.c` already asserts that an
# INVITE reaches the INVITEE, so a substring search for "INVITE" on any socket here is
# satisfied by the delivery and every claim has to be a count.
irc_add_integration_test(test_invite_notify test_invite_notify.c)

# RFC 2812 conformance (Phase 11), split into one file per numeric group rather than
# one file for the whole phase, because each group is a different subsystem and each
# wants to be able to fail on its own. See docs/RFC2812_CONFORMANCE.md.

# 319 RPL_WHOISCHANNELS in WHOIS. Its own file because it is the one numeric whose
# ABSENCE was a defect: until Phase 11 a WHOIS named a person and never named a
# channel, which is the whole content of a WHOIS to a client looking for somebody.
irc_add_integration_test(test_whois_channels test_whois_channels.c)


# The ban-list query surface: `MODE #chan +b` answered with 367/368, and a full
# list answered with 478. Its own file because the observable is a LIST -- the
# assertions are counts of 367 lines and a check that 368 comes last -- and a
# substring search reports success for both a correct count and an empty list.
irc_add_integration_test(test_banlist test_banlist.c)

# The rest of the server-query surface Phase 11 checked: 254 RPL_LUSERCHANNELS,
# 433 recovery, and PING/PONG token echoing. Its own file because 254 is the only
# one that needed code -- the other two are here as the WIRE EVIDENCE that the
# sweep found them conformant, which is worth having in the suite rather than only
# in the phase report.
irc_add_integration_test(test_query_surface test_query_surface.c)

# 461's `<command>` field, asserted by PARSING THE LINE rather than by matching its
# bytes, plus the two numerics that must not grow one. Its own file because the
# other seventeen 461 needles in the suite cannot fail on this defect: a needle of
# `461 alice :Not enough parameters` passes against a node that omits the field,
# and a needle of `461 alice PRIVMSG :...` passes against one that hardcoded the
# verb. This file drives twenty-two probes over seventeen verbs and decomposes the
# answer, so "the field is present" and "the field is the right verb" are separate
# failures with separate messages.
irc_add_integration_test(test_numeric_arity test_numeric_arity.c)

# Phase 12: TLS. Its own file, and its own SHAPE, because of the optional-dependency
# decision: `-DWITH_TLS=ON` is off by default, so this test exists in both builds and
# asserts, in each, the behaviour THAT BUILD ACTUALLY HAS. In the default build it
# asserts the refusals and the absence of any `tls`/`sts` capability -- which are the
# assertions that matter most for the configuration this project ships. In the TLS
# build it adds a real implicit-TLS handshake, a real STARTTLS upgrade, three refused
# handshakes (wrong CA, expired, not-yet-valid, wrong name) and --tls-require's
# refusal of a plaintext client.
#
# NEITHER BRANCH SKIPS. `tests/known_skips.txt` stays empty, which is the point: a
# test that returned the skip code would assert nothing on the default build, and
# that is the exact failure scripts/check-skips.sh exists to prevent.
#
# Certificates are GENERATED INTO A TEMPORARY DIRECTORY by tests/harness/tls_fixture.c
# and never committed; tls_fixture.h says why at length, and the short version is that
# a key in git history is public for ever while an "expired is refused" case needs a
# certificate whose expiry is computed at run time.
irc_add_integration_test(test_tls test_tls.c)

# CERTIFICATE REVOCATION on the outbound peer-link path: OCSP stapling, the one
# boolean failure policy, and the source inspection that keeps the check from
# growing a fetch. Its own file because the deliverable is a PAIR of directions on
# one fixture -- GOOD establishes, REVOKED is refused, and a policy boolean that
# gets inverted passes every other test in this suite.
#
# IT NEEDS A CA AND NOT JUST CERTIFICATES, which is the one thing that makes it
# unlike test_tls.c and test_peer_tls.c: a revocation status can only be issued by
# somebody other than the certificate's subject, so a mesh where each node trusts
# the other's self-signed certificate directly has no issuer to ask. Every case here
# builds a real authority, two CA-issued leaves and five real signed OCSP responses
# -- revoked, stale, undated, good, and one signed by a stranger -- because a
# corruption is not a revocation and a test that cannot tell the difference is
# asserting nothing.
#
# TIMEOUT. Nine cases, each of which spawns two nodes and waits on observable lines:
# the establishing cases out to 20s, each refusal out to 4s to establish the
# ABSENCE. Six times the slow configuration's expectation, rounded up to the next
# 30s, per the rule above.
set(irc_timeout_test_tls_revocation 240)
irc_add_integration_test(test_tls_revocation test_tls_revocation.c)

# THE VERSION, AND THE RULE THAT KEEPS IT FROM DRIFTING. Its own file because the
# claim is a NEGATIVE -- no file outside the definition may hold a literal -- and a
# negative is only checkable by looking at every candidate at once. It also runs in
# the default build: every check is a source inspection or a run of the shipped
# binary's --help and startup line, and none of them needs a crypto library.
irc_add_integration_test(test_version_truth test_version_truth.c)

# Phase 12 item 5: TLS on a PEER LINK, and the mixed-mesh decision. Its own file
# because the decision is the deliverable as much as the code is: a mesh may MIX TLS
# and plaintext links, and what makes that safe is that a link's mode is STICKY --
# `server_link_t::require_tls` is written once from the operator's command line and
# is never cleared by anything, which is asserted by inspection because the only way
# to prove it behaviourally would be to have a downgrade path to observe.
#
# It runs against the SHIPPED BINARY on a command line, because --peer-tls and
# --tls-ca are main()'s options and an inline child has no command line. In the
# default build it asserts the one thing that build can: --peer-tls is REFUSED at
# startup rather than accepted and ignored.
set(irc_timeout_test_peer_tls 180)
irc_add_integration_test(test_peer_tls test_peer_tls.c)

# The log-injection set (#121): `conn_byte_is_bad()` and the three policies built
# on it. Its own file because the three fields have three different CONSUMERS and
# therefore three different answers -- a servername nothing reads is MEASURED, an
# away message and a topic that reach other members' terminals are STRIPPED and the
# strip is announced, and a realname that is reported to third parties is still
# REFUSED -- so "one predicate, per-field policy" is only checkable if all three
# policies and both positive controls are in one place. The two "keeps good bytes"
# cases are the ones that keep the strip from eating spaces and UTF-8, which is the
# failure mode that would be worse than the injection because it is silent.
irc_add_integration_test(test_control_bytes test_control_bytes.c)

# The LOG-ONLY client-supplied fields (#121, second pass). Its own file because its
# claim is a NUMBER rather than a per-site assertion: put a control byte in every
# position a client can put one and require that NONE of them reaches this node's
# stdout. That is a stronger claim than "each site was fixed", because it also
# covers the site nobody enumerated -- and the audit method that found the 22
# surviving bytes was exactly this one, so committing it is what stops the finding
# from having to be rediscovered.
irc_add_integration_test(test_log_injection test_log_injection.c)

# The REACHABILITY property, replacing the site enumeration that did not work.
# test_log_injection.c's battery is hand-listed: somebody decided which verbs and
# which argument positions reach a log line, and #121 shipped with two live
# bypasses precisely where that list was wrong. This one derives the verb list out
# of `commands.c`'s `k_commands[]` -- the dispatch table itself -- and generates the
# (verb, argument position, marker byte) space rather than listing it, so a verb or
# a position added tomorrow is covered tomorrow. The claim is unchanged and is the
# one that matters: no byte in the terminal-injection set reaches this node's stdout
# or any client socket. Its own file because that is a different KIND of claim from
# the battery's -- the battery asserts per-site, this one asserts a property of the
# reachable surface -- and because a sweep this wide is the one place where the
# "whole-buffer walk, not a substring search" requirement has to be load-bearing.
irc_add_integration_test(test_terminal_sweep test_terminal_sweep.c)

# The SAME sweep on the PEER path. Same instrument -- tests/harness/sweep_scan.h --
# and a different surface: a raw socket standing in for the other node, so the
# bytes a peer sends that reach this node's log, its forward to a second peer, or a
# client all get swept. It is a separate binary because reaching a peer link needs a
# different fixture, not because it is a different claim.
irc_add_integration_test(test_peer_terminal_sweep test_peer_terminal_sweep.c)

# The relay SHAPE behind four #121 bugs: an emission carrying `m->params` instead of
# the value the node stored. A source test, because the defect leaves every runtime
# invariant intact -- a field and its announcement can be two different values and
# nothing on the wire says so -- which is the same situation test_close_sites.c
# checks by looking rather than by running. It counts what it expects to FIND as
# well as what it expects not to, so deleting the emissions turns it red instead of
# vacuous.
irc_add_integration_test(test_relay_shape test_relay_shape.c)

# Relayed PRIVMSG/NOTICE text: the strip/keep split, end to end. Its own file
# because the rule is two-sided and a test of only one half passes while the other
# is broken -- a strip that removed ESC but also the mIRC codes passes every
# "nothing dangerous arrived" assertion and silently breaks colour on every client.
# test_msg_text.c asserts BOTH halves, the two C1 subtleties (the pair, and the
# UTF-8 that collides with it), and the announcement decision.
irc_add_integration_test(test_msg_text test_msg_text.c)
