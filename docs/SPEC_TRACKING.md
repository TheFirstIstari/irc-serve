# Spec Tracking

**Last verified: 2026-09-28.** This document records the *actual* state of the
code against `docs/SERVER_DESIGN.md` and the RFCs. Where the two disagree, the
code wins and the disagreement is written down.

The previous revision of this file (dated 2026-09-06) claimed features were
"observable" that were in fact skipped, dead, or vacuous. It was wrong on
message-id, SASL, IRCv3 tag roundtrip, peer discovery, reconnect, and topic
persistence. That is the specific failure mode this revision is written to
prevent: **every claim below names a file, a test, or a command, and every
command in this document was run on 2026-09-28.**

## How this was verified

| Step | Command |
|---|---|
| Build | `cmake -B <build> -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_BENCHMARK=ON` then `cmake --build <build> --parallel 8` — clean, no warnings, no errors |
| Test run | `ctest --timeout 60` in the build tree — **39 tests: 31 passed, 8 skipped, 0 failed** |
| Behaviour | the shipped `irc-serve` binary was run on an ephemeral port and driven with a raw TCP client; the wire bytes quoted in this document are captured from that session |
| Build membership | `src/CMakeLists.txt`, `nm` on the linked binary, and a repo-wide `grep` over every `CMakeLists.txt` |
| Phase state | `gh issue list --milestone "Federated IRC Server v1.0" --state all` |

**Not verified, and not claimed:** whether GitHub Actions is currently green. No
CI run was observed in this pass. The only execution evidence given here is the
local Release run above, on macOS/darwin with the system compiler.

**A Phase 7 addendum, and what it supersedes.** This document is a dated audit
against a named commit and most of it is left exactly as written, because
rewriting a snapshot would destroy the evidence it exists to provide. Three
claims below were superseded by Phase 7 and are corrected **in place** rather than
left to be disproved, because they are statements about the tree and the tree has
changed: **§2** (the skip list, and the claim that CI does not count skips),
**§5.1** (which phase owns the skip gate), and the `TopicPersistence` row of
§2's table. Everything else here is as of 2026-09-28.

**A Phase 10.1 addendum, in the same spirit.** Nothing in the audit below is
rewritten, because none of it is about accounts; what Phase 10.1 adds is a new
**§10** at the end, which is the only place in this document that records what
the account subsystem did and did not unblock. The one claim below that the phase
**does** falsify is corrected in place and marked as such: **§8's** IRCv3 bullet,
which said CAP negotiation, SASL and `msgid` were unimplemented — already false at
Phase 8, but Phase 10.1 is the phase that made `account-tag` a decision rather
than an absence, so it is the right place to say so.

### Commit under verification

`HEAD` = `e958ea9` ("Phase 2: server core - poll loop, conn_t framing,
registries"), plus **uncommitted working-tree changes**: `src/core/commands.{c,h}`,
`src/core/reply.{c,h}`, seven new integration tests, and edits to
`src/CMakeLists.txt`, `src/core/server.h`, `src/node_main.c`, the test harness,
and `docs/SERVER_DESIGN.md`. Everything marked *Implemented (Phase 3)* below
lives in that uncommitted work and is **not in `main`**.

### Status vocabulary

| Word | Meaning |
|---|---|
| **Implemented** | Compiled into the shipped library or binary, and exercised by a test that asserts on it. |
| **Implemented, unreachable** | Compiled and unit-tested, but nothing in the shipped binary calls it. |
| **Partial** | Some of the spec area exists; the row says exactly which part. |
| **Vacuous** | Code and/or test exists and passes, but the test cannot fail for the reason it names. |
| **Dead** | Not compiled by any build target in the repo. |
| **Declared only** | Advertised on the wire with no evaluator behind it. |

---

## 1. Feature status

### 1.1 Phase 1 — message seam (`message.{c,h}`)

All rows verified in `src/core/message.{c,h}` (1011 + 440 lines) and
`src/core/CMakeLists.txt:6`.

| Feature | Spec / source | Actual status | Evidence |
|---|---|---|---|
| Tokenizer: tags, `:prefix`, command, ≤15 params, 15th absorbs rest | RFC 1459 §2.3, §3.1 / design §3.2 | **Implemented** | `message_parse_n()` `src/core/message.c:377`; `tests/protocol/test_message_parse.c` (`MessageParse`, 150 assertion sites) |
| Embedded CR/LF/NUL rejection | design §3.2 | **Implemented**, and only on the counted entry point | `message_parse_n` `message.c:377`. `message_parse()` `message.c:537` is structurally blind to bytes after a NUL — `strlen()` hides it. `poll_loop.c:94` calls the `_n` form, so the wire path is the strong one. |
| One heap allocation, two regions (`raw` vs fields) | design §3.2 | **Implemented** | `message.h:12-46` (contract); `message_t` `message.h:179` |
| Zero-`*out`-on-reject, idempotent free | design §3.2 | **Implemented** | `message_free()`; `poll_loop.c:96` frees on a path where parse rejected |
| Outbound constructor + formatter | design §3.2 | **Implemented** | `message_build` `message.c:561`, `message_format` `message.c:695`; `tests/protocol/test_message_format.c` (`MessageFormat`) |
| Formatter never echoes `raw` | design §3.2 | **Implemented** | `message.c:695` renders from fields only |
| Formatter refuses CR/LF in any field | design §3.2 | **Implemented** | `tests/protocol/test_message_format.c`; `reply.c:95` records that `message_format()` "terminates nothing" and that `reply()` is therefore where CRLF is appended |
| 15-param cap | RFC 1459 §2.3 | **Implemented** | `IRC_MAX_PARAMS 15` `message.h:71` |
| Line cap 8192 incl. CRLF | design §3.2 | **Implemented** | `IRC_MAX_LINE 8192` `message.h:77`; `test_framing` asserts the boundary over real TCP |
| Relay cap 8013 = 8192 − 179 | design §3.2 | **Implemented** as a constant | `IRC_MAX_RELAY_LINE` `message.h:148` |
| Tag overhead constant is 179, derived not estimated | design §3.2 | **Implemented and pinned** | `IRC_MAX_TAG_OVERHEAD 179` `message.h:135`; `test_message_format.c:581` asserts the measured worst case **equals** the constant, and `:590` asserts `179 == IRC_MAX_LINE - IRC_MAX_RELAY_LINE` |
| **Over-cap relay line is dropped with a client-side notice** | design §3.2 "Relay truncation policy" | **Not implemented** | The constant exists. `message.h:143-147` says so explicitly: the drop-with-notice "is Phase 6 relay work and is NOT implemented yet". No caller. |
| IRCv3 tag escaping `\:` (semicolon), `\s`, `\\`, `\r`, `\n`; a colon is RAW; invalid escape drops its backslash; lone trailing `\` is dropped | IRCv3 message-tags / design §3.2 | **Implemented, and the set this row used to name was wrong** | One table, `ircv3_escape_value` / `ircv3_unescape_value` in `src/ircv3_tags.c`; `message_tag_escape`/`message_tag_unescape` in `core/message.c` are thin wrappers over it. The row previously read `` `\:` `\;` `\s` `\\` `\r` `\n` `` and the implementation agreed with it: `;` was written `\;` and `:` was escaped. Both were retracted in Phase 8 — see design §5. Reproduced directly: `message_tag_escape("a:b;c d\\e")` → `a:b\:c\sd\\e`. Pinned by `test_tag_roundtrip_hostile` over a corpus of 34 hostile values, both directions, plus `test_message_format.c:389-447` |
| Case-insensitive tag lookup | IRCv3 | **Implemented** | `message_tag_get` `message.c:254` |
| Internal `irc-serve-origin/epoch/id/hops` format + value grammar | design §2.4 | **Implemented** | `irc_serve_tags_t` `message.h:365`; grammar `message.h:351-364`; `irc_serve_tags_valid` `message.c:861`, `_format` `:873`, `_parse` `:899`; `irc_serve_server_name_valid` `message.c:779` |
| Internal tags are actually *stamped on relayed messages* | design §2.4 | **Implemented, unreachable** | Every caller of `irc_serve_tags_format` / `_parse` / `message_tag_escape` is in `tests/`. Zero call sites in `src/` outside the definitions. There is no relay path. Phase 6. |
| `valid_nick()` charset rule | design §2.1, §5; RFC 2812 §2.3.1 | **Implemented and enforced at runtime** | `message.c:992`, rule spelled out `message.h:401-436`. Wire evidence below. |
| **No leak on any rejection path** (one alloc, explicit free before reuse) | design §7/Phase 1 hygiene | **Asserted, not verified** | No sanitizer flag exists anywhere in the build or CI (`grep -rniE 'sanitize\|fsanitize\|asan\|ubsan'` over `CMakeLists.txt`, `ci.yml`, `local-ci.sh`, `Makefile` → no hits). The design doc itself says this clause is asserted, not verified. The reuse-without-free leak is not covered by any test. |

### 1.2 Phase 2 — server core

All rows verified in `src/core/{connection,server,poll_loop}.{c,h}` and
`src/node_main.c`. The six §3.4 requirements are checked individually.

| §3.4 requirement | Status | Evidence |
|---|---|---|
| Nonblocking dial with a dial FSM | **Implemented, unreachable** | `server_dial` `server.c:642`, states `server.h:112-115`; `tests/integration/test_dial_fsm.c` (`test_dial_fsm`) passes. `grep -rn 'server_dial(' src/` finds only the definition — no caller. |
| The poll tick drives time | **Implemented (hook only)** | `server_tick` `server.c:391`; called at the single fixed point `poll_loop.c:276` with `server_now_ms()`. `on_tick` is **never assigned** in `src/` — only the dispatch site exists. Phase 6's timeout/liveness/eviction logic is not written. |
| Bounded write queues ~256 KB, saturate = drop | **Implemented** | `CONN_WQ_MAX` 256 KiB `connection.h:74`, cap on the unsent tail; `conn_queue` refuses the append, `server_queue` marks CLOSING. `tests/integration/test_writeq_overflow.c` + `test_partial_write.c` over real TCP |
| The send path never closes a connection | **Implemented** | `conn_queue`/`conn_pump` never close; single close site is the reaper. `tests/integration/test_close_sites.c` is a **source-inspection** test (labelled as such in its own header); runtime half in `test_reaper_close.c` |
| Peer addresses pre-resolved (no `getaddrinfo` in the loop) | **Implemented** | `server_dial` takes a resolved `struct sockaddr`; no resolution helper exists in `src/` |
| Explicit `fd >= FD_SETSIZE` rejection | **Implemented** | `server.h:131` `SERVER_FD_TABLE FD_SETSIZE`; `SERVER_ACCEPT_REJECTED (-2)` `server.h:136`; `tests/integration/test_fdsize_reject.c` |

| Feature | Spec / source | Actual status | Evidence |
|---|---|---|---|
| `poll()` loop: 8 ordered steps, 50 ms tick, EINTR-safe | design §3.4 | **Implemented** | `poll_loop_step` `poll_loop.c:163`, step comments `:1-21`, `POLL_TICK_MS 50` `poll_loop.h:17`. `tests/integration/test_eintr.c` drives the EINTR path from outside via `SIGUSR1` (`node_main.c:75`, no `SA_RESTART` at `node_main.c:92`) |
| Listener drained, not one-per-tick | design §3.4 | **Implemented** | `poll_loop.c:231-240` |
| `conn_t` identity fields | design §2.1 | **Implemented**, final shape | `connection.h:95-114` |
| `conn_t::peer_name` and `::chans` | design §2.1, §2.2 | **Declared, always empty** | `connection.h:99,104`; `chans` is `struct chan **`, and `struct chan` does not exist yet (`connection.h:53`). Phase 4 |
| RFC 1459 §2.3 framing, partial-write safe | design §3.3 | **Implemented** | `conn_next_line` `connection.c`; `woff` retained. `tests/integration/test_framing.c` (668 lines) and `test_partial_write.c` (471 lines) over real TCP |
| Bounded read buffer | design §3.2/§3.3 | **Implemented** | `CONN_RBUF_MAX = IRC_MAX_LINE` `connection.h:82` — a client cannot grow it by withholding a newline |
| fd-indexed connection registry, O(1) | design §3.3 | **Implemented** | `server.h:142`; `tests/integration/test_registries.c` |
| Nick registry (per-server, claim/release/lookup) | design §2.1 | **Implemented** | `server.h:283-285`; `test_registries.c` |
| Channel registry — **key space only** | design §2.2 | **Partial** | `server.h:294-296`. Names are inserted and looked up; **the value is always NULL** because `struct chan` does not exist. Phase 4. |
| Per-SERVER monotonic msg id + per-boot epoch | design §2.4 | **Implemented, unreachable** | `server_next_msg_id` `server.c:396`; `server.h:156-157`. Callers are in `test_registries.c:125-148` only. No message is ever stamped. |
| Node name validated against the §2.4 tag grammar | design §2.4 | **Implemented** | `server_init` `server.h:210`; `NODE_NAME "irc.test"` `node_main.c:61` |
| Port is an argument, `0` = ephemeral, reported back | design §7/Phase 2 | **Implemented** | `node_main.c:107` `parse_port`, `:188` `server_port`; the tests rely on this to run in parallel |

### 1.3 Phase 3 — registration (`commands.c`, `reply.c`)

All rows verified in `src/core/commands.c` (566 lines), `src/core/reply.c`
(183 lines), `src/core/reply.h` (159), `src/core/commands.h` (52).

| Feature | Spec / source | Actual status | Evidence |
|---|---|---|---|
| `reply()` is the only outbound-to-client path | design §3 | **Implemented** | `reply.c:46` `emit_to_client()` is the only function in `src/` that calls `server_queue()` for a client message; both `reply()` and `send_pong()` funnel through it |
| Numerics never reach a peer link | design §3 | **Implemented** | `reply.c:55` refuses `CONN_SERVER` as `peer_target`. `tests/integration/test_reply_guard.c` passes; running it prints the refusals: `reply_refused: fd=3 code=433 reason=peer_target`, `code=PONG reason=peer_target`, `code=401 reason=no_target`, `code=001 reason=closing` |
| Refusal is counted and always printed | design §3 | **Implemented** | `n_reply_refused` `server.h:199`; `refuse()` `reply.c:33` deliberately not gated on `s->trace` |
| A peer link is exempt from the client state machine | design §2.3 | **Implemented, unreachable** | `commands.c:512` skips `CONN_SERVER`. Unreachable in the shipped binary: nothing calls `server_dial`, so the only `CONN_SERVER` construction site (`server.c:787`) is never reached. `commands.c:509` says so. |
| Registration state machine, 4 states, recomputed not incremented | design §2.1 | **Implemented** | `update_state` `commands.c:178`; states `connection.h:64-68`; `commands_registered` `commands.c:45` |
| `PASS` | RFC 1459 §2.4 | **Recorded, NOT authenticated** | `handle_pass` `commands.c:242` increments `n_pass_seen` and nothing else. There is no credential store. A client sending `PASS hunter2` and one sending nothing are treated identically. Observed on the wire: node stdout `[observable] pass: fd=4 recorded=1 authenticated=0`, `loop_stats: ... pass_seen=1 ...` |
| `NICK` | RFC 2812 §3.1 | **Implemented** | `handle_nick` `commands.c:278`; claim-then-release ordering at `:304-325` |
| `432` for an illegal nickname | RFC 2812 §2.3.1; design §4.4 | **Implemented** | `commands.c:296`. Note: `commands.c:261-266` records that **432 is not in design §4.4's numeric list** — the RFC numeric is used and the discrepancy is flagged for the design |
| `433` for a legal nickname already claimed | RFC 2812 §2.3.1 | **Implemented** | `commands.c:309`; `tests/integration/test_dup_nick.c` (`test_dup_nick`) passes |
| `431` / `461` | RFC 2812 §3.1 | **Implemented** | `commands.c:284`, `:245`, `:291`, `:364` |
| `USER` — the asserted hostname is **discarded** | RFC 2812 §3.1 | **Implemented, deliberately** | `handle_user` `commands.c:358` never touches `c->host`; `c->host` keeps the observed peer address from `accept`. Rationale and its cost stated at `commands.c:330-357`. The assertion is printed, not stored: `[observable] user: ... asserted_host=* host=127.0.0.1 host_source=observed` |
| `PING` / `PONG` | RFC 1459 §2.4 | **Implemented** | `commands.c:381` / `:396`; `send_pong` `reply.c:166`. Bare `PING` with no token answers with the server name (`reply.c:178`) |
| `QUIT` | RFC 1459 §2.4 | **Implemented** | `handle_quit` `commands.c:423`; marks CLOSING, releases the nick, does **not** close the fd (the reaper does) |
| `MOTD` 372–376 | RFC 2812 §3.7 | **Implemented** | `send_motd` `commands.c:126`; `k_motd` `commands.c:99` |
| Welcome burst 001–005 | RFC 2812 §3.1/§3.2 | **Implemented** | `send_welcome` `commands.c:140` |
| `005` ISUPPORT: `NETWORK=`, `CHANTYPES=#&`, `PREFIX=(ov)@+`, `CASEMAPPING=ascii`, `NICKLEN=63` | design §4.4 | **Implemented** | `k_005` `commands.c:85-94`. `CASEMAPPING=ascii` is correct and deliberate: `message.c`'s upper-casing is ASCII-only, so advertising `rfc1459` would be a lie (`commands.c:89-92`) |
| **`004` advertised modes** | RFC 2812 §4.2.2 | **Declared only — nothing evaluates them** | `NODE_USER_MODES "i"`, `NODE_CHAN_MODES "b,k,l,imnpst"` `commands.c:77-78`. No mode parser, no mode state, no `+b`/`+k`/`+l` evaluation anywhere in `src/`. A client that offers `+k` and is refused by nothing gets silent divergence. `commands.c:70-76` states the trade honestly: 421 is the honest answer until Phase 4/7. |
| `451` pre-registration gate | RFC 2812 §3.1 | **Implemented** | `commands.c:537`. Gate runs **before** the unknown-command check, per RFC order. `tests/integration/test_pre_register.c` passes |
| `421` for a known-but-unimplemented verb and for an unknown verb | RFC 2812 §3.1 | **Implemented** | `commands.c:545` (unknown verb) and `:549-561` (in `k_commands` with a NULL handler). Both paths are distinguished in stdout: `cmd_unknown:` vs `cmd_unimplemented:` |
| `JOIN` `PART` `PRIVMSG` `NOTICE` `TOPIC` `NAMES` `MODE` `KICK` `KILL` | RFC 1459 §2.4; design §4.1 MUST | **Not implemented** | `commands.c:469-477` — present in the table with `NULL` handlers. Each answers `421` with `cmd_unimplemented` in stdout |
| design §4.2 SHOULD commands | design §4.2 | **Not implemented** | No entry in `k_commands`; answered `421` as unknown |
| design §4.3 server-to-server verbs (`FEDERATE`, `SBURST`, `SJOIN`, …) | design §4.3 | **Not implemented** | No such verb anywhere in `src/`. Phase 6 |
| Channel numerics 331 332 333 353 366 324 329 | RFC 2812 §3.3; design §4.4 | **Not implemented** | No code path emits them |
| Query numerics 311–319, 321–323, 351–352, 315 | RFC 2812 §3.4; design §4.4 | **Not implemented** | — |
| Server-info numerics 251–266 | RFC 2812 §3.4.1; design §4.4 | **Not implemented** | — |

#### Wire evidence (shipped binary, ephemeral port, raw TCP client)

`PASS hunter2 / NICK good / USER u 0 * :Real Name` then `PING :abc123`,
`NICK a@evil`, `NICK 9lead`, `PRIVMSG #chan :hi`, `JOIN #x`, `BOGUSVERB arg`,
`QUIT :bye` produced exactly:

```
:irc.test 001 good :Welcome to the irc-serve network good!u@127.0.0.1
:irc.test 002 good :Your host is irc.test, running version irc-serve-0.1.0
:irc.test 003 good :This server was created Mon Sep 28 19:29:13 2026 (UTC)
:irc.test 004 good irc.test irc-serve-0.1.0 i b,k,l,imnpst :are supported by this server
:irc.test 005 good NETWORK=irc-serve CHANTYPES=#& PREFIX=(ov)@+ CASEMAPPING=ascii NICKLEN=63 :are supported by this server
:irc.test 372 good :- irc-serve: a federation-native IRC node.
:irc.test 372 good :- this build answers PASS, NICK, USER, MOTD, PING, PONG and QUIT.
:irc.test 372 good :- registration, channels, messaging and peer federation are implemented.
:irc.test 375 good :- Message of the day -
:irc.test 376 good :End of /MOTD command.
:irc.test PONG irc.test abc123
:irc.test 432 good :Erroneous nickname: a@evil
:irc.test 432 good :Erroneous nickname: 9lead
:irc.test 421 good PRIVMSG :Unknown command
:irc.test 421 good JOIN :Unknown command
:irc.test 421 good BOGUSVERB :Unknown command
```

Node shutdown counters for that session:

```
[observable] loop_stats: ticks=50 eintr=1 accepted=1 closed=1 lines=10
  parse_reject=0 frame_error=0 writeq_overflow=0 write_error=0 partial_writes=0
  rejected_fd=0 pass_seen=1 reply_refused=0
```

Note `004` advertising `i b,k,l,imnpst` against `421` for both `PRIVMSG` and
`JOIN` in the same session. That contradiction is the honest current state.

### 1.4 The older modules — assessed individually, not as a group

These predate the design and are **not** of equal quality. The status table must
not imply they are.

#### `src/protocol_parse.c` — genuinely good, with one real hole

`parse_nick` and `parse_user` have correct capacity discipline (every field is
length-checked against its caller's buffer before the copy, and an
insufficient-capacity case returns `-1` rather than truncating) and correct
embedded-newline rejection (`line_text_len` returns `(size_t)-1` on any CR/LF
before the terminator, `protocol_parse.c:53-61`). `parse_user` also strips
exactly one leading `:` from the realname and preserves interior spaces
(`:151-162`).

**`parse_nick` performs no charset validation whatsoever.** Verified by running
it against the linked library:

```
parse_nick("NICK a@evil")  -> rc=1  nick="a@evil"   <- accepted
parse_nick("NICK 9lead")   -> rc=1  nick="9lead"    <- accepted
parse_nick("NICK a#b")     -> rc=1  nick="a#b"      <- accepted
parse_nick("NICK a;b")     -> rc=1  nick="a;b"      <- accepted
parse_nick("NICK a:b")     -> rc=1  nick="a:b"      <- accepted
parse_nick("NICK a b")     -> rc=-1                  <- rejected (2 params, not charset)
```

The only rejections are structural (wrong command word, missing nickname,
capacity, embedded newline, trailing junk). For contrast, the predicate that
replaces it:

```
valid_nick("a@evil")=0  valid_nick("9lead")=0  valid_nick("a#b")=0
valid_nick("a;b")=0    valid_nick("a:b")=0    valid_nick("good")=1
```

`parse_nick` is **superseded, not on any live path**: the node's nick path is
`commands.c:295` → `valid_nick()`. `parse_nick` is still compiled into
`irc_core` and still tested (`tests/protocol/test_nick_user.c`), so it reads as
live to anyone grepping the tree. Design §5 says it must not be preserved as-is;
that has not been actioned (it has been neutralised instead).

| Feature | Spec | Status | Evidence |
|---|---|---|---|
| `parse_nick` charset rule | RFC 1459 §2.4 | **Not implemented** | above; `protocol_parse.c:68-103` contains no character test |
| `parse_user` field discipline | RFC 2812 §3.1 | **Implemented** | `protocol_parse.c:105-166`; `test_nick_user.c` |
| `parse_command` token counting | — | **Implemented, superseded** | `protocol_parse.c:17`. Only counts tokens; replaced by `message_parse_n`. Retained as the throughput benchmark's labelled LEGACY BASELINE, alongside the production measurement of `message_parse_n` (§4) |

#### `src/ircv3_tags.c` — weak

`tags_parse` (`ircv3_tags.c:62`) and `tags_serialize` (`:66`) are **the same
function**. Both call `tags_validate_copy` (`:49`) — validate, then `memcpy` the
input to the output unchanged. There is no parse-to-a-list step and no
serialize-from-a-structure step, so the module cannot do either job its names
promise.

**The "roundtrip" test therefore proves nothing.**
`tests/compliance/test_tags_roundtrip.c` asserts `serialize(parse(x)) == x`. Since
`serialize` *is* `parse`, that reduces to `f(f(x)) == f(x)` for a deterministic
`f` — it cannot fail for any reason connected to tags. It is reported as passing
(`TagsRoundtrip`).

**IRCv3 escaping is absent.** The grammar rejects a space in a tag
(`tags_valid`, `ircv3_tags.c:28,35,42`), so a value needing `\:`/`\;`/`\s` is
refused rather than escaped:

```
tags_parse("@m=a:b;c d")  ->  -1
```

No test in the repo exercises `\:` `\;` `\s` `\\` `\r` `\n` against this module.
The escaping that **does** exist is in Phase 1's `core/message.c`, which is a
different module with a different API.

What this module does do well: `tests/compliance/test_ircv3_tags.c` (`Ircv3Tags`,
passes) genuinely pins the structural grammar — optional `@`, `=` inside values,
empty values, empty key, empty pair, stray space, lone `@`, NULL args, and
capacity rejection without truncation. **That test is real; the roundtrip test
is not.** Design §5 puts the real fix in Phase 8.

#### `src/sasl_framework.c` — now in the shipped library, still a placeholder

- **In `irc_core` since #86.** It used to be absent, with its only build site
  `tests/compliance/CMakeLists.txt:3` compiling it *into the test binary*; the
  file is now a source of `irc_core` and `test_sasl_handshake` links the library
  like every other test. `nm` on `libirc_core.a`: seven `sasl_*` symbols. What
  remains true below is that the implementation is a placeholder -- #86 put it in
  the library, it did not make it real. #82 does that.
- **`sasl_step` discards its input and auto-completes after 2 calls.**
  `sasl_framework.c:44-45` is `(void)server_data; (void)len;`, `client_out` is
  set to length 0, and `:50-52` sets `SASL_COMPLETED` on `step_count >= 2`.
  There is no mechanism, no credential store, no base64, no PLAIN.
- **The self-test harness lives in `src/`.** `sasl_state_machine()` at
  `sasl_framework.c:87` is ~40 lines of `assert()`s and `printf`s calling the
  API it lives beside. The test that runs it is 11 lines with one assertion:
  `tests/compliance/test_sasl_handshake.c`.

| Feature | Spec | Status | Evidence |
|---|---|---|---|
| SASL PLAIN | IRCv3 SASL / design §5 | **Not implemented** | No mechanism code, no credential store |
| SASL state machine shape | IRCv3 SASL | **Vacuous** | The test exercises `sasl_state_machine()` in `src/`, not a real exchange. It passes because the machine completes on call count. |
| SASL is in `irc_core` | design §5 | **Yes** | Fixed by #86: `sasl_framework.c` is a source of `irc_core`; `nm libirc_core.a` shows seven `sasl_*` symbols |

#### `src/message_id.c` — deleted (#86)

- **Was not in any `CMakeLists.txt` in the repo.** `grep -rn 'message_id'
  --include=CMakeLists.txt .` returned nothing. `Makefile` and `local-ci.sh` both
  drive CMake (`Makefile:26-27`, `local-ci.sh:35-36`), so there was no second
  build path that could pick it up.
- Never compiled, never tested, no test file referenced it.
- Its format was wrong for the design anyway: a file-static `int`
  `msg_id_counter` and `"msg%d"` — not IRCv3-shaped, and not the per-SERVER
  `(epoch, id)` pair design §2.4 requires. There was no `epoch` at all.
- **Now deleted**, along with its two entries in `test_close_sites.c`'s
  file lists (the file no longer exists, and that test fails on an unreadable
  one). Real message-ids land in Phase 8 (#82) via `(origin, epoch, id)`.

**Trap worth naming (historical):** the repo root once contained **34 stale `.o`
files**, gitignored by the `*.o` rule at `.gitignore:7`, including
`message_id.o` and `sasl_framework.o`. Their presence at the top of the tree is
almost certainly what led an earlier revision of this document to call
message-id "observable". They have since been cleaned up — there are no `.o`
files at the repo root now.

| Feature | Spec | Status | Evidence |
|---|---|---|---|
| IRCv3 message-id | IRCv3 message-tags | **Dead** | no build site, no test, no symbol in the binary |
| Per-SERVER `(epoch, id)` | design §2.4 | **Implemented elsewhere, unused** | `server_t::msg_id`/`epoch` `server.h:156-157`, `server_next_msg_id` `server.c:396`; no relay caller |

#### `src/federation_handshake.c` — real, and the one to keep

A genuine finite state machine over a caller-owned context: no module-global
mutable state, every transition NULL-safe, and a rejected transition returns `-1`
without modifying the context (`federation_handshake.c:21-24`). All five
transition functions plus `heartbeat_check` are exercised by
`tests/federation/test_federate_handshake.c` (`FederateHandshake`, passes) and
`tests/federation/test_heartbeat.c` (`Heartbeat`, passes).

**`handshake_receive` reaches `ESTABLISHED` unconditionally**
(`federation_handshake.c:33-38`): from `HANDSHAKE_SENT` it sets `ESTABLISHED` and
returns 0, with no peer identity check, no secret, no `FEDERATE` exchange.
Design §2.3 requires rejection *before* `ESTABLISHED` and server-name uniqueness
at the same point; design §8 makes "two nodes cannot both be named `irc.a`" a
definition-of-done item. **Neither is implemented here.** The FSM is the right
skeleton to drive peer links in Phase 6; its acceptance step is a stub.

| Feature | Spec | Status | Evidence |
|---|---|---|---|
| Handshake FSM (INIT→HANDSHAKE_SENT→ESTABLISHED/FAILED/TIMED_OUT) | design §2.3 | **Implemented** | `federation_handshake.c:11-57`; `FederateHandshake` passes |
| Peer authentication at handshake | design §2.3, §8 | **Not implemented** | `handshake_receive` `:36` — unconditional |
| Server-name uniqueness at handshake | design §8 | **Not implemented** | no comparison exists |
| `heartbeat_check` | design §4.3 | **Implemented** as a state predicate | `:59-62`; it reports whether the FSM is `ESTABLISHED`. It is not an interval timer and does not fail a link |

#### `tests/contracts/lockfree_contract.c` — passes, and proves nothing

The whole test is a `volatile int` (`lockfree_contract.c:11`) written by one
thread and read by another. There is **no `_Atomic`, no `<stdatomic.h>`, no CAS,
no compare-and-swap, no `memory_order_*`, no mutex, and no barrier** anywhere in
the file. The reader's assertion
(`:30`) is `state == 0 || state == 42`, which holds for any value the writer can
produce, so it cannot fail. The only real assertion is the final `== 42` after
`pthread_join` (`:45`) — which is a single-threaded fact observed through two
threads.

Design §5 says the action is to **delete** this file and remove the lock-free
claim from the docs. It has been neither deleted nor made real.
`docs/ARCHITECTURE.md:4` still advertises "lock-free structures where possible"
as a design goal, and design §3.4/§2 explicitly justify the single-threaded
loop *because* no lock-free structure is needed. The claim and the design
contradict each other; see §5.

---

## 2. The seven skipped tests

**Phase 7 corrected this section; it previously said eight.** All seven are
CTest skips: the test binary prints a `SKIP:` line and returns `77`, and the
CMakeLists registers `SKIP_RETURN_CODE 77` so CTest reports `***Skipped`. This is
the honest choice — a fabricated passing assertion would be worse — and it has a
consequence that must be stated plainly.

`TopicPersistence` is **no longer here.** Phase 7 implemented the feature it was
named for: a channel's topic survives the channel being disposed, through a
bounded cache on `server_t` (`server_topic_remember` / `server_topic_restore` in
`src/core/channel.c`). The test is now `tests/integration/test_topic_persist.c`
and asserts it on the wire, on both sides of a dispose and both sides of a
dropped connection, including that 333 still names the original setter and the
original time. The row's "Phase 4 / 9 (no `chan_t` exists yet)" was wrong on both
counts by then: a `chan_t` had existed since Phase 4, and the feature needed
neither Phase 4 nor Phase 9.

| CTest name | File | Feature it is waiting on | Lands in | Issue |
|---|---|---|---|---|
| _(none)_ | — | **the skip list is EMPTY** | — | — |

**As of Phase 9 (issue #83) there are no skipped tests.** All five Phase 9 skips
were retired by implementing the feature, and each skip line was deleted from
`tests/known_skips.txt` in the same commit — `SyncState` and `FailoverReconnect`
by the link policy (backoff, retry budget, heartbeat-driven redial, resync on
link-up); `Reconnect` by the bounded session window; `PeerDiscovery` by
`ADVERTISE`/`SHUTDOWN`; `AutoScale` by propagation and graceful leave, scoped to
what a node can honestly do. `MultiPrefix` and `CapNegotiation` landed in Phase 8.

Two honest notes about the gate now that the list is empty. `check-skips.sh` fails
in **both** directions — a skip the list does not permit, and a list line naming no
skip — and with no lines the first arm is total while the other three pass
*vacuously*. That is not the same four-way check it was, and it should be read as
such rather than as a stronger gate. And a green suite is now **necessary, not
sufficient**: with nothing skipped there is no list saying which behaviour is
still unimplemented, so this document and `docs/SERVER_DESIGN.md` §8 are the only
places left that can record it, and they have to be read.

**This table and `tests/known_skips.txt` must agree, and CI checks that they
do.** The list is the single authoritative copy — one line per skip, naming the
test, the phase that owns it and the issue that closes it — and
`scripts/check-skips.sh` fails if the two disagree in **either** direction. The
`#` column above (4, 11, 13, 17…) is gone for that reason: CTest's test NUMBERS
shift whenever a test is added, so a table keyed on them is a table that rots,
and this one is now keyed on the test NAME, which is what the gate compares.

### CI did not count skips. It does now.

**Everything in this subsection up to the last paragraph was true on 2026-09-28 and
is retracted here.** The finding was correct: `ctest` excludes a skipped test from
the percentage and from the pass/fail exit code, so

```
100% tests passed out of 39
```

…while 8 of those 39 were skipped. **"100% tests passed" coexisted with 8
unimplemented features**, and a green CI run proved nothing about any of them.

Design §6.4 specified the fix as a `KNOWN_SKIPS` list in `tests/CMakeLists.txt`
that CI fails against, and the finding below this paragraph was also correct:
**`KNOWN_SKIPS` did not exist**, `grep -rn 'KNOWN_SKIPS'` matched only
`docs/SERVER_DESIGN.md:532-533`, and the gate was entirely unbuilt.

**Phase 7 built it, and built it differently from the design's wording.** The
finding named the defect accurately and the remedy wrongly, in one respect: §6.4
also said the list "must reach empty by Phase 7", and that is not reachable —
§7/Phase 8 owns CAP and multi-prefix, §2.3 says "Peer discovery and auto-scale stay
Phase 9" in as many words, and §7/Phase 9 owns reconnect and failover. So the
gate is a **ratchet**, not a zero:

- `tests/known_skips.txt` is the single authoritative list, one line per skip with
  the phase and the issue.
- `scripts/check-skips.sh` fails if a test **skips without** a line (the original
  blind spot) **and** if a listed test **no longer skips** (which is what stops
  the list rotting into a permanent allowlist), **and** if a listed name is not a
  registered CTest test, **and** if it cannot read the skip set from the output at
  all — "we could not tell" is not "there are none".
- It runs in `ci_test`, in `local-ci.sh` and in `make test`, reading the log the
  suite run just wrote so the suite is not run twice.

| Entry point | Counts skips? | Where |
|---|---|---|
| `.github/workflows/ci.yml` `ci_test` | **Yes** | the `Skip gate (ratchet)` step, after `Unit Tests` |
| `local-ci.sh` | **Yes** | `./scripts/check-skips.sh -b build "${CTEST_LOG}"` |
| `Makefile` `test` | **Yes** | `./scripts/check-skips.sh -b $(BUILD_DIR) …` |
| `.github/workflows/ci.yml` `ci_compliance` | No, deliberately | it runs `-L Compliance` only, so a skip outside that label is not its business; `ci_test` covers the whole suite |

Design §6.4 and §7/Phase 7 have been corrected in place to say the same thing, and
`docs/DEVELOPMENT.md` has a section on how to add and how to close a skip.

---

## 3. Test suite as it actually stands

`ctest --timeout 60`, Release, macOS/darwin, 2026-09-28:

```
39 tests: 31 passed, 8 skipped, 0 failed
Total Test time (real) = 16.57 sec
```

| Label | Tests | Passed | Skipped |
|---|---|---|---|
| `Protocol` | 8 | 6 | 2 |
| `Federation` | 4 | 2 | 2 |
| `Compliance` | 4 | 3 | 1 |
| `LoadBal` | 3 | 0 | 3 |
| `Integration` | 17 | 17 | 0 |
| `Benchmark` | 2 | 2 | 0 |
| *(unlabeled)* `LockfreeContract` | 1 | 1 | 0 |

The 17 integration tests are the substantive part: they exec the **shipped
binary** over real TCP and assert on wire bytes. That is what design §6.1
mandates and it is genuinely in place. Ten of the seventeen are Phase 2 loop and
framing properties; seven are Phase 3 (`test_registration`, `test_nick_rule`,
`test_dup_nick`, `test_pre_register`, `test_ping_pong`, `test_quit`,
`test_reply_guard`) — all seven pass when run directly.

Test-harness quality is good. The API matches design §6.1 (`tc_connect`,
`tc_send`, `tc_expect`, `tc_close` all present in `tests/harness/irc_client.h`,
plus `tc_send_raw`, `tc_expect_eof`, `tc_half_close`, `tc_read_exact`), servers
bind port 0 and report the real port, and there is **no `sleep()` anywhere in
`tests/harness/*.c`** — design §6.3's no-fixed-sleep rule holds.

Two caveats on §8's "no test asserts internal plumbing":

- `test_close_sites.c` is a **source-inspection** test. It reads the sources to
  check the close-site rule by construction, and says so in its own header. That
  is the right call and it is labelled — but it is not a behavioural test.
- `test_reply_guard.c` is **both**: a source check *and* a runtime one (it
  installs a `CONN_SERVER` conn and asserts the refusals). Its header says the
  end-to-end version waits for Phase 6.

---

## 4. Benchmarks

| Feature | Spec | Status | Evidence |
|---|---|---|---|
| Throughput benchmark | design goals | **Runs, and measures the production path** | `tests/benchmark/throughput.c` benchmarks `message_parse_n()` — the tokenizer the node actually calls on the wire (`poll_loop.c:94`) — over a federated workload with peer prefixes, tag blocks, escaped tag values, the 15-param cap and a line at the 8192-byte cap. The legacy `parse_command()` counter is retained as an explicitly labelled baseline, not as server throughput. Real output (clang 23, arm64, Release): production `batched_mean=0.143us`, legacy baseline `batched_mean=0.028us`, 5.2x. p50/p99 are quantised to the 1000ns CLOCK_MONOTONIC granularity, which the run now reports. |
| Memory footprint | `docs/ARCHITECTURE.md` "<10MB per federated node" | **No threshold is enforced** | `tests/benchmark/footprint.c:36-44` reads an **opt-in** `FOOTPRINT_RSS_MB_THRESHOLD` env var. Nothing in the repo sets it — `grep -rn FOOTPRINT_RSS_MB_THRESHOLD` matches only `footprint.c` itself. CI therefore cannot fail on it. Running it gives `rss_peak: ... rss=1.58 MiB`, but that is a process whose entire body is one `getrusage()` call: **it does not measure a running node with connections, so it does not support a per-node footprint claim.** |

The previous revision of this document said `footprint.c` "asserts
`mean_rss_mb < 10.0`". There is no such assertion. There is no mean, and there
is no default threshold.

---

## 5. Where the code and the design document disagree

Reported, not silently resolved. `docs/SERVER_DESIGN.md` is the plan;
where the two conflict the code is what runs.

1. **Which phase owns the skip gate — RESOLVED in Phase 7, and not the way the
   design said.** Design **§6.4** said `KNOWN_SKIPS` "must reach empty by
   **Phase 6**" (the copy this audit was run against said Phase 7 in §6.4 and
   Phase 7 in §7, which is itself the contradiction). GitHub issue **#81** is
   Phase 7 and is titled "Remaining command surface and empty skip gate", so §6.4
   was the outlier and Phase 7 is where the gate belonged. **Phase 7 built it
   there — and then retracted the "reach empty" half, because it is not
   reachable**: §7/Phase 8 owns CAP and multi-prefix, and §2.3 says "Peer
   discovery and auto-scale stay Phase 9" verbatim. The gate is a **ratchet**:
   `tests/known_skips.txt` plus `scripts/check-skips.sh`, failing in both
   directions. Both design sections now say so, and this entry is closed rather
   than removed — the contradiction was real and the correction is the useful
   part of it.

2. **The lock-free claim is still published.** Design §5 orders
   `lockfree_contract.c` **deleted** and the claim removed from the docs.
   `docs/ARCHITECTURE.md:4` still says "lock-free structures where possible",
   the file is still present, and it still passes. Design §2 and §3.4 both argue
   the single-threaded loop makes lock-free structures unnecessary, so §5's delete
   is the consistent position and `ARCHITECTURE.md:4` is the leftover.

3. **The design doc's stated verification commit is stale.** `SERVER_DESIGN.md:6`
   says "Verified against source at commit `2910979`". `2910979` is *"docs:
   correct spec tracking and architecture status; packaging updates"* — it is
   three commits behind `HEAD` (`e958ea9`, Phase 2), and the Phase 3 work in the
   working tree is not in any commit at all.

4. **The design doc does not list `432` among the error numerics**, while
   `commands.c:296` emits it. `commands.c:261-266` flags this itself and argues
   the RFC numeric is right and §4.4's list is incomplete. Phase 4+ should
   decide, and §4.4 should probably be amended.

5. **The design doc's §3.4 file layout names files that do not exist.**
   `SERVER_DESIGN.md:400-401` lists `src/core/fanout.c` and `src/federation/link.c`.
   Neither is present. The actual Phase 6 seam is the already-present
   `server_dial` / `server_dial_progress` pair in `server.c`, and the tick hook
   `server_t::on_tick`.

6. **Design §5 says `server.c` "parses literal `\"PING\"`" and that `node_main.c`
   "closes every client immediately (line 115)".** Both were true of the code
   `SERVER_DESIGN.md` replaced (commit `738f254`); neither is true now. Not
   errors, but a reader checking §5 against today's tree will be confused.

7. **Design §2.3 says peer auth "is rejected before `ESTABLISHED`"**, and §8
   makes it a definition-of-done item. `federation_handshake.c:36` reaches
   `ESTABLISHED` unconditionally. The design's requirement is simply unmet; this
   is a gap, not a contradiction, but it is unmet **in the module the design
   names as the thing to reuse.**

---

## 6. Phase progress

Source: `gh issue list --milestone "Federated IRC Server v1.0" --state all`
(2026-09-28). Milestone #5, 2 closed / 7 open.

| Phase | Issue | Title | Issue state | Code state (2026-09-28) |
|---|---|---|---|---|
| 1 | #75 | Phase 1: Message tokenizer, tag format, nick charset rule | **CLOSED** | Done. Committed in `8d8c416`. One clause unverified: the no-leak criterion (§1.1), because no sanitizer is in the build. |
| 2 | #76 | Phase 2: Server core - poll loop, connection, framing, registries | **CLOSED** | Done. Committed in `e958ea9` (= `HEAD`). All six §3.4 requirements implemented (§1.2). |
| 3 | #77 | Phase 3: Registration and single-node correctness | **OPEN** | Implemented in the working tree and passing (§1.3), but **uncommitted and not in `main`**. Both acceptance criteria are met and testable: `test_registration` (registers, receives `001` and `005`) and `test_dup_nick` (duplicate nick → `433`). |
| 4 | #78 | Phase 4: Channels with final struct shapes and single-writer rule | OPEN | Not started. `chan_t` does not exist; the channel registry holds keys with NULL values. |
| 5 | #79 | Phase 5: Messaging (working-server milestone) | OPEN | Not started. |
| 6 | #80 | Phase 6: Federation link - peer sockets, SBURST resync, loop prevention | OPEN | Not started. Dial FSM and handshake FSM exist and are tested; nothing calls `server_dial`, no peer link, no `SBURST`, no dedup, no relay. |
| 7 | #81 | Phase 7: Remaining command surface and empty skip gate | OPEN | Not started. `KNOWN_SKIPS` does not exist. |
| 8 | #82 | Phase 8: IRCv3 - real tag escaping, CAP negotiation, SASL PLAIN | OPEN | Not started. Turns `CapNegotiation` green and replaces `ircv3_tags.c` and `sasl_framework.c`. |
| 9 | #83 | Phase 9: Federation hardening, peer discovery, auto-scaling | DONE | Turns `SyncState`, `FailoverReconnect`, `PeerDiscovery`, `Reconnect`, `AutoScale` green. All five retired; `tests/known_skips.txt` is EMPTY and the gate is "no test may skip". Auto-scale is scoped to propagation + graceful leave, NOT node lifecycle (§2.3). |

**The table above is the 2026-09-28 `gh issue list` snapshot and is left as
written.** Phase 10.1 (issue **#117**) is not in it because that list predates it;
**§10** is where the account subsystem is measured, including which of the seven
IRCv3 specifications it unblocked and which it did not.

Phases 1 and 2 are done and committed. **Phase 3 is not done in any sense a
reader can rely on** — the work exists and passes, but it lives in uncommitted
changes on `phase/3-registration` and issue #77 is still open. Design Phase 5 is
the "working server" milestone; the milestone description on #5 says the same.

Two unmilestoned issues are worth knowing about, because both bear directly on
this document's subject:

- **#86** "Cleanup: dead code and misplaced build targets found during the build
  audit" (OPEN) — presumably the dead/orphan material in §1.4.
- **#85** "Build: `-Weverything` never runs on macOS (STREQUAL Clang excludes
  AppleClang)" (OPEN) — the `CMakeLists.txt:55` guard means the strict Clang
  warning set has not been applied to any build run on this machine. The clean
  Release build recorded above is a `-Wall -Wextra -Werror -Wpedantic` build.

---

## 7. Known gaps and known-bad

Blunt, because the value of this document is that it can be trusted.

### Known-bad — present, wired in, and wrong

1. **`parse_nick` has no charset validation.** It returns `1` and yields
   `a@evil` for `NICK a@evil`, and accepts a leading digit, `#`, `;` and `:` in a
   nickname. It is not on the live path — `valid_nick()` is — but it is still
   compiled into `irc_core`, still tested, and still looks like the NICK parser
   to anyone reading the tree. `src/protocol_parse.c:68-103`.

2. **`ircv3_tags.c`'s roundtrip test is vacuous.** `tags_parse` and
   `tags_serialize` are the same function (`ircv3_tags.c:62,66` → `:49`), so
   `serialize(parse(x)) == x` is `f(f(x)) == x` for a deterministic `f` and
   cannot fail. `TagsRoundtrip` passes and proves nothing. `src/ircv3_tags.c`,
   `tests/compliance/test_tags_roundtrip.c`.

3. **`message_id.c` was dead; #86 deleted it.** No `CMakeLists.txt` in the repo
   referenced it, it was never compiled, never tested, and had no symbol in the
   binary. The 34 sibling stale `.o` files that once sat at the repo root are
   the likely origin of the previous revision's claim; they are gone now.

4. **The lock-free contract is fake.** `tests/contracts/lockfree_contract.c:11`
   is a `volatile int` with no atomics, no CAS, no memory ordering, no mutex and
   no barrier; its reader-side assertion cannot fail. It passes. The design goal
   it claims to verify is unimplemented and design §5 says to delete it.
   `docs/ARCHITECTURE.md:4` still advertises the goal.

5. **`004` advertises modes nothing evaluates.** `i` and `b,k,l,imnpst`
   (`commands.c:77-78`) go out in the same session where `PRIVMSG` and `JOIN`
   answer `421`. There is no mode parser, no mode state, and no evaluator. A
   client that sets `+k` and is told nothing is in silent divergence.

6. **`PASS` records but does not authenticate.** `handle_pass`
   (`commands.c:242`) increments a counter. No credential store exists; SASL is
   Phase 8. A wrong password is accepted exactly like a right one. The node says
   so honestly at `commands.c:230-241` and prints `authenticated=0`.

7. **`federation_handshake.c` reaches `ESTABLISHED` unconditionally.** No peer
   identity, no shared secret, no server-name uniqueness check
   (`federation_handshake.c:36`). Design §2.3 and §8 both require the opposite.

8. **The SASL test exercises a self-test harness that lives in `src/`.**
   `tests/compliance/test_sasl_handshake.c` is 11 lines with one assertion, all
   of it against `sasl_state_machine()` (`sasl_framework.c:87`) in the source
   tree, and `sasl_step` auto-completes on call count (`:50`) while discarding
   its input (`:44-45`).

9. **The throughput benchmark now measures `message_parse_n`**, the tokenizer
   the node runs, and keeps `parse_command` as a labelled baseline (#91). Its
   p50/p99 remain quantised to the platform's 1000ns CLOCK_MONOTONIC granularity,
   so the batched per-call figure is the one it reports as quotable.

10. **The footprint benchmark enforces nothing** and measures an empty process,
    not a node. No default threshold, no CI env var, so it cannot fail
    (`footprint.c:36-44`).

11. **The `raw` region and the reuse-without-free leak are untested.** The
    one-allocation contract is asserted in a header comment and exercised
    indirectly; there is no sanitizer in the build, so the leak clause design §7
    calls for cannot be verified locally, and `message_parse`/`message_build`
    zero `*out` without freeing what was there (`message.h:40-46`) — a loop that
    reuses one `message_t` leaks, and no test covers that shape.

12. **Nine dead file-local macros, hidden by a suppression whose reason does not
    cover them** (found while enabling `-Weverything` on Apple clang, #85). The
    flag set carries `-Wno-unused-macros` for the harness macros in
    `test_util.h`, which are genuinely used across translation units — but it also
    hides `T_READY_MS` in nine integration tests
    (`test_conn_lifecycle.c:40`, `test_registration.c`, `test_ping_pong.c`,
    `test_quit.c`, `test_pre_register.c`, `test_queries.c`, `test_reaper_close.c`,
    `test_dup_nick.c`, `test_nick_rule.c`, `test_channels.c`), each defined and
    never used. Both compilers report them, so this is pre-existing and not
    something Apple clang found. Left in place deliberately: it is unrelated dead
    code, not a diagnostic the #85 change surfaces, and the honest options are to
    delete nine macros across nine test files or to narrow the suppression, which
    would then need per-file reasoning. Worth a separate cleanup.

### Known-absent — not started, and correctly reported as such

- **No channels.** `chan_t` does not exist. `struct chan` is forward-declared
  (`connection.h:53`) and `conn_t::chans` is never grown
  (`connection.h:104-106`). The channel registry holds names with NULL values
  (`server.h:294-296`). No `331`/`332`/`333`/`353`/`366`/`324`/`329`.
- **No messaging.** `PRIVMSG` and `NOTICE` are NULL handlers (`commands.c:471-472`).
  No fan-out, no §3.1 routing table, and no `src/core/fanout.c` at all.
- **No federation.** No peer socket in the shipped binary, no `FEDERATE`, no
  `SBURST`, no `SJOIN`/`SPART`/`SPRIVMSG`/`STOPIC`, no dedup table, no hop
  counter, no never-forward-own-origin check. The `irc-serve-*` tag format is
  frozen and unit-tested but nothing stamps it on a message.
- **No design §4.2 SHOULD commands** and no design §4.3 server-to-server verbs.
- **No IRCv3 CAP negotiation**, no real SASL, no IRCv3 message-id.
- **No skip gate.** `KNOWN_SKIPS` does not exist, so CI cannot fail on a skip.
- **No two-node fixture** (design §6.2), so nothing in this repo has ever
  observed two nodes talking.
- **No sanitizers** anywhere in the build or CI, so design §8's
  "ASan/UBSan/LeakSanitizer clean" is unverified.
- **The tick hook and the dial FSM have no callers.** `on_tick` is never
  assigned; `server_dial` is never called. Both are landed plumbing for Phase 6.
- **The observability dump** design §8 requires (peers + FSM states, channels
  with origin and local/remote sets, dedup table size) does not exist. The
  `[observable]` line format covers loop and command events, not topology.

---

## 8. Spec references

These three are checked by CI (`.github/workflows/ci.yml:55-62`, job
`ci_compliance`, step "Verify Spec References"), which greps
`docs/SPEC_TRACKING.md` for each and fails if any is absent. All three are
present:

- **RFC 1459** — https://datatracker.ietf.org/doc/html/rfc1459
  Base protocol: §2.3 message format and 512-byte floor, §2.4 commands
  (`NICK`/`USER`/`PASS`/`PING`/`PONG`/`QUIT`), §3.1/§3.3 the grammar this
  project's `message_parse_n` implements. Superseded in practice by RFC 2812
  (nickname syntax, numerics) and RFC 7194, both of which this project also
  depends on.
- **Modern IRC** — https://modern.ircdocs.horse/
  Practical supersession of the RFCs for client behaviour; the `005` ISUPPORT
  tokens this node emits (`NETWORK=`, `CHANTYPES`, `PREFIX`, `NICKLEN`,
  `CASEMAPPING`) are specified here.
- **IRCv3** — https://ircv3.net/
  Message tags and the tag-escaping rules (implemented in `core/message.c`),
  **CAP negotiation, SASL PLAIN and `draft/message-ids`** (implemented in Phase 8 —
  this bullet said the three were *not* implemented and had been false since then;
  corrected here because Phase 10.1 made `account-tag` a decision rather than an
  absence, and this is the reference that bullet governs), and the account family
  (§10). **There is no official IRCv3 conformance suite** —
  `ircv3/ircv3-test-suite` and `ircv3/chathistory-test-suite` do not exist, so
  every compliance claim in §10 is hand-written tests against spec text, which is
  a weaker guarantee than a green third-party runner.

Additional reference named by RFC 2812, which the design and code rely on for
nickname syntax and `432`/`433`, and which is not CI-checked:
https://datatracker.ietf.org/doc/html/rfc2812

---

## 9. What this document does not claim

- **It does not claim CI is green.** No CI run was observed on 2026-09-28. The
  only execution evidence is a local Release build and `ctest` run on
  macOS/darwin.
- **It does not claim the 8 skips are covered by anything.** They are skips.
- **It does not claim Phase 3 is landed.** It is uncommitted working-tree work.
- **It does not describe anything as "observable"** without saying observable
  how — a named test, a named file:line, or a quoted wire byte or command
  output. Where the only available observation is a `printf` and nothing asserts
  on it, that is called out.
- **It does not restate the design.** `docs/SERVER_DESIGN.md` is the plan;
  this file is the measurement of the code against it. Where they conflict, §5.

---

## 10. Phase 10.1 — the account subsystem

Issue #117. `docs/SERVER_DESIGN.md` §2.1.1, §2.5, §2.5.1–§2.5.4 and §7's Phase 10
block carry the reasoning; this section is the measurement, and it has one job:
**which of the seven gated specifications are now unblocked and which are not.**

### 10.1 The gate, as it was

`src/` had **zero** hits for `account_tag`, `logged_in`, `serviced_login` or
`account_name`. That single absence blocked seven specifications at once, because
`account-tag` needs to know who is logged in on *every* message and `extended-join`
needs the account on *every* `JOIN`. None of them is a capability that can be
bolted on, which is why P10.1 is a subsystem and the rest follows from it.

### 10.2 The seven, one by one

**"Unblocked" here means: the missing account concept exists, so the
specification no longer needs a new subsystem. It does NOT mean the specification
is implemented** — every one of these still has its own implementation phase, and
saying otherwise is exactly the failure this document is written to prevent.

| Spec | Unblocked by P10.1? | What is still missing, and where it lands |
|---|---|---|
| `account-registration` | **Yes, and REFUSED rather than implemented.** The identity it would describe exists and `330` reports it. | `REGISTER`/`UNREGISTER` answer `482`; the draft's own header says not to implement it in production and says to use `draft/account-registration`, and its wire form is `FAIL ACCOUNT_REGISTER`, which needs **standard-replies** (Phase 10 item 8). Design §2.5.2 gives four independent reasons. |
| `account-tag` | **Yes — the identity it carries now exists.** | **Nothing.** **IMPLEMENTED in Phase 10.2a.** The tag is stamped once per emission in `fanout.c`, per destination on the recipient's own `account-tag` (plus `message-tags`), withheld from an unidentified sender, withheld from a node with no registry, and **not** forwarded across a link. Design §2.5.3. |
| `account-notify` | **Yes.** | **PARTLY IMPLEMENTED in Phase 10.2b, and the part left is named.** The `ACCOUNT <account> PASS` / `ACCOUNT *` line, gated on the recipient's own negotiation, with the capability available **unconditionally** because "you have no account" is an answer this node can give truthfully. **Not implemented:** the *channel-scoped* half of the specification and `ACCOUNT <account> FAIL`. On this node the association is established by SASL before registration, so when it becomes true the connection has no nickname, no hostmask and no channel — there is never a shared member to notify, and there is no logout to notify about. Design §2.5.6. |
| `extended-join` | **Yes.** | **IMPLEMENTED in Phase 10.3, with one named limit.** The `JOIN` echo carries the account **and** the realname, per destination on the recipient's own negotiation, with `*` for a member who is not logged in — and the capability is advertised even with no registry, because `*` is a complete answer there. `SJOIN` and `SBURSTM` carry the account (design §4.3.1). **Not implemented:** this node emits no extended JOIN for a member it learned from a PEER, because 4.3's SJOIN carries only a server prefix and a JOIN with a server prefix is a line no client can parse — so a remote member's account is stored on the roster and not yet shown. Design §2.5.7. |
| `away-notify` | **Yes — and it needed nothing from this phase at all.** | The unsolicited `AWAY` on state change. It was never account-gated; it was simply not started. Listed here because issue #117 groups it with the account family, and the honest answer is that this phase unblocked **nothing** for it. Phase 10.3. |
| `chghost` | **Partly, and the part is worth naming.** It needs the **account on the `CHGHOST` echo**, which now exists. | The verb itself, and the `userhost-in-names` interaction. Phase 10.3. |
| `oper-tag` | **Yes.** | The `+` tag on `PRIVMSG`/`NOTICE` — which needs **operator flags**, and **this node has no operator concept at all** (`CHOPER` answers `464` for every request). So `oper-tag` is now unblocked *as far as the account is concerned* and blocked *on a subsystem that does not exist*. Phase 10.8. |
| `account-extban` | **Yes.** | `~&account:name` match types, which need the account **and** a ban-expression evaluator — and this node evaluates **no** channel modes beyond the ones §4.4 advertises. Phase 10.8. |

**Summary as of Phase 10.1: all seven are unblocked as far as the ACCOUNT is
concerned; zero are implemented.** One (`away-notify`) was never account-gated at
all. One (`oper-tag`) is blocked on operator flags rather than on accounts. One
(`account-registration`) is delivered as a **refusal**, which is a decision rather
than an implementation and is recorded as such.

**Updated as of Phase 10.3: `account-tag` and `extended-join` are IMPLEMENTED and
`account-notify` is IMPLEMENTED IN PART**, which makes the count **two of seven
implemented, one partly implemented and four not.** The table above is the per-spec record and each
row says which. "Partly implemented" is not a rounding of "implemented": for
`account-notify` the two missing halves (the channel-scoped fan-out and the `FAIL`
form) are unreachable on this node rather than merely unstarted, and design §2.5.6
says why. Nothing else moved: `away-notify` and `chghost` were never account-gated, and
`oper-tag` and `account-extban` are blocked on subsystems this node does not have
(`CHOPER` answers 464 for everything, and this node evaluates no channel modes
beyond the ones §4.4 advertises).

### 10.3 What P10.1 actually delivered, with evidence

| Claim | Where | Evidence |
|---|---|---|
| An account name on `conn_t`, set only from a verified credential | `src/core/connection.h` (`CONN_MAX_ACCOUNT`), `src/core/account.c` (`account_set()`) | `test_account.c`'s in-process case, on return values |
| **An account grants nothing** | `connection.h`'s "what none of them grant" block, design §2.1.1 | — (a negative claim, stated where a future editor reads it) |
| A registry, as a **separate operator file** with the credential store's discipline | `src/account_store.{h,c}`, `--account-store` in `node_main.c` | `test_account.c`: five refusal cases, each landing in the no-registry state |
| Passwords overwritten before release | `account_store_free()` — `volatile` write pass | **LeakSanitizer is Linux-only**; reasoned at design §2.5.4, verified on the CI job |
| `account == ""` indistinguishable from no account system | `account_logged_in()`, one writer, two stores | `test_account.c` runs **one** assertion set over a node with a registry and a node without |
| Two operator files disagreeing ⇒ not identified | `account_set()`'s registry check | `test_account.c`: `reason=NOT_IN_REGISTRY`, then the not-identified path byte-for-byte |
| `REGISTER`/`UNREGISTER` refused with `482`, never `421` | `core/commands.c` | `test_account.c`, with the 421 absence asserted |
| **`account-tag` advertised only where it is emitted** | `src/core/cap.h` (the argument is in the header), `cap.c`'s `account_possible()` | `test_account.c`: in `CAP LS` and ACKed with a registry; absent and NAKed without one; the whole list compared byte-for-byte on a default node |
| The one wire surface: `330 RPL_WHOISACCOUNT` | `src/core/msg_verbs.c` | `test_account.c`, from the client **and from a second client** |
| The teardown arm | `server_shutdown()`, `[observable] account_store_close: store=OPEN|NONE` | asserted on both states; the `free` itself asserted by source inspection (`tf_calls`), because a line with no free behind it satisfies the line |

### 10.5 The four non-account specifications of issue #117

Issue #117 groups eight specifications, and §10.2's seven are the account family.
These four are **independent of the account subsystem** — none of them reads
`conn_t::account`, and none was blocked by Phase 10.1 — so they were implemented
as their own passes rather than as a consequence of anything above. Each is
recorded here with what it cost, and the table is the measurement rather than the
design (design §4.4.1 carries the reasoning for the first).

| Spec | Status | What it cost, and what is named as missing |
|---|---|---|
| `extended-ispupport` | **IMPLEMENTED (Phase 10.4).** The `005` went from five hand-written tokens to eleven, every `*LEN` rendered from the constant that **enforces** it, and eight tokens that would have been claims about unimplemented features deliberately left out. **Twelve tokens now — Phase 10.9 closed the `KICKLEN` gap.** | **One finding closed, one still open.** `KICKLEN` was absent because `handle_kick()` took `<reason>` verbatim with no length test, so no number in the tree described the largest reason accepted and an over-long one reached `message_format()` and tripped `n_reply_refused` — the counter `reply.c` holds at zero. **Phase 10.9 added `CHAN_MAX_KICK_REASON` (255), the `417` and the token**, so the absence is struck rather than deleted (design §4.4.4). `USERLEN` is still absent even though `CONN_USER_MAX` exists, because `USER`'s ident is *truncated* rather than refused, so the token would promise a limit the node does not apply — that is now the worked example of an omission that must stay. `PREFIX=(ov)@+` remains a written-out token: no constant names the mode letters, and making one would mean changing the mode evaluator. The cost of the work itself is one new constant (`MSG_MAX_TARGETS`), two sigil macros, `CHAN_MAX_KICK_REASON`, and a test that holds the whole `005` against **literals** rather than the constants. |
| `userhost-in-names` | **IMPLEMENTED (Phase 10.5).** `353` renders `nick!user@host` per destination, on the recipient's own negotiation, for local *and* remote members. | **The privacy decision, stated plainly: this discloses every member's ident and observed host to every other member of the channel.** It is why the capability is opt-in and why the roster shape is decided per destination. The cost is `chan_remote_t::user` — the ident was on the wire in `SBURSTN` and in the burst shadow all along and was being **discarded**, so a federated roster could not have rendered a hostmask without it; +64 bytes per remote-member element, 4 KiB per channel's addressed array. See design §4.4.5. |
| `setname` | **IMPLEMENTED in part (Phase 10.6).** The command, the capability, `NAMELEN`, and the confirmation to the originating client. | The validation is a predicate **shared with `USER`** (`conn_realname_check()`), which is what makes "not a looser path than registration" a property of the code; `SETNAME` refuses over-long and control-bearing values while `USER` truncates length and empties a hostile one, because refusing `USER` would strand a half-registered client — §4.2.1 argues it. **The common-channel fan-out is NOT implemented, and that is the specification's MUST.** `core/fanout.c`'s per-destination decision is a choice between two wire **shapes** (the `fanout_form_t` the extended JOIN introduced); "send this member nothing" is a **third** outcome, and expressing it means a contract change to the routing module — which is the reason the alternative, a second member walk inside a handler, is worse. Named rather than faked. The refusals are also not `FAIL SETNAME INVALID_REALNAME` as the spec asks, because `standard-replies` is a separate pass and inventing a `FAIL` numeric was out of bounds; the node answers `417`, which is the numeric this tree already uses for an over-long parameter. |
| `echo-message` | **IMPLEMENTED (Phase 10.7).** A sender who negotiated it gets its own `NOTICE` back, with its own hostmask as the source. | **Almost nothing, and the reason is the interesting part: `PRIVMSG` was already echoed.** This node delivers a channel `PRIVMSG` to every local member *including* the sender, so the copy `echo-message` requires already exists on the wire — the spec's example is byte-identical to what the normal path produces. The only gap was `NOTICE`, which RFC 1459 2.4.2 says is never returned to its sender. So the implementation is **one argument**: `exclude` stays `c` unless the sender negotiated the capability. There is no second emission, and that is the whole defence against the double-delivery bug the capability invites. `batch` echoes are out of scope, as is the acknowledgement for a `nick@server` target (no local destination exists to send one to). |

### 10.6 What the four cost, with evidence

| Claim | Where | Evidence |
|---|---|---|
| Every advertised `005` value is derived from the constant that enforces it | `commands.c` `k_005[]`, rendered by `IRC_STR()` | `test_registration.c`: the whole `005` byte-for-byte against **literals**, each token individually, and the twelve names that must be absent. A literal is the point — a test built from `CHAN_MAX_TOPIC` would follow the constant and never notice `005` was left behind |
| `CHANTYPES=#&` and the validator cannot disagree | `channel.h`'s `CHAN_TYPES` / `CHAN_TYPE1` / `CHAN_TYPE2`, used by `chan_name_valid()` | `test_registration.c` asserts `CHANTYPES=#&`; `test_channels.c` and `test_dup_nick.c` already refuse a name the advertised token would not admit |
| `NAMELEN` is the realname bound, not a figure of speech | `CONN_MAX_REALNAME` in `connection.h`; `conn_realname_check()` | `test_setname.c`: 255 accepted, 256 refused with `417` and the field **unchanged** |
| A `353` roster's shape differs per destination for the same sender | `chan_verbs.c`'s `send_names_list()` / `names_emit()` | `test_userhost_in_names.c`: one channel, one member, three connections — negotiated, not negotiated, and a second negotiated one — with the long form required on two and the bare nick required on one |
| The federation roster can render a hostmask at all | `chan_remote_t::user`, fed from `SBURSTN` | `test_fed_roster.c` — the ident was previously discarded by `burst.c`'s shadow→roster join and is now stored, which is the only reason a remote entry is not stuck at `nick` |
| A sender who negotiated `echo-message` gets exactly **one** copy | `msg_verbs.c`'s `send_message()`, the `exclude` argument | `test_echo_message.c`: `PRIVMSG` to a channel counts 1 for a negotiating sender, 0 for a non-negotiating one; `NOTICE` counts 1 and 0 the same way |
| The echoed copy is not *also* delivered by the normal path | there is one delivery call; `echo-message` chooses `exclude`, it does not add a second | `test_echo_message.c`: the double-delivery fault (an extra `fanout_deliver_local()` aimed at the sender) is injected and watched failing with **2 copies where 1 is expected** |
| A client that did **not** negotiate is served exactly as before | `exclude` stays `c` unless the sender negotiated | the same test, cases 2 and 4: a non-negotiating sender's `PRIVMSG` gets **one** copy and its `NOTICE` gets **zero** |
| `setname` is refused pre-registration / without the capability / over-long / hostile | `handle_setname()`'s three gates and `conn_realname_check()` | `test_setname.c`: `451`; **silence** (asserted exhaustively — the drain `PONG` must be the only line); `417` at 256 with the previous value read back off the wire through a `JOIN`; `417` for ESC+BEL; 255 accepted; empty accepted |
| `userhost-in-names` is a per-destination decision, not a per-node one | `chan_verbs.c`'s `names_entry()` | `test_userhost_in_names.c`: three connections, one channel, one member; the long form required on two and the bare nick required on one |
| The federation roster can render a hostmask at all | `chan_remote_t::user`, fed from `SBURSTN` via `shadow_ident()` | `test_fed_roster.c` still passes with the field added; the ident was previously **discarded** by burst.c's shadow→roster join |
| Teeth, each watched red with the **build checked first** | the TEETH blocks at the foot of each test | **18 faults red across the four passes** (2 for `extended-ispupport`, 4 for `userhost-in-names`, 7 for `setname`, 5 for `echo-message`), plus **2 that did not compile** and so never reached a run. Four of them found a missing assertion or a no-op check; all four are recorded in place rather than quietly fixed — see 10.6a |

### 10.6a The teeth that found something

Eighteen faults were watched go red. **Four of them found a defect in the tests
rather than in the node**, and they share one class: *a check that is only
sometimes checked.* They are recorded here and in the test files rather than fixed
quietly, because a negative that passes once is the kind of thing that survives
indefinitely.

- **`setname` answered with `482` instead of staying silent.** The case asserted the
  absence of `417`, `421`, `451` and the `SETNAME` line — a list of the numerics
  somebody thought of, which is not a test of silence. Fixed by requiring the drain
  `PONG` to be the **only** line in the window (`lines_since()`), so any reply of any
  kind fails.
- **The `echo-message` source-prefix fault was a no-op**, because it only rewrote the
  prefix when `exclude != NULL` and that never holds in the passing cases. The test
  went green on a fault that changed nothing — the same trap reached from the other
  side, and caught the same way: the test being green is not evidence that the fault
  was harmless.
- **Two faults did not compile** and so never reached a run: an `if (0)` branch trips
  `-Wunreachable-code`, and the first `userhost-in-names` gate fault left `dst`
  unused in `chan_verbs.c` under `-Weverything` (moved to `cap.c`, where it
  compiles). A fault that does not build leaves the previous binary in place and
  reports a pass — which is why the build is checked before every run and the
  per-fault build result is recorded rather than assumed.
- **`userhost-in-names`'s per-destination gate fault did not compile** in
  `chan_verbs.c` (`dst` becomes an unused parameter under `-Weverything`), so it was
  moved to `cap.c`. Recorded because a fault that does not build leaves the previous
  binary in place and reports a pass, and the build check is what caught it.

### 10.7 The honest limits of these four

- ~~**`setname` does not fan out to common channels.**~~ **CLOSED IN PHASE 10.11.**
  It does now, per destination, on the RECIPIENT's own `setname` negotiation. The gate
  side was the open question, not the mechanism; §10.10 records the decision and §4.2.1
  carries the shape argument for why it needed a union walk rather than one
  `fanout_deliver_local_gated()` call per channel.
- **`echo-message` is not implemented for a `nick@server` target.** 3.1's last row
  is forward-only, so there is no local destination to acknowledge to. The
  acknowledgement would have to be a local-only emission invented here.
- **`userhost-in-names` does not change `352` or `311`.** Those numerics already
  carry `<user>` and `<host>` in the RFC's shape, so they were never the gap; the
  gap was `353` alone.
- ~~**`extended-ispupport` did not close the `KICKLEN` gap**~~ **CLOSED IN PHASE 10.9.**
  The cost §10.5 named was one bound, one `417` and one token, and that is what it took:
  `CHAN_MAX_KICK_REASON`, refused in `handle_kick()` immediately after the arity test. The
  interesting half was not the token but the reachable `n_reply_refused` — a client command
  could make the node file a bug report about itself, and `test_standard_replies.c` asserts the
  ABSENCE of that line so a regression fails on the defect rather than on a symptom.

### 10.9 `standard-replies`, the fanout contract, and the two that follow

Issue #117's remaining four are `standard-replies`, `chghost`, `away-notify` and
the routing **contract** the other three needed. None of them reads
`conn_t::account`, so §10.2's table was never the thing standing in front of them;
what stood in front of `chghost` and `away-notify` was a **contract**, and that is
what landed first.

**THE ORDER WAS CHOSEN, and the reason is retrofitting.** The contract came first
because three specifications would otherwise each have grown its own member walk.
`standard-replies` came before the other two because `chghost` and `away-notify`
want `FAIL` and `ERROR`-class numerics rather than legacy ones, and changing a
numeric afterwards means touching the same handlers twice.

| Spec | Status | What it cost, and what is named as missing |
|---|---|---|
| `standard-replies` | **IMPLEMENTED (Phase 10.9), as a PARTIAL migration and the partial is the point.** `FAIL <command> <code> [<context>...] :description` for a client that negotiated the capability; the **byte-identical legacy numeric** for one that did not. `WARN` and `NOTE` are implemented and have no producer. | **The line drawn: a legacy numeric migrates where it answers more than one question ON THIS NODE**, so the number alone cannot tell a client which refusal happened. Four qualify — `417` (four refusals), `461` (too few AND too many, its text saying "not enough" for both), `482` (three, two of which differ by three letters and mean unrelated things), `464` (two) — and every other numeric answers exactly one question and stays, which `test_standard_replies.c` asserts on `401` and `451` as well. **Cost:** those four numbers stop reaching a negotiating client, so a client pattern-matching `417` for "line too long" must read `FAIL <cmd> ERR_INPUTTOOLONG`; nothing that connected to an earlier build is affected, because the capability did not exist to negotiate. **The tension with the specification is recorded, not glossed** (design §4.4.3): it says servers SHOULD NOT replace standardised numerics, and all four are standardised — what makes it defensible is that these four are the ones this node's own use made unclear, which is the complaint the specification's introduction makes. `ERROR` is **not** implemented because the specification does not define it. | 
| `chghost` | **NOTHING TO NOTIFY — and after Phase 10.10 the reason is the tidy one, because the one thing that COULD change cannot.** The capability is **absent** from `CAP LS` and NAKed on request; a client-sent `CHGHOST` is `421`. **Phase 10.10 closed the ident hole this row was built on.** `handle_user()` wrote `conn_t::user` unconditionally and `USER` is `pre_reg`, so a registered client could re-send `USER` and move its own ident with nothing told to anyone; it now returns **`462 ERR_ALREADYREGISTRED` before the write**. The threat model is what picked that fix: nothing is **granted** to an ident here (no privilege, no account, and the ident is client-asserted and unverified at registration, so two users may already share one), so this is **not impersonation** — but `chan_banned()` runs on every `JOIN` and matches a mask against the composite `nick!user@host`, so a mask of the shape `mallory!*@*` was defeatable by moving the ident and re-joining. That is an access-control bypass reachable from one client command, and it is why "accept and notify" would have been wrong: a `CHGHOST` does not stop the rejoin. **The cost:** a client that re-sends `USER` after `001` gets one numeric it did not ask for and **loses nothing** — the connection, nickname, channels and realname all survive; only the ident move is gone, which was the defect. The gate is `commands_registered()` and not "has seen a `USER` before", so a client that sends `USER` twice *while registering* still works last-one-wins. `462` is **not migrated**: 4.4.3's rule moves only a numeric that answers more than one question on this node. **`test_chghost.c` case 3 is INVERTED, not deleted** — the same sequence now requires the ident unchanged, the `462`, a zero line count on the peer, and `reason=ALREADY_REGISTERED` in the log with `user=mallory` absent; cases 4 and 5 pin the two edges. Design §4.4.6. |
| `away-notify` | **IMPLEMENTED (Phase 10.8b), on BOTH edges of the change.** `:nick!user@host AWAY [:message]` — present means going away, absent means removing — to the users sharing a channel with the setter, per destination, through the Phase 10.8a gate. | **The cleared edge is the half implementations miss** and it is in the same test case as the set edge for that reason: without it every member believes the user is still away for ever, because the parameterless `AWAY` is the only thing that carries the fact. **Two exclusions, and they are different questions**: the gate asks "did this destination ask?", and the **setter is excluded** because the specification says a user "SHOULD NOT be sent AWAY messages to notify them of their own away status" — `305`/`306` are those numerics, and the setter negotiated the capability, so only `exclude` keeps it out. **Not forwarded**: the notification goes through `fanout_deliver_local_gated()`, the local-only entry point, because away *state* federates through 4.3's SBURST and a notification is not state. `test_away_notify.c` settles every connection before opening a window and then asserts the exact line on both edges, `301` present then absent, zero lines for a member who did not negotiate and for a member of another channel, exactly one line for a member of one of two channels, and nothing for a refused over-long `AWAY`. **Not implemented, and named:** the specification also says a user joining with an away message set is announced, and that half is not landed — `chan_admit()` has no notification, and it needs one emitted *after* the extended-JOIN echo (which is a fixed shape with no room for it). |
| the fanout contract (Phase 10.8a) | **IMPLEMENTED, as a contract rather than a feature.** §3.1.1: a per-destination **gate** beside the existing per-destination shape choice, so one emission has **three** outcomes per destination — the plain shape, the alternate shape, and **nothing**. | `fanout_form_t` chose between two wire **shapes**, and a choice between two answers cannot express "send this member nothing". All three of the remaining specifications publish to a SUBSET of a channel's members, so each would have grown its own member walk — the exact duplication `fanout.c` exists to prevent, and the reason `chan_verbs.c`'s Phase 4 broadcast helper lost its forward arm. The gate is asked **inside the walk that already asks the shape question**, in the order liveness → `exclude` → gate, and it is asked about local destinations only, so there is deliberately **no gated variant of the forwarding entry point**: a peer is not a client that negotiated anything, so the question is unaskable there rather than answerable-but-ignored. Nothing on the wire produces a gated emission until `away-notify` lands, so `test_fanout_gate.c` asserts the three outcomes **against the API** — the same argument `test_nick_index.c` makes — while still comparing the exact CRLF-terminated bytes queued for each descriptor, and asserting **zero bytes** for the refused member rather than the absence of a needle. |

### 10.10a Phase 10.10 — the second `USER`, and what the RFC actually says

The one deliverable here is a **closing**, and it is worth a section of its own because
the reason the previous pass declined to close it was **factually wrong**.

`docs/SERVER_DESIGN.md` §9 carried the row "REPORTED, NOT FIXED, and the reason is that
the fix is a decision about an RFC 1459 MUST command — refusing a second `USER` is a
behaviour change with nothing in the RFC requiring it". RFC 2812 **3.1.3** lists `USER`'s
numeric replies as exactly two, `ERR_NEEDMOREPARAMS` and `ERR_ALREADYREGISTRED`, and RFC
2812 **§9**'s entry for `462` names the case outright: *"user details from second USER
message"*. RFC 1459's `USER` section says nothing about a second one, which is evidently
what was read. So `462` is not a judgement call here; it is the RFC's own answer.

| Claim | Where | Evidence |
|---|---|---|
| A second `USER` is refused and the ident is not written | `commands.c`'s `handle_user()`, the `commands_registered(c)` branch | `test_chghost.c` case 3: the `311` read back off a **second** connection carries the registration ident, not the one the second `USER` asserted |
| The refusal is the RFC's numeric and it is said exactly once | `reply_refused(..., "USER", NULL, "462", NULL, 0, ...)` | `test_chghost.c` case 3: the literal `462` line, then `expect_only_replies(..., 1u)` — a COUNT, so a flood fails too |
| It is **not** migrated for a `standard-replies` client | the NULL `fail_code`, which selects `reply_refused()`'s legacy branch | `test_chghost.c` case 4, on a connection that DID negotiate: the byte-identical `462`, plus the absence of any `FAIL` |
| Nothing was told to the channel | the gate returns before the write, and there is no emitter | `test_chghost.c` case 3: `expect_only_replies(..., 0u)` on bob's idle socket — the same zero-line assertion the hole-proving version made, now for a different and better reason |
| The operator's log is not lying | the `[observable] user_refused:` line, and the return before `copy_field()` | `test_chghost.c` case 3: `reason=ALREADY_REGISTERED` present **and** `user=mallory` absent |
| The compatibility half still works | the gate is `commands_registered()`, not "has seen a USER before" | `test_chghost.c` case 5: `CAP REQ` NAKed so registration is held, two `USER`s, then `CAP END` → `001 preuser!second@…`, and **no** `462` anywhere in what that client received |
| Teeth, build checked before the run was believed | `commands.c`, the branch replaced by `if (0) { }` | **1 fault, red.** Build check **0 errors / 0 warnings** first, then `test_chghost` failed at `test_chghost.c:346`. `TF_CHECK_MSG` exits on the first failure, so the case's other three assertions were **not reached** — recorded as a property of the assertions, not as observed failures |

### 10.10 The honest limits of the fanout contract

- ~~**`setname`'s common-channel broadcast is still not implemented.**~~
  **CLOSED IN PHASE 10.11**, and this row's own prediction turned out to be incomplete
  in a way worth recording. It said "a caller needs a gate predicate and a walk of
  `c->chans[]`", which is right about the gate and wrong about the walk: `setname`'s
  server-to-client line has **no channel parameter**
  (`:nick!user@host SETNAME :<realname>`), and 3.1's row prepends the resolved target —
  so one call per channel would put `#chan` where a client expects the realname **and**
  would hand a member of three shared channels three copies of one fact. **The gate was
  necessary and not sufficient**, which is the lesson: "express the audience question
  once, inside the routing module" says nothing about whether the LINE is per channel.
  The gate side is now decided too — **the RECIPIENT's negotiation**, because the
  specification says the message MUST NOT be sent to clients which did not negotiate it
  and because `cap.h` already gates the confirmation that way, so a sender-gated
  fan-out would make the two halves of one specification contradict each other.
  `fanout_deliver_union_local_gated()` is the mechanism: the union of `c->chans`, each
  destination written once, de-duplication by search so there is no cache and therefore
  no teardown arm.
- **The gate answers about a destination, not about a peer's clients.** A relayed
  emission is never gated, so in a mesh a notification reaches peers' clients
  according to what THEY negotiated, with no way for the originating node to know.
  That is the same position `account-tag` takes (§2.5.3) and for the same reason:
  the originating node has no registry it could ask.


### 10.12 The honest limits of `away-notify`

- ~~**A user who JOINS with an away message set is not announced.**~~ **CLOSED IN
  PHASE 10.11**, in the shape this section predicted. It is one
  `fanout_deliver_local_gated()` call in `chan_admit()` — after the JOIN echo, before
  the joiner's own numerics — gated on the RECIPIENT's `away-notify`, excluded to the
  joiner, and conditioned on `c->away[0] != '\0'`.
  **IT IS A SEPARATE EMISSION RATHER THAN A FOURTH `JOIN` PARAMETER, and the
  specification requires that rather than this file preferring it:** the two messages
  have different grammars and different audiences. The extended `JOIN` is a statement
  about the roster; `away-notify`'s is `:nick!user@host AWAY #chan [:message]`, a
  statement about ONE user's away STATE. Folding the away message into the `JOIN` would
  make a line a client parses as a roster carry a fourth field, and would hand every
  member the away message whether or not it negotiated — the exact
  unsolicited-notification defect §3.1.1's gate exists to prevent.
  **AND THE TWO SPECIFICATIONS NEED DIFFERENT WALKS, WHICH IS WHY THE UNION ENTRY
  POINT EXISTS RATHER THAN A REWRITE OF THE AWAY PATH:** `away-notify`'s line NAMES its
  channel, so one call per channel is right and a member of three shared channels gets
  three true statements about three channels; `setname`'s does not, so it needs the
  union walk. That asymmetry is a property of the two message shapes and is the whole
  reason there are two entry points.
- **The notification is not forwarded, and that is not a limitation of the
  mechanism.** Away *state* federates (4.3's `SBURST` carries it and a resync
  rebuilds it), so a mesh member's clients learn an away message the next time they
  see the roster or ask a `WHOIS`; what does not cross a link is the *notification*,
  because the entry point used is the local-only one and a peer is not a client that
  negotiated anything (design §3.1.1).
- **A member who is in the channel and negotiated the capability still gets nothing
  about their own state**, which is the specification's instruction rather than a
  gap, and is why the setter is excluded by `exclude` rather than by the gate.

### 10.13 Phase 10.11 — the two the fanout gate unblocked, and the disclosure decision

Phase 10.8a built the gate and could not use it twice. Phase 10.11 uses it twice, and
the interesting half of each is a decision the gate does not make for you.

| Claim | Where | Evidence |
|---|---|---|
| The `setname` fan-out is gated on the **RECIPIENT**, not the sender | `cap.c`'s `cap_gate_setname()`, handed to `fanout_deliver_union_local_gated()` by `commands.c`'s `setname_notify_channels()` | `test_setname.c` `case_fanout`: a member who negotiated is told, a member who did **not** is not, by a line count |
| The line is the specification's shape, with **no channel parameter** | the union entry point builds no `all[]` and prepends no target | the same case, on the literal `:nick!user@host SETNAME :<realname>` |
| A member of **two** shared channels gets exactly **one** copy | `fanout_deliver_union_local_gated()`'s "already reached?" search | the same case: `tf_count(...) == 1u`, a COUNT because two identical copies are indistinguishable from one to a substring search |
| The origin gets **one** line, not two | `exclude = c`, because the confirmation already answered it | the same case: the setter's window holds exactly 2 lines (the `SETNAME` and the drain `PONG`) |
| The join-time `AWAY` announcement is a **separate emission** | `chan_verbs.c`'s `announce_join_away()`, after the `JOIN` echo, before the joiner's numerics | `test_away_notify.c` `case_join_while_away`: the exact line, and the `JOIN` echo at a **LOWER BUFFER OFFSET** than the announcement |
| A joiner who is **not** away produces **no** line | `if (c->away[0] == '\0') return;` | the same case: a second joiner with no away message, `watcher`'s window holds exactly 3 lines and no ` AWAY ` for them |
| The joiner is excluded about its **own** state | `exclude = c`, mirroring `notify_away()` | the same case, on a connection that DID negotiate — so the gate would have let it through and only `exclude` keeps it out |
| Teeth, build checked before the run was believed | four faults | **4 red.** `setname`: gate on the sender, `exclude` → `NULL`, the union's de-dup made unreachable — **0/0 each**. `away-notify`: the join-time `exclude` removed — **0/0**. **Two faults that did not compile or did nothing are recorded rather than dropped** — see `test_setname.c`'s TEETH block for the `for (j = 0; j < 0u; ...)` and `s->name != NULL` attempts, both of which left a GREEN test against a stale binary |

**WHAT THE SHAPE ARGUMENT COST, and it is the finding.** §3.1.1's gate answers *who
hears about an emission*. It does not answer *whether the emission is per channel*, and
for `setname` that second question is the one that bites: 3.1's row prepends the
resolved target, and `setname`'s specified line carries no target. The union entry point
is therefore **not** a generalisation of the away path — the away path is still one
`fanout_deliver_local_gated()` per channel, because its line names its channel. Two
entry points for two message shapes is the honest answer and it is recorded here so a
future phase does not read the union one as "the way fan-out should now work".

### 10.14 Phase 10.12 — `batch`, and two findings from the specifications themselves

| Claim | Where | Evidence |
|---|---|---|
| `batch` is advertised because it is implemented | `cap.c`'s `k_caps[]` | `test_batch.c` case 1, beside an assertion that `away-notify` **is** advertised — so the presence is not satisfied by a `CAP LS` that stopped early |
| `BATCH` exists and a malformed reference is **not** `421` | `commands.c`'s verb table, `pre_reg = 1` | `test_batch.c` case 1: `462` for a reference with no sign. `421` would tell a client this server has never heard of the verb |
| Inside an open batch, **every** line carries `batch=<ref>` | `reply.c`'s `emit_built_ex()`, `batch_line_tag()`'s open-batch arm | `test_batch.c` case 2: a four-line `WHOIS`, 4 of 4 numerics tagged, counted over the **numerics** and not over the window — because the drain `PONG` is inside the batch too and must be |
| After `BATCH -ref`, **no** line is tagged | the same function, one-shot arm | the same case: 0 tagged lines in the following window |
| A **mis-cased** `BATCH -ref` refuses AND leaves the batch open | `batch.c`'s `strcmp()` | `test_batch.c` case 3: the `462`, then 4 of 4 lines still carrying `@batch=Who1` — the case-sensitivity claim and the state claim in one case |
| `+<ref>` tags **exactly one** line and is consumed | `batch_begin_command()` / `batch_line_tag()`'s one-shot arm | `test_batch.c` case 4: 1 of 4, then 0 of 4 on the next command |
| An **invalid** reference is ignored and the response still arrives, and nothing is stored | `note_reference()`'s early `return` | the same case: 0 tagged lines, 4 delivered — and then **0 on the following command**, which is the half that proves it was not stored |
| `INVALID_REFTAG` is a `FAIL` **per destination** | `reply_refused(..., "BATCH", "INVALID_REFTAG", "417", ...)` | `test_batch.c` case 5, on two connections differing in exactly that negotiation: `FAIL BATCH INVALID_REFTAG` on one, byte-identical `417` on the other |
| 64 accepted, 65 refused, and neither truncated | `batch_ref_valid()`'s `n > CONN_MAX_BATCH_REF` | the same case, at both edges. **The 64 half exists because the first `reply.c` sized its tag buffer at `CONN_MAX_BATCH_REF + 1` and dropped the tag at exactly this boundary** |
| A `BATCH` carrying a `batch=` tag is refused and opens **nothing** | `batch_line_tagged_inbound()`, checked first in `handle_batch()` | `test_batch.c` case 7, half one — sent with **no batch open**, so the one-batch rule cannot fire and only the nesting check can. Half two: the OUTER batch still tags afterwards and `@batch=inner` appears nowhere |
| The state is per connection and outlives the message | `conn_t`'s three fixed-size fields | `test_batch.c` case 6: `b` sees no tag while `a` has one open, and `a`'s is still tagging several commands later |
| Teeth, build checked before the run was believed | four faults | **4 red, 0/0 each.** **ONE WAS GREEN ON ITS FIRST RUN** — the obvious shape of the nesting case cannot see the fault, because a nested `+` is refused by the one-batch rule anyway and the numeric and the line count come out identical. The case was rewritten to discriminate and re-run. That is recorded at the test's TEETH block rather than quietly replaced |

**THE TWO FINDINGS, both of them about the specifications rather than about this node.**

1. **`@<ref>` is unimplementable, and that is a property of the tag grammar.** The
   retired `reference-tags` specification paired `@<ref>` ("send the response nowhere")
   with `+<ref>`. `@` is the tag-block **marker**, and a conformant parser consumes
   exactly one of them, so `@ref` parses as a valueless tag named `ref` and `@@ref` is
   **refused by `message_parse_n()`**. Both were run, not reasoned about. `+` is the
   sigil the modern grammar keeps inside the key, so `+<ref>` is implemented and the drop
   form is recorded as not implemented. `conn_t` has no field for it and says why.
2. **`client-batch` has no code for the refusals it implies.** It defines three `FAIL`
   codes — `INVALID_REFTAG`, `TIMEOUT`, `UNKNOWN_TYPE` — and none of them covers a
   second open batch, a mismatched close, or a nested `BATCH`, all of which its own prose
   forbids. Those use a borrowed `462` with the reason in the text; §6 forbids a new
   numeric and §4.4 forbids silence.

**WHAT IS NOT IMPLEMENTED, by name.** `netsplit` and `netjoin` batch types (a suppression
feature this node has no event to batch, and the capability does not claim them — the
specification says batch types are not advertised and a client may ignore an unknown
one); `UNKNOWN_TYPE` (see §4.4.7 for the argument); `TIMEOUT` (a code with no specified
duration); `draft/multiline` (needs the framing, which this is, plus the interpretation
of `;draft/multiline-concat` values and the splitting of one command into several); and
`batch/react`, which is a **client-only** batch type and is N/A for a server.

### 10.15 Phase 10.13 — `labeled-response`, and what "exactly one logical message" costs

| Claim | Where | Evidence |
|---|---|---|
| The label is **copied**, never referenced past the request | `conn_t::label`, a fixed-size field; `label.c`'s `ircv3_unescape_value()` into it | `test_labeled_response.c` case 6: a 64-byte value comes back **byte for byte**. The FAULT (a stored `char *`) is **red** but **ASan is SILENT** — see the note below |
| The label appears in **exactly one** logical message | `label_line_tag()`: `label=` on the batch start, `batch=<ref>` after | case 3: 4 of 4 numerics carry `@batch=…` and exactly **1** line carries `@label=…` |
| A multi-line response is grouped, `BATCH +` **tagged with the label**, `BATCH -` untagged | `label_line_tag()`'s first-line arm, `label_finish_command()` | case 3, on the specification's own example shape, with the reference **read back out of the opening line** so the rest of the assertions are about what the node minted |
| A single-line response is **wrapped too** | the same arm — the batch is opened on the first line, before the node knows how many there will be | case 1: 3 lines (batch, answer, close) and exactly one `@label=`. **This is the cost and it is named at §4.4.8** |
| A labelled `PRIVMSG` to a channel the sender is not on produces a labelled **`404`** | the whole path | case 5, with a second client on the channel so the answer is `404` and not `403` — and with the assertion that **the channel heard nothing** |
| `ACK` for a command that produced nothing, and **not** for one that did | `label_finish_command()`'s two arms | case 4: a labelled `PONG` → `ACK`; a labelled `PING` → a PONG and **zero** `ACK` |
| A message **to itself** carries no tag, and the label lands on the `ACK` instead | `conn_t::label_self`, set by `msg_verbs.c` | case 7: the echoed `PRIVMSG`'s line begins with a bare `:` (walked back to the line start), `@label=self` appears once, and it is on the `ACK` |
| A message to a **channel** IS labelled on the echo, and the label never travels | the same field, `0` for a channel target | the same case, second half: `@label=other` once on the sender, and **no** `label` anywhere on the recipient's socket |
| 64 accepted, 65 **ignored and not truncated**, a valueless `@label` ignored | `CONN_MAX_LABEL`, checked before the copy | case 6, all three: 64 comes back byte-for-byte; 65 produces **no** `label=` at all and the response still arrives |
| Per destination: the label, no `BATCH`, no `ACK` for a client that negotiated nothing | `cap_labeled_response_enabled()` gating the batch and the `ACK`, never the label | case 2, on a connection that negotiated `away-notify` and nothing else |
| Teeth, build checked before the run was believed | five faults | **5 red, 0/0 each** — with **two recorded as faults of the FAULT rather than of the test**: the grouping fault needed a `(void)s` to compile (`unused-parameter`), and the pointer fault is **red without ASan reporting anything**. Both are in the test's TEETH block |

**THE ASAN FINDING, and it is the interesting one.** The fault the pass plan asked for —
"a label pointer retained past the request (use-after-free under ASan)" — **does not produce
an ASan report in this design**, and the reason is a fact about the ordering rather than
about the fault. The label is consumed inside `commands_dispatch()`: the `BATCH +<ref>` line
is emitted from `emit_built_ex()` while the handler is still running, and the `BATCH -<ref>`
from `label_finish_command()` before dispatch returns. **`poll_loop.c` frees the parser's
buffer after dispatch returns.** So a stored pointer is dangling but still *readable* at
every point it is used.

What the fault produces instead is a **corrupted label on the wire** — the fault's run
shows `@label=<two bytes of whatever the allocator had>` — and the test is red on that. So
the fixed-size field is defended by a **wire-level assertion rather than by the
sanitizer**, which is a weaker guarantee than this project usually claims, and it is stated
here and at the test's TEETH block rather than dressed up. If a future phase moves any
labelled emission outside dispatch, the fault becomes a real ASan report and the claim
becomes stale in the useful direction.

**TWO MORE DEFECTS THIS TEST FOUND BY RUNNING**, both invisible to review and both of the
same class — *a rule that was true of the code and not of the protocol*:

1. `label_finish_command()` cleared its state **after** emitting, so the `ACK` triggered the
   batching the function exists to prevent and came out as
   `@batch=<its own ref>;label=<value>` on one line. Fixed by disarming first.
2. The "sent to itself" test was keyed on the line's **prefix** rather than on the message's
   **target**, so it withheld the label from every `echo-message` copy on the node: a
   labelled `PRIVMSG #chan` returned an unlabelled echo followed by an `ACK`. Fixed by
   `conn_t::label_self`, set where the target is in scope.

### 10.16 Phase 10.14 — `invite-notify`, and a misreading corrected rather than implemented

| Claim | Where | Evidence |
|---|---|---|
| The **audience is the channel**, and the line is the specification's | `notify_invite()` in `chan_verbs.c`, through the union entry point with a one-element list | `test_invite_notify.c` case 1, byte for byte: `:in_op!in_op@127.0.0.1 INVITE in_g #I`. **The first version rendered `INVITE #I in_g #I`** — 3.1's row prepends the resolved target and the specification's grammar is the other way round |
| A member who negotiated is told **exactly once** | `cap_gate_invite_notify()` | case 1: `tf_count(" INVITE ") == 1` |
| A member who did **not** negotiate is told **nothing** | the same gate | case 1's `blunt`, by line count of 0 |
| The **inviter** gets its `341` and nothing else, and that is `exclude` not the gate | `notify_invite()`'s last argument | case 1's `op`: the inviter DID negotiate, so the gate would have let it through — which is what makes this the case that proves the two are different questions |
| The notification is addressed to **one** channel | the one-element channel list | case 2: two channels, three connections; the member of the other channel gets nothing about this one, and the other invitation reaches the other channel |
| A **refused** INVITE notifies nobody | the call site, after every refusal in `handle_invite()` has returned | case 3: a non-op's `482`, and the channel's member window is empty |
| **One connection per nickname**, which is why the other reading is vacuous | the nick registry | case 4: a second connection claiming a held nick is `433` |
| Teeth, build checked before the run was believed | four faults | **4 red, 0/0 each** — the gate ignored, the inviter not excluded, the notification moved above the authority check, and the parameters swapped |

**THE CORRECTION, because it is the substance of the pass.** The plan for this phase
described `invite-notify` as "`INVITE` reaching a client's other connections", and
predicted a vacuous result on the grounds that this node has one connection per user.
**The premise is wrong and the prediction follows from it.** The specification is about
**channel members**: "allows a client to specify that it would like to be notified when
users are invited to channels", with the message `:<inviter> INVITE <target> <channel>`.
The source is the inviter and the subject is a third party doing something to a channel the
recipient is on; RFC 2812 3.3.6's "Other channel members SHOULD NOT be notified" is the
rule this capability exists to let a client opt out of. Nothing in it concerns the
invitee's connections.

The vacuity is still worth recording, and it is recorded as a **fact about the node** rather
than as the outcome: one connection may hold a nickname (the registry answers `433`), so
the "other connections" set is empty and case 4 asserts that. Had the feature been built
to the brief's reading it would have been a no-op with a passing test.

### 10.17 Phase 10.15 — the seven specifications that are NOT implemented, and why

**NO CODE IN THIS PASS.** Every row below is a decision, a block, or a correction of a
misreading, and each carries its reasoning rather than a shrug. Where a specification is
blocked, the missing thing is named; where it is out of scope, the scope boundary is named;
where the brief was wrong about it, that is said first.

| Specification | Status | The reasoning |
|---|---|---|
| **`chathistory`** | **NOT IMPLEMENTED — a DESIGN CONFLICT, and the instruction is to document it and leave it** | See below. This is the only item in the phase that is not a "not started" |
| **`websocket`** | **OUT OF SCOPE — a transport, not a protocol feature** | See below |
| **`sts`** | **OUT OF SCOPE — a crypto surface** | See below |
| **`sasl-3.2`** | **OUT OF SCOPE for the MECHANISMS; the framework is present** | See below |
| **`client-tags/channel-context`, `react`, `reply`, `typing`, `batch/react`** | **N/A FOR A SERVER** | See below |
| **`oper-tag`** | **BLOCKED — on a subsystem that does not exist** | See below |
| **`account-extban`** | **BLOCKED — on the one gap already named twice** | See below |

---

#### `chathistory` — a design conflict, documented and NOT implemented

**THE INSTRUCTION WAS EXPLICIT: document the conflict, do not implement.** This section is
that document, and it is the longest thing in this phase that is not code.

**WHAT IT WOULD REQUIRE.** `draft/chathistory` answers "what was said in `#t` while I was
away". On this node the answer is: nothing, because nothing is kept. `resume.c`'s restore
hands a client back the channels it was in at disconnect, and that is a **session** — it
keeps nothing that was not said while the client was connected, so it cannot answer a
question about last week. §4.4.2 already refuses to advertise `draft/CHATHISTORY` for
exactly this reason: "Advertising it would put a client into a state it cannot leave."

**THE CONFLICT IS WITH §2.2's DISPOSAL RULE, and it is not a matter of effort.** §2.2
frees a channel with no local members and no member-server, and the paragraph above it
gives the reason in one sentence: "holding one per channel *name* a client ever typed
would be an **unbounded store reachable from the wire**." A message history is exactly
that, and worse — it is unbounded in **time** as well as in name, because a channel's
history grows for as long as anybody is talking.

The design already solved this once, and the solution is the template for what a history
would need. A channel's **topic** is the one field whose loss a client can see, so
`topic`/`topic_who`/`topic_when` are copied into a **bounded cache on `server_t`** at
disposal and copied back at creation. Four limits are stated there rather than left to a
reader: it does not survive a restart, only the topic is carried, the bound is small, and
the cache's lifetime is exactly the channel's.

**WHAT WOULD HAVE TO CHANGE IN THE DESIGN, stated as the four things and not as a shrug:**

1. **A bounded, time-boxed history per channel**, on `server_t`, with a bound on **both**
   axes — messages per channel and age. §2.2's rule is about the first; a history needs the
   second, and an age bound is a new kind of thing on this node because nothing in the
   design currently ages anything out on a timer. §3.4 forbids a write inside the event
   loop, so the eviction would have to run from the poll tick.
2. **A stated answer to "what is the bound, and who decided".** §2.2's topic cache has a
   bound this project chose and documented. A history's bound is a *policy* an operator
   will have opinions about, which makes it a configuration surface — and §4.5's
   `--sasl-store` / `--account-store` argument is about secrets, not about retention, so
   there is no existing precedent for it.
3. **A decision about federation, which is the one that would actually be expensive.** 4.3's
   frozen verb table has no message verb for history and `SBURST` carries nicks, channels,
   topics and away — **not messages**. So a mesh member's history would be empty unless a
   new S-verb were added, and §6 forbids inventing a wire format after Phase 6. The two
   S-verbs that already exist (`SPRIVMSG`, `SNOTICE`) are live traffic, and a history is
   not live traffic: replaying old messages through them would put them in every
   duplicate-suppression store and every `msgid` namespace as though they were new.
4. **A storage decision, and this is where the fail-closed posture bites.** The posture is
   fail-closed with no buffered state, and a history is buffered state on purpose. §2.2's
   channel disposal and §2.3's load reporting both assume that what a node holds can be
   recomputed from the mesh; a history cannot be, because the mesh does not carry it.

**THE COST OF LEAVING IT OUT, and it is small.** A client that joins a channel after a
conversation sees nothing of it. Every IRC client already treats that as normal, because
`chathistory` is a draft and no widely-deployed client requires it. **The cost of
implementing it without the four decisions above is larger**: unbounded wire-reachable
memory, which is the exact defect §2.2 names.

---

#### `websocket`, `sts`, `sasl-3.2` — a transport, a crypto surface, and two mechanisms

**`websocket` — a TRANSPORT, not a protocol feature.** The specification changes how bytes
reach the node: an HTTP upgrade handshake, then a framed stream instead of CRLF lines.
Everything above that — the parser, `dispatch()`, every capability, every numeric — is
unchanged, which is a good sign that it is a different layer rather than a missing
feature. Implementing it means: a listener that speaks HTTP for exactly one request, a
frame codec, and a decision about what a half-open upgrade costs while a client
misbehaves. **None of that is protocol work and all of it is this node's job**, which is
precisely why it is out of scope for a phase about IRCv3 specifications. §4.4.1's rule
gives the honest alternative: if it is wanted, `WEBSOCKET=302` is an `005` token and
there is a place to add it.

**`sts` — a CRYPTO SURFACE, and the reason is stronger.** `sts` ("Strict Transport
Security") tells a client to *only* ever use TLS, and it depends on a `tls` capability
this node does not have. Advertising `sts` without `tls` would be advertising a promise
this node cannot keep, which is `cap.h`'s rule in its strongest form. **And it is not
implementable in isolation**: `sts` is a policy layered on `tls`, and `tls` is Phase 8's
`STARTTLS` which this node does not implement either. Two specifications, one transport,
and the bottom one is missing.

**`sasl-3.2` — the FRAMEWORK IS HERE; the two MECHANISMS ARE NOT.** This needs splitting,
because the brief listed it as one thing and it is two:

- **The SASL framework is implemented.** `sasl_framework.c` implements RFC 4616 `PLAIN`
  against a credential store, `CAP LS` withholds `sasl` when no store was loaded (a node
  with no credentials cannot authenticate anybody), and `AUTHENTICATE` is answered inside
  the registration burst.
- **`sasl-3.2` names `SCRAM-SHA-1`/`SCRAM-SHA-256` and `EXTERNAL`, and this node
  implements neither.** `EXTERNAL` authenticates a client by a credential it presented
  *elsewhere* — a TLS client certificate, or an already-authenticated `sasl` identity from
  a bouncer — and this node has neither TLS nor bouncer support, so there is nothing for
  `EXTERNAL` to assert. `SCRAM` is a challenge-response mechanism: the server holds a
  **salted, iterated hash** rather than a plaintext-equivalent secret, and
  `account_store.c` holds the latter. Storing SCRAM verifiers correctly is a credential
  store redesign, and getting it wrong is a silent authentication weakness rather than a
  loud failure.
- **`sasl-3.1` IS RETIRED IN FAVOUR OF `3.2`, and that is why `3.1` is not on this list at
  all.** Implementing the retired version would mean implementing the wrong one.

**WHAT WOULD HAVE TO CHANGE, briefly:** for `websocket`, a transport layer and a new
listener; for `sts` and `tls`, a TLS listener and `STARTTLS`, and then a policy on top;
for `sasl-3.2`, a credential store that can hold a SCRAM verifier, which is a change to
`account_store.c`'s file format and to every test that reads it.

---

#### Client-only specifications — N/A FOR A SERVER, with the reasoning

`client-tags/channel-context`, `client-tags/react`, `client-tags/typing`,
`client-tags/reply`, and the `batch/react` batch type. **All five are N/A for a server, and
the reason is one sentence from the specifications themselves: their subject is the
PRESENTATION OF A MESSAGE TO A HUMAN.**

- **`typing`** is "the user is typing a message". A server can observe the `TAGMSG` but the
  observation has no meaning without the typing indicator the client draws.
- **`react`** is a reaction to a message. The IRCv3 registry records it as a **client-only
  tag**; a server relaying it is a `PRIVMSG`-shaped relay with no semantics, and the
  specification's own framing is that the client shows the reaction.
- **`reply`** marks a message as a reply to another `msgid`. The server half of that is
  **already implemented**: `msgid` is stamped on every line this node relays (Phase 10) and
  forwarded across a link with 2.4's identity intact. What the `reply` tag adds is the
  *display* — an indent, a quote — and that is the client's.
- **`channel-context`** is "display this private message as if it were in `#chan`". A server
  has no display.
- **`batch/react`** is a **batch type**, and the `batch` specification says batch types are
  "not advertised by servers nor explicitly requested by clients" — a server-emitted
  `react` batch would be a server deciding how a client presents reactions, which is the
  opposite of what the type is for.

**THE GENERAL RULE, and it is worth having written down**: a **client-only tag** is one the
IRCv3 specifications define as travelling *directly between clients with no server
involvement*. A server that recognises one and acts on it is inventing semantics. The one
partial exception here is `reply`, and the partial exception is `msgid`, which this node
already emits and which is what the tag's value refers to.

---

#### `oper-tag` — blocked on a subsystem this node does not have

The specification adds a `+` tag to `PRIVMSG`/`NOTICE` **when the sender is an IRC
operator**. So it needs operator flags.

**This node has no operator concept at all**, and that is not a gap in one handler:
`conn_t` has no operator field, `004` advertises a user-mode set of `i` that nothing
evaluates, `CHOPER` answers `464` for every request, and `KNOCK` is refused with `482`
precisely because "the only thing the RFC names as that authority is an IRC operator". So
the block is not "the tag is hard" — it is that **the predicate the tag asks about does not
exist**. A node cannot stamp `+` on messages from operators it does not have.

**WHY IT WAS NOT IMPLEMENTED AS AN ALWAYS-ABSENT TAG.** An absent tag is a smaller lie than
a wrong one: a client that sees `+` on a message reads "this person is an operator", and a
client that sees nothing reads nothing. Adding the tag with no operator model behind it
would produce the first.

**WHAT WOULD HAVE TO CHANGE**, and it is a whole phase rather than a handler: §5's operator
model — a way to be one, a way to stop being one, a way to be *seen* to be one (the
capability's own `oper` argument), and a `MODE`-independent privilege set. §9's risk row
for "fabricating a load metric to decide node lifecycle" is the same shape of problem: a
node deciding something on the strength of a value it invented.

---

#### `account-extban` — blocked on the ONE gap this document has already named twice

The specification adds `~&account:<name>` mask types to a channel ban list, so that an
operator can ban an account rather than a hostmask.

**It needs two things and this node has neither:**

1. **The account.** Delivered in Phase 10.1 and available.
2. **A ban-expression parser.** `+b` stores a mask verbatim and `chan_banned()` tests it by
   **string equality and a glob**, per §2.2. There is no expression language, so there is
   no `~&account:` to parse.

**AND THIS IS ONE GAP NAMED TWICE ALREADY**, which is the point of listing it here rather
than writing a new paragraph: §4.4.2 already records that `EXTBAN=` is **deliberately
absent from `005`** because "There is no ban-**expression** parser, so there is no
`~&account:name` and no `EXTBAN` value", and it says in the same breath "This is the same
missing evaluator that blocks `account-extban`". §10.2's table says it a third time from the
account side.

**So the honest status is: one missing subsystem, three consequences, and they should be
counted once.** A `+b` that stores a mask verbatim is not a bug and is not a gap in
`chan_banned()` — it is a complete implementation of what §2.2 specifies, and the missing
piece is the *expression grammar* that would sit above it.

**WHAT IT WOULD COST**, and the estimate is deliberately coarse because the design is not
written: a mask grammar and a parser; an evaluator with a defined precedence and a defined
answer for a mask it cannot parse (fail closed, or ignore the mask? — the two answers have
opposite failure modes and §2.2's posture says fail closed); an `EXTBAN=` token rendered
from the constants the evaluator enforces, in `005`; and a per-channel bound on how much
work one mask may cost, because a glob over a long mask against a long roster is a place a
client can spend the node's time. **That last one is the part that has to be designed
before it is coded**, and it is why this is a decision rather than an omission.

### 10.11 The honest limits of the account phase

- **The identity is visible on ordinary traffic for LOCAL senders only.**
  `account-tag` (Phase 10.2a) stamps it on every line an identified client emits
  to a client that negotiated the capability, and `330 RPL_WHOISACCOUNT` still
  answers a `WHOIS` about a person the client named. Neither reaches a message
  this node **relayed**, and neither reaches a numeric — the tag on numerics is
  the specification's SHOULD, not its MUST. Design §2.5.3 names all three.
- **No client can create or delete an account.** By decision (§2.5.2), and the
  cost is stated: a deployment wanting open registration must not use this node.
- **Accounts do not federate, and that is now a WIRE decision rather than only a
  limitation of the subsystem.** A registry is per node and per operator, exactly
  as `sasl_store_t` is — a two-node mesh with two registries will disagree about
  who somebody is. Phase 10.2a therefore **does not** put `+account` on a relayed
  message (§2.5.3), so per-message identity stops at the node that verified the
  credential; the account reaches a peer as **membership** state instead, through
  `extended-join` (Phase 10.3). Closing the per-message gap needs an account
  authority both nodes trust, and this node has none.
- **`account-extban` and `oper-tag` are unblocked by accounts and blocked by
  subsystems that do not exist** (no channel-mode evaluator, no operator flags).
- **Compliance is hand-written tests against spec text**, not a third-party runner:
  `ircv3/ircv3-test-suite` and `ircv3/chathistory-test-suite` do not exist.

## 11. Phase 11 — the RFC 2812 conformance sweep

**The deliverable is [`docs/RFC2812_CONFORMANCE.md`](RFC2812_CONFORMANCE.md)**, a
table of every numeric RFC 2812 section 5 defines (160 of them) with what this
node does with each one and why. It is a document in its own right because the
next sweep — and the TLS work that precedes it, which touches the event loop and
every read/write path — should start from that table rather than from six source
files. Counts: **59 emitted**, **91 absent with the reason**, **10 N/A** (in RFC
2812 5.3 only, with no role on any server), **0 unaccounted for**. The node also
emits **8** numerics RFC 2812 does not define; §4 of that document names the
de-facto or IRCv3 origin of each.

### 11.1 What was added, and what it fixes

| Numeric | Why | Test |
|---|---|---|
| `319` `RPL_WHOISCHANNELS` | A `WHOIS` named a person and never named a channel. **The one confirmed modern-client defect**, and it is what makes `away-notify`'s own documented promise true: the specification excludes the setter from the notification because `305`/`306` tell the setter their own state, and those two numerics tell nobody else *where* that person is | `test_whois_channels.c` §1, §2 |
| `367`/`368` for `MODE #chan ±b` | RFC 2812 3.3.2 defines the ban list as a query with no mask. It was answered `461` — a refusal for the form that *asks* — so every client that populates a ban list on window open got an error and an empty list, on a channel where the bans were being enforced perfectly well | `test_banlist.c` §2–§4 |
| `478` replacing `696` | `696` is `RPL_ENDOFMODES` from the historical `MODE` draft, not a ban-list-full refusal, and it named no mode letter. `478`'s field list is `<channel> <char> :Channel list is full` | `test_banlist.c` §5 |
| `254` `RPL_LUSERCHANNELS` | RFC 2812 3.4.2 requires it whenever the channel count is non-zero, and it was never sent, so `/LUSERS` omitted a figure every client displays | `test_query_surface.c` §1, §2 |

### 11.2 Two findings the sweep produced that were not numeric gaps

- **`CHAN_MAX_BANS` was never enforced.** `chan_ban_add()` doubled `bcap` on
  demand with nothing comparing `nbans` to the constant, so `channel.h`'s claim
  that it is "a real limit rather than a formality" was false and the refusal
  branch above was **unreachable**. Enforcing it is what makes `478` a fact rather
  than a comment. Found by asking the obvious question — *is that refusal
  reachable at all?* — which is a question this document now asks of every numeric
  it lists.
- **`MODE <nick>` is answered `403 ERR_NOSUCHCHANNEL`.** `handle_mode()`
  canonicalises its first parameter as a channel name, so a nickname is refused as
  an unknown channel, with the name echoed upper-cased. RFC 2812 3.3.2 answers a
  MODE naming a nickname with `221`, or `501`/`502` for a change. A client that
  queries a user's modes is told "no such channel" about a connected user, and
  `501`/`502`/`221` are all unreachable as a result. It was left unchanged: every
  answer needs a user-mode string this node does not have.

### 11.3 Two arity deviations found, and NOT fixed — this is the open decision

Both are in `docs/RFC2812_CONFORMANCE.md` §6 with their client-visible symptoms.
Neither was changed, and the reason is the same for both: **the existing tests
assert the non-conformant bytes**, so correcting the arity means correcting them,
and this phase's constraint was that the existing suite is not edited.

- **`461` omits the RFC's `<command>` field.** RFC 2812 5.1:
  `<command> :Not enough parameters`. All ~30 call sites pass `NULL, 0`.
  *Symptom:* a client that attributes the error to a command cannot.
  *Pinned by:* `test_knock.c` ×2, `test_messaging.c` ×2, `test_invite.c` ×2,
  `test_standard_replies.c` ×3, `test_account.c` ×1 — nine sites, seven files.
- **`472` sends `<channel>` where the RFC sends `<char>`.** RFC 2812 5.1:
  `<char> :is unknown mode char to me for <channel>`. The node names no mode
  character at all.
  *Symptom:* a user who mistyped `+k` is told "unknown mode character" without
  being told which; and a client parsing 472 positionally reads `#MO` as the mode
  character that was rejected, so it believes the node rejected the sigil `#`.
  *Pinned by:* `test_channels.c` ×2, `test_serverinfo.c` ×1 — three sites, two
  files.

The one assertion Phase 11 DID have to change is `test_away_notify.c`'s two `WHOIS`
**line counts** (5 → 6 and 4 → 5), because `319` adds a line to every `WHOIS` of
a user in a channel. That assertion is a count on purpose — it is what makes
"exactly the lines this WHOIS produced" checkable — so a new numeric has to be
accounted for in it rather than tolerated.

### 11.4 The `317` decision, recorded

RFC 2812 3.3.4 makes `317`'s trailing parameter free text, so `"seconds idle"` and
`"seconds idle, signon time"` are equally conformant and conformance cannot choose
between them. **Left at the RFC's own literal string.** (1) It is the
specification's literal, so a client whose numeric table carries the RFC's text
matches this line byte for byte. (2) No client parses the trailing text of `317`;
every one dispatches on the numeric and reads the middle parameters by position,
so rewriting decoration nothing reads buys no compatibility. (3) An anchored
`:seconds idle` match is a real thing in the wild and a rewritten sentence does not
satisfy it. The full argument is at the call site in `msg_verbs.c`, next to the
`317` the arithmetic is in.

### 11.5 Teeth

Nine faults across the three new test files, each **build-checked to 0 errors and
0 warnings before its result was read** — the gate refused three earlier attempts
that did not compile clean (`-Wunused-function`, `-Wunreachable-code`) rather than
reporting a result for them. All nine bit. **One did not bite on the first run and
that is recorded rather than quietly fixed**: the `319` field-order assertion
covered only the single-line case, so a fault moving the nick into the trailing
text of the *chunk-flush* `reply()` passed every check. It is now asserted on every
chunked line, and the fault fails it.
