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
| IRCv3 tag escaping `\:` `\;` `\s` `\\` `\r` `\n`, lone-`\` rule | IRCv3 message-tags / design §3.2 | **Implemented** | `message_tag_escape` `message.c:197`, `message_tag_unescape` `message.c:245`; `test_message_format.c:389-402` pins each of the six. Reproduced directly: `message_tag_escape("a:b c\\d")` → `a\:b\sc\\d` (n=10) |
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
| `MultiPrefix` | `tests/protocol/test_multi_prefix.c` | IRCv3 `multi-prefix` capability (multi-`prefix` in `353`) | Phase 8 | #82 |
| `SyncState` | `tests/federation/test_sync_state.c` | the §4.3 resync **driven by a reconnect** — backoff, retry budget | Phase 9 | #83 |
| `FailoverReconnect` | `tests/federation/test_failover_reconnect.c` | Peer failover / reconnect | Phase 9 | #83 |
| `CapNegotiation` | `tests/compliance/test_cap_negotiation.c` | IRCv3 CAP negotiation (`LS`/`REQ`/`ACK`/`NAK`) | Phase 8 | #82 |
| `PeerDiscovery` | `tests/loadbal/test_peer_discovery.c` | Load-balancer peer discovery (advertise / graceful leave) | Phase 9 | #83 |
| `Reconnect` | `tests/loadbal/test_reconnect.c` | Client reconnect preserving session state | Phase 9 | #83 |
| `AutoScale` | `tests/loadbal/test_autoscale.c` | Auto-scaling (spawn / shutdown / propagation) | Phase 9 | #83 |

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
| 9 | #83 | Phase 9: Federation hardening, peer discovery, auto-scaling | OPEN | Not started. Turns `SyncState`, `FailoverReconnect`, `PeerDiscovery`, `Reconnect`, `AutoScale` green. |

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
  and the three features this node has **not** implemented: CAP negotiation,
  SASL, and `msgid`.

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
