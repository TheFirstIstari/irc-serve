# IRC Server Design — Federation-Native Architecture

Status: **authoritative design**. Supersedes the status claims in
`SPEC_TRACKING.md` and `ARCHITECTURE.md`, which overstate what is implemented.

Date: 2026-09-28. Verified against source at commit `2910979`.

**Design principle: federation is not a feature bolted on at the end. It is a
property of the core data model.** Every design decision below is chosen so
that adding a second node is a transport concern, not a rewrite. A single-node
server that obeys these rules is a degenerate case of the federated one.

---

## 1. Why federation-first

The naive approach — build a single server, bolt on federation later — forces
a rewrite at exactly the point where the rewrite is most expensive: the
message path, the nick registry, and channel ownership. The cost of federation
is dominated by *retrofitting three invariants* into code that assumed a
single global truth:

1. Nicknames are globally unique
2. Channels are globally shared objects
3. Every message is local

Getting these right up front costs a small amount of discipline and saves a
rewrite. Concretely, this design makes three choices that pay off later:

| Naive | Federation-native | Why |
|---|---|---|
| global nick table | `nick@server` per-server nick table | collision resolution is a peer concern, not a lock |
| channel is one struct | channel has an **origin server**, membership is a set of (server, user) | no broadcast of every join to every node |
| one conn type | `conn_t` has a `kind` (client \| server) | peers and clients share the dispatch path |

The result: adding a peer link is ~400 lines of transport and handshake. No
command handler, registry, or protocol change.

---

## 2. Core data model

Everything below is single-threaded behind one event loop, so no structure
needs internal locking. That is deliberate — it is what makes the federation
logic tractable.

### 2.1 Identity: scoped nick

```c
typedef struct conn {
    int      fd;
    int      kind;              /* CONN_CLIENT | CONN_SERVER */
    char    *peer_name;         /* server name, for CONN_SERVER */
    char     nick[64];          /* local nick, pre-@ */
    char     user[64], host[128], realname[256];
    int      state;             /* REG_PASS | REG_NICK | REG_USER | REG_READY | CLOSING */
    uint64_t id;                /* monotonic, per-process; basis for message-ids */
    struct chan **chans; size_t nchans, cap;   /* channels this conn is in */
} conn_t;
```

The **qualified name** `nick@server` is computed on demand:

```c
char *qualify(const conn_t *c, char *out, size_t cap);
```

Nick uniqueness is enforced **per server**, not globally. On collision, the
*incumbent* server keeps the nick and the joining one returns `433`. This is
exactly the behaviour of a single node, so nothing changes for a lone server.

### 2.2 Channels: origin-owned

```c
typedef struct chan {
    char      name[64];         /* always uppercase-normalised */
    char      origin[64];       /* server that first created it */
    char      topic[256], topic_who[64]; time_t topic_when;
    char      modes[32];
    struct member { conn_t *c; } *members; size_t nmembers, cap;  /* LOCAL members only */
} chan_t;
```

A `chan_t` holds **only local members**. Remote membership is *implicit*: it is
represented by the peer links that reported it. This is the key simplification
— a server never stores or synchronises the full member list of a channel it
does not own, and a join on a remote channel costs one message to the owner.

**Ownership rules:**
- First server to see a channel owns it.
- For an **owned** channel: apply joins/parts/topics locally, and forward to
  each peer that has members in it.
- For a **non-owned** channel: forward the action to the owner; do not
  broadcast.

### 2.3 Servers and peers

```c
typedef struct server_link {
    char      name[64];
    int       fd;
    int       state;            /* mirrors handshake_state_t */
    struct server_link *next;
} server_link_t;
```

Reuses the **existing, tested** `federation_handshake.c` FSM
(`INIT → HANDSHAKE_SENT → ESTABLISHED | FAILED | TIMED_OUT`) — no new
handshake concept is invented. The FSM is per-peer.

### 2.4 Loop prevention and dedup

Every relayed message carries a hidden tag:

```
@irc-serve-origin=<server> ;irc-serve-id=<n>  :<server> PRIVMSG #chan :hi
```

- A node drops a message whose `irc-serve-id` it has already seen (bounded LRU
  per peer).
- A node never forwards a message whose `irc-serve-origin` is itself.
- The origin tag is stripped before delivery to clients.

Without this, two nodes bounce a message forever. This is the single most
common federation bug, so it is specified up front and tested early.

---

## 3. Message path

One path for local and remote input. This is the core of "simple to implement".

```
socket read ──▶ framing ──▶ message_parse ──▶ dispatch(cmd_t)
peer   read ──▶ framing ──▶ message_parse ──▶ dispatch(cmd_t)
                                                │
                    cmd_handler(server_t*, conn_t* src, message_t*)
                                                │
                          origin_tag added ──────┤
                                                ▼
                                    fan_out(server_t*, m)
                                     ├── local conns  → send
                                     └── owner server → forward
```

`dispatch` never asks "is this local or remote?" — `src->kind` is the only
difference, and handlers that care (most do not) read it.

### 3.1 Fan-out rules

| Target | Action |
|---|---|
| local user | write to `conn_t` |
| local channel with only local members | write to each local member |
| local channel with remote members | write to local members **and** forward to peers holding members |
| remote channel (not owned) | forward to owner; no local write |
| remote user `nick@server` | forward to that server |

Loop guard applies at forward time (§2.4).

### 3.2 Message representation

`parse_command()` currently only *counts* tokens; it is replaced by a real
tokenizer:

```c
typedef struct {
    char  *tags;          /* raw tag block, may be NULL */
    char  *prefix;        /* source, may be NULL */
    char  *command;       /* uppercased */
    char  *params[15];
    int    nparams;
    const char *raw;      /* the original line, for faithful echoing */
} message_t;

int  message_parse(const char *line, message_t *out);  /* 0 ok, -1 reject */
void message_free(message_t *m);
```

Rules (RFC 1459 §3.1, §3.3; IRCv3 message-tags):
- optional `@tags`, then optional `:prefix`, then command
- ≤15 params; the 15th absorbs the remainder verbatim
- a param starting `:` consumes the rest of the line
- total line ≤512 bytes including CRLF (RFC 1459 §2.3)
- embedded CR/LF or NUL in the middle → reject
- **accepts a leading `:` prefix**, which is what makes peer messages parse
  identically to local ones

### 3.3 Connection framing

```c
typedef struct conn {
    /* ... identity fields above ... */
    char   *rbuf; size_t rlen, rcap;   /* read buffer  */
    char   *wbuf; size_t woff, wlen, wcap;  /* write queue, partial-write safe */
} conn_t;
```

Partial writes matter: nonblocking `send()` may write fewer bytes than
offered, so `woff` is retained and drained across poll iterations.

### 3.4 Event loop

**Single-threaded `poll()`.** Not `epoll`/`kqueue`: portable across Linux and
macOS, one file, and the `FD_SETSIZE` 1024 ceiling is acceptable for this
scope. Document the limit; migrate only if measured load demands it.

```
src/core/poll_loop.c   poll() dispatch, EINTR-safe, 50ms tick (also drives heartbeat)
src/core/server.c      server_t lifecycle, registries, link management
src/core/connection.c  conn_t buffers, framing, lifecycle
src/core/message.c     message_parse / message_free / formatter
src/core/fanout.c      §3.1 routing table
src/federation/link.c  peer sockets, handshake FSM driving, keepalive
```

---

## 4. Command surface

### 4.1 Client commands — MUST

`PASS` `NICK` `USER` `PING` `PONG` `QUIT` `JOIN` `PART` `PRIVMSG` `NOTICE`
`TOPIC` `NAMES` `MODE` `KICK` `KILL`

### 4.2 SHOULD (Phase 6)

`WHO` `WHOIS` `ISON` `LIST` `AWAY` `INVITE` `MOTD` `LUSERS` `ADMIN` `INFO`
`USERHOST` `KNOCK` `CHOPER`

### 4.3 Server-to-server (internal, not client-facing)

`FEDERATE` (link handshake — existing FSM) `SJOIN` `SPART` `SPRIVMSG` `SNOTICE`
`STOPIC` `SNAMES` `SSMODE` `SKICK` `SQUIT` `SHASH`

These are the internal verbs behind the client commands. Designing them as
*distinct verbs* rather than reusing `JOIN`/`PRIVMSG` is what keeps the wire
protocol unambiguous and lets a node distinguish "a user joined" from "a
server tells me a user joined" — which is what makes loop prevention and
ownership decidable.

### 4.4 Numerics

Registration `001`–`005`; channel `331` `332` `333` `353` `366` `324` `329`;
query `311`–`319` `321`–`323` `351`–`352` `315`; server info `251`–`266`
`372`–`376`; errors `401` `403` `404` `405` `421` `422` `431` `433` `441` `442`
`443` `451` `461` `462` `464` `465` `482`.

`005` with `PREFIX=(ov)@+`, `CHANTYPES=#&`, `NETWORK=` is effectively
mandatory — many clients misbehave without it.

---

## 5. Fix the weak and fake parts

| Item | Problem | Action |
|---|---|---|
| `ircv3_tags.c` | `tags_parse` and `tags_serialize` are the same function; roundtrip is vacuous; no escaping | Real parse → tag list, real serialize, and IRCv3 escaping (`\:` `\;` `\s` `\\` `\r` `\n` + lone-`\` rule) **both ways**. Doubles as the internal `@irc-serve-*` transport tags (§2.4) |
| `sasl_framework.c` | not in `irc_core`; `sasl_step` discards input, auto-completes after 2 calls; self-test harness lives in `src/` | Move the harness to `tests/`; implement real SASL PLAIN (base64 → `authzid\0authcid\0passwd` → credential store). Credentials are per-server, so a federated deployment shares via link auth |
| `message_id.c` | orphan, not compiled, not tested, global counter, not IRCv3-shaped | Fold into §2.4: ids from the per-connection monotonic counter + origin server, unique without a global lock |
| `lockfree_contract.c` | `volatile int`, one writer, no atomics | **Delete.** The single-threaded loop needs no lock-free structure. The claim comes out of the docs |
| `server.c` | `printf` theatre; parses literal `"PING"` | Rewrite as the real `server_t` |
| `node_main.c` | closes every client immediately (line 115) | Keeps its real `socket`/`bind`/`listen` and signals; loop becomes §3.4; port configurable, not hardcoded 6667 |

**Preserved as-is:** `parse_nick` / `parse_user` (correct validation
discipline — becomes the house rule) and `federation_handshake.c` (real FSM,
becomes the peer-link driver).

---

## 6. Test strategy

Every test skipped or faked is what let a green suite coexist with a
non-functional server. Wire-level integration tests are mandatory from Phase 2.

### 6.1 Harness

```c
/* tests/harness/irc_client.h — blocking client against a spawned server */
int  tc_connect(test_client_t *c, int port);
int  tc_send(test_client_t *c, const char *line);           /* appends CRLF */
int  tc_expect(test_client_t *c, const char *needle, int timeout_ms);
void tc_close(test_client_t *c);
```

Servers bind port 0 and report the chosen port, so tests never collide. Tests
assert on **wire output**, so they survive internal refactors.

### 6.2 Two-node harness

Federation needs a multi-node harness, not just a client:

```c
/* spawn a second node in-process or as a child, connect two via an
   in-memory pipe pair, drive both, assert convergence */
int  two_node_fixture(fixture_t *f);   /* node A + node B + peer link */
```

This is what proves "seamless" rather than asserting it.

### 6.3 No flaky sleeps

`tc_expect()` polls with a short `select()` timeout in a loop until the
substring arrives or the deadline expires. **No fixed `sleep()` anywhere** — a
fixed sleep is the leading cause of CI flake.

### 6.4 Skip gate

`KNOWN_SKIPS` in `tests/CMakeLists.txt` lists every legitimately-skipped test.
CI fails if a test reports `Skipped` and is not listed, and `KNOWN_SKIPS` must
reach empty by Phase 6. This closes the `return 77` blind spot that let 8 dead
tests pass unnoticed.

---

## 7. Phased plan

Each phase ships leaving the server working. Federation seams land early and
are exercised early, so no phase ends with a structural rewrite pending.

**Phase 1 — Tokenizer.** `message_t` + `message_parse`, **including leading
`:` prefix and hidden internal tags** (not deferred — this is the seam).
*Accept:* unit tests for trailing params, 15-param cap, oversized lines,
embedded control chars, peer-style prefixed lines. Existing `parse_nick`/
`parse_user` tests stay green.

**Phase 2 — Server core.** poll loop, `conn_t`, framing, registries.
*Accept:* a client connects and is closed cleanly (assert accept → EOF).
First phase where the binary does something real.

**Phase 3 — Registration + single-node correctness.** NICK/USER/PASS,
numerics 001–005, MOTD, PING/PONG, QUIT, 433. *Accept:* integration test
registers and receives `001` and `005`; duplicate nick → `433`.

**Phase 4 — Channels.** JOIN/PART/TOPIC/NAMES/LIST/KICK/MODE, ownership
established (locally that means `origin == self`). *Accept:* two clients join
`#t`, each sees both in `353`; `332`/`333` on TOPIC; non-op KICK → `482`.

**Phase 5 — Messaging. ← "working server" milestone.** PRIVMSG/NOTICE with
fan-out through §3.1, `WHO`/`WHOIS`/`ISON`, `AWAY`. *Accept:* two clients
exchange a PRIVMSG; NOTICE not echoed to sender.

**Phase 6 — Federation link. ← the federation test.** Peer socket, existing
handshake FSM driving, `FEDERATE`, `SJOIN`/`SPART`/`SPRIVMSG`/`STOPIC`, origin
tag + dedup. *Accept (two-node fixture):* a user on node A JOINs a channel and
a user on node B JOINs the same channel; both see each other; a PRIVMSG from A
reaches B exactly once; a two-node ping-pong does not loop.

**Phase 7 — Command surface + skip gate empty.** The SHOULD commands; CI fails
on any skip. *Accept:* zero skipped tests.

**Phase 8 — IRCv3.** Real tag escaping + roundtrip, CAP negotiation
(LS/REQ/ACK/NAK), real SASL PLAIN, message-ids. Turns the 5 skipped IRCv3
tests green.

**Phase 9 — Federation hardening.** Link failure/reconnect, re-sync on
reconnect, peer discovery, heartbeat-driven failover. This is where the
existing `federation`/`loadbal` issues belong.

Parallelisable: Phase 1's tokenizer and the IRCv3 tag-escaping work are
independent. Phase 2 blocks the rest. Phase 6 is the largest single phase and
should not be split across people.

---

## 8. Definition of done

Single node:
- [ ] Zero skipped tests; CI fails if any test is skipped
- [ ] Two clients connect, register, `#JOIN` a channel, exchange a `PRIVMSG`,
      `#QUIT` cleanly
- [ ] All MUST commands and numerics in §4 implemented
- [ ] `005` advertises `PREFIX=(ov)@+`, `CHANTYPES=#&`

Federated:
- [ ] Two-node fixture: cross-server join visibility, cross-server `PRIVMSG`
      delivered exactly once, no message loops
- [ ] Link loss and reconnect re-syncs channel state
- [ ] Nick collision between nodes resolves without a global lock

Quality:
- [ ] ASan/UBSan/LeakSanitizer clean
- [ ] CI green on gcc and clang, Release and Debug
- [ ] `SPEC_TRACKING.md` matches source, verified by reading it
- [ ] No test asserts internal plumbing

---

## 9. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Scope: 9 phases | never ships | MUST set (§4.1) + Phase 5 is the ship line; the rest follows |
| Federation loop bugs | message storms, outages | Origin tag + dedup specified in §2.4, tested in Phase 6 before anything builds on it |
| Integration test flake | suite loses credibility | `tc_expect()` polling, no sleeps, generous deadlines |
| poll() FD_SETSIZE 1024 | caps connections | Document; measure before epoll |
| Rewriting the good parsers | loses real work | Existing tests stay green as a Phase 1 gate |
| Buffer overflows in formatting | memory safety | bounds-checked formatters; ASan in CI from Phase 2 |
