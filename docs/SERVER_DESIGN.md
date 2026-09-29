# IRC Server Design — Federation-Native Architecture

Status: **authoritative design**. Supersedes the status claims in
`SPEC_TRACKING.md` and `ARCHITECTURE.md`, which overstate what is implemented.

Date: 2026-09-28. Source claims verified against the tree; see `docs/SPEC_TRACKING.md` for the per-phase audit.

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
| global nick table | `nick@server` per-server nick table | keys are distinct, so no global lock; network-visible ambiguity is a separate rename policy (§2.1) |
| channel is one struct | channel has an **origin server**, per-member list plus a per-channel set of member-servers | forward only to the servers that actually hold members |
| one conn type | `conn_t` has a `kind` (client \| server) | peers and clients share the parse/dispatch path — not the reply path (§3) |

The result: adding a peer link is ~400 lines of transport and handshake. No
command handler, registry, or protocol change.

---

## 2. Core data model

Everything below is single-threaded behind one event loop, so no structure
needs internal locking. That is deliberate — and it is *not* because of
federation; §3.4 gives the actual reason.

### 2.1 Identity: scoped nick

```c
typedef struct conn {
    int      fd;
    int      kind;              /* CONN_CLIENT | CONN_SERVER */
    char    *peer_name;         /* server name, for CONN_SERVER */
    char     nick[64];          /* local nick, pre-@ */
    char     user[64], host[128], realname[256];
    int      state;             /* REG_PASS | REG_NICK | REG_USER | REG_READY | CLOSING */
    /* no per-conn id: message ids come from server_t (§2.4) */
    struct chan **chans; size_t nchans, cap;   /* channels this conn is in */
} conn_t;
```

The **qualified name** `nick@server` is computed on demand:

```c
char *qualify(const conn_t *c, char *out, size_t cap);
```

`@ # & + ! : ;` are not legal nick characters, and the first character may not
be a digit, so `nick@server` is unambiguous and splits at the **last** `@`. A
local `valid_nick()` predicate enforces this (§7 Phase 1) — `parse_nick` as it
stands does not; see §5. The digit rule is **RFC 2812 §2.3.1**: the first
character of a nickname is a letter or a "special", and a digit is neither. A
peer may enforce the same rule, depending on its implementation; a nick this
node holds that a peer will not accept is already divergence, and federation
stays cheap only while the nodes agree. It is *not* a wire-parsing rule: the
parser keeps prefix and command word in separate fields, so `:123 PRIVMSG #c :hi`
and `:server 123 target :text` are distinct. `:` is the prefix and
trailing-parameter marker in §3.2's grammar; `;` is the IRCv3 tag separator.

Nick uniqueness is enforced **per server**, not globally, and needs no policy and
no lock: `bob@a` and `bob@b` are distinct registry keys, so there is no
collision to resolve. This is exactly the behaviour of a single node, so nothing
changes for a lone server.

That is not sufficient. `bob` on two servers is just `bob` to a user.
Network-visible nick ambiguity needs a **rename-the-loser** policy plus a
**nick-registry broadcast**; that lands in **Phase 9**. Until then, duplicate
nicks across servers are user-visible and undefined.

### 2.2 Channels: origin-owned

```c
typedef struct chan {
    char      name[64];         /* always uppercase-normalised */
    char      origin[64];       /* server that first created it */
    char      topic[256], topic_who[64]; time_t topic_when;
    char      modes[32];
    struct member { conn_t *c; } *members; size_t nmembers, cap;  /* LOCAL members only */
    struct server **servers; size_t nservers, scap; /* refcounted: servers with >=1 member */
} chan_t;
```

A `chan_t` holds **only local members**. Remote membership is *implicit*: the
peer links that reported it, plus a refcounted `servers[]` set recording which
servers hold at least one member. Without `servers[]` the §3.1 row "forward to
peers holding members" cannot be evaluated, and `353` cannot be answered for a
channel that is mostly remote.

**The second half of that sentence is now partly untrue, and the correction is
recorded here rather than left to a reader to derive from the code.** A `chan_t`
holds only local members *in `members[]`*; remote membership is a `remotes[]`
roster **plus** the `servers[]` set. What changed is that the *names* are kept
rather than being derivable: a node cannot name a member it has never heard the
name of, and `353` is the whole of 4.2's answer for a channel the node is not in.
The `servers[]` half is still exactly true and is still what §3.1's forward target
set is built from.

The roster is keyed by `(nick, server)`, and its entry carries a `host` as well as
a nickname and prefix flags:

```c
typedef struct chan_remote {      /* one user on another server */
    char     nick[64];
    char     server[64];          /* the 2.3 server holding them   */
    char     host[128];           /* "" until a resync supplies it */
    unsigned flags;               /* +o / +v, as for a local member */
} chan_remote_t;
```

**`host` is filled by §4.3's `SBURST` and by nothing else, and an empty one is the
normal state rather than a defect.** A live `SJOIN` carries no host, so a member
learned from one has `host == ""` and only a resync can fill it — and a resync is
the rarer event. Anything that renders a remote member has to handle the empty case
rather than printing half a `nick!user@host`. The reason `server` is part of the
key is 2.1: duplicate nicks across servers are undefined until Phase 9's
rename-the-loser, so a nickname alone is not an identity here.

The claim "a server never stores remote state" is **false** — `topic` /
`topic_who` / `topic_when` are already remote-originated. The honest rule:
**local state is authoritative; a bounded per-channel remote cache holds topic,
modes, and the member-server set.** That cache is O(servers) plus a bounded roster,
not O(users), so it does not reintroduce per-join broadcast cost.

**Ownership rules:**
- First server to see a channel owns it. The creation race is broken by
  `(creation_epoch, server_name)`, higher wins; the loser re-keys to the
  winner's origin. Both halves are single-node-testable in Phase 4.
- For an **owned** channel: apply joins/parts/topics locally, and forward to
  each peer in `servers[]`.
- For a **non-owned** channel: forward the action to the owner. Verb-dependent —
  see the verb class in §3.1.

**Single-writer rule — the highest-leverage rule in the design.** A node never
applies a channel state change it cannot route to the channel's origin; it
refuses the action (`437`). It does not queue and apply later. This converts
permanent divergence into transient, self-healing divergence.

**Owner death — fail closed.** Origin is immutable for a channel's lifetime.
With no ESTABLISHED link to the origin the channel is **locally orphaned**:
local members still see each other, but origin-requiring actions are refused
with `437`. Re-linking a server of the same name resurrects the channel.
Re-election instead is out of scope — see §9.

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

**Peer auth is not user SASL.** A peer connection is exempt from the client
registration state machine entirely: no `PASS`/`NICK`/`USER`, no `001`–`005`, no
MOTD. It authenticates with the `FEDERATE` handshake secret and is **rejected
before `ESTABLISHED`**. Server-name uniqueness is enforced at the same point —
two nodes both named `irc.a` is catastrophic and undetectable later. Peer
discovery and auto-scale stay Phase 9.

### 2.4 Loop prevention and dedup

Every relayed message carries hidden internal tags:

```
@irc-serve-origin=<server>;irc-serve-epoch=<n>;irc-serve-id=<n>;irc-serve-hops=<n>  :<server> PRIVMSG #chan :hi
```

- Ids come from a **per-SERVER monotonic counter owned by `server_t`** — not a
  per-connection counter. A per-connection counter makes two connections on
  server A both emit `(a,1)`, and a peer then silently drops the second.
- `epoch` is a per-boot value, so a restart resets the counter without colliding
  with pre-restart ids.
- Dedup key is `(origin, epoch, id)`, scoped **per node** — not per peer.
  Per-peer dedup does nothing in a 3+ node mesh where a message arrives by two
  paths.
- `irc-serve-hops` increments per forward and the message is dropped at 10.
- A node never forwards a message whose `irc-serve-origin` is itself.
- All `irc-serve-*` tags are stripped before delivery to clients.

Hop count + never-forward-own-origin + per-node `(origin,epoch,id)` dedup is
sufficient here; the per-connection counter and the per-peer LRU are not, which
is why that scheme was replaced. The per-connection notion is deleted, not
deprecated. Phase 1 freezes **this** format rather than a placeholder: the
previous draft's format was wrong, and Phase 1 tests would have locked the bug
in. The tag BLOCK grammar (`@k=v;k2=v2`) is Phase 1 as well.

Vector clocks and causal delivery are **deliberately rejected**: the state space
is tiny, full-state resync on link change (§4.3) is sufficient, and TCP already
gives per-link ordering. Do not reopen this in Phase 9.

Without these rules two nodes bounce a message forever. This is the single most
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

"One path" is true of **parsing and dispatch** and false of the **reply path**,
which is a separate concern. The original claim was overstated:

- Numerics are **never** written to a peer link and never relayed. Enforced in
  exactly one `reply()` function, never ad hoc per handler.
- `src` may be **NULL** for server-originated messages — `SQUIT`, a peer `KILL`,
  a resync burst. `reply()` documents what NULL means per numeric.
- A **deferred-reply** mechanism is required for any handler needing remote
  information (`SNAMES`, remote `WHO`/`ISON`), because the loop cannot block.

### 3.1 Fan-out rules

| Target | Verb class | Action |
|---|---|---|
| local user | either | write to `conn_t` |
| owned channel | `message` | write to each local member **and** forward to every peer in `servers[]` ∪ every `ESTABLISHED` link — the same forward arm as `state-change` |
| owned channel | `state-change` | apply locally **and** forward to every peer in `servers[]` ∪ every `ESTABLISHED` link |
| non-owned channel | `message` | write to local members **and** forward to the owner |
| non-owned channel | `state-change` | **forward only** — never a local write |
| remote user `nick@server` | either | forward to that server |

The verb class is what resolves the old table's self-contradiction: a non-owner
with local members matched both "remote channel → forward only, no local write"
and "local channel with remote members → write locally AND forward".
Concretely, `SPRIVMSG` to a non-owned channel does **both** (local write +
forward to owner); `SJOIN` does **only** forward. §2.2's "do not broadcast" is
true only for state-changes.

After the amendment above the class decides one thing only: **whether the caller
also writes locally.** It no longer selects a forward target set — the two owned
rows name the same one and the two non-owned rows name the same one. A `message`
that a node has nobody to deliver to is still forwarded, because membership this
node happens to hold is not evidence about whether the line should travel.

**Correction (Phase 6, corrective pass after C3): the owned/`message` row's
stated reason was wrong.** It read *"write to each local member; no forward — the
origin already holds every member"*, and "the origin already holds every member"
is false on a mesh of three or more nodes. The origin holds those members in its
**remote roster**, and a roster entry is not a delivery path: only a peer link
can deliver to them. The row is recorded rather than silently rewritten, because
the original claim is exactly the kind of thing a reader re-derives from the
code and believes, and because a table that was wrong for a whole phase is
evidence that the reasoning — not just the row — needs to be visible.

Three consequences, which is why it is written down:

- The origin forwarded nothing, so a member sitting on a **third** node never
  heard a message for a channel it was on. The channel looked live from inside
  the origin and silent from the far side.
- A relay node in a mesh exists to carry a message onward to servers the origin
  holds no members on directly. With the old row there were **no such relays**:
  the only path a `message` took across a link was leaf → owner, so a node that
  was neither origin nor leaf never received one.
- That made Phase 6's fifth acceptance criterion — *"a node with zero local
  members in the channel still relays that channel's `SPRIVMSG` to the owner"* —
  **unreachable from the code as specified**. It is reachable now, and
  `test_fed_relay.c` asserts its literal wording rather than a client `NOTICE`
  substitute.

**The cost, stated plainly.** An owner re-broadcasts, so a channel whose members
sit on *N* member-servers costs *N* forwards per message where it cost 1, and an
owner holding no local member of a channel now spends a forward on a message it
delivers to nobody. `servers[]` ∪ `ESTABLISHED` links is a broadcast, not a
unicast (§3.1's topology paragraph below concedes exactly that). This is bought
with a loop that did not exist before: see the guard note.

**The second half of that cost had no test until C4, and the reason is worth
recording because it is a property of the table rather than of the code.** The
amended `owned`/`message` row applies whether or not the owner has a local member,
and a fault injected at the spot where the forward is emitted — gating it on the
local write's result — produced **no failure at all**, because in every message
test the owner did have somebody to write to. Reaching the zero-member owner
takes a PART, and only a PART: the owner is left owning a channel with
`nmembers == 0` and `nservers >= 1`, which is precisely the state
`chan_dispose_if_empty()` exists to keep. `test_fed_relay.c` now asserts that row
on **both** sides of it — a non-owner with no local member, and an *owner* with no
local member — because the two are different rows of this table and a forward arm
serving both is not evidence that either is right.

**Topology.** Full mesh, one bidirectional link per pair of nodes, and a node
relays onward from peer P to peer Q. Forwarding to each peer holding members
*is* a broadcast — the earlier claim of "no broadcast of every join to every
node" was wrong for a full mesh. What is avoided is the *global* list: fan-out
targets the member-server set plus the node's own links, never every node.

**Loop guard applies at forward time (§2.4), and the amended `message` row is
what makes it load-bearing.** Owner and relay can now hand one message back and
forth, so §2.4's three rules bound the bounce rather than being belt-and-braces
around a topology that could not loop: the `hops` ceiling bounds how far it
spreads, never-forward-own-origin stops the copy returning to the server whose
client wrote it, and the per-node dedup store drops the copy that comes back to a
node that has already seen that `(origin, epoch, id)`. Exactly one bounce is the
*designed* behaviour and is asserted as such — `test_fed_loop.c` waits for it,
requires it to be exactly one, and then requires the counters to stop moving.

### 3.2 Message representation

`parse_command()` currently only *counts* tokens; it is replaced by a real
tokenizer:

```c
typedef struct {
    char  *tags;          /* tag block, WIRE form (escaped), may be NULL */
    char  *prefix;        /* source, may be NULL */
    char  *command;       /* uppercased */
    char  *params[15];
    int    nparams;
    const char *raw;      /* original line; SECOND region of buf */
    char  *buf;           /* the one heap allocation described below */
} message_t;

int  message_parse(const char *line, message_t *out);  /* 0 ok, -1 reject */
int  message_parse_n(const char *line, size_t len, message_t *out);
int  message_build(message_t *out, const char *tags, const char *prefix,
                   const char *command, const char *const *params, int nparams);
void message_free(message_t *m);
size_t message_format(const message_t *m, char *out, size_t cap);
```

**Memory model.** `message_parse` allocates **one** heap buffer; `tags`,
`prefix`, `command` and `params[]` are interior pointers into it and
`message_free` frees once. The buffer has **two regions**: the received line,
verbatim, at the front — that is what `raw` points at — and the parsed fields,
NUL-terminated and packed, after it. `raw` is therefore a **second region of the
same single allocation, not the same bytes as the fields**. Keeping them apart
is the whole point: NUL-terminating the fields in place inside the line is the
natural-looking approach and it destroys `raw`, because there is then no longer
any copy of the original line. The formatter **always re-renders** and never
echoes `raw` — echoing `raw` would relay internal `irc-serve-*` tags to
clients, which the previous draft contradicted itself about. The seam is
parse↔format, so Phase 1 tests both, not parse alone.

**Tag storage is WIRE form; unescaping happens on lookup.** `tags` is the tag
block byte-for-byte as it arrived, with IRCv3 escaping still applied. It is
plainly *not* undecodable bytes — it is a valid, still-escaped block whose
separator structure is walkable as received. The escape boundary sits between
**storage and lookup**: the parser stores the escaped form untouched, and
`message_tag_get()` unescapes a single value at the moment it is asked for.
Unescaping the whole block at parse time was rejected because the block's own
`;` separators are only unambiguous *while escaped*, so a block unescaped in
bulk re-splits incorrectly. The reverse direction is `message_tag_escape()` /
`message_tags_format()`, which escape on the way out.

**Two parse entry points, not one.** `message_parse()` takes a NUL-terminated
`const char *`; `message_parse_n()` takes an explicit byte count. A NUL
terminates a C string, so `message_parse()` is structurally blind to any byte
after the first NUL and cannot reject an embedded one. The framing layer of
§3.3 knows the frame length, so it uses `message_parse_n()` and gets the
embedded-NUL rejection, which is a hard requirement. `message_build()` is the
outbound constructor: `message_format()` renders from a `message_t`'s fields,
so without `message_build()` nothing could be sent.

Rules (RFC 1459 §3.1, §3.3; IRCv3 message-tags):
- optional `@tags`, then optional `:prefix`, then command
- ≤15 params; the 15th absorbs the remainder verbatim
- a param starting `:` consumes the rest of the line
- total line ≤**8192** bytes including CRLF, decided here because this is the
  place the rule is enforced. 512 is the RFC 1459 §2.3 floor; irssi and weechat
  send 8192 and ratbox uses 8192 server-to-server, so a 512 cap truncates honest
  clients
- **Relay truncation policy:** the §2.4 internal tags add bytes to a relayed
  line, so the client-facing cap is `8192 − worst-case tag overhead (179)`. A
  ~500-byte client `PRIVMSG` to a remote channel stays legal — under the
  rejected 512 cap it would already have been over. A line that still exceeds
  the on-wire cap is **dropped with a client-side notice**, never silently
  truncated mid-parameter

  The 179 is derived, not estimated, and the derivation is spelled out because
  the earlier figure of `~96` here was wrong and Phase 6 must not hardcode it:

  ```
    1   '@'                    block marker
   17   irc-serve-origin=      16 name + '='
   17   ;irc-serve-epoch=      1 + 15 name + '='
   14   ;irc-serve-id=         1 + 12 name + '='
   16   ;irc-serve-hops=       1 + 14 name + '='
    1   ' '                    block/prefix separator
   --
   66   fixed
   63   origin                 <= IRC_MAX_SERVER_NAME (§2.3)
   20   epoch                  <= UINT64_MAX, 20 digits
   20   id                     <= UINT64_MAX, 20 digits
   10   hops                   <= UINT32_MAX, 10 digits
   --
  113   values
   ==
  179   worst case
  ```

  The four tag names with their `=` are 61 bytes before a single value byte
  appears, which is most of what `~96` missed. 179 is the **exact** worst case,
  not a padded one: the largest legal block measures 177 and the `@` plus the
  one separating space are the remaining 2. The cap must equal the largest
  **legal** tag set rather than an average or a rounded guess, because a
  relayed line that overruns the on-wire limit is precisely the failure the
  constant exists to prevent. Phase 1 formats a maximally-long legal block and
  asserts the measured overhead **equals** 179, so raising a value bound above
  without re-deriving fails the suite instead of the network.
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

Single-threading is kept because the state is *node-local*, not because
federation is concurrent. Federation is **distribution**: no state is shared
between nodes, so there is nothing for a lock to guard. Threads would make this
*harder* — every registry would need a lock, and the §2.2 ownership rules are
far easier to reason about against a single writer. The event loop, not the
threading model, is what makes federation tractable.

What the loop actually forces — all of it Phase 2:

- **Nonblocking dial with a dial state machine.** A blocking `connect()` stalls
  every client on the node.
- **The poll tick drives time**, not wall-clock calls scattered in handlers:
  handshake timeouts, link liveness, and dedup LRU eviction.
- **Bounded write queues**, ~256 KB per connection. A saturated peer link is
  **dropped**, not buffered.
- **The send path never closes a connection.** It marks `CLOSING`; a reaper runs
  at a fixed point in the loop.
- **Peer addresses are pre-resolved.** Any `getaddrinfo` in the loop blocks it.
- **Explicit `if (fd >= FD_SETSIZE) reject`** at every accept/dial site.

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

### 4.2 SHOULD (Phase 7)

`WHO` `WHOIS` `ISON` `LIST` `AWAY` `INVITE` `MOTD` `LUSERS` `ADMIN` `INFO`
`USERHOST` `KNOCK` `CHOPER`

### 4.3 Server-to-server (internal, not client-facing)

`FEDERATE` (link handshake — existing FSM) `SJOIN` `SPART` `SPRIVMSG` `SNOTICE`
`STOPIC` `SNAMES` `SSMODE` `SKICK` `SQUIT` `SHASH` `SBURST`

These are the internal verbs behind the client commands. Designing them as
*distinct verbs* rather than reusing `JOIN`/`PRIVMSG` is what keeps the wire
protocol unambiguous and lets a node distinguish "a user joined" from "a
server tells me a user joined" — which is what makes loop prevention and
ownership decidable.

**`SBURST` is the resync verb.** On **every** link establishment the initiator
sends full state:

- server name + `epoch`
- all nicks: `user` / `host` / `modes` / `away`
- all channels: `origin`, `topic`, topic-set-time, `modes`, and a per-member list

A resync **replaces** state for that origin; it never merges. There is no
partial burst and no delta. `SBURST` is **Phase 6**, not Phase 9 — it defines the
wire format, and a wire format cannot be invented later.

#### 4.3.1 The wire format, frozen in Phase 6

One line per record, and one line per **member** rather than a packed member
list. Five verbs:

```
:<origin> SBURST  <epoch> <nnicks>
:<origin> SBURSTN <nick> <user> <host> <modes> <signon> :<away>
:<origin> SBURSTC <chan> <origin> <topic_who> <topic_when> <modes> :<topic>
:<origin> SBURSTM <chan> <nick> <flags>
:<origin> SBURSTE <epoch> <nnicks> <nchans> <nmembers>
```

Every line carries §2.4's internal tag block with `hops=0`, and the id is
**different per line** — a burst is O(n) lines, and one id for the transaction
would leave every record after the first dropped as a duplicate. The prefix is
the burst origin. `<epoch>` is how a peer restart is detected, and it is also how
`server_link_t::epoch` is populated on the far side; a terminator whose epoch
differs from the link's is a restart, and the link adopts it, because §2.4's dedup
key pairs the epoch with the id and a mismatched pair aliases. An empty middle
parameter is the literal `-` (empty middle tokens are unrepresentable — see 3.2);
`<flags>` is `-`, `o`, `v` or `ov`, **not** the SJOIN token's `+ov`.

**One line per record, and not a packed list, is the load-bearing choice.** `topic`
is 256 bytes and `away` is 256 bytes and both may contain spaces, `:` and `;`, so
a packed list needs an escape alphabet — and every escape alphabet is a second
grammar to get wrong on both sides of a wire that cannot be revised. There is also
no legal separator: §2.1's `valid_nick()` excludes `@ # & + ! : ;` and every byte
`<= 0x20` but **accepts `,`, `%` and every byte `>= 0x80`**, so `nick,nick` and
`nick%nick` are both legal nicknames and neither can be forbidden. One line per
record sidesteps the whole thing, because 3.2's formatter already refuses a
parameter containing SP/HTAB/CR/LF, refuses `:` outside the final position, and
renders the final parameter colonned: **there is no escape function and no
delimiter.** The price is bytes, and it is charged against a bound rather than a
line length — see below.

**It is a BEGIN/COMMIT transaction because a receiver cannot know a burst has
ended unless it is told.** Records accumulate in a shadow and are installed in one
step at `SBURSTE`, so a burst that stops half way is invisible. `SBURSTE`'s three
counts are **asserted against what was accumulated, never trusted**: a mismatch is
a truncated transaction and the whole thing is discarded, leaving the previous
state untouched. The shadow is discarded on a count mismatch, on a volume overrun,
on a malformed record, on a link drop, and on a new `SBURST` beginning; a guard
rejection *mid*-burst needs no separate rule, because every record a burst can
carry is counted and a dropped one makes the terminator disagree.

**The budget is volume, not line length.** The worst case is 753 bytes for
`SBURSTC` and 787 for `SBURSTN` against an `IRC_MAX_LINE` of 8192 — 9%, so a
per-line check would be a formality. The real constraint is that 3.4 **drops** a
saturated peer link rather than buffering it, and a burst is O(nicks + members), so
a large node's burst can be megabytes and queueing it all would starve every live
message behind it. A burst is therefore assembled into a staging buffer of
`IRC_BURST_MAX_BYTES` = `CONN_WQ_MAX / 2` — half a link's queue, so a resync can
never crowd out a live message — and a burst that does not fit is **refused in
full** with one `n_burst_refused`: nothing queued, the link untouched, no
truncation. The receiver charges every record against the same bound, because the
shadow is memory made out of what a peer *said*. `fanout_line_fits()` is not used:
it charges the *client* envelope (a 64-byte channel name and a 64-byte hostmask)
against `IRC_MAX_RELAY_LINE`, and a `SBURST*` line is neither.

**Both sides burst, which is a deliberate superset of "the initiator sends full
state".** A node only forwards to peers that already hold the `chan_t`, so if only
the initiator burst, the responder's channels would never reach the initiator: in a
two-node fixture a user on the responder would be invisible to the initiator for
ever, and Phase 6's full-`353` criterion would fail on one of the two nodes. Both
sides bursting is a superset of the sentence above, costs one extra burst per link,
and is what makes "on **every** link establishment" mean what a reader expects. The
two transactions cross on the wire and neither waits for the other: a burst is a
statement about the sender, and the sender's state does not change because somebody
received it.

**What Phase 6 deliberately does not do.** The burst is the origin's own state, not
a relayed one: a burst whose tag block names a third server is refused, and the
whole family is refused *untagged*, because a node that could replace its entire
view of an origin with lines whose 2.4 identity the receiver invented has no loop
prevention at that point. A member record is keyed by the **burst origin**, not by
the member's own server, because 4.3's frozen `SBURSTM` carries no server field;
that is exact on a two-node mesh and a cache on a larger one, and a member the
receiver already knows under any key is left alone rather than installed twice —
two entries for one person is a `353` that renders the same nickname twice with
nothing on the node able to explain it. `SBURSTN` carries `user`, `modes`, `signon`
and `away` and the receiver keeps only `host`; the rest are for 2.1's remote-nick
registry, which is Phase 9. A channel's creation race is **not** re-keyed from a
burst: 2.2's tie-break needs the (epoch, name) of the *first* creator and the wire
carries one epoch. **Driving** the resync — link loss, reconnect, backoff — is
Phase 9, which is why 8's "link loss and reconnect re-syncs channel state via
`SBURST`" is still open: Phase 6 owns the verb and the format, not the policy.

### 4.4 Numerics

Registration `001`–`005`; channel `331` `332` `333` `353` `366` `324` `329`;
query `311`–`319` `321`–`323` `351`–`352` `315`; server info `251`–`266`
`372`–`376`; errors `401` `403` `404` `405` `421` `422` `431` `432` `433` `441` `442`
`443` `451` `461` `462` `464` `465` `482`.

Three more, each added when a phase needed it and each a gap in the list above:
`301` `RPL_AWAY` (WHOIS away text — the only numeric that can carry an away
message, so without it "WHOIS reflects AWAY" is unimplementable); `303`
`RPL_ISON`; and `417` `ERR_INPUTTOOLONG` (an over-long away message is
**refused**, not truncated — truncating would store a message the user did
not write and then report it in `301` as theirs).

`432` `ERR_ERRONEUSNICKNAME` is for a nickname that is **malformed** — illegal
under §2.1. It is distinct from `433` `ERR_NICKNAMEINUSE`, which is for a legal
nickname already claimed. The two must not be conflated: answering an illegal
nickname with `433` tells the client the name is taken, so it retries with a
different name on a false premise, and the real cause is never surfaced.

`005` with `PREFIX=(ov)@+`, `CHANTYPES=#&`, `NETWORK=` is effectively
mandatory — many clients misbehave without it.

---

## 5. Fix the weak and fake parts

| Item | Problem | Action |
|---|---|---|
| `ircv3_tags.c` | `tags_parse` and `tags_serialize` are the same function; roundtrip is vacuous; no escaping | Real parse → tag list, real serialize, and IRCv3 escaping (`\:` `\;` `\s` `\\` `\r` `\n` + lone-`\` rule) **both ways**. Doubles as the internal `@irc-serve-*` transport tags (§2.4) |
| `sasl_framework.c` | not in `irc_core`; `sasl_step` discards input, auto-completes after 2 calls; self-test harness lives in `src/` | Move the harness to `tests/`; implement real SASL PLAIN (base64 → `authzid\0authcid\0passwd` → credential store). Credentials are per-server, so a federated deployment shares via link auth |
| `message_id.c` | orphan, not compiled, not tested, global counter, not IRCv3-shaped | Fold into §2.4: per-SERVER monotonic counter + boot `epoch`, dedup key `(origin,epoch,id)` scoped per node — unique without a global lock |
| `lockfree_contract.c` | `volatile int`, one writer, no atomics | **Delete.** The single-threaded loop needs no lock-free structure. The claim comes out of the docs |
| `server.c` | `printf` theatre; parses literal `"PING"` | Rewrite as the real `server_t` |
| `node_main.c` | closes every client immediately (line 115) | Keeps its real `socket`/`bind`/`listen` and signals; loop becomes §3.4; port configurable, not hardcoded 6667 |

**Preserved as-is:** `federation_handshake.c` (real FSM, becomes the peer-link
driver).

`parse_user` is a good model for buffer/field discipline and is preserved as
such. **`parse_nick` is not preserved as-is**: it does zero character
validation — `parse_nick("NICK a@evil", …)` returns 1 and yields the nickname
`a@evil`. The previous draft claimed both were "correct validation discipline";
that was wrong. A nick **CHARSET RULE IS MISSING** and must be added: `@`,
`#&+!`, `:` and `;` are not legal nick characters, the first character may not
be a digit (RFC 2812 §2.3.1), and `nick@server` splits at the **last** `@`
(§2.1). Add a `valid_nick()` predicate to Phase 1 (§7) — the whole scoped-nick
scheme is unsound without it. The charset is deliberately narrower than "almost
any character": the delimiter set is what later phases build on, and every
character admitted here is one a mode string, a channel list or a prefix is
made of.

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
/* two child processes over real TCP on port 0, deterministic readiness
   handshake, assert convergence */
int  two_node_fixture(fixture_t *f);   /* node A + node B + peer link */
```

Two child processes over real TCP. The in-process / in-memory-pipe-pair option
is **dropped**: hosting two nodes in one process needs either two event loops
or a hand-driven pump, which would make the harness the hardest component in the
project rather than the cheapest. Readiness is deterministic — each child writes
one line to stdout (or to fd 3) once its `poll()` is armed, and the parent waits
for both lines before connecting anyone.

This is what proves "seamless" rather than asserting it.

### 6.3 No flaky sleeps

`tc_expect()` polls with a short `select()` timeout in a loop until the
substring arrives or the deadline expires. **No fixed `sleep()` anywhere** — a
fixed sleep is the leading cause of CI flake.

### 6.4 Skip gate

`KNOWN_SKIPS` in `tests/CMakeLists.txt` lists every legitimately-skipped test.
CI fails if a test reports `Skipped` and is not listed, and `KNOWN_SKIPS` must
reach empty by Phase 7 (Phase 6 is the federation link; the gate lands with
the command surface it protects). This closes the `return 77` blind spot that let 8 dead
tests pass unnoticed.

---

## 7. Phased plan

Each phase ships leaving the server working. Federation seams land early and
are exercised early, so no phase ends with a structural rewrite pending.

**Phase 1 — Tokenizer, tag format, nick rule.** `message_t` + `message_parse` +
`message_format`, **including leading `:` prefix and the hidden internal tags**
(not deferred — this is the seam). The §2.4 tag format
(`origin`/`epoch`/`id`/`hops`) and the `@k=v;k2=v2` block grammar are **frozen
here**, not left as placeholders: the previous draft's format was wrong and
Phase 1 tests would have locked it in. Also add `valid_nick()` (§2.1/§5).
*Accept:* unit tests for trailing params, 15-param cap, oversized lines,
embedded control chars, peer-style prefixed lines; a **round-trip property test**
`parse → format → parse` over values containing space, `;`, `:` and a backslash;
and `valid_nick` rejecting `a@evil`, `a#b`, a leading digit, an embedded `:`
and an embedded `;`. Existing `parse_nick`/`parse_user` tests stay green.

*Accept (hygiene — the seam now owns an allocation, so this is a new
criterion rather than a detail):* exactly **one** allocation per successful
parse; **no leak on any rejection path**; and reusing a `message_t` requires an
explicit `message_free()` first, because `parse` and `build` zero `*out` rather
than freeing what was in it. This is a leak check, so it needs a leak checker,
and the platform limits are not cosmetic: **LeakSanitizer is not supported on
macOS/Darwin.** An ASan build with `detect_leaks=0` runs clean, but asking for
`detect_leaks=1` on Darwin does not report leaks — it hangs. So a green macOS run
of this criterion means "ASan reported nothing", NOT "LSan ran", and it must not
be read as evidence for the no-leak clause. Run the leak clause in CI on a
platform where LSan is supported, and record that as a standing CI step once the
build carries sanitizer flags. Until then this clause is asserted, not verified,
and the tests do not cover the reuse-without-free leak.

**Phase 2 — Server core.** poll loop, `conn_t`, framing, registries.
*Accept:* a client connects and is closed cleanly (assert accept → EOF).
First phase where the binary does something real.

**Phase 3 — Registration + single-node correctness.** NICK/USER/PASS,
numerics 001–005, MOTD, PING/PONG, QUIT, 433. *Accept:* integration test
registers and receives `001` and `005`; duplicate nick → `433`.

**Phase 4 — Channels.** JOIN/PART/TOPIC/NAMES/LIST/KICK/MODE, ownership
established (locally that means `origin == self`). **This phase lands the final
struct shapes**, not a draft that Phase 6 rewrites:

- per-member flags (`+o`/`+v`) on `member` — without them this phase's own
  acceptance criterion "non-op KICK → `482`" is unimplementable
- `353` ordering fixed: nicks, then ops, then voiced
- channel-mode **authority**: only the origin evaluates `+b`/`+e`/`+I`. A
  non-owner's `modes[]` is a cache and cannot enforce
- remote fields present but unpopulated (`servers[]`, remote `topic_who`, …) so
  Phase 6 fills them rather than changing the struct

*Accept:* two clients join `#t`, each sees both in `353` in the fixed order;
`332`/`333` on TOPIC; non-op KICK → `482`; the creation race is broken by
`(creation_epoch, server_name)` with the loser re-keying.

**Phase 5 — Messaging. ← "working server" milestone.** PRIVMSG/NOTICE with
fan-out through §3.1, `WHO`/`WHOIS`/`ISON`, `AWAY`. *Accept:* two clients
exchange a PRIVMSG; NOTICE not echoed to sender.

**Phase 6 — Federation link. ← the federation test.** Peer socket, existing
handshake FSM driving, `FEDERATE`, **`SBURST` resync (§4.3)**,
`SJOIN`/`SPART`/`SPRIVMSG`/`STOPIC`, the origin+epoch+id+hops tags and per-node
dedup. The resync requirement moved here from Phase 9: it defines the wire
format and cannot be invented later. *Accept (two-node fixture, asserted on
**both** nodes):* a user on node A JOINs a channel and a user on node B JOINs
the same channel; the **full `353` contents** on each node, in the Phase 4
order — a truncated roster does not pass; a PRIVMSG from A reaches B exactly
once; a two-node ping-pong does not loop; and a node with **zero local members**
in the channel still relays that channel's `SPRIVMSG` to the owner.

The last of those is only reachable because §3.1's owned/`message` row was
amended — see the correction recorded there; with the original row there were no
relay nodes for the criterion to be about. A message relayed back to where it
came from is **expected** under the amended row and is bounded by §2.4 rather
than forbidden by the routing table: `test_fed_loop.c` requires exactly one such
bounce and then requires the loop counters to stop moving.

*Accept status after C4 (what is provably met, and what is not).* Criterion 2 is
met **after a resync** as well as before one, which is the stronger form: three
resyncs over one established link, and the full `353` contents on both nodes after
each. The replace-not-merge property behind the word "resync" has four distinct
tests, and two of the four could **not** be produced by client commands on a
two-node mesh at all — a member the origin loses is always removed on the far side
by an `SPART` first, and a channel A no longer has is always removed by its
forwarded `PART` — so the fixtures create those states deliberately and say so.
Not met, and deliberately so: **link loss and reconnect driving a resync** is
Phase 9, so §8's "link loss and reconnect re-syncs channel state via `SBURST`"
remains open and this phase makes no claim about it. A three-node mesh, the only
topology in which a resync is a genuine *re*-sync rather than a first exchange, is
also out of scope here; §4.3.1 records what the format gives up on a larger mesh
(member records are keyed by the burst origin, and a receiver that already knows a
nickname leaves the existing attribution alone).

**Phase 7 — Command surface + skip gate empty.** The SHOULD commands; CI fails
on any skip. *Accept:* zero skipped tests.

**Phase 8 — IRCv3.** Real tag escaping + roundtrip, CAP negotiation
(LS/REQ/ACK/NAK), real SASL PLAIN, message-ids. Turns the 5 skipped IRCv3
tests green.

**Phase 9 — Federation hardening.** Link failure and reconnect handling, driving
the §4.3 `SBURST` resync (Phase 6 owns the verb and its wire format, not this
phase), plus network-visible nick rename-the-loser (§2.1), peer discovery,
auto-scale, and heartbeat-driven failover. This is where the
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
- [ ] Link loss and reconnect re-syncs channel state via `SBURST`
- [ ] Two nodes cannot both be named `irc.a` — rejected at handshake
- [ ] Observability: a way to dump peers + their FSM states, channels with
      origin and local/remote server sets, and the dedup table size.
      Split-brain debugging without this is guesswork
- [ ] Per-server nick uniqueness needs **no** policy and **no** lock:
      `bob@a` and `bob@b` are distinct registry keys. (The old criterion,
      "nick collision between nodes resolves without a global lock", was
      vacuous — there is no collision for it to resolve.)
- [ ] *Phase 9:* network-visible nick ambiguity resolved by rename-the-loser
      plus a nick-registry broadcast. Until then, duplicate cross-server nicks
      are user-visible and undefined

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
| Channel origin dies | channel stuck | Fail closed: origin immutable, channel locally orphaned, origin-requiring actions → `437`; re-linking the same name resurrects it (§2.2) |
| Re-electing a dead channel origin | interacts fatally with dedup | **Not started.** Needs a per-channel epoch in the dedup key, which breaks §2.4's `(origin,epoch,id)`. Must not begin without re-opening §2.4 first |
| Two nodes share a server name | catastrophic, later undetectable | Enforced at handshake (§8) |
| Blocking call in the event loop | stalls every client on the node | Dial state machine, pre-resolved peer addresses, bounded write queues (§3.4) |
| Nick charset left unvalidated | `nick@server` ambiguous; scoped identity unsound | `valid_nick()` in Phase 1 (§5) |
| Vector clocks reopened | scope creep | Deliberately rejected in §2.4; explicitly not a Phase 9 item |
