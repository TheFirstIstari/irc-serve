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
    /* Phase 10.1: the second axis. See "THE SECOND AXIS" below. */
    char     account[64];       /* "" == not logged in */
    int      logged_in;         /* a password was verified for `account` */
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

### 2.1.1 The second axis: an account

**Added in Phase 10.1. This subsection is the amendment §2.1 needed and did not
know it needed until seven IRCv3 specifications turned out to be blocked on it.**

`nick@server` answers **"how does this node address a user"**. It is a correct
answer, it is why federation needs no lock, and it is **not** an answer to **"who
is this person"** — because `bob@irc.a` and `bob@irc.b` are two registry keys and
both are true, and **neither survives the person reconnecting**.

An **account** is the other axis: a name that outlives the socket and is the same
on every node that knows about it. The two axes are not alternatives:

| | scoped nick (§2.1) | account (§2.1.1) |
|---|---|---|
| scope | one connection, one node | the person, across connections |
| set by | `NICK` | a verified credential, operator-side |
| survives a reconnect | no | yes |
| uniqueness | per server, no policy | per deployment, via the registry |
| what it grants | nothing | **nothing** |

**AN ACCOUNT GRANTS NOTHING ON THIS NODE, and that is Phase 10.1's most
load-bearing negative claim.** It is a *name* and a *fact about a connection*; it
is not an operator flag, not channel privilege, not an exemption from a mode
change and not a mode any consumer reads yet. §5's Phase 8 entry says SASL
"grants nothing: no operator flag, no channel privilege, no service, no exemption
from a mode change", and the account identity is on the same footing. What it
buys is **visibility** — `330 RPL_WHOISACCOUNT` reports it when a client asks, and
`account-tag` stamps it on every line an identified sender emits (§2.5.3) — and
visibility is not authority. A later phase that
wants `logged_in` to mean a *privilege* is making a different decision and owes a
threat model for it.

The invariant that makes the subsystem **additive**, and which is structural
rather than conventional:

> **`account == ""` is indistinguishable from "this node has no account system".**

There is exactly one writer (`account_set()` in `core/account.c`), it requires
both an operator's credential store *and* an operator's account registry to
verify the credential, and the predicate every consumer asks (`account_logged_in()`)
is local to the connection and consults no store. So a node with no registry
answers "not logged in" to every client — which is the answer it gives a client
that declined to authenticate. A deployment that configures nothing keeps exactly
the behaviour it had.

The three guards that produce the invariant are **redundant on purpose**, and the
teeth proved which of them is load-bearing: `account_set()` refuses an empty name,
`account_store_verify()` refuses one, and `account_store_add()` refuses to create
a record *named* one. Deleting only the first is invisible; deleting all three is
what makes `""` an account, and `tests/integration/test_account.c`'s in-process
case asserts the third — the **key space** — as the one that matters. An account
name that no registry record can carry is a name no connection can be logged in
as, whatever the predicate does with the string it is handed.

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

**A channel's TOPIC outlives the channel; nothing else does, and a bounded
cache on `server_t` is why.** The disposal rule below frees a channel with no
local members and no member-server, and it is right to — holding one per
channel *name* a client ever typed would be an unbounded store reachable from the
wire. The topic is the one field whose loss a **client** can see, because a
channel everybody has left comes back topicless and that is indistinguishable
from a channel that never had one. So `topic`/`topic_who`/`topic_when` are
copied into a bounded cache on `server_t` when the channel is disposed and copied
back when a channel is **created**; the only two call sites are the disposer and
`JOIN`'s creation branch, so the cache's lifetime is exactly the channel's.

Four limits are stated here rather than left to `core/channel.h`, because a
reader deciding whether a topic survives needs them and should not have to go
looking:

- **It does not survive a node restart.** The cache is heap memory; 3.4 forbids a
  write inside the event loop and an on-disk topic store is a new deployment
  surface. It is a bounded cache, not persistence in the usual sense.
- **Only the topic is carried.** Not the modes, not the bans, not the members.
  2.2 says the origin owns those, and a cache restoring them would be a *second
  authority for channel state* — the exact thing the single-writer rule exists to
  prevent.
- **`topic_who` and `topic_when` travel with it**, because 333 reports both. A
  cache holding only the text would make 333 name whoever rejoined and the moment
  they rejoined, which is a lie about two facts at once.
- **It is bounded, and a loss is counted rather than refused.** Past the bound
  the topic is lost exactly as it would have been without the cache, and
  `server_t::n_topic_cache_full` records it. The cache can therefore only fail to
  help; it never refuses a client command.

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
discovery and auto-scale were deferred to Phase 9, where both are now implemented.
**What "auto-scale" means here is a scoping decision, not an oversight** — the
placeholder that stood for it said "honest CTest skip rather than fabricated node
lifecycle / 'RSS' claims", and that was a statement about a boundary rather than about
missing work:

- **A node does not spawn or stop nodes.** That is a supervisor's job — systemd, an
  orchestrator, a replica controller — and it is outside this program. The reason is
  not that it would be hard: it is that **this node cannot measure its own load**. The
  percentage in an `ADVERTISE` is an *operator's value* (`fed_set_load()`), not a
  metric, so a node that spawned another node on a "the load is high" signal would be
  deciding on a number it does not believe, and the failure mode is a fork bomb on a
  mesh. There is therefore no `node_spawned()`, no `get_connection_load()` and no
  `node_shutdown()`, and no test asserts anything about any of them.
- **Propagation is implemented, and it deliberately stops at reporting.** A peer
  publishes how loaded it is; this node records it, and when the figure crosses a
  threshold the *operator* set (`fed_set_shed_pct()`, default **0 = no opinion**) it
  prints one `fed_shed: … action=REPORT_ONLY rebalance=NO reason=NO_MOVE_MECHANISM`
  per crossing and counts it in `n_fed_shed`. It does **not** move clients, channels
  or load, for two structural reasons rather than out of caution: §2.2 makes a
  channel's origin **immutable** and fails closed when it dies, so re-homing a
  channel *is* origin re-election (§9's risk table records that as not to be begun
  without re-opening §2.4), and a client's session belongs to the node its socket is
  connected to, with no session-transfer verb and no client-visible redirect in §4.3
  to move it. The default of 0 is the honest one: the level at which a peer's load
  matters is a deployment's judgement, and shipping a constant would be inventing a
  figure this codebase cannot justify.
- **A graceful leave is the other half, and it is the half a node really can do.**
  `server_shutdown()` calls `fed_send_shutdown()` *before* it closes anything, so a
  `SIGTERM`'d node says goodbye on the wire; each peer marks the link cleanly
  departed, purges that origin's roster, relays a `SQUIT` onward, and **arms no
  retry**. Two defects had to be fixed for that goodbye to survive its own journey,
  both in the poll loop and both documented at the site: a node that wrote its last
  line and closed in the same breath had that line **discarded** (the end-of-stream
  arm returned without framing what it had already read, and "send the line, then go"
  *is* the graceful leave), and a departing node had to **drain** each peer socket
  before closing, because a `close()` with unread data in the receive queue makes the
  kernel send `RST` instead of `FIN` and an `RST` discards the goodbye in flight.
  `tests/integration/test_autoscale.c` is the acceptance, over real nodes and real
  sockets; no payload in it is written by the test except the third case's, which
  exists precisely to reach the framing defect that the (correctly robust) shipped
  departure path hides.

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

**The identity is minted ONCE PER EMISSION, and that is a property the dedup store
alone would not have forced.** The obvious place to mint is where the line leaves
the node toward a peer, and that is where this node used to do it — which meant a
message forwarded to two peers was stamped with two different ids. For the dedup
store that was survivable (the store is per node, and the two copies of one
message to two peers are not one message arriving twice). It is fatal for the
client-visible `msgid`, which is **rendered from this same triple** as
`<origin>_<epoch>_<id>`: two members of one channel on two nodes would have been
told two different values for one message, which is exactly the failure the
IRCv3 `draft/message-ids` capability exists to remove. So `fanout_deliver()`
computes the stamp once, before the local write and before the target walk, and
both consume it. Deriving the msgid from the triple rather than from a second
counter is what makes it invariant for free: a counter for msgids would mean one
thing here and something else to a peer, so no relay could carry it.

The `irc-serve-id` in a relayed line and the `msgid` a client reads are therefore
the same three numbers rendered twice — one for a peer, one for a client. They
are **not** the same tag and they are **not** the same audience: `irc-serve-*` is
internal and stripped, `msgid` is negotiated and public. A node that served both
from one counter without saying so would have a value that means two things, and
the `msgid` would stop being derivable from a dedup key.

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

### 2.5 The account registry

**Added in Phase 10.1.** §2.1.1 defines the identity; this is where it comes from,
and the three decisions below are the ones a reader should be able to check
rather than take on trust.

#### 2.5.1 A SEPARATE FILE FROM THE CREDENTIAL STORE, AND WHY

The registry is `--account-store PATH`, one record per line:

```
<name> TAB <password> TAB <created>
```

It is **a different file from `--sasl-store`**, and the argument is that the two
answer different questions with different lifetimes and different blast radii:

- `sasl_store_t` — **who may AUTHENTICATE here.** One row per authcid. SASL PLAIN
  grants nothing on this node (§5), so this file is a gate and nothing more: a row
  can be rewritten freely, because deleting one stops a login working and affects
  nobody else.
- `account_store_t` — **which accounts EXIST.** A row is a statement about a
  *name*: `alice` is an account whether or not she has ever connected. Losing one
  is the loss of an **identity**, not of access, and that is a different kind of
  event.

The alternative — one file with a per-record "this is also an account" flag — was
rejected because it makes the FILE's meaning a property of a byte inside a line,
and a credential file whose rows mean different things depending on a flag is a
file whose blast radius is one bad edit wide. **The cost, stated: an operator
configures two files**, read at the same point in `main()` and in the same
pre-loop phase §3.4 requires, and the two must agree or authentication stops
(§2.5.3).

It is otherwise the **same kind of thing and held to the same discipline**:
bounded (`ACCOUNT_MAX_RECORDS` 64, all four bounds constants rather than
configuration, for `sasl_framework.h`'s reason that a store whose size comes from
the file is a store whose bound is the file), operator-supplied, and file-backed
with the **hardened credential path** — `fopen(path, "re")` and then `fstat()` on
the **descriptor**, never `stat()`-then-open, plus `S_ISREG` and a refusal when the
group or world bits are set. The passwords are **overwritten through a `volatile`
pointer before the memory is released**, for `sasl_store_free()`'s reason: `free()`
scrubs nothing, and the allocator reuses the buffer for the next node of the same
size. `email` is **deliberately not stored**; §2.5.2 says why.

A **malformed record fails the whole load** and the node comes up with **no**
registry, which is the same state as "the operator configured none" and is why
§2.1.1's invariant needs no special case for it.

#### 2.5.2 REGISTER and UNREGISTER ARE REFUSED — a security decision, not a feature

**`account-registration` is NOT implemented. It is refused.** That is the
deliverable of this subsection, and four independent reasons support it; each is
sufficient on its own.

1. **The specification says not to.** `account-registration` is a
   work-in-progress document whose own header says implementations **"MUST NOT
   use the unprefixed account-registration capability name"**, SHOULD use
   `draft/account-registration` instead, and that it **"may change at any time and
   we do not recommend implementing it in a production environment"**. Shipping a
   stable `REGISTER` that a draft will redefine is how a server becomes
   un-upgradable without anyone noticing.
2. **Its wire form does not exist yet.** The draft answers with the standard
   replies framework — `FAIL ACCOUNT_REGISTER <reason>` — and this node has no
   `FAIL`, no `ERROR` and no `WARN`: they are Phase 10 item 8. There is no numeric
   a real client parses as a registration answer, and inventing a different answer
   in a different numeric is the "a numeric that lies about what it is" failure
   §4.4 refuses.
3. **Open registration here would be a name-claiming primitive, not a feature.**
   `REGISTER` takes a password and an optional email. With no verification mail
   (no MTA, no outbound queue, and §3.4 forbids both inside the loop) and no rate
   limit, nothing stops an unauthenticated client from taking any name. And taking
   a name is not a nuisance once `account-tag` exists: the account name is stamped
   on every message a client sends, and the **entire value of that tag is that it
   means "this is who this is"**. An open registry makes it worthless to every
   honest user and perfectly usable as an impersonation tool against them. There
   is also no write in this tree that could record a registration even if one were
   allowed: the store is read once at start-up.
4. **`UNREGISTER` is worse than nothing, which is why it is refused too.** The
   store is an operator's file, loaded before the loop, so an in-memory removal
   vanishes on the next restart. Telling a user "your account has been deleted"
   and then finding it intact after a restart is a falsehood from the one server
   that is supposed to be the authority on whether an account exists — and account
   deletion is precisely the case where a user is relying on the answer.

**The threat model, stated once.** On a node with this pair refused, an attacker
can still connect, register a nickname, send messages and join channels —
everything this node has always allowed. What they **cannot** do is assert an
account identity, because the only writer of `conn_t::account` is `account_set()`
and it requires a credential the operator's credential store holds **and** a
registry entry the operator's registry holds. The **cost** of that model is that
accounts on this node are created by an operator editing a file: real, the reason a
deployment wanting open registration should not use this node, and cheaper than
the alternative.

**The numeric is `482 ERR_CHANOPRIVSNEEDED` and it is wrong.** Not wrong in its
RFC text — *"Permission Denied- You're not an IRC operator"* — which is the
truest answer available, since this node has no operator concept at all and a
client that has not been made one is being told the truth. It is wrong in its
**name**, which is channel-specific. It is also the numeric `CHOPER` already
answers with for the same reason, so "there is no operator here" is one numeric.
The honest numeric is `FAIL ACCOUNT_REGISTRATION NOT_ENABLED`, and it arrives with
standard-replies.

`draft/account-registration` is **not** in `cap.c`'s table either: this build has
not heard of it, which is true, and a capability this node refuses is a `421`
rather than a `NAK`.

#### 2.5.3 `account-tag`: THE EMISSION, AND WHERE IT STOPS

**Added in Phase 10.2.** Phase 10.1 built the identity and deliberately left the
capability **out** of `cap.c`'s table. Both halves are now on, and this subsection
is the argument for where the tag is emitted and where it stops.

**WHY 10.1 WAS RIGHT TO WITHHOLD IT, AND WHY WITHHOLDING IT IS NO LONGER THE
ANSWER.** The specification's own sentence is the whole of it:

> The tag MUST be named `account`… If the user is not identified to any services
> account, the tag MUST NOT be sent.

The tag's **absence is an assertion**. A client reads "no `account` tag" as "this
user is anonymous", so advertising `account-tag` on a node that never emits the
tag tells every client that **every logged-in user on this node is anonymous** —
which, once a registry exists, is the subsystem's entire observable purpose
inverted by its own advertisement. A **missing** capability is a client that
carries on; a **listed** one is a client that draws the wrong conclusion from
every line. That reasoning was correct, and the resolution was never to overturn
it: **the name went in at the same moment as the emission**, so the advertisement
is a claim about something real rather than about an absence.

**THE AVAILABILITY CHECK IS `account_possible()`, BESIDE `sasl_possible()`.** A
node with no `--account-store` can never establish an account on any connection —
`account_set()`'s second check consults the registry and an absent registry fails
it — so listing `account-tag` there would be a client switching on a tag this node
will never write. `CAP LS` on such a node is byte-for-byte what it was before this
phase, and that invariant has a test of its own (`test_default_node`).

**WHERE THE TAG IS STAMPED, AND WHY THAT IS THE ONLY CORRECT POINT.**
`fanout_deliver()`, **once per emission**, above the routing switch:

- **The account NAME is resolved once**, in `fanout_emitter_account()`, from the
  emission's own `prefix`. Every line this node originates carries the acting
  client's hostmask (RFC 2812 3.3.1), so the prefix **is** the identity the
  emission is about; the local nick registry answers it, and a prefix naming
  nobody local resolves to `""`. It has the same shape as 2.4's `(origin, epoch,
  id)`, computed by `fanout_stamp()` at the same point, for the same reason: an
  identity is a property of one emission.
- **The DECISION to render it is per destination**, in `fanout_tag_block()`,
  because the capability is per connection. Two members of one channel are free to
  disagree about whether they want to be told who sent a message, and a block
  written once for the emission would put it on the line of the one who asked for
  none.
- **Resolving the name per forward target is the `msgid` bug again.** It looks up
  "whoever is at the other end" instead of "who sent this", which on a relayed
  `SPRIVMSG` resolves to nothing and drops the tag for exactly the messages whose
  sender identity is in question.

**`message-tags` IS REQUIRED AS WELL, and the reason is `draft/message-ids`'s.**
`account` is a tag, and 3.2's parser reads a block or it does not; a client that
asked for `account-tag` inside a support it declined does not get one. The cost is
stated at the emission: a client whose `CAP REQ` lists `account-tag` alone gets an
ACK and no tag.

**`+account` DOES NOT CROSS TO A PEER — a deliberate decision.** An account
registry is **per node and per operator**: §2.1.1 says two nodes with two
registries will disagree about who somebody is, with nothing to arbitrate.
Forwarding one node's claim would hand the far side's clients an identity no
registry they can consult holds, and a client has no way to check it — the tag is
precisely the assertion a client trusts. **This node asserts only what it
verified**, and the relay arm of `fanout_emitter_account()` is one branch on
`relayed` rather than a property of the prefix's bytes.

*The cost, named:* a member of a shared channel on a peer sees **no** `account`
tag on the peer's messages, so per-message identity stops at the node that
authenticated the sender. `extended-join` (Phase 10.3) carries the account as
**membership** state, which is the claim federation does have a channel for.
Closing the per-message gap needs an **account authority both nodes trust** — a
services registry, not a tag — and this node has none.

**`330 RPL_WHOISACCOUNT` IS STILL WORTH HAVING** (§4.4), because a `WHOIS`
answers a question a client asked **about a person it named** — which is how a
client learns an account for somebody who has said nothing since joining, and
which the tag cannot answer at all.

**WHAT THE LINE BUDGET COSTS.** 3.2 reserves `IRC_MAX_TAG_OVERHEAD` (179 bytes)
for whatever block an outbound line carries. A client-facing line may now carry
`msgid` **and** `account`, whose worst case is larger, so `fanout_line_fits()`
charges the largest client-visible block against `IRC_MAX_RELAY_LINE` rather than
leaving the overflow to be discovered when `message_format()` refuses the line. The
cost is a **250-byte shorter maximum `PRIVMSG`**; the alternative is losing a
user's message to a decoration at the cap. The peer-facing predicate
(`fanout_line_fits_n()`) is unchanged, because a forwarded line carries 2.4's
internal block and `IRC_MAX_RELAY_LINE` already excludes it by construction.

**AND WHAT IS STILL NOT HERE.** `account-tag` does not reach **numerics** ("directly
caused by the sender"). The specification says **SHOULD**, not MUST, and an
erratum relaxed it precisely because it was widely not implemented; adding it would
mean the numeric path grows a tag block of its own, and this node's numerics carry
a client's own reply rather than a message.

#### 2.5.4 WHERE IT IS FREED, for LeakSanitizer

**LeakSanitizer does not run on Darwin** (§7/Phase 1's hygiene note), so the
account registry's release is *reasoned about* here and *verified* on the Linux CI
job:

- `server_shutdown()` calls `account_store_free(s->account_store)` and NULLs the
  field, beside `sasl_store_free()`. It is safe at that point because every
  connection was closed by the `by_fd` walk above and every one of those closures
  called `account_clear()`, so no `conn_t::account` — and no connection that
  borrowed the registry — can still be pointing into it.
- The arm prints `[observable] account_store_close: store=OPEN|NONE records=N`,
  following `fed_burst_close: shadow=OPEN|NONE`. That makes the arm **asserted**
  on every platform and **verified** on the one with a leak checker.
- The `[observable]` line proves the arm **ran**. It does **not** prove the `free`
  happened — a build that prints the line and drops the call satisfies it exactly,
  and that was one of this phase's ten injected faults. So the call itself is
  asserted by **source inspection** in `test_account.c`, using `test_util.h`'s
  `tf_calls()`, for the same reason `test_close_sites.c` exists: no runtime test
  can check it, because the failure mode is a missing call that leaves every
  runtime invariant intact.
- No other site allocates one. `account_store_load()` frees the half-built store
  on every refusal path (which is why a refused file leaks nothing), and
  `test_account.c`'s in-process case builds one with `account_store_new()` and
  releases it through `server_shutdown()` rather than a second path.

#### 2.5.6 `account-notify`: WHICH ACCOUNT, SAID OUT LOUD

**Added in Phase 10.2b.** `account-tag` says who sent a line; this says **which
account a client is associated with**, as a command rather than a decoration:

```
:nick!user@host ACCOUNT <account> PASS
:nick!user@host ACCOUNT *
```

**`account-notify` IS AVAILABLE UNCONDITIONALLY, AND THAT IS THE DIFFERENCE FROM
`account-tag` THAT IS WORTH THE SUBSECTION.** §2.5.3 withholds `account-tag` on a
node with no registry, because a tag that says nothing is an assertion of
anonymity. **`ACCOUNT *` is not nothing** — it is the specification's own way of
saying "this user is not associated with an account", and a node with no account
system can give it truthfully. Withholding the name there would be a node keeping
a true and useful fact from a client that asked for it. So `cap_available()` asks
`sasl_possible()`-shaped questions about two capabilities and gets two different
answers, and the reason is written at `cap.h` beside both.

**THE COLLISION, AND WHAT WAS FOUND.** `ACCOUNT` was, in the retired draft, the
**nickname-change** command: a client changed its nickname and supplied a password
in one command, and `ACCOUNT <password>` is the shape every server of that era
accepted. **This node dispatched no `ACCOUNT` at all before Phase 10.2b** — there
was no row in the command table, so a client that sent it got `421`, and a
nickname change was, and is, `NICK <newnick>` and nothing else. **There was
therefore no live verb to collide with**, and the reason this is written down at
length is that it is the kind of thing a reader of the protocol assumes IS a live
collision.

The **shapes are disjoint** as well, which is what makes the cost zero rather than
merely zero today:

| form | parameters | meaning now |
|---|---|---|
| `ACCOUNT <password>` | one | **retired.** 461 |
| `ACCOUNT` | none | the query, answered with the current association |

**THE IRCv3 POSITION IS THAT THE NICK-CHANGE MEANING IS GONE**, not merely
unfashionable: an account association changed through the account service, not
through the server, and a server that took a password on a nickname change was
asking for a credential it had no way to verify. What survives is the word, reused
by `account-notify` for an unrelated fact — so a future phase that wanted a
one-parameter `ACCOUNT` would have to decide to take it back deliberately rather
than find it already spoken for.

**WHERE THE NOTIFICATION GOES, AND THE LIMIT THAT IS LOAD-BEARING HERE.** The
specification says the line goes to clients on common channels with the user,
**including the user**. **On this node the second half is the only half there is,
and that follows from the account lifecycle rather than from a choice.** The
association is established by `account_set()`, which SASL runs *before*
registration: at the moment it becomes true the connection has no nickname, no
publishable hostmask and no channel. By the time a client has channels the
association has been fixed for its whole life, and there is no later transition to
report. A subscriber-style fan-out would have exactly one member to address and no
reachable path to a second.

*The cost, named:* **two users in a channel do not learn each other's account from
this line.** They learn it from `extended-join` (Phase 10.3) or from `330
RPL_WHOISACCOUNT`, and a client whose channel-mates logged in before it joined
learns neither without asking. Making the channel-scoped half reachable needs a
services layer with a real logout.

**`ACCOUNT <account> FAIL` IS NOT EMITTED, AND SAYS WHY.** There is no logout on
this node: SASL PLAIN has none, there is no account service to log out of, and
`account_clear()` runs only from `server_close_conn()`, where the connection is
already gone and there is nobody left to tell. **There is no event the form
describes**, so a test that asserted its presence would be asserting a feature.
`account_notify_current()` is the single emitter and the comment on it says where
an emitter for `FAIL` goes when a phase adds one — which is a services layer, not
a line.

**IT IS NOT SOLICITED TO A CLIENT THAT DID NOT NEGOTIATE IT**, and it is not
refused to one that asks: the capability governs the unsolicited line at the end of
the welcome burst, and a question a client put on the wire is answered whatever it
negotiated. A node that knows the answer and will not give it because of a
negotiation bit is being unhelpful on purpose.

#### 2.5.7 `extended-join`: THE CHANNEL ROSTER, WITH ACCOUNTS, IN ONE LINE

**Added in Phase 10.3.** This is the capability that makes the account axis useful
*inside a channel* rather than only per message, and it is the one that answers
"who is in here" without a `NAMES` flood:

```
:nick!user@host JOIN #channel <account> :<realname>
:nick!user@host JOIN #channel * :<realname>
```

**IT IS AVAILABLE ON A NODE WITH NO ACCOUNT SYSTEM, AND THAT IS THE THIRD
DIFFERENT ANSWER THREE ACCOUNT CAPABILITIES GIVE.** §2.5.3 withholds
`account-tag` because a tag that says nothing asserts anonymity; §2.5.6 advertises
`account-notify` unconditionally because `ACCOUNT *` is a true answer; and this
one is advertised unconditionally because **`*` is a complete answer** to "did this
user log in to an account before channel ingress". A node with no registry has not
got one to log in to. `cap.h` carries all three arguments together, and the reason
they differ is that **one of the three capabilities carries a NAME and the other
two carry a FACT**.

**THE SHAPE IS PER DESTINATION, AND IT IS A DIFFERENT THING FROM A TAG.** Two
members of one channel can disagree about `extended-join`, and the two forms are
not two decorations of one line: a client that did not ask and received the extra
parameters would read the account name as a topic and the realname as a reason, and
it would do that silently. So `fanout_deliver_forms()` exists: `plain` is what
everybody gets, `extended` is what a recipient that negotiated gets, and the
**forward always uses `plain`** — the peer-facing shape is 4.3's SJOIN, which is
built from the channel's own membership, and which of this node's *clients*
negotiated a capability must not change what this node says to a *peer*.

**THE ACCOUNT IS `<account>` OR `*` AND NEVER AN EMPTY PARAMETER**, and the rule is
`account_logged_in()` rather than `c->account[0]`. That is §2.1.1's invariant one
layer down: an empty account field would be a parameter a client reads as an empty
one, and 3.2 cannot represent an empty middle parameter at all — so the node would
be asserting a thing its own grammar has no way to say. `*` is one byte, never
needs a colon, and is the protocol's own token for the absence.

**AN ACCOUNT NAME MUST NOW BE WRITABLE AS A PARAMETER, AND THAT IS A RULE.**
`account_name_wire_safe()` (in `account_store.h`, where the name's key space
already lives) refuses a name holding SP, HTAB, CR, LF, any other control byte, or
a leading `:`. **The tag and the parameter have different rules** — a message tag
*escapes* `;`, `:`, `\`, SP, CR and LF, so a name holding them is fine in
`account-tag` — and the parameter list is the binding one because a parameter can
escape nothing at all. This was already true of `330 RPL_WHOISACCOUNT`, which has
carried the account as a middle parameter since Phase 10.1; Phase 10.3 gave the
name three more parameter positions to be wrong in, which is what made it visible.
**The cost is stated: an operator cannot create an account whose name holds a
space, and a registry record holding one is REFUSED rather than loaded with a name
this node could not publish to anybody.** A restriction, enforced at the one writer
of the field rather than discovered at a renderer.

**WHAT IT FEDERATES, AND WHAT IT STILL DOES NOT.** `SJOIN` is now
`<channel> <member> <flags> <account>` — four parameters, the fourth derived from
the MEMBERSHIP exactly as the flags are — and `SBURSTM` carries the same fifth
field so a resync does not lose what the live path writes (§4.3.1 argues why it is
on the member record and not on `SBURSTN`). `chan_remote_t` grows an `account`, and
`chan_remote_add()` takes one.

**What is still absent, and it is a bigger gap than the capability's absence:**
**this node emits no local client line for an INBOUND `SJOIN`.** 4.3's SJOIN carries
only a server prefix, so `verbs.c` cannot render `:bob!user@host JOIN #T alice *`
from a prefix that says `irc.b`, and a JOIN with a server prefix is a line no client
understands. A local member therefore learns about a remote member through the
roster (`353`) and not through an extended JOIN — which is the pre-existing gap
`verbs.c` names, and it means the account a peer reported is stored and not yet
shown. Closing it needs a hostmask for a remote member, which is `chan_remote_t`'s
`host` field and a decision this phase does not make.

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
requires it to be exactly once, and then requires the counters to stop moving.

#### 3.1.1 The third outcome: a destination that is sent nothing

The table above says **where** a line goes. It says nothing about **which
destinations inside a row are addressed**, and per-destination decisions were
already being made for two other reasons: the two wire *shapes* `extended-join`
introduces, and the per-member tag block. A third reason arrived with Phase 10.8a
and it is not a variation on the first two.

**Two shapes is a choice between two answers.** `fanout_form_t` chose between a
plain parameter list and an extended one, per destination, and a choice between
two answers cannot express a third: **"send this member nothing."** Three
specifications need that third answer, and each states its audience as a subset:

| Spec | The sentence that needs a third outcome |
|---|---|
| `setname` | "servers MUST send the new name to all clients in common channels, as well as to the client from which it originated" |
| `chghost` | "servers MUST send the `CHGHOST` message to other clients who share channels with the target client **and who have enabled the `chghost` capability**" |
| `away-notify` | "clients will be sent an AWAY message when a user sharing a channel with them sets, changes or removes their away state" |

Each is **unsolicited**, which is what makes the outcome an *absence* rather than
a line. `away-notify` is the sharp case: the notification's whole grammar is
`:nick!user@host AWAY [:message]`, so a node that "notified" a client which had not
asked would be sending a line asserting the user is no longer away — a state
change that did not happen. The same reasoning as `account-tag`'s absent tag
(§2.5.3): an unsolicited assertion is as wrong as a missing one.

**So the outcome is a per-destination GATE, asked by the caller, inside the walk
this module already owns.** `fanout_deliver_local_gated()` takes
`fanout_gate_fn(const conn_t *dst, void *ctx)` and asks it once per destination;
a destination the gate refuses receives no line, no tag block, and no entry in the
returned count. `NULL` is "every destination the emission reaches" and is exactly
the pre-existing `fanout_deliver_local_forms()` — the same sentence this file uses
for a NULL `extended`.

**The alternative, and why it loses.** Three handlers each walking the roster is
the duplication this module exists to prevent. `chan_verbs.c` grew its own
broadcast helper in Phase 4 for exactly that reason and **it had no forward arm,
and the missing forward was lost**. A handler walk also has to reproduce
`chan_member_live()`, and one that does not manufactures an `n_reply_refused` —
the counter `reply.c` holds at zero because a non-zero value is a bug report.

**The gate is asked of a LOCAL DESTINATION and nothing else**, which is why there
is no gated variant of the forwarding entry point: a peer is not a client that
negotiated anything, so on that path the question is unaskable rather than
answerable-but-ignored. A parameter a caller can set on a path where it cannot
mean anything is a parameter that will be set and believed.

**The order inside the walk is liveness, then `exclude`, then the gate**, cheapest
first. Asking the gate last would still send the right bytes, but it would have
rendered a tag block and possibly reported a `fanout_unhandled_form` for a
destination that was never going to be written to — and the second of those is a
bug report on the node's observable output caused by a member who was never in the
conversation.

**Verified where the outcome is not yet reachable from a command.**
`tests/integration/test_fanout_gate.c` holds one channel, three members and three
negotiations at once — none, `extended-join`, `extended-join` plus a gate that
refuses — and asserts all three outcomes from one call: the exact plain line, the
exact extended line, and **zero queued bytes** for the member the gate refused.
Zero rather than "the line is absent from the buffer", because absence-from-a-
buffer is satisfied by a line that arrived somewhere else in the stream. It also
asserts that the gate is asked once per destination and **not at all** about a
destination `exclude` had already removed, which is the one property no
byte-comparison can see.


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

  **A `msgid` does NOT go into this 179, and the reason is worth stating because
  adding it is the obvious move.** This constant is the cost of the INTERNAL
  block on a PEER link, and the `msgid` is a CLIENT-facing tag: 2.4's tags are
  stripped before delivery, so the two never appear on the same line and there is
  nothing to add. What does need checking is the SUM on the client side, and it
  fits:

  ```
    client-facing cap                8013   IRC_MAX_RELAY_LINE
    '@' + worst-case msgid tag        112   1 + IRC_MAX_MSGTAG (111)
    --
    8125   against IRC_MAX_LINE      8192   67 bytes of headroom
  ```

  That headroom is why `reply.c` has **no** "drop the tag, keep the message"
  retry: the window in which a maximal client line could not carry a maximal tag
  does not exist, and `tests/integration/test_ircv3_msgid.c` asserts the headroom
  as bytes rather than taking this paragraph's word for it. Every other emission
  this node makes — the numerics, a `353`, a `STOPIC`, an `SJOIN` — is bounded by
  its own field sizes and has no path to a maximal line at all.
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

#### 4.2.2 `echo-message` (Phase 10.7, IRCv3)

`echo-message` says a server MUST send `PRIVMSG` and `NOTICE` back to the client that
sent them. On this node **that copy already existed for `PRIVMSG` before the
capability did**: `fanout.c`'s `write_to_members()` writes to every live local member
**including the author**, and the specification's own example

```
--> PRIVMSG Attila :hi
:example!ex@example.com PRIVMSG Attila :hi
```

is byte-identical to what that path has produced since Phase 5. `exclude` has been
`NULL` for `PRIVMSG` for exactly that reason.

**So the implementation is one argument, and the bug it invites is a second
delivery.** A node that "implements" this by sending the message normally and then
acknowledging it delivers every message twice to every client that negotiated the
capability — the exact defect the capability exists to remove, reached from the
other side. The two copies differ only in their prefix, so a substring assertion
passes; `tests/integration/test_echo_message.c` therefore **counts** copies over a
marked region of the wire, and one of its faults adds exactly that second emission
and is watched failing with `2 != 1`.

What the capability actually changes is the one verb whose RFC rule removes the
sender from the audience: **RFC 1459 2.4.2's `NOTICE`**, which is never returned to
the client that sent it. For a sender that negotiated `echo-message` it is put back;
for one that did not, nothing changes. There is **no second emission, no second
stamp, and no second message identity** — `fanout.c` mints the emission's 2.4
identity once, above its switch, so the sender's copy carries the same `msgid` as
every other recipient, which is what "the final version of the message" means.

**Not covered, and named:** `TAGMSG` echoes, `batch` echoes, and a `nick@server`
target. The last is a routing fact rather than an omission — §3.1's last row is
forward-only, so the target has no local destination and there is nobody on this
node to acknowledge to.

#### 4.2.1 `SETNAME` (Phase 10.6, IRCv3)

`SETNAME :<realname>` changes `conn_t::realname` on a live connection. It is not in
§4.1's MUST list or §4.2's SHOULD list because it is an **extension**, and adding it
to either would put a document in a chain this project has been careful not to
extend. Three gates, in order, and the order is the argument:

1. **Registered.** `451` otherwise, and it is `pre_reg = 0` in the dispatch table so
   the gate is the table's rule rather than a check in the handler. It has to be a
   gate: a pre-registration connection has an *empty* realname, so without one a
   `SETNAME` would "succeed" at setting state that does not exist yet.
2. **The capability.** Refused **silently** — no reply, no change — which is the
   specification's own instruction and the opposite of what every other capability
   here does. A `FAIL SETNAME CANNOT_CHANGE_REALNAME` is what the specification asks
   for and **`standard-replies` is a separate phase this node does not have**;
   inventing a `FAIL` to stand in for it would put a command word on the wire that no
   client on this node has been told to expect. Silence is a shape every client
   already handles, and it is observable: nothing arrives, and nothing changes.
3. **Validation**, through `conn_realname_check()` — the **same predicate
   `handle_user()` runs**, which is what makes this not a looser path than
   registration. A refusal is `417` and the previous realname is left exactly as it
   was. It is **not truncated**: 3.2's rule, and the reason is that this value is
   then shown to every member of every channel the user is on.

**The predicate, and why there is one.** `conn_t::realname` has two writers and three
readers (the extended-`JOIN` echo, `352`'s `<realname>`, and 4.3's `SBURSTN`). One
function, called by both writers, is what makes "same validation" a property of the
code rather than a claim about it. It refuses two things:

- **over-long** — longer than `CONN_MAX_REALNAME`, which §4.4.1's `NAMELEN` advertises.
  A truncated realname is one the user did not write, reported to third parties as
  though it were theirs.
- **a C0 control or DEL** — the log-injection set. `message_parse_n()` already
  refuses CR, LF and NUL, but the rest get through, and a realname reaches this
  node's own `printf("%s")` with no escaping. `0x07` rings the recipient's bell; ESC
  followed by `[` is a CSI sequence any terminal executes, which is a channel member
  rewriting an operator's screen. The test is `ch <= 0x1f || ch == 0x7f`, the same
  rule `chan_name_valid()` already applies to a channel name. **TAB is inside that
  range and is therefore refused too** — a TAB in a GECOS field is a rendering
  accident rather than a name, and no current client sends one. That is the cost and
  it is named rather than assumed.

**Why `USER` behaves differently on length, on purpose.** `USER` *truncates* an
over-long realname and *empties* a control-bearing one, where `SETNAME` refuses both.
The asymmetry is about when the command arrives: `SETNAME` lands on a live
connection where refusing costs nothing, while refusing `USER` would leave the client
half-registered with no recovery but a reconnect — for a value no current client
sends. Registration therefore completes with an empty realname, which is already a
legal state here (`extended-join` renders it as a bare `:`), and the refusal is
reported on the node's own output rather than being invisible.

**What is NOT implemented, and it is the specification's MUST.** On success this node
sends the server-to-client form

```
:nick!user@host SETNAME :<new realname>
```

to the **originating client**. It does **not** send it to the clients in common
channels. `core/fanout.c`'s per-destination decision is a choice between two wire
**shapes** — the `fanout_form_t` the extended `JOIN` introduced — and "send this
member **nothing**" is a *third* outcome that the form cannot express. Adding it is
a contract change to the routing module; the alternative, a second member walk
inside a handler, is exactly the duplication `fanout.c` exists to prevent. So the
limitation is named rather than faked (SPEC_TRACKING §10.5).

### 4.3 Server-to-server (internal, not client-facing)

`FEDERATE` (link handshake — existing FSM) `SJOIN` `SPART` `SPRIVMSG` `SNOTICE`
`STOPIC` `SNAMES` `SSMODE` `SKICK` `SQUIT` `SHASH` `SBURST` `SNICK` `ADVERTISE`
`SHUTDOWN`

`SJOIN` is `<channel> <member> <flags> <account>`: the account field is Phase
10.3's and is `*` for a member who is not logged in to an account, derived from
the membership exactly as the flags are. It is also `SBURSTM`'s fifth parameter,
for the reason §4.3.1 records.

These are the internal verbs behind the client commands. Designing them as
*distinct verbs* rather than reusing `JOIN`/`PRIVMSG` is what keeps the wire
protocol unambiguous and lets a node distinguish "a user joined" from "a
server tells me a user joined" — which is what makes loop prevention and
ownership decidable.


The last three are **Phase 9's**, and they are a different kind of verb from the
ones above. `SNICK` renames a remote member across the mesh, and is the network-
visible half of §2.1's rename-the-loser: a duplicate nick is resolved on the wire
rather than silently in one node's memory. `ADVERTISE` publishes this node's
operator-set load figure to each established peer, and `SHUTDOWN` announces a
deliberate departure.

Both of the latter two are **observational or terminal, never load-bearing for
routing**. An advertised name or address is read by logs, by the stats line and by
name-collision detection — **never by the dial path** — because a peer that could
name a host this node would then connect to has turned a shared secret into an
SSRF. That separation is structural rather than a matter of remembering: the
advertised table is a distinct type with no path into `server_dial()`. And a
`SHUTDOWN` is a **clean leave, not a failure** — it is the one teardown that must
not arm §4.2's retry ladder, since retrying a peer that said goodbye is exactly
what "graceful leave" exists to prevent. Presence detection remains T4's job;
neither verb replaces it.

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
:<origin> SBURSTM <chan> <server> <nick> <flags> <account>
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

**`<account>` was added to `SBURSTM` in Phase 10.3, and it is on THIS RECORD RATHER
THAN ON `SBURSTN` ON PURPOSE.** An account is naturally a user property and
`SBURSTN` is the user record, so the first instinct is the other one. It is here
because **the thing a receiver can render to a client is the roster entry**: a
remote member has no `conn_t`, so a fact delivered on `SBURSTN` would have to be
re-joined onto the roster at install time, while a live `SJOIN` — the other way a
member ever arrives — would have to put the same field somewhere else. Two records
holding one fact is how a format comes to disagree with itself, and that is the
very failure the `<server>` paragraph below is about. So `SBURSTM` carries exactly
what `SJOIN` carries, in the same position, and both land in
`chan_remote_t::account`: **agreement by construction rather than a join at install
time.** The cost: **+64 bytes** on the worst-case `SBURSTM` line (510 rather than
446), `CONN_MAX_ACCOUNT + 1` on every shadow member during a transaction and on
every remote roster entry — 32 KiB more of shadow on the 500-member channel the
budget prices — and nothing else.

**`<server>` was added to `SBURSTM` before a second implementation existed, and it
is the reason the frozen format is worth freezing.** The prefix answers *whose
state is this*; `<server>` answers *where is this person*. They coincide on a
two-node mesh and for a member the origin hosts itself, and they **diverge** the
moment the origin is a relay reporting somebody else's member. Without the field
a member living on a third node is stored under the relaying server, which is
wrong twice over: the roster misattributes it, and §2.1's scoped `nick@server`
cannot be resolved from the roster at all, because the roster would answer with
the name of a server that does not host the member. Neither is repairable from
inside a receiver — the information is not on the wire. The cost, stated rather
than implied: **+64 bytes** on the worst-case `SBURSTM` line (446 rather than
382), one field in the receiver's shadow member record, and one field in
`chan_remote_t`. It is in the format now precisely because §4.3 says a wire
format cannot be invented later, and a field added after two implementations run
is a compatibility break rather than a change.

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
per-line check would be a formality (`SBURSTM`, at 510 after the `<server>` and
`<account>` fields, is 6.2% and is not what the budget turns on). The real constraint is that
3.4 **drops** a saturated peer link rather than buffering it, and a burst is
O(nicks + members), so a large node's burst can be megabytes and queueing it all
would starve every live message behind it. A burst is therefore assembled into a
staging buffer of `IRC_BURST_MAX_BYTES` = `CONN_WQ_MAX / 2` — half a link's
queue, so a resync can never crowd out a live message — and a burst that does not
fit is **refused in full** with one `n_burst_refused`: nothing queued, the link
untouched, no truncation. The receiver charges every record against the same
bound, because the shadow is memory made out of what a peer *said*.
`fanout_line_fits()` is not used: it charges the *client* envelope (a 64-byte
channel name and a 64-byte hostmask) against `IRC_MAX_RELAY_LINE`, and a
`SBURST*` line is neither.

**A truncated transaction is counted twice, under two names, and the second name
is the one that says why.** `n_burst_abandoned` counts an inbound burst discarded
before its terminator — a count mismatch, an over-large transaction, a malformed
record, or a link that went away. `n_burst_truncated` counts the one of those
that is a *truncation*: `SBURSTE`'s counts disagreeing with what arrived. They
are incremented on the same branch, for the same reason §2.4's
`n_fed_dup_drop`/`n_fed_dedup_dup` are two names for one event — they are read at
two different levels. The first says "a transaction was thrown away", which is the
number an operator diagnosing a stale roster wants; the second says "and the peer's
terminator disagreed with its own records", which is a different fault with a
different fix (a lossy or saturating link, not a peer that does not implement
4.3). Before `n_burst_truncated` existed that fault was visible only as one
`[observable] fed_burst_truncated:` log line. Neither is counted as
`n_fed_malformed`, which is documented as *a line* failing validation: every line
of a transaction that reaches the terminator passed, and what failed is the
transaction.

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
prevention at that point. A member record is **keyed** by the **burst origin**, not
by the member's own server, and that is a deliberate separation rather than a
leftover: the key is what a resync replaces *against* (§4.3.1's replace-never-merge
is per-origin, so the entries a previous resync from the same origin installed have
to be nameable as a set), while `SBURSTM`'s `<server>` field is what the entry is
*for* — the member's actual holder, stored in `chan_remote_t::member_server`.
Keying by the holder would make a relay's resync unable to replace what the relay
itself installed, and a member the origin dropped would linger for ever. On a
two-node mesh the two strings are always the same; on a larger one they part
company, which is what the field is for. A member the receiver already knows
*under any key* is left alone rather than installed twice — two entries for one
person is a `353` that renders the same nickname twice with nothing on the node
able to explain it. `SBURSTN` carries `user`, `modes`, `signon` and `away` and the
receiver **keeps only `host`**; the other four are on the wire and **discarded on
purpose**, because they exist for §2.1's remote-nick registry ("which server holds
the user called `X`", the thing that makes `nick@server` resolvable for a member
this node has no `conn_t` for) and that registry is **Phase 9** with no home on
`server_t` yet. Building it here would be Phase 9's design decision taken in
Phase 6 without the rest of Phase 9; a reader who finds the fields discarded should
read that as the deferral it is. A channel's creation race is **not** re-keyed from
a burst: 2.2's tie-break needs the (epoch, name) of the *first* creator and the
wire carries one epoch. **Driving** the resync — link loss, reconnect, backoff — is
Phase 9, which is why 8's "link loss and reconnect re-syncs channel state via
`SBURST`" is now CLOSED, and was closed by Phase 9 rather than by Phase 6: Phase 6 owned the verb and the format, and Phase 9 owned the policy — the backoff, the retry budget and the heartbeat-driven redial that decide WHEN a resync happens. §4.3.1's frozen burst format is unchanged by any of it.

**A node's resync shadow is released at shutdown, and that arm is verified by
LeakSanitizer on the Linux runner rather than on the developer machine.** The
shadow is a module global — the one allocation on a node whose owner is not a field
on `server_t` — so `server_shutdown()` calls `fed_burst_close()` for it, next to
the dedup table free that is the same kind of arm. C4 declined to add it, on the
reasoning that it could not be checked on Darwin (LeakSanitizer is Linux-only, per
the hygiene note in 7/Phase 1). That reasoning was backwards and is retracted here
and at the three places it was written down: an arm that is unverifiable *locally*
is precisely the one worth adding when LSan **does** run on the CachyOS CI runner,
and leaving it out meant a node that stopped mid-transaction leaked up to
`IRC_BURST_MAX_BYTES` to the kernel on every shutdown. The arm prints whether a
shadow was open at teardown, so it is *asserted* on every platform and *verified*
on the one that has a leak checker.

**OPEN, AND DELIBERATELY UNRESOLVED: should a relay burst its own caches to peers
that already hold the channel?** Today it does, because `fed_burst_send()` walks
every channel the node holds and the receiving side has no filter for "you already
know this". The design does not say, and this pass does not decide it. The two
answers are:

- **Yes, as today.** A relay's cache is a cache (2.2) and is exactly as stale as
  the origin's own report would be, so re-sending it is redundant but harmless:
  the receiver's per-origin purge then replaces the relay's earlier copy with the
  relay's later one, which converges to the same answer. It costs one transaction
  per link establishment and it is what makes "on **every** link establishment the
  initiator sends full state" mean what a reader expects, because a relayed
  channel would otherwise never reach a node that linked up later.
- **No — burst only what this node is authoritative for.** A relay's caches are
  somebody else's state, and 4.3's per-origin rule already says a node replaces
  state *for an origin*; a relay claiming a third server's roster in a transaction
  of its own is the same category as the RELAYED_BURST refusal the guard chain
  already performs, one layer up. Filtering would cut the bytes a relay sends by
  most of them on a large mesh, at the cost of a rule that has to decide what
  "authoritative" means for a channel this node does not own — and that
  definition is Phase 9's re-election question, which 9 says must not be begun.

Nothing in the tree depends on the answer, and neither answer is cheaper enough to
be obviously right: today's costs bytes, the alternative's costs a policy. It is
recorded here so that whoever first sees the cost decide it with the numbers in
front of them rather than rediscovering them.

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

Phase 7 walked through four more of the same kind, and the argument is identical
each time: the list has a gap and the protocol does not, the RFC numeric is the
one a client understands, and the discrepancy is flagged at the emission.

- `302` `RPL_USERHOST` — the reply to `USERHOST` and nothing else. Below the
  `311`-`319` range this section lists for queries.
- `371` `RPL_INFO` and `374` `RPL_ENDOFINFO` — `INFO`'s body and its terminator.
  They sit in the gap between this section's `251`-`266` and `372`-`376` ranges.
  `375` and `376` are **not** reused for them: those are
  `RPL_MOTDSTARTING`/`RPL_MOTDEND`, and an INFO terminated with them would make
  the MOTD's terminator lie.
- `402` `ERR_NOSUMSERVER` — a `LUSERS` or `ADMIN` `<server>` mask naming a node
  this one cannot reach. On a single node there is nowhere to forward the
  question, which is precisely what 402 says.

Phase 10.1 added a sixth of the same kind, and the gap is the same shape:

- `330` `RPL_WHOISACCOUNT` — `<client> <nick> <account> :is logged in as`, and
  **sent only when there is an account**. RFC 1459 3.3.4 defines it and §2.1.1's
  account identity is what finally gives it a second parameter to carry: before
  Phase 10.1 this tree had no `<account>` value to put in it. Its absence means
  "not identified", which on this node is exactly and only true.
  It is still worth having **now that `account-tag` exists**, and the two are not
  redundant: a `WHOIS` answers a question a client asked **about a person it
  named**, which is how a client discovers an account for somebody who has said
  nothing since joining, and a tag answers "who sent *this line*" for a client that
  negotiated it. §2.5.3 says when each is asked for, and it is also the only place
  a person's account name is revealed to a user who negotiated nothing at all.

`432` `ERR_ERRONEUSNICKNAME` is for a nickname that is **malformed** — illegal
under §2.1. It is distinct from `433` `ERR_NICKNAMEINUSE`, which is for a legal
nickname already claimed. The two must not be conflated: answering an illegal
nickname with `433` tells the client the name is taken, so it retries with a
different name on a false premise, and the real cause is never surfaced.

`005` with `PREFIX=(ov)@+`, `CHANTYPES=#&`, `NETWORK=` is effectively
mandatory — many clients misbehave without it.

#### 4.4.1 The full `005`, and the rule it is built on

Phase 10.4 replaced the five-token list with eleven. The rule is one sentence:
**a token is advertised only where a bound or a feature behind it can be named.**

`005` is a list of *claims*. A client sizes a buffer from `CHANNELLEN`, decides
whether one message may name six targets from `MAXTARGETS`, wraps a name at
`NAMELEN`. So a token that is wrong is not a cosmetic defect — it is a client
acting on a lie — and the two failure directions have different fixes: a **missing**
token is a client that carries on, while a **wrong** one is a client that switches
a feature on and then behaves as though the node agreed. That is the same rule
`cap.h` holds `CAP LS` to, applied to the other list every client reads.

| Token | Value | Derived from / honoured by |
|---|---|---|
| `NETWORK` | `irc-serve` | `NODE_NETWORK`, commands.c. A deployment property, not a node property |
| `CHANTYPES` | `#&` | `CHAN_TYPES` in `channel.h`, and the two bytes `chan_name_valid()` accepts (`CHAN_TYPE1`, `CHAN_TYPE2`). One declaration, one validator |
| `PREFIX` | `(ov)@+` | 4.4. The two prefix modes `channel.h` defines (`CHAN_MEMBER_OP`, `CHAN_MEMBER_VOICE`) and `names_signs()` draws. **Not** derived from constants — see the finding below |
| `CASEMAPPING` | `ascii` | `message.c`'s `up()` and `fanout.c`'s `ascii_lower()` are ASCII-only. True, and the rfc1459 alternative is priced below |
| `AWAYLEN` | `255` | `CONN_MAX_AWAY`; an over-long AWAY is **refused** with `417`, not truncated |
| `CHANNELLEN` | `63` | `CHAN_MAX_NAME`; `chan_name_valid()` refuses anything longer |
| `KICKLEN` | `255` | `CHAN_MAX_KICK_REASON`; an over-long KICK `<reason>` is **refused** with `417`. Added in Phase 10.9 — see §4.4.4 |
| `LINELEN` | `8192` | `IRC_MAX_LINE`; `conn_fill()`'s read cap and `message_parse_n()`'s on-wire cap |
| `MAXTARGETS` | `1` | `MSG_MAX_TARGETS` in `msg_verbs.h`, which is the arity check `send_message()` applies — RFC 2812 3.3.1 gives PRIVMSG exactly one `<msgtarget>` and no message verb here parses a list |
| `NAMELEN` | `255` | `CONN_MAX_REALNAME`; the value bound of `conn_t::realname`. **Mandatory** for a node advertising IRCv3's `setname`, so it is stated whether or not that command is present |
| `NICKLEN` | `63` | `IRC_MAX_NICK`; `valid_nick()` refuses anything longer |
| `TOPICLEN` | `255` | `CHAN_MAX_TOPIC`; an over-long TOPIC is **refused** with `417` |

Every `*LEN` is rendered by `commands.c`'s `IRC_STR()` from the constant that
*enforces* the limit, so raising a bound in another file moves the token with it.
The test asserts the **literals** (`TOPICLEN=255`), not the constants, which is
the whole of the teeth: a test built from `CHAN_MAX_TOPIC` would follow it and
never notice that `005` was not updated. `tests/integration/test_registration.c`
holds the whole `005` byte-for-byte, each token individually, and the list of
tokens that must be **absent**.

**`IRC_STR()` cannot stringify an expression.** `#x` stringifies an argument's
token sequence rather than evaluating it, so a `sizeof(...)`-derived constant in
that position renders as the literal text `sizeof(((conn_t *)0)->realname) - 1u`.
That contains spaces, a middle parameter containing a space is `unrepresentable`,
and the consequence is that the *entire* `005` is refused and every connecting
client gets no ISUPPORT at all. `CONN_MAX_REALNAME` is therefore a written `255`
— the same reason `CONN_MAX_AWAY` is — and the derivation that *can* be
stringified runs one level up, in `k_005[]`.

#### 4.4.2 The tokens deliberately NOT advertised, and two findings

An absent token and a forgotten one look identical on the wire, so each absence is
named at `k_005[]` with its reason. In summary:

- **`BOT=B`** — 004 advertises `i` for users and `b,k,l,imnpst` for channels and
  this node evaluates neither set. No BOT mode, no services, nothing that reads it.
- **`EXTBAN=`** — `+b` stores a mask verbatim and `chan_has_ban()` tests it by
  string equality (§2.2). There is no ban-**expression** parser, so there is no
  `~&account:name` and no `EXTBAN` value. This is the same missing evaluator that
  blocks `account-extban` (SPEC_TRACKING §10.2) — one gap, named twice.
- **`SAFELIST`** — no safelist. `+S` is not a mode §4.4 advertises and `chan_t` has
  no safe-mask store.
- **`MONITOR`, `WATCH`, `WATCHNICK`** — no such verbs, so no watch list and no
  ceiling on one.
- **`MSGREFTYPES=`** — no message reference is recognised. `PRIVMSG @#chan :hi`
  reaches `fanout_resolve()` with `@#chan` as the whole target, which is not a
  valid channel name, so it is `403` rather than a reference to a history window.
- **`ACCEPT`** — no `EXCEP`/`INVEX`, no accept-list store, no evaluation of either.
- **`silence`** — no `SILENCE` verb and no silence store. This one is a fact rather
  than a gap: a silence list is an operator list and this node has no operator
  model at all (`CHOPER` answers `464` for every request).
- **`draft/CHATHISTORY`** — no history. `resume.c`'s restore hands a client back the
  channels it was in at disconnect, which is a *session* and not a history: it
  keeps nothing that was not said while the client was connected, so it cannot
  answer "what was said in `#t` last week". Advertising it would put a client into
  a state it cannot leave.
- **`MODES`** — this token is a *count* of mode changes permitted in one `MODE`
  command, not a mode string (§4.4's `004` carries those). Nothing here caps one.

**Two findings, reported rather than answered.**

1. ~~**`KICKLEN` is omitted because no bound exists.**~~ **CLOSED IN PHASE 10.9.**
   The original finding, kept because the shape of it is the argument for the whole
   list: `handle_kick()` took `<reason>` verbatim with no length test, so no number in
   this tree described the largest reason the node accepts, and writing `255`
   because `CHAN_MAX_TOPIC` and `CONN_MAX_AWAY` happen to be 255 would have
   advertised a limit nothing enforces. The consequence was worse than an absent
   token: an over-long KICK reason reached `fanout_deliver()` and then
   `message_format()`, which **refused it as `unrepresentable`** — a refusal on
   `n_reply_refused`, the counter `reply.c` holds at zero because a non-zero value of
   it is a bug report. So the missing bound was a reachable way to make a **client
   command** trip a counter reserved for bugs.

   `CHAN_MAX_KICK_REASON` (255) now bounds it, `handle_kick()` answers `417`, and
   `KICKLEN` is advertised. §4.4.4 has the bound and the boundary. The finding is
   struck rather than deleted because a list of absences is only trustworthy if the
   ones that used to be on it are visibly gone.
2. **`USERLEN` is omitted although a bound exists**, because that bound is not
   *enforced*: `USER`'s ident is truncated into `conn_t::user` rather than
   refused, so `USERLEN=` would promise a limit the node does not apply to the one
   parameter it is about. `NAMELEN` is advertised for the opposite reason — that
   bound *is* what can be stored, and `SETNAME` refuses beyond it.

**`PREFIX=(ov)@+` is the one advertised token that is still written out.** The
mode letters (`o`, `v`) and the sigils (`@`, `+`) are literals inside
`names_signs()` and inside the mode parser, and no constant names them. Deriving
the token would mean making the mode letters constants and threading them through
the mode evaluator — a change to what a mode *is* in this tree, made for the sake
of one string. It is named here as a finding rather than done quietly.

#### 4.4.3 `standard-replies`, and the four numerics this node got wrong

Phase 10.9 adds IRCv3's `standard-replies`: `FAIL <command> <code> [<context>...]
:description`, plus `WARN` and `NOTE`, rendered **only for a client that negotiated
the capability**. A client that negotiated nothing receives the legacy numeric,
byte-for-byte, and that is the guarantee this section is mostly about.

**`ERROR` IS NOT ONE OF THE THREE, and that is a fact rather than a gap.** The
specification's introduction, its format section and its capabilities section name
`FAIL`, `WARN` and `NOTE` and nothing else; the draft's own history carried a fourth
verb (`OK`) which was dropped before publication. `ERROR` is a separate, older server
command with no relation to this specification, so emitting it under this capability
would be putting a command word on the wire that no client negotiated the capability
**for**. `WARN` and `NOTE` have **no producer on this node** — it has no command that
warns and none that notes — and their absence is a named limit, not a claim.

**THE LINE, IN ONE SENTENCE: a legacy numeric migrates where that numeric answers
more than one question ON THIS NODE**, so the number alone cannot tell a client which
refusal happened.

| Numeric | The questions it answers here | Becomes |
|---|---|---|
| `417` `ERR_INPUTTOOLONG` | `PRIVMSG` text, `AWAY` message, `SETNAME` realname (length **and** bad byte), `KICK` reason — **four** | `ERR_INPUTTOOLONG` / `ERR_INVALID_PARAM` |
| `461` `ERR_NEEDMOREPARAMS` | too few **and** too many — and its text reads "Not enough parameters" in the too-many case too | `NEED_MORE_PARAMS` / `TOO_MANY_PARAMS` / `INVALID_PARAMS` |
| `482` `ERR_CHANOPRIVSNEEDED` | not a channel operator (`KICK`, `MODE`, `INVITE`), not an IRC operator (`KNOCK`), the verb is disabled (`REGISTER`) — **three** | `ERR_CHANOPRIVSNEEDED` / `ERR_NOPRIVILEGES` / `ERR_ACCOUNTREGISTRATIONDISABLED` |
| `464` `ERR_NOPRIVILEGES` | not an IRC operator (`CHOPER`), SASL authentication failed (`AUTHENTICATE`) | `ERR_NOPRIVILEGES` / `INVALID_AUTHENTICATE` / `ERR_AUTHENTICATIONFAILED` |

**EVERY OTHER NUMERIC STAYS**, and the reason is the same rule pointed the other way:
`401`, `403`, `404`, `421`, `431`, `432`, `433`, `437`, `441`, `442`, `451`, `472`
and the rest each answer exactly **one** question on this node, so the number is
unambiguous and replacing it would take away the name the client already handles in
exchange for a line it must now learn. The specification's own introduction states
the complaint this table answers — *"numerics themselves and the mapping of numerics
to names can be unclear or conflicting"* — and these four are where this node's own
use makes them unclear. `test_standard_replies.c` asserts both halves: the four, and
`401` and `451` reaching a negotiating client **unchanged**, because a migration of
every numeric would pass every other case in that file.

**THE COST, and who pays it.** After this, `417`, `461`, `482` and `464` stop
reaching a client that negotiated `standard-replies`. A client that pattern-matches
`417` for "line too long" must read `FAIL <cmd> ERR_INPUTTOOLONG` instead. That is a
real cost and it is the price of the ambiguity being fixed. **No client that
connected to an earlier build is affected**, because the capability did not exist to
negotiate — the change is unreachable from any pre-existing client, which is also
why the legacy rendering is left byte-identical rather than tidied.

**AND THE TENSION WITH THE SPECIFICATION'S OWN SENTENCE, recorded rather than
glossed:** it says servers "SHOULD NOT replace standardised error numerics with
standard replies, unless the replacement is explicitly described by some other
specification", and all four of these are standardised by RFC 1459/2812. Three
things make the partial migration defensible here, and none of them is that the
sentence is wrong:

- the exception's **purpose** is served. The introduction's complaint is precisely
  that these mappings are unclear, and on this node they are. A node with one 482
  meaning three unrelated things has the defect the sentence is aimed at.
- the replacement is **per destination**, so nothing is taken away from anybody who
  did not ask for it — which the sentence's own framing ("to a client which supports
  this capability") presupposes.
- `setname` is the one case the exception covers **outright**, because its own
  specification names the replacement. §4.2.1's silence for a client that did not
  negotiate is *unchanged* and no longer justified by the capability's absence: the
  specification asks for silence there, and a `FAIL` is a response.

**WHERE IT LIVES, and why that is the only defensible place.** `reply.c` is already
"the ONE place a numeric is emitted", and the migration is one table plus one branch
there. `reply_refused()` renders the text **once** and hands it to whichever shape was
chosen, so the legacy and `FAIL` renderings are guaranteed to be the same string; and
a `legacy` this node does not migrate takes the legacy branch, which makes the
function safe at any call site rather than only at the 39 that are on the list.

#### 4.4.4 `KICKLEN`, and the bound it names

`CHAN_MAX_KICK_REASON` is 255, beside `CHAN_MAX_TOPIC`, `CONN_MAX_AWAY` and
`CONN_MAX_REALNAME` — **one bound for "a sentence a user typed"** rather than four
that differ for no stated reason. It is a **written literal** rather than a
`sizeof(...)` because 005 renders it through `IRC_STR()` and `#x` stringifies an
argument's token sequence rather than evaluating it: a derived constant in that
position renders as text containing spaces, a middle parameter holding a space is
`unrepresentable`, and the consequence is that the **entire `005` is refused** and
every connecting client gets no ISUPPORT at all. `CONN_MAX_REALNAME` carries the
long note; the rule is the same one.

It is a **cap, not a truncation point**, for the reason the other three are: a KICK
reason is shown to every member of the channel as though the kicker had written it.
`handle_kick()` refuses with `417` and leaves the roster untouched, and the bound is
checked **immediately after the arity test** rather than near the send, because a
command carrying a parameter the node will not accept is malformed whatever the
sender's standing on the channel.

The interesting assertion is not the 417 but the absence of a `reply_refused:` line on
the node's own output — because with no bound the reason reaches `message_format()`,
which refuses rather than reshapes, and the only outcome at that depth is a refusal
counted on a counter `reply.c` holds at zero. `test_standard_replies.c` asserts the
absence, so a node that dropped the bound again fails on the **defect** rather than on
a symptom.

#### 4.4.5 `userhost-in-names`, and the disclosure it makes

Phase 10.5 lets a `353` roster carry `nick!user@host` instead of a bare nickname.

**This is a privacy decision and it is stated as one.** What the capability does is
disclose **every member's ident and observed host address to every other member of
the channel** — to clients that member has never spoken to, and to clients who
joined after them. There is no per-member consent anywhere in it: one client asking
puts the whole roster's hostmasks on the wire to that client. The ident in
particular is the thing RFC 1459 gives servers *permission* to know about a user
and never tells a client to expect to learn.

Two properties follow, and both are load-bearing rather than stylistic:

- **The shape is decided per destination.** `chan_verbs.c`'s `names_entry()` asks
  `cap_userhost_in_names_enabled(dst)` for the connection being answered, so two
  clients on one channel see two different roster shapes for the same member. A
  node that decided once per channel — or once per node — would hand every
  member's hostmask to every member whether they asked or not, which is a
  disclosure nobody agreed to. This is the same per-destination discipline as
  `multi-prefix` and `extended-join`; here the cost of getting it wrong is not a
  mis-drawn sigil.
- **`352` and `311` are untouched.** Those numerics already carry `<user>` and
  `<host>` in the RFC's own shape, so they were never the gap. The gap was `353`
  alone and so is the scope.

**The federation roster, and what it cost to be able to render one.** A remote
member has no `conn_t`, so the `nick!user@host` had to come from
`chan_remote_t` — and `chan_remote_t` had a `host` and **no ident**. 4.3's `SBURSTN`
carries `<user>`, `federation/burst.c`'s shadow has stored it since Phase 6, and
the join from the shadow to the roster copied only the host across: **half a
hostmask was on the wire and being discarded.** Phase 10.5 adds
`chan_remote_t::user` and `chan_remote_set_user()`, fed from `shadow_ident()` in the
same place the host is. The cost is 64 bytes per remote-member element and
`CHAN_MAX_REMOTE_MEMBERS` (64) elements, so **4 KiB per channel of addressed array**
of which only the used prefix is touched.

**When the node has no hostmask to draw, it draws the bare nick.** A remote member
learned from a *live* SJOIN has neither half — 4.3's SJOIN is
`<server> <chan> <nick> <flags>` — and that empty host is the documented normal
state (`channel.h`'s `chan_remote_t` says so). Putting `*` in place of a missing
half was refused: `*` is a byte that reads as part of a hostmask and means nothing
to a client parsing one. A negotiated client that still sees a bare nickname has
learned the true thing, and RFC 2812 3.3.5 permits a `353` of bare nicknames, so
the mixed roster is parseable rather than surprising.

**What `CASEMAPPING=rfc1459` would cost**, since the honest answer is only useful
if the alternative is on the record: `[]\~` and `{}\|^` become fold-equivalent,
which makes it *unsafe* to use any of those bytes in a nickname, a channel name or
a hostmask component — `#a[b` and `#a{b` become one channel. Every comparison that
folds then has to fold the same way or two of them disagree:
`server_nick_lookup()`, `chan_same_name()`, `fanout.c`'s `ascii_lower()`,
`channel.c`'s `up_ascii()`, and the WHO mask matcher. That is five call sites
plus the *set of bytes the validators must now refuse*, and the validators are the
expensive half — `valid_nick()` and `chan_name_valid()` would both grow a
deny-list. It is a change to what a nickname may be, which is not something a
`005` token decides.

---

## 5. Fix the weak and fake parts

| Item | Problem | Action |
|---|---|---|
| `ircv3_tags.c` | `tags_parse` and `tags_serialize` are the same function; roundtrip is vacuous; no escaping | Real parse → tag list, real serialize, and IRCv3 escaping **both ways**. Doubles as the internal `@irc-serve-*` transport tags (§2.4) |
| `sasl_framework.c` | not in `irc_core`; `sasl_step` discards input, auto-completes after 2 calls; self-test harness lives in `src/` | Move the harness to `tests/`; implement real SASL PLAIN (base64 → `authzid\0authcid\0passwd` → credential store). Credentials are per-server, so a federated deployment shares via link auth |
| `message_id.c` | orphan, not compiled, not tested, global counter, not IRCv3-shaped | Fold into §2.4: per-SERVER monotonic counter + boot `epoch`, dedup key `(origin,epoch,id)` scoped per node — unique without a global lock |
| `lockfree_contract.c` | `volatile int`, one writer, no atomics | **Delete.** The single-threaded loop needs no lock-free structure. The claim comes out of the docs |
| `server.c` | `printf` theatre; parses literal `"PING"` | Rewrite as the real `server_t` |
| `node_main.c` | closes every client immediately (line 115) | Keeps its real `socket`/`bind`/`listen` and signals; loop becomes §3.4; port configurable, not hardcoded 6667 |

**The escape set named above was wrong, and is corrected here rather than left
for a reader to disprove.** Phase 8 checked it against the IRCv3 message-tags
specification and this row listed `` `\:` `\;` `\s` `\\` `\r` `\n` ``, which is
a plausible reading and is the wrong table in both directions: a semicolon is
written `` `\:` `` and a **colon is not escaped at all**. `core/message.c` carried
that table in its own `switch` and had asserted it in `test_message_format.c`
for several phases, which is the usual way one survives — the test looked like the
thing protecting the value while it was the thing keeping it wrong. Both were
corrected in Phase 8: the escape table now lives in exactly one place
(`src/ircv3_tags.c`) and `message_tag_escape()`/`message_tag_unescape()` delegate
to it, because two copies are a tree that disagrees with itself about what a tag
value means. Unescaping was wrong in a second, less visible way — a `\` before a
character outside the set kept the backslash, so `\x` decoded to `\x` where the
specification says `x`; it now drops it, which is also what makes a block written
with the wrong table by a peer decode to the value its author meant.

A tag value's escape set is **not** a parameter's, and the two are not
interchangeable: RFC 1459 has no parameter escaping at all, and 3.2's formatter
refuses or colons a parameter rather than escaping it.

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

**The gate is a RATCHET, and "zero skipped tests" is not reachable in Phase 7.
Both of the claims this section used to make were false, and they are retracted
here rather than left for a reader to disprove.**

The first was that *"`KNOWN_SKIPS` in `tests/CMakeLists.txt` lists every
legitimately-skipped test"*. **No such list existed at any point.** The
`return 77` blind spot this section describes was real — `ctest` excludes a skip
from its pass rate and from its exit code, so a green run coexisted with eight
unimplemented features — and nothing in the tree enforced anything about it. The
second was that the list *"must reach empty by Phase 7"*.

**It cannot, and the reason is this document's own phase allocation rather than an
oversight.** §7 gives CAP negotiation and multi-prefix to **Phase 8**; §2.3 says
"Peer discovery and auto-scale stay Phase 9" in as many words, and §7/Phase 9
owns reconnect and failover as well. Those skips are not unfinished Phase 7 work.
They are work Phase 7 has explicitly been given no time to do. A gate demanding
zero would be demanding a feature Phase 7 must not build, and the only two ways
to satisfy it would be to delete the tests — which is exactly what the blind spot
looks like — or to build Phase 8 and Phase 9 inside Phase 7.

**What is enforced instead is the real intent: the count only goes down, and every
skip is accounted for by name.** `tests/known_skips.txt` is the single
authoritative list: one line per skip, naming the CTest test, the phase that owns
it, and the issue that closes it. `scripts/check-skips.sh` compares that list with
the set CTest actually reports as skipped, in **both** directions:

- a test that skips and is not on the list **fails** — the blind spot above;
- a test on the list that no longer skips **also fails**, so the list cannot rot
  into a permanent allowlist still naming tests that were implemented years ago.
  *This second direction is what makes it a ratchet rather than an allowlist, and
  it is the half a "fail on any skip" rule gets for free while an allowlist does
  not.*
- a listed name that is not a registered CTest test **fails** — a typo, or a
  deleted test.
- output the script cannot read the skip block from is a **failure**, not a pass:
  "we could not tell" is not "there are none".

The gate runs in `ci_test` (the required merge gate), in `local-ci.sh`, and in
`make test`. `CONTRIBUTING.md`'s rule — *if a feature is absent, return CTest's
skip code with a message naming it* — is unchanged, and the first direction is
what enforces it: **a new skip without a line in `tests/known_skips.txt` is red.**

**ZERO SKIPS ARE PERMITTED TODAY, and that is the state, not a goal.** §7/Phase 8
retired the two IRCv3 ones and §7/Phase 9 retired the other five, so
`tests/known_skips.txt` is now **empty** — comments and nothing else — and the gate is
a plain "no test may skip", which is the phrase this section always said the goal was.

Two things about that are worth stating because neither is visible from the gate's
behaviour:

- **THE FILE IS KEPT, NOT DELETED.** The script fails on a **MISSING** list by
  design, because a test that skipped with no list would otherwise be permitted by the
  accident of the file's own absence. So an empty file is the finished state and an
  absent one is a broken gate, and the difference between them is not something a
  reader can infer from a passing run. `tests/known_skips.txt` now carries the account
  of how all seven were closed.
- **THE GATE STILL FAILS IN BOTH DIRECTIONS, but one direction is now total.** The
  "skipped but not listed" arm was already the strict one; with no lines, *every* test
  that skips falls into it. The other two arms have nothing to check and pass
  vacuously, which is worth saying plainly rather than leaving a reader to assume a
  three-way check is still running.

Adding a line back requires no change to the script. A developer who genuinely cannot
implement something writes the line, and the skip is red until they do — which is still
the whole point of the file.

The "seven" this section used to say was correct when it was written — Phase 7
landed with seven — and went stale the moment Phase 8 closed the first of them,
because a sentence that is only updated when a phase *begins* is not a ratchet.
The count here is now the count in the file, and Phase 8 is where it moved.

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

*Accept status after C5 (what is provably met, and what is not).* Criterion 2 is
met **after a resync** as well as before one, which is the stronger form: three
resyncs over one established link, and the full `353` contents on both nodes after
each. The replace-not-merge property behind the word "resync" has four distinct
tests, and two of the four could **not** be produced by client commands on a
two-node mesh at all — a member the origin loses is always removed on the far side
by an `SPART` first, and a channel A no longer has is always removed by its
forwarded `PART` — so the fixtures create those states deliberately and say so.
C5 added `SBURSTM`'s `<server>` field (§4.3.1) before a second implementation
existed, and `n_burst_truncated` for the one discard reason that had only a log
line. Neither changes what the tests can prove on a two-node mesh: on that mesh a
member's server and the burst origin are the same string, so the field is
exercised but not *distinguished* — which is the honest limit, and the reason
§4.3.1 says what the field is worth rather than claiming it is covered. Not met,
and deliberately so: **link loss and reconnect driving a resync** is
Phase 9, so §8's "link loss and reconnect re-syncs channel state via `SBURST`"
remains open and this phase makes no claim about it. A three-node mesh, the only
topology in which a resync is a genuine *re*-sync rather than a first exchange, is
also out of scope here; §4.3.1 records what the format gives up on a larger mesh
(a receiver that already knows a nickname leaves the existing attribution alone)
and §4.3.1's open question records the one relay behaviour the design has not
picked.

*Accept status after C5, part two: what a node does when a peer goes away.* §2.2's
fail-closed rule and `SQUIT` are the other half of Phase 6, and they are **proved
on the wire** by `test_fed_resync.c`:

- **Orphaned, fail closed.** With no `ESTABLISHED` link to a channel's origin, a
  client on a node that does not own that channel gets `437` **naming the origin**,
  asserted from the client's own bytes and not from a node log line, with the
  `state=ORPHANED` line beside it to say which refusal it was. `NAMES` still
  answers in the same state, and the local members still see each other, and the
  remote roster is still served — a dead **link** is not a departed **server**, and
  nothing purges it.
- **No auto-redial.** The latch is `server_link_t::created_ms`; `fed_link_reset()`
  is the only thing that clears it and the tick does not, so a node whose link
  fails dials that peer exactly once. Asserted *after* the case's client traffic,
  not the moment the link died: checked there it passes against a node that
  re-dials on every tick, because that tick has not run yet. The teeth found that.
- **Resurrection.** Re-linking a server of the **same name** brings the channel
  back, and the assertion is a **round trip** — the client is accepted, the
  `SJOIN` is forwarded, and the far node's own output shows the member arriving —
  because an absence of `437` is also what a node that silently dropped the
  request produces. Reaching it required one fix outside the new code: the
  handshake's uniqueness check treated a link with **no descriptor** as a rival
  claim on the name, so a peer that re-dialled after a partition was told
  `NAME_IN_USE` by a link with no socket on it and §2.2's resurrection was
  unreachable. A link that holds a descriptor is still a claim; one that does not is
  a name and a destination, and it is reused rather than duplicated.
- **`SQUIT` fan-out, and the per-origin purge.** A link going down tells every
  **other** `ESTABLISHED` peer that this node's name is gone, with **one** 2.4
  identity for the whole fan-out (the dedup store is per node, so two peers
  carrying one key is what lets a third node drop the second copy). The receiver
  purges that origin's roster entries and its `servers[]` name and **forwards it
  onward**, and the purge is **per origin**: a roster belonging to an unrelated
  origin survives, which is the assertion with teeth. `SQUIT` is **not** in the
  S-verb table `fed_sverb_for()` reads — that table is §4.3's *forwarded*
  vocabulary and a departure relays nothing — and it is **refused** on a peer that
  says *this* node is gone, on its own counter, without costing the link.

**The topology limits of those claims, stated rather than implied.** A link going
down can only be announced to a peer that is *still up*, so a **two-node** mesh
produces no announcement at all: the link that died was the only link. The
smallest fixture that reaches the claim is **four** nodes (an announcer with two
peers, a receiver with two, and a second origin for the receiver), which
`test_fed_resync.c` builds and says so. And on a two-node mesh the member's server
and the burst origin are the same string, so §4.3.1's `SBURSTM` `<server>` field is
exercised for **shape** but cannot distinguish a receiver that honours it from one
that ignores it; a **three-node** fixture is the only thing that tests it, and
there is none. A roster purge is proven per origin **across** channels, not within
one: only a node that believes it owns a channel emits an `SJOIN` for it (§3.1's
non-owned row forwards to the owner and nowhere else), so two origins reporting
one channel means two owners, which is the creation-race gap `fed_in_channel()`
documents. None of this is coverage that exists.

**What is still open, after all of that.** §8's "link loss and reconnect
re-syncs channel state via `SBURST`" remains open: C5 proves that a failed link is
**not** re-dialled and that a *deliberate* retry works, and it drives the retry
from the test through the `fed_link_reset()` seam. What is missing is the policy —
backoff, a retry budget, whether a peer that was ever established is dialled more
eagerly than one that never was — and a `SBURST` **triggered** by a reconnect
rather than by establishment. §2.2's re-election is not started and must not be:
§9's risk row says it needs a per-channel epoch in the dedup key, which breaks
§2.4's `(origin,epoch,id)`.

**One cost of the `SQUIT` trigger, which is a design property and not an
implementation detail.** The announcement is made when *one link* dies, not when
the node leaves, so on a mesh where this node is still reachable by somebody else
the peers told here purge a roster for a server that is still there, and it comes
back only from a later `SJOIN` or the next burst — which Phase 9 owns. That window
is the price of telling anybody at all, and it is bounded only by that policy; a
reader who finds it surprising should read it as the question Phase 9 answers
rather than as a defect C5 could have avoided.

**Phase 7 — Command surface, and the skip gate becomes a ratchet.** The remaining
§4.2 SHOULD commands; CI gains the skip gate. *Accept:* the seven remaining verbs
answer on the wire, `test_topic_persist` is a real test of real topic
persistence, and the gate fails in **both** directions. **"Zero skipped tests", as
this phase once read, is not met and was never reachable here** — §6.4 gives the
argument and `tests/known_skips.txt` was the phase-by-phase account of the seven
that remained at the end of this phase. **Five, not seven, is what it accounts for
now**: Phase 8 closed the two IRCv3 ones, and the number here is corrected in
Phase 8 rather than left for a reader to disprove against the file, which is the
same retraction §6.4 made about the two claims it used to carry.

*What is in, and what the honest refusals are.* `INVITE` `LUSERS` `ADMIN` `INFO`
`USERHOST` `KNOCK` `CHOPER` are implemented, and two of them are refusals rather
than features, because the RFC wants something this tree cannot honestly supply:
`KNOCK` is gated on an **IRC operator**, and there is no operator concept here at
all, so it answers `482` for every request and says so in its text; `CHOPER`
implies operator flags and a credential store, and this node has neither — `PASS`
is *recorded, not checked* — so it answers `464` and never `381`. The alternative
in both cases was a numeric claiming a success that nothing would act on.
`LUSERS` reports a real `<max clients>` (the connection table's bound) and says
that is what it is, because there is no configured maximum to report.

*Four new numerics that are not in §4.4's list, added the way 301, 303 and 417
already were:* `302` (RPL_USERHOST, for `USERHOST`), `371`/`374` (RPL_INFO and its
terminator, for `INFO`), and `402` (ERR_NOSUMSERVER, for a `LUSERS`/`ADMIN` mask
naming a node this one cannot reach). In each case the list has a gap and the
protocol does not, the RFC numeric is the one a client understands, and the
discrepancy is flagged at the emission. `375`/`376` are **not** reused for INFO's
terminator: they are `RPL_MOTDSTARTING`/`RPL_MOTDEND`, and reusing them would make
the MOTD's terminator lie.

*Topic persistence is a Phase 7 feature, and it is a bounded cache and not a disk
write.* §2.2 requires a channel with no members to be disposed, and the topic is
the one field whose loss a client can see, so `chan_t::topic`/`topic_who`/
`topic_when` are copied into a bounded cache on `server_t` when the channel is
disposed and copied back when a channel is created again. A topic does **not**
survive a node restart, because 3.4 forbids a write inside the event loop; the
cache's bounds, its three alternatives that were considered and rejected, and what
it deliberately does **not** carry are in `core/channel.h`.

**Phase 8 — IRCv3.** Real tag escaping + roundtrip, CAP negotiation
(LS/REQ/ACK/NAK), real SASL PLAIN, message-ids, multi-prefix. Both IRCv3 skips
this phase was given are retired: `CapNegotiation` and `MultiPrefix`, and both of
their lines are out of `tests/known_skips.txt`, which is the ratchet's other
direction and has to be the same change. The count goes 7 → 5.

*What landed, and the two decisions in it that a reader should be able to check.*

**`msgid` is 2.4's own `(origin, epoch, id)` rendered, not a second counter** —
`<origin>_<epoch>_<id>`, `_` because 2.4's origin grammar excludes it and the
three fields therefore stay separable. The argument is in 2.4: a second counter
would mean one thing to this node and something else to a peer, so no relay could
carry it and the tag would be defeated by the first hop. The consequence is that
the emission's identity is minted **once**, in `fanout_deliver()`, and the same
stamp feeds the local write and every forward target — see 2.4, which now says so
and which is the claim `test_ircv3_msgid.c`'s two-client case checks.

**`multi-prefix` is implemented rather than declined**, and it was a real choice:
asserting "this node does not offer it" is legitimate and checkable, but the
change is two draws in two functions and both were already gated on a
`cap_multiprefix_enabled()` that had existed with no implementation behind it.
Shipping a capability table with a reserved bit, a gate and no behaviour is the
"documented but absent" pattern this project keeps retracting. It is offered in
**353 and in 352**, because IRCv3's multi-prefix names both numerics and honouring
it in one alone would be a node whose `353` is authoritative and whose `WHO` is a
summary. 005's `PREFIX=(ov)@+` is the table the drawn run is ordered by — a client
indexes the run left to right into PREFIX — so `PREFIX=` is load-bearing for the
rendering and not merely decoration. Without the capability a member who is both
op and voiced is drawn `@nick`, exactly as before, because a client that did not
negotiate it indexes the first byte and would otherwise be handed a nickname it
cannot resolve.

**Phase 9 — Federation hardening.** Link failure and reconnect handling, driving
the §4.3 `SBURST` resync (Phase 6 owns the verb and its wire format, not this
phase), plus network-visible nick rename-the-loser (§2.1), peer discovery,
auto-scale, and heartbeat-driven failover. This is where the
existing `federation`/`loadbal` issues belong.

**Phase 9 is COMPLETE, and it is the phase that closes §8's first item.** All five
skips it owned are retired — `SyncState`, `FailoverReconnect`, `Reconnect`,
`PeerDiscovery` and `AutoScale` — each implemented, each moved to
`tests/integration/` with its **CTest name unchanged** (the ratchet names tests by
that name, so renaming a target and keeping the name is the move that keeps the gate
honest), and each line deleted from `tests/known_skips.txt` **in the same change**.
`tests/known_skips.txt` is now empty and `scripts/check-skips.sh` passes on an empty
list: the gate is "no test may skip", which is the phrase §6.4 always said the goal
was.

The three that moved were classified by the *skip's name* rather than by the feature,
and it was wrong the same way for all of them — none is a property of a single node,
and a target in `tests/loadbal/` links `irc_core` and nothing else: it cannot spawn a
node, cannot own one end of a link, cannot drop a socket and cannot read a `366`.
`tests/loadbal/` is now a directory of no tests and says so in full.

**"Auto-scale" is scoped, deliberately, to what a node can honestly do** — §2.3 gives
the whole argument, and the short form is that a node does not spawn or stop nodes
(that is a supervisor's job) and propagates load by **reporting** it rather than by
moving it (2.2's origin is immutable and a client's session belongs to its socket's
node). The half that is a node's business — **announcing its own departure and having
peers treat it as terminal rather than as a failure** — is implemented and tested over
real links. Two defects in the poll loop had to be fixed for that announcement to
survive its own journey; both are documented where they were fixed.

Parallelisable: Phase 1's tokenizer and the IRCv3 tag-escaping work are
independent. Phase 2 blocks the rest. Phase 6 is the largest single phase and
should not be split across people.

**Phase 10 — IRCv3 client support.** Ten sub-phases against 41 non-draft IRCv3
specifications, in the order the dependencies force.

**Phase 10.1 — THE ACCOUNT SUBSYSTEM (issue #117). COMPLETE.** It exists because
issue #117's gate was a single absence: `src/` had **zero** hits for
`account_tag`, `logged_in`, `serviced_login` or `account_name`, and that one
absence blocked **seven** specifications at once, because `account-tag` needs to
know who is logged in on *every* message and `extended-join` needs the account on
*every* `JOIN`. None of them is a capability that can be bolted on.

What landed: §2.1.1's second axis on `conn_t`; §2.5's registry as a separate
operator file; §2.5.2's refusal of `REGISTER`/`UNREGISTER`; and §2.5.3's
deliberate **absence** of `account-tag` from `cap.c`'s table. The one wire
surface was `330 RPL_WHOISACCOUNT` (§4.4).

**What was NOT in Phase 10.1, and why each was left:** `account-tag` **emission**,
`account-notify`, `extended-join`, `oper-tag`, `chghost`, `account-extban` and
`away-notify` all **consume** this subsystem and were P10.2/P10.3/P10.8.
chathistory and websocket/sts/SASL-SCRAM are **decisions for the user, not
implementation tasks** — chathistory because this design's posture is fail-closed
with no buffered state, and that is a genuine conflict with §2.2's disposal rules
rather than an omission.

**Phase 10.2a — `account-tag` (issue #117). COMPLETE.** §2.5.3's emission: the tag
is stamped once per emission in `fanout.c`, gated per destination on the
recipient's own `account-tag`, withheld from an unidentified sender and withheld
from a node with no registry — and the capability went into `cap.c`'s table **in
the same pass**, which is what resolves rather than overturns the argument 10.1
made for leaving it out.

**Phase 10.2b — `account-notify` (issue #117). COMPLETE.** §2.5.6: the
`ACCOUNT <account> PASS` / `ACCOUNT *` line, gated on the recipient's own
negotiation, with the capability available unconditionally because "you have no
account" is an answer this node can give truthfully. The retired nickname-change
meaning of the word is documented and refused on arity, and `NICK` is unaffected.

**Phase 10.3 — `extended-join` (issue #117). COMPLETE.** §2.5.7: the JOIN echo
carrying the account and the realname, per destination, with `*` for a member who
is not logged in to an account — and the capability advertised even with no
registry, because `*` is a complete answer there. `SJOIN` and `SBURSTM` carry the
account (§4.3.1), and `account_name_wire_safe()` makes an account name
representable as an IRC parameter, which `330` already needed.

**The remaining order:** `away-notify`, `chghost`; then the nine with no
dependencies —
`extended-isupport`, `userhost-in-names`, `setname`, `echo-message`,
**standard-replies** (which §2.5.2 is waiting on), `labeled-response` +
`client-batch`, `invite-notify`, `read-marker`. `client-tags`/`channel-context`,
`react`, `reply` and `typing` are **client-only** and are to be documented as
**N/A**: a server implementing them would be implementing something that is not
their subject.

**Phase 10.8a put a routing-contract change in FRONT of all three**, because all
three needed one and none of them could have introduced it without duplicating
it. `setname`'s common-channel broadcast was recorded as unimplemented because the
per-destination decision was a choice between two wire **shapes**; `chghost` and
`away-notify` need the same third outcome, and the three together are three member
walks in three handlers unless the routing module expresses it once. §3.1.1 is that
expression: a per-destination **GATE** beside the existing per-destination shape
choice, both asked inside the one walk `fanout.c` already owns.

**There is no official IRCv3 conformance suite.** `ircv3/ircv3-test-suite` and
`ircv3/chathistory-test-suite` do not exist. Compliance here is hand-written tests
against spec text, which is a weaker guarantee than a green third-party runner and
is stated rather than implied.

---

## 8. Definition of done

Single node:
- [x] Zero skipped tests; CI fails if any test is skipped — **MET. Phase 9 closed
      the last five, and the box is ticked because the ratchet now passes on an
      EMPTY list.**
      The history matters and the original wording was wrong twice over. It read as
      an outcome, and Phase 7 could not reach it: §7 allocated CAP and multi-prefix
      to Phase 8 and peer discovery, auto-scale, reconnect and failover to Phase 9,
      so demanding zero in Phase 7 would demand a feature Phase 7 must not build. §6.4
      therefore replaced it with a **RATCHET** — the count only goes down, every skip
      is accounted for by name, and the gate fails in **both** directions, which is
      what stops the list rotting into a permanent allowlist.
      **Phase 8 closed two (the IRCv3 ones) and Phase 9 closed the remaining five**,
      each implemented and each line deleted in the same change as the feature. The
      list is now empty, the file is **kept** rather than deleted (check-skips.sh
      fails on a MISSING list by design — a test that skipped with no list would
      otherwise be permitted by the accident of the file's absence), and the gate is
      "no test may skip", which is the phrase §6.4 always said the goal was. Adding a
      line back still needs no change to the script: a developer who genuinely cannot
      implement something writes the line and the skip is red until they do.
- [ ] Two clients connect, register, `#JOIN` a channel, exchange a `PRIVMSG`,
      `#QUIT` cleanly
- [ ] All MUST commands in §4 implemented
- [ ] `005` advertises `PREFIX=(ov)@+`, `CHANTYPES=#&` — **and `PREFIX=` is now
      load-bearing rather than decorative.** Phase 8's `multi-prefix` draws a
      member's whole prefix set in the order `PREFIX=` names the sigils, because a
      client indexes the run left to right into that table; a node that drew `+@`
      while advertising `(ov)@+` would be telling a client a status it does not
      hold. `tests/integration/test_multi_prefix.c` asserts the drawn token and
      `005` in the same case.
      **Phase 10.4 widened the same obligation from three tokens to eleven**, and
      the rule is §4.4.1: a token is advertised only where the bound or feature
      behind it can be named, every `*LEN` is rendered from the constant that
      *enforces* it, and the tokens this node cannot honour are absent with a
      reason. `test_registration.c` now holds the whole `005` byte-for-byte against
      **literals** — not against the constants, which would follow them and never
      notice that `005` was left behind — plus each token individually and the
      list of tokens that must be absent. **`KICKLEN` was on that absent list and is
      not any more**: Phase 10.9 added the bound it was waiting for (§4.4.4), and with
      it the token. `USERLEN` is the remaining omission that has a bound behind it and
      no way to advertise one, which is what keeps the list from being empty.
- [ ] `005` advertises `PREFIX=(ov)@+`, `CHANTYPES=#&` — **and every roster a
      client is shown is the roster THAT client asked for.** Phase 10.5 added
      `userhost-in-names`, and its obligation is not "draw a hostmask" but "draw
      one for the client that negotiated it and a bare nickname for the client that
      did not, on the same channel, at the same time" (§4.4.5). That is a
      **disclosure** capability — it hands every member's ident and host to every
      other member — so the per-destination decision is the security-relevant part,
      not a rendering detail.
      `tests/integration/test_userhost_in_names.c` runs three connections against
      one channel and one member: two that negotiated and one that did not, and the
      bare-nick answer is asserted on a connection that has seen nothing else.
- [x] *Phase 10.9:* **the four ambiguous refusals are `FAIL`s for a client that
      asked, and byte-identical numerics for one that did not.** §4.4.3. The line is
      one sentence — a legacy numeric migrates where it answers more than one
      question on this node — and it names exactly four: `417` (four refusals),
      `461` (too few **and** too many, with a text that calls both "not enough"),
      `482` (three refusals, two of which differ by three letters and mean unrelated
      things) and `464` (an operator refusal and a credential failure). Every other
      numeric answers exactly one question and is untouched, which
      `test_standard_replies.c` asserts on `401` and `451` as well as on the four: a
      migration of everything would pass every other case in that file.
      The guarantee is **structural** — `reply_refused()` has one branch and it is
      the old `reply()` call — and the text is rendered once and handed to whichever
      shape was chosen, so the two renderings are the same string by construction.
      The cost is stated where it is paid: those four numbers stop reaching a
      negotiating client, and nothing that connected to an earlier build is affected
      because the capability did not exist to negotiate.
- [x] *Phase 10.9:* **`KICKLEN` is advertised because a bound now exists.**
      `CHAN_MAX_KICK_REASON` (255) and a `417` in `handle_kick()`, checked immediately
      after the arity test. The defect this closes was not a wrong token: an over-long
      reason reached `message_format()`, which **refuses** rather than reshapes, so a
      client **command** was a reachable way to put a non-zero on `n_reply_refused` —
      the counter `reply.c` holds at zero because a non-zero value is a bug report.
      `test_standard_replies.c` asserts the 417, the boundary from both sides, the
      ` KICKLEN=255 ` token, that the member was **not** removed, and **that no
      `reply_refused:` line was printed** — so a node that dropped the bound again
      fails on the defect rather than on a symptom.
- [x] *Phase 10.8a:* **the routing module can express all THREE per-destination
      outcomes**, and does so in one place. §3.1.1: a plain shape, an alternate
      shape, and **nothing at all** for a destination the caller declines to
      address. This is a precondition for three specifications whose audiences are
      subsets of a channel — `setname`, `chghost`, `away-notify` — and it is a
      precondition rather than a feature because the alternative was three member
      walks in three handlers, which is the duplication `fanout.c` exists to
      prevent (`chan_verbs.c`'s own broadcast helper lost a forward arm that way in
      Phase 4).
      `tests/integration/test_fanout_gate.c` holds one channel, three members and
      three negotiations at once and asserts the exact plain line, the exact
      alternate line, **zero queued bytes** for the refused member, and that the
      gate is asked once per destination and not at all about one `exclude` had
      already removed. That last claim is invisible on the wire — it is why the
      file counts rather than searching — and it went green the first time the
      corresponding fault was injected, which is why the case exists.

Federated:
- [ ] Two-node fixture: cross-server join visibility, cross-server `PRIVMSG`
      delivered exactly once, no message loops
- [x] Link loss and reconnect re-syncs channel state via `SBURST` — **MET in Phase 9.**
      Phase 6 owned the verb, the wire format and the *effect* of a resync, and proved
      the two halves either side of the gap: a failed link is **not** re-dialled (the
      latch), and a deliberate retry through `fed_link_reset()` re-establishes and
      re-bursts. What Phase 6 named as missing was the **policy**, and Phase 9 supplies
      it: `IRC_FED_RETRY_BASE_MS` doubling per attempt, capped by
      `IRC_FED_RETRY_MAX_MS`, bounded by a budget of three that is **spent and
      reported** (`link_retry_exhausted:`) rather than retried for ever.
      `tests/integration/test_failover_reconnect.c` asserts the ladder's shape, and
      `tests/integration/test_sync_state.c` asserts the other half — that a reconnect
      **drives** the resync and that what it drives **replaces** rather than merges,
      checked on the wire with a member who parts and one who joins *while the link is
      down*, which is the only way to produce state the mesh cannot already have seen.
      Both shorten the ladder's SCALE per process and neither shortens its rules.
      **A third now does, and it is the one whose absence was a CI failure.**
      `test_fed_resync.c` called `fed_set_timeouts()` but never `fed_set_retry()`, so
      its nodes ran the shipped base of **90 s** — a COMPILE-time constant derived
      from the shipped `IRC_FED_DEAD_MS`, which `fed_set_timeouts()` does not touch.
      A link that connected and then missed the handshake armed
      `delay_ms=90000`, and T7 dials only once `now_ms` reaches `retry_at_ms`, so
      one transient miss was **terminal for the rest of the process** and no raise of
      `T_IO_MS` below 90 s could have helped. Measured after the fix on a ten-core
      host: `test_fed_resync` passed **20/20** consecutive, the suite passed
      **65/65 at `-j8` three times** and **65/65 at CI's `-j2`**, and removing the
      override again makes it fail **0/6** on its new rung assertion. The two
      constraints the scale has to satisfy are both real and are argued where the
      numbers are set; the honest limit is that this file drives **one** rung, so it
      can prove a rung is a value the configured ladder could produce and **cannot**
      prove the ceiling was *reached* — the deeper ladder stays
      `test_failover_reconnect.c`'s claim.
- [x] A peer that goes away is announced and forgotten — **MET, twice over, and Phase 9
      closes the second half C5 could not reach.**
      The C5 half is unchanged and still has the topology limit C5 stated: a link
      going down makes the node send `SQUIT` for its own name to every other
      `ESTABLISHED` peer, the receiver purges **that origin's** roster and `servers[]`
      entry and forwards the announcement on, an unrelated origin's roster survives,
      and a claim about **this** node is refused without costing the link. Not proven
      even now: the purge is proven across channels rather than within one, and "the
      node's own name is gone" is an over-claim when only one of its links died.
      **What C5 could not reach was a node ANNOUNCING its own departure.** Until
      Phase 9 `fed_send_shutdown()` had no caller in `src/` at all, so a `SIGTERM`'d
      node said nothing and every peer discovered the departure by timeout — arming a
      retry budget against it and leaving its name in the roster of the whole mesh,
      because the node that would have sent the `SQUIT` was the one that went away.
      `server_shutdown()` now calls it before it closes anything: the peer marks the
      link **cleanly departed**, purges, relays a `SQUIT` onward to a node two hops
      away, and **arms no retry at all** (`clean_leave` is the single condition T7
      checks, and `fed_link_reset()` is the operator's only way back).
      `tests/integration/test_autoscale.c` asserts all of that over real nodes, and
      asserts the *counts* — one dial for the life of the node, one ladder arm — rather
      than the log's own `retried=0`, because a node can print a flag it did not
      honour.
- [ ] Two nodes cannot both be named `irc.a` — rejected at handshake
- [ ] Observability: a way to dump peers + their FSM states, channels with
      origin and local/remote server sets, and the dedup table size.
      Split-brain debugging without this is guesswork
- [ ] Per-server nick uniqueness needs **no** policy and **no** lock:
      `bob@a` and `bob@b` are distinct registry keys. (The old criterion,
      "nick collision between nodes resolves without a global lock", was
      vacuous — there is no collision for it to resolve.)
- [x] *Phase 9:* network-visible nick ambiguity resolved by rename-the-loser
      plus a nick-registry broadcast. Until then, duplicate cross-server nicks
      are user-visible and undefined
- [ ] **An identity that outlives a socket** — **PARTIAL, and the partial is
      stated rather than rounded up.** §2.1.1's second axis exists: a connection
      carries an account name and the fact that a password was verified for it,
      the only writer requires an operator's credential store *and* an operator's
      account registry to agree, and `330 RPL_WHOISACCOUNT` reports it on the wire.
      **Not met, and three things are missing rather than one.** (a) An account
      **cannot be created by a client** — `REGISTER` is refused, deliberately,
      for the four reasons in §2.5.2, so this criterion is only reachable by an
      operator editing a file. (b) An account **cannot be left**, and `UNREGISTER`
      is refused for the same family of reasons (§2.5.2 reason 4), so an account's
      lifetime is entirely the operator's business. (c) The identity **is now
      visible on ordinary traffic** for a client that negotiated `account-tag` on a
      node with a registry (§2.5.3), and **not at all across a link** — the tag
      stops at the node that verified the credential, because an account registry
      is per node and per operator and a peer cannot check the claim. The same
      subsection states that limit as a cost rather than leaving it to be
      discovered.
- [x] *Phase 10.3:* **`extended-join` carries the account into the channel, per
      destination.** `:nick!user@host JOIN #chan <account> :<realname>` to a client
      that negotiated it, `:nick!user@host JOIN #chan * :<realname>` for a member
      who is not logged in, and RFC 2812 3.3.1's bare JOIN to everybody else — the
      last two of those three being observable **for the same JOIN and the same
      sender**, which is what makes it a per-destination decision rather than a
      per-verb one. `*` is never an empty parameter, and §2.5.7 says what is still
      missing: this node emits no extended JOIN for a member it learned from a
      peer, because 4.3's SJOIN carries no hostmask to render one from.
- [x] *Phase 10.2b:* **`account-notify` answers, and only to a client that asked.**
      A client that negotiated it is told `ACCOUNT <account> PASS` or `ACCOUNT *`
      at the end of its own registration burst; a client that negotiated nothing is
      sent nothing; a client that *asks* is answered whatever it negotiated. The
      capability is available on a node with no registry **on purpose** — the `*`
      form is an answer this node can give truthfully — which is the opposite of
      `account-tag`'s store check and is why §2.5.3 and §2.5.6 give different
      answers to the same shape of question. What is **not** here is the
      channel-scoped half of the specification: on this node the association is
      established before the connection has a channel, so there is never a
      shared member to notify, and `ACCOUNT <account> FAIL` has no event either
      because there is no logout. Both limits are stated where the emitter is.
- [x] *Phase 10.1:* **`account == ""` is indistinguishable from "this node has no
      account system"**, and the invariant is structural rather than conventional:
      one writer, two stores consulted, a connection-local predicate. A
      deployment that configures nothing keeps exactly the behaviour it had, which
      is what makes the subsystem additive rather than a change to who can log in.
      `tests/integration/test_account.c` runs **one** set of assertions against a
      node WITH a registry and a node WITHOUT, for the same not-logged-in client,
      and both must hold.
- [x] *Phase 10.1:* **zero new skips, and the advertised capability table still
      names only implementations.** `cap_available()` gained no name, because the
      capability whose implementation landed would tell a client that every
      logged-in user here is anonymous (§2.5.3).
- [ ] Origin is immutable and a dead origin is **failed closed**: local members
      still see each other, origin-requiring actions are `437` naming the origin,
      and re-linking a server of the same name resurrects the channel — **met in
      C5, and no code path re-elects an origin.** The only writer of
      `chan_t::origin` after creation is Phase 4's `chan_rekey()` creation-race
      tie-break, which is not a re-election; §9's risk row says re-election needs a
      per-channel epoch in the dedup key and must not begin without re-opening
      §2.4.

Quality:
- [x] **ASan/UBSan** clean at **65/65**, zero AddressSanitizer errors and zero UBSan runtime errors. LeakSanitizer is a **Linux-only** gate and has not run — it does not exist on Darwin — so it closes when the CI job reports. Three teardown arms were added specifically so it can: `fed_advert_close()` in `server_shutdown()` (a `calloc` that had no caller, so `advs` was never freed), beside `fed_burst_close()` and `resume_close()`.
- [x] **0 errors and 0 warnings on all three compilers, Release and Debug**: gcc-16 `-Wall -Wextra -Werror -Wpedantic`, upstream Clang 23.1.2 and Apple Clang 21 `-Weverything`. An earlier pass in this phase reported upstream clang "not installed locally"; it is, at /opt/homebrew/opt/llvm/bin/clang, so the three-compiler claim is now actually three compilers. This row also closes on the CI run for the branch.
- [x] **Integration tests are load-independent at `-j8`.** One `-j8` run of the
  ASan build failed `test_nick_duplicate`; it then passed 3/3 alone, 3/3 at
  `-j8`, and 65/65 serially and at `-j4`. Under ASan every timing margin
  shrinks by roughly 3x, so a deadline that is comfortable in Release can
  be tight on the sanitizer job. Recorded rather than dismissed: the fix is a
  wider margin in that test, and until it lands the sanitizer job can go red
  for a reason that is not a defect.
- [x] **A wider deadline is not a fix for a starved test, and the row above
  is the one that proves it.** `ci_macos` failed `test_fed_resync` on
  `main` at 52d57dd — `TIMEOUT after 30000 ms waiting for
  "link_established: peer=irc.a"` on a two-core runner at `-j 2` — and
  Phase 9 had already answered that failure once by raising this test's
  `T_IO_MS` from 15000 to 30000. It did not help, and the reason is
  arithmetic rather than tuning: the node had armed a retry of **90000 ms**,
  three times the whole budget, so the second attempt the raise was paying for
  could not happen at ANY budget under 90 s. The defect was that this one test
  overrode `fed_set_timeouts()` and not `fed_set_retry()`, so it ran a ladder
  120x longer than the dead window it had itself configured. **What is measured
  and not believed:** the fix holds `T_IO_MS` at **30000** — the window now buys
  a genuine second attempt (miss at 12000, rung at 16000, linked by ~16100), which
  is what the raise was reaching for and did not buy — and the same file passed
  **20/20** consecutive on a ten-core host, **10/10** under three concurrent full
  suites. **What is NOT measured:** the two-core CI failure itself was not
  reproduced locally. Sustained CPU starvation was applied (up to 160 busy
  loops taking ~460–730% of 1000%) and the **pre-fix** test still passed 12/12,
  median 3.7 s against 3.0 s idle — this host has ten cores and the runner has
  two, and the gap is not something more load can bridge. The evidence for the
  fix is therefore the failing rung assertion (0/6 without the override), the
  90000-vs-30000 arithmetic, and the CI log, not a local reproduction.
- [ ] `SPEC_TRACKING.md` matches source, verified by reading it
- [x] No test asserts internal plumbing

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
| Re-electing a dead channel origin | interacts fatally with dedup | **Not started, and Phase 9 declined it deliberately.** Needs a per-channel epoch in the dedup key, which breaks §2.4's `(origin,epoch,id)`. Must not begin without re-opening §2.4 first. **This is also why §2.3's auto-scale reports load rather than acting on it:** re-homing a channel to a quieter node *is* this row, and a mesh-load feature that moved channels would have walked into it |
| Fabricating a load metric to decide node lifecycle | fork bomb on a mesh | **Not possible by construction.** `load_pct` is an *operator's value* (`fed_set_load()`), never a measurement, and nothing in the node spawns or stops nodes — that is a supervisor's job. `fed_set_shed_pct()` defaults to **0 = no opinion**, so a node with no threshold configured prints no verdict about any peer's load, and the `fed_shed:` line carries `action=REPORT_ONLY rebalance=NO reason=NO_MOVE_MECHANISM` so the refusal is on the wire rather than only in a comment |
| Two nodes share a server name | catastrophic, later undetectable | Enforced at handshake (§8) |
| Blocking call in the event loop | stalls every client on the node | Dial state machine, pre-resolved peer addresses, bounded write queues (§3.4) |
| Nick charset left unvalidated | `nick@server` ambiguous; scoped identity unsound | `valid_nick()` in Phase 1 (§5) |
| Vector clocks reopened | scope creep | Deliberately rejected in §2.4; explicitly not a Phase 9 item |
| **An account name becomes a claimable string** (Phase 10.1) | impersonation: `account-tag` stamps the name on every message, so a name anybody can take is a name that proves nothing — and is a tool against the people who chose theirs | **Registration is operator-side only.** `REGISTER` is refused (§2.5.2), so the name space changes only when an operator edits a file, and only ONE writer of `conn_t::account` exists and it requires a credential verified against *two* operator stores. The cost is stated: no client may create an account, so a deployment that wants open registration must not use this node. |
| **Advertising `account-tag` without emitting it** (Phase 10.1) | every client concludes every logged-in user is anonymous — the tag's absence is an assertion | **RESOLVED in Phase 10.2, and by doing the thing 10.1 declined rather than by reversing it.** The capability is now in `cap.c`'s table *and* the tag is emitted (§2.5.3), so the advertisement is a claim about something real. The whole argument is still written down at §2.5.3 and at `cap.h`, because the incoherent version is one table line away. |
| **Stamping `+account` on a relayed message** (Phase 10.2) | a client is shown an account name no registry it can consult holds, and cannot check it — the tag is exactly the assertion a client trusts | **The relay arm resolves nothing** (`fanout_emitter_account()` branches on `relayed`), because an account registry is per node and per operator. The cost is named at §2.5.3: per-message identity stops at the authenticating node. |
| **Account identity treated as authority** (Phase 10.1) | a future phase reads `logged_in` as a privilege and every access-control rule silently inherits it | `logged_in` is documented at the struct and at the module as a NAME plus a VERIFICATION and grants nothing (§2.1.1), and the "what none of them grant" block in `connection.h` says so where a future editor will read it |
| **The account store drifting from the credential store** (Phase 10.1) | a client authenticates and is not identified, or is identified for a name the operator removed | Both must agree or authentication stops (§2.5.1), the refusal is counted on `n_account_refused` and named on the node's own output, and `test_account.c` runs the not-identified path against a node whose two files **disagree** — byte-identical to a node with no registry at all |
| **An `005` token this node does not honour** (Phase 10.4) | a client sizes a buffer from a bound nothing enforces, or switches on a feature this node has not implemented, and then behaves as though the server agreed — which is worse than the token's absence, because absence is a client that carries on | **Every token is derived from the constant that enforces it, and every absence is named with its reason (§4.4.2).** `k_005[]` renders each `*LEN` through `IRC_STR()` from the bound itself rather than writing it out, and `test_registration.c` asserts the whole `005` against **literals**, so raising a bound in another file fails the test unless `005` moved with it. The absences with a live feature behind them — `BOT`, `EXTBAN`, `SAFELIST`, `MONITOR`, `MSGREFTYPES`, `ACCEPT`, `silence`, `draft/CHATHISTORY` — are asserted **absent** on the wire, so adding one without implementing it fails a test |
| **`userhost-in-names` disclosing hostmasks to the wrong client** (Phase 10.5) | every member's ident and host reach every other member of the channel, including clients that member has never spoken to — and there is no per-member consent anywhere in the capability | **The roster shape is decided per DESTINATION**, in `chan_verbs.c`'s `names_entry()`, for the connection being answered — so a client is shown the long form only if it negotiated it (§4.4.3). A node deciding once per channel would disclose to the whole channel on one client's request. A member the node cannot render a hostmask for gets the **bare nick**, not a `*` placeholder: inventing a half would put a byte on the wire that reads as part of a hostmask and means nothing |
| **A realname stored without validation** (Phase 10.6) | an unbounded or under-validated realname is a memory-safety bug and a **log-injection vector** — the field reaches this node's own `printf("%s")` with no escaping, so `0x07` rings a recipient's bell and ESC `[` is a CSI sequence a terminal executes | **One predicate, two writers.** `conn_realname_check()` is called by *both* `handle_user()` and `handle_setname()`, so "SETNAME is not a looser path than registration" is a property of the code rather than a claim about it. It refuses over-long values and every C0 control and DEL; `message_parse_n()` refuses CR/LF/NUL ahead of it, and the test covers the rest. `SETNAME` refuses; `USER` empties rather than refusing, because refusing `USER` would strand a half-registered client — §4.2.1 argues it and the empty result is a legal state |
| **`SETNAME` silently ignoring a client that did not negotiate** (Phase 10.6) | read as "the command does not exist" by a client that tried it anyway, which `setname` explicitly permits | **It is the specification's instruction**, and it is implemented rather than worked around: no reply, no change. A `FAIL SETNAME CANNOT_CHANGE_REALNAME` needs `standard-replies`, which this node does not have, and inventing a `FAIL` would put a command word on the wire no client here has been told to expect. The test asserts **exhaustively** — the drain `PONG` must be the only line in the window — because a list of absent numerics is not a test of silence (a `482` fault passed the first version of it) |
| **A message delivered twice to a client that negotiated `echo-message`** (Phase 10.7) | every message the user sends appears twice, from two different-looking prefixes — the defect the capability exists to remove, arrived at from the other side | **There is no second emission.** The capability decides one thing: whether the sender stays in the audience of the delivery that is happening anyway (`msg_verbs.c`'s `exclude`). The sender of a channel `PRIVMSG` was *already* in the audience, so the copy is that one; only `NOTICE`, which RFC 1459 2.4.2 removes, is affected. `test_echo_message.c` **counts** copies rather than searching for them — the two copies are identical apart from the prefix, so a substring assertion passes — and one of its faults adds exactly the extra emission |
| **An unsolicited notification reaching a client that did not ask** (Phase 10.8a) | the notification is an ASSERTION about a user — their realname changed, their ident and host changed, they are away or no longer away — so sending it to a client that did not negotiate is as wrong as not sending it to one that did. `away-notify` is the sharp case: the line's whole grammar is `:nick!user@host AWAY [:message]`, so a "notification" with no message asserts the user is no longer away | **There is ONE per-destination gate, inside the one walk that decides who gets what (§3.1.1), and it is the absence of a line rather than a third shape.** A gate that returned a third *shape* would still have sent a line, and an empty one reads as "no longer away". The three-handler alternative was rejected for the same reason `fanout.c` exists: `chan_verbs.c`'s own broadcast helper lost a forward arm that way in Phase 4. `test_fanout_gate.c` asserts **zero queued bytes** for the refused member rather than the absence of a needle, because absence-from-a-buffer is satisfied by a line that arrived elsewhere in the stream |
| **`FAIL` reaching a client that did not negotiate `standard-replies`** (Phase 10.9) | `FAIL` is a command word no such client has ever been told to expect and RFC 1459 2.3 parses it as an unknown command — so the migration would break exactly the clients it was supposed to leave alone, and the breakage is a client that stops rendering errors rather than one that fails loudly | **The branch is `reply.c`'s, and there is exactly one of them.** `reply_refused()` asks `cap_standard_replies_enabled(src)` before it does anything else; a client that did not negotiate reaches `reply()` with the legacy numeric, the same middle parameters and the same text, and the two renderings are the same string because the format is rendered ONCE and handed to whichever branch was chosen. `test_standard_replies.c` runs every case on two connections differing in exactly that one negotiation and asserts **both** answers byte-for-byte, plus the absence of `FAIL`, `WARN` and `NOTE` and a line COUNT for the window — a list of absent numerics would pass a fault that answered with a number nobody thought of |
| **A legacy numeric migrated for a client that did not ask** (Phase 10.9) | the client loses the numeric it was matching on, and the four that stop arriving are four that clients most often match | **The migration is per destination and the legacy rendering is byte-identical**, and no client that connected to an earlier build can be affected because the capability did not exist to negotiate. The list is four numerics and not thirty, and the rule that chose them is a property of THIS NODE (one number, several questions) rather than a preference: `test_standard_replies.c` asserts `401` and `451` still arrive at a negotiating client unchanged, so the list cannot grow by accident |
| ~~**`KICKLEN` has no bound to advertise**~~ (Phase 10.4) | an over-long KICK reason is not refused with a numeric; it reaches `message_format()`, which refuses it as `unrepresentable` — a non-zero `n_reply_refused`, the counter `reply.c` holds at zero because a non-zero value of it is a bug report | **RESOLVED in Phase 10.9, and by adding the bound rather than by muting the symptom.** `CHAN_MAX_KICK_REASON` (255) refuses it with `417` before anything is applied, and `KICKLEN` is advertised from the same constant (§4.4.4). The refusal leaves the roster untouched, so a node that answered 417 *after* removing the member — which both 417 assertions would have passed — is caught by a PRIVMSG from the kicked connection arriving as a delivery rather than a 404 |
