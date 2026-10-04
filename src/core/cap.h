/* cap.h -- IRCv3 capability negotiation, and the connection state it owns.
 *
 * Authority: docs/SERVER_DESIGN.md 7/Phase 8 ("CAP negotiation (LS/REQ/ACK/NAK)")
 * and the IRCv3 capability-negotiation specification.
 *
 * ---------------------------------------------------------------------------
 * WHAT "CAP" IS FOR, IN ONE PARAGRAPH, BECAUSE IT IS NOT OPTIONAL DECORATION
 * ---------------------------------------------------------------------------
 * A modern client connects and sends `CAP LS` before it says NICK or USER,
 * because it has extensions to find out about and it must not be told 451 in the
 * middle of asking. The server answers with the capabilities it has, the client
 * picks the ones it wants with `CAP REQ`, and then it sends `CAP END` to say
 * "I am done negotiating" -- and THE REGISTRATION MUST NOT COMPLETE UNTIL THAT
 * ARRIVES. That last clause is the whole point of the subcommand: a server that
 * completes registration as soon as it has NICK and USER sends 001-005 in the
 * middle of the client's CAP exchange, the client treats the burst as the answer
 * to something else, and the connection hangs with no error on either side. Every
 * modern client hangs against such a server. Getting it wrong is not a
 * compatibility detail.
 *
 * ---------------------------------------------------------------------------
 * THE RULE THIS MODULE EXISTS TO ENFORCE: ADVERTISE ONLY WHAT IS REAL
 * ---------------------------------------------------------------------------
 * `CAP LS` lists capabilities THIS NODE IMPLEMENTS. A listed capability that is
 * not implemented is worse than a missing one, and it is worse in a specific way:
 * a missing one is a client that carries on without the feature, which works,
 * while a listed one is a client that switches the feature on and then behaves
 * as though this node honoured it. That is the same rule this project has held
 * numerics to since Phase 3 -- a 324 that disagrees with the node's modes, a 433
 * that claims a malformed nick is taken, an INFO that lists features nothing
 * implements. CAP LS is that rule applied to a list rather than a numeric.
 *
 * So the table below is a list of implementations, not a list of intentions, and
 * `sasl` is in it CONDITIONALLY: a node started without `--sasl-store` holds no
 * credential store and therefore cannot authenticate anybody, so it does not
 * advertise `sasl`. A client that saw `sasl` and then got 908 would have been
 * told a capability existed and does not.
 *
 * ---------------------------------------------------------------------------
 * RELATIONSHIP TO 005's PREFIX=, STATED RATHER THAN LEFT IMPLICIT
 * ---------------------------------------------------------------------------
 * `005 PREFIX=(ov)@+` names the SIGILS this node uses for prefix modes: '@' is
 * op, '+' is voice. It says which sigils exist and what they mean, and it is
 * true regardless of whether `multi-prefix` is enabled. `multi-prefix` is a
 * separate thing and says only whether a `353` may render MORE THAN ONE sigil
 * per member -- it changes how much is drawn, not what the sigils mean. The two
 * therefore do not contradict each other, and a node that renders one sigil per
 * member is still a node whose sigils are '@' and '+'.
 *
 * What multi-prefix DOES commit this node to, and the part that is easy to get
 * half right, is the ORDER of the drawn run. `chan_verbs.c`'s names_signs()
 * draws in PREFIX order -- '@' before '+' -- because a client reads the run left
 * to right and looks it up in PREFIX, and a run in any other order gives it an
 * answer the node does not hold. The same capability also governs `352`
 * RPL_WHOREPLY (`msg_verbs.c`'s who_flags()), because IRCv3's multi-prefix names
 * both numerics and a node that honoured it in 353 alone would be a node whose
 * 353 is authoritative and whose 352 is a summary.
 *
 * The consistency that DOES have to hold is between `CAP LS` and the code: every
 * name in cap_available() must be a name something here implements. That is why
 * there is no `cap-notify` (this node never sends an unsolicited CAP NEW).
 *
 * **`chghost` is absent for a reason that is NOT the tidy one, and it is worth the
 * space.** The specification's trigger is "when a client username or host is
 * changed". This node cannot change a HOST after accept() -- `describe_peer()` is
 * its only writer, and `resume.c` *requires* (nick, ident, host) to match to resume,
 * so a resume refuses rather than applying a new identity -- and there is no
 * `CHGHOST` verb in `k_commands[]` and no emitter anywhere in `src/`. So there is
 * nothing to send.
 *
 * **But an IDENT *CAN* change, and that is the finding.** `handle_user()` writes
 * `conn_t::user` unconditionally, and `USER` is a `pre_reg` verb that the dispatch
 * table still routes for a REGISTERED connection -- so a client may re-send `USER`
 * and change its own ident at any time, silently, with nothing told to anybody.
 * `tests/integration/test_chghost.c` makes the whole of that provable: the change
 * on the wire through a third party's `311`, the absence of any notification on an
 * idle second connection, and the `421` for a client-sent `CHGHOST`.
 *
 * So the capability is absent because **the one thing that changes is not supposed
 * to be able to** -- which is a defect in `handle_user()`, reported in §9 and not
 * fixed here, rather than a feature waiting to be notified. No way to move a host
 * was invented to make the notification implementable: `WEBIRC`/`spoofing` is the
 * territory that belongs to, and adding a verb that sets `conn_t::host` would be
 * inventing a spoofing surface to satisfy a specification.
 *
 * **Phase 10.5 onward retired several names from that sentence.** It used to read
 * "and no `server-time` or `userhost-in-names` (it stamps neither)" — true when
 * written, and no longer true of `userhost-in-names` (Phase 10.5), `setname`
 * (Phase 10.6), `echo-message` (Phase 10.7), `standard-replies` (Phase 10.9) or
 * `away-notify` (Phase 10.8b), all of which are in the table above and implemented
 * behind it. `server-time` is still absent, and `chghost` is still absent for the
 * reason its own paragraph below gives, which is not the tidy one.
 * The line is corrected rather than deleted because an out-of-date "and no X" in a
 * header is the exact shape of the incoherence this file exists to prevent, and the
 * build cannot see it.
 *
 * ---------------------------------------------------------------------------
 * `account-tag` IS IN THE TABLE, AND BOTH HALVES OF IT LANDED TOGETHER
 * ---------------------------------------------------------------------------
 * Phase 10.1 built the account identity -- a `conn_t` carries an account name and
 * a `logged_in` flag, set from the SASL `authcid` when -- and only when -- both
 * an operator's credential store and their account registry verify the
 * credential -- and DELIBERATELY left the capability out of k_caps[].
 *
 * The reason it left it out was the specification's own sentence, quoted because
 * paraphrasing it loses the part that matters: **"If the user is not identified
 * to any services account, the tag MUST NOT be sent."** The tag's ABSENCE is an
 * assertion -- a client reads "no `account` tag" as "this user is anonymous" --
 * so advertising the capability and then never emitting the tag would not merely
 * fail to help: it would tell every client that every logged-in user on this node
 * is anonymous.
 *
 * THAT REASONING WAS CORRECT AND IT IS NOW RESOLVED RATHER THAN OVERTURNED. The
 * name went in at the same moment as the emission -- fanout.c's
 * `fanout_tag_block()` writes the tag, and this table lists the name -- and with
 * both halves present the incoherence does not arise: a client that negotiates
 * `account-tag` gets the tag on every line a logged-in sender emits to it, and a
 * client that does not negotiate it is written to exactly as before. The
 * advertisement is no longer a claim about an absence, and the paragraph above is
 * KEPT rather than deleted because the incoherent version is one table line away
 * and nobody should have to rediscover the argument.
 *
 * THE AVAILABILITY CHECK IS ACCOUNT_POSSIBLE(), beside sasl_possible() below, and
 * it is 0 on a node with no registry for exactly the reason `sasl` is withheld
 * there: with nothing behind the name there is nothing the tag could say, and a
 * node that listed it would be a node whose every logged-in user -- which cannot
 * exist -- is anonymous. The check asks whether there is anything to SAY, which is
 * what makes it the right question now that there is something to say.
 *
 * THE TAG IS NOT SENT TO A CLIENT THAT DID NOT NEGOTIATE IT, and that is a
 * second, independent gate in cap_account_tag_enabled() below. Absence is an
 * assertion, so an UNSOLICITED `account` tag is as wrong as a missing one: it
 * tells a client that opted out of tags that this user is identified. The emission
 * is therefore per DESTINATION, exactly like the `msgid` tag, and the ACCOUNT NAME
 * ITSELF is resolved once per emission in fanout.c rather than once per
 * destination -- the comment on fanout_emitter_account() gives the argument, and
 * getting it wrong is the same class of bug as the one an emission's id had.
 */

#ifndef IRC_CORE_CAP_H
#define IRC_CORE_CAP_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* Capability names, as one constant each.
 *
 * Named rather than written as literals at the call sites because a capability
 * that is spelled two ways is a capability that is ACKed once and NAKed once, and
 * that looks like a bug in the negotiation rather than a typo. */
#define CAP_MULTIPREFIX "multi-prefix"
#define CAP_MESSAGE_TAGS "message-tags"
#define CAP_MESSAGE_IDS "draft/message-ids"
#define CAP_SASL "sasl"
#define CAP_ACCOUNT_TAG "account-tag"
#define CAP_ACCOUNT_NOTIFY "account-notify"
#define CAP_EXTENDED_JOIN "extended-join"
#define CAP_USERHOST_IN_NAMES "userhost-in-names"
#define CAP_SETNAME "setname"
#define CAP_ECHO_MESSAGE "echo-message"
#define CAP_STANDARD_REPLIES "standard-replies"
#define CAP_AWAY_NOTIFY "away-notify"
#define CAP_BATCH "batch"
#define CAP_LABELED_RESPONSE "labeled-response"
#define CAP_INVITE_NOTIFY "invite-notify"
/* PHASE 12. Two names, and they are NOT interchangeable -- the `tls`
 * specification is deprecated in favour of `sts`, and this codebase implements
 * both because they answer different questions about the same node.
 *
 *   tls   "the server supports the STARTTLS command". A hint. Deprecated by the
 *         IRCv3 working group in favour of `sts`, but implemented here because the
 *         STARTTLS command is implemented here and a client that wants to upgrade
 *         has to be able to find out that it can. Its specification is also the
 *         only one that says when STARTTLS may be used, which is load-bearing for
 *         commands.c's handler.
 *
 *   sts   Strict Transport Security. NOT a hint: it carries a policy value
 *         (`sts=duration=...,port=...`) that a conforming client acts on by
 *         refusing to make insecure connections at all. It is the only part of
 *         this phase that protects a RETURN visit, which is why it is the one that
 *         matters, and why the implicit-TLS listener exists at all.
 *
 * BOTH ARE WITHHELD ON A NODE WITH NO CERTIFICATE, which is cap.h's rule rather
 * than a decision of this phase: a node that advertised either could not honour
 * it. */
#define CAP_TLS "tls"
#define CAP_STS "sts"

/* The `sts` capability's VALUE, rendered for CAP LS.
 *
 * IT IS RENDERED AND NOT REQUESTED, which is the part of the specification that
 * is easy to get backwards. From the `sts` specification:
 *
 *   - "When enabled, the capability has a REQUIRED value: a comma (,) separated
 *     list of tokens."
 *   - "Clients MUST NOT request this capability with `CAP REQ`. Servers MAY reply
 *     with a `CAP NAK` message if a client requests this capability."
 *
 * So `CAP LS` carries `sts=...`, a `CAP REQ :sts` is NAKed, and a client never
 * negotiates it. That is why `sts` is the ONE name in this file whose REQ is
 * refused, and why it is refused in cap.c's REQ handler rather than by leaving it
 * out of the table: a client that asked and got an ACK would believe it had
 * negotiated a policy that governs what it may connect to.
 *
 * The two keys, and which is REQUIRED when:
 *
 *   port=       REQUIRED on an INSECURE connection -- it is the port the client
 *               must reconnect to. Omitted when this node has no --tls-port,
 *               because there is then no port a client could be told to use, and
 *               advertising one that does not exist would send every client to a
 *               closed port. Its absence is CORRECT: the specification says a
 *               client that receives a persistence policy with no port over an
 *               insecure connection ignores it.
 *   duration=   REQUIRED on a SECURE connection -- how long the client must keep
 *               using TLS. 0 means "no persistence policy", which is the shipped
 *               default on the specification's own advice: "Server
 *               implementations should consider using a default value of
 *               duration=0 in their example configurations. This will require
 *               server administrators to deliberately choose an expiry according
 *               to their specific needs rather than (perhaps unknowingly) rely on
 *               an arbitrary generic value."
 *
 * The buffer is a constant rather than a caller-chosen size for the same reason
 * CAP_LS_MAX is: `sts=duration=4294967295,port=65535` is 34 bytes, and a capability
 * that could be truncated is a capability that silently hides its own policy. */
#define CAP_STS_VALUE_MAX 48

/* 410 ERR_INVALIDCAPSUBCOMMAND. Not in design 4.4's numeric list, which is a gap
 * in the list rather than in the protocol, for the same reason 301, 303, 417,
 * 302, 371/374 and 402 are: the RFC defines it and it is the one a client
 * understands. The alternative -- 421, which the wire DOES have for an unknown
 * command -- would be a lie about what happened, because CAP is a known command
 * with an unknown SUBcommand, and a client that retried `CAP` on a 421 would get
 * the same answer for ever. */
#define RPL_INVALIDCAPSUBCOMMAND "410"

/* 908 RPL_SASLMECHS: the mechanisms this node offers. It is sent in answer to
 * `AUTHENTICATE` with a mechanism this node does not implement, which is the only
 * place a client learns what to try instead. */
#define RPL_SASLMECHS "908"

/* Initialise `c`'s capability state. conn_new() gets this right for free because
 * it callocs, and it is here so that a caller which already has a conn_t can say
 * so explicitly. Idempotent. */
void cap_init(conn_t *c);

/* Is `name` a capability THIS BUILD knows about at all? Distinct from
 * cap_available(), which also asks whether this NODE can do it right now: a
 * capability this build has never heard of is answered 410, and one this build
 * knows but this node cannot currently do is answered NAK. */
int cap_known(const char *name);

/* Can this node offer `name` RIGHT NOW? 1 offered, 0 not. */
int cap_available(const server_t *s, const char *name);

/* Render the available set into `out` as the space-separated list a `CAP LS`
 * trailing parameter carries. Returns the byte count written, or 0 if it does not
 * fit -- which cannot happen for a buffer sized CAP_LS_MAX, and is reported
 * rather than truncated if it somehow does. */
size_t cap_available_list(const server_t *s, char *out, size_t cap);

/* A buffer that holds every capability this node can advertise plus their
 * separators and a NUL. It is a constant rather than a caller-chosen size so a
 * new capability cannot be added without the buffer growing with it -- which is
 * the failure where a truncated LS silently hides a capability from every client
 * that asks. */
/* The worst case a CAP LS/REQ/NAK reply can occupy, DERIVED rather than picked.
 *
 * This was 256, and CodeQL was right that three snprintf calls could overflow it:
 * cap_split() accepts up to CAP_MAX_REQ names of up to CAP_NAME_MAX bytes each, so
 * the reply can need CAP_MAX_REQ * (CAP_NAME_MAX + 1) bytes of names PLUS one
 * separator between each pair -- 1040 + 15 = 1055 into a 256-byte stack buffer.
 * Reachable from the wire by any client sending sixteen long capability names.
 *
 * The arithmetic is spelled out here so the number cannot drift from the inputs
 * again, which is what made 256 wrong in the first place: it was a guess about how
 * much text a reply needs rather than a function of how much text can arrive. */
/* How many capability names one CAP REQ may carry, and the longest name accepted.
 * cap_split() rejects anything longer than CAP_NAME_MAX as "not a capability", and
 * more than CAP_MAX_REQ names as "more than we will consider" -- both refusals,
 * not silent truncation. They live here rather than in cap.c because CAP_LS_MAX is
 * derived from them and a derived constant in one file reading inputs in another is
 * how the two drift apart. */
#define CAP_MAX_REQ 16
#define CAP_NAME_MAX 64

/* The worst case a CAP LS/REQ/DEL/NAK reply can occupy, DERIVED from its inputs.
 *
 * This was 256, and CodeQL was right that the accumulating snprintf calls in cap.c
 * could overflow it. cap_split() accepts up to CAP_MAX_REQ names of up to
 * CAP_NAME_MAX bytes each, so a refused list can need
 * CAP_MAX_REQ * (CAP_NAME_MAX + 1) + CAP_MAX_REQ bytes -- 1040 + 16 = 1056 --
 * into what was a 256-byte STACK buffer. Measured: sixteen 64-character capability
 * names, which any client may send, need 1040 bytes, so the overflow is 784 bytes
 * and it is reachable from the wire.
 *
 * The accumulation is what makes it an overflow rather than a truncation:
 * snprintf returns the length it WOULD have written, so `rn` grows past the end of
 * the buffer, `refused + rn` is already out of bounds, and `sizeof refused - rn`
 * underflows as a size_t. Three bugs in one expression.
 *
 * 256 was a guess about how much text a reply needs rather than a function of how
 * much text can arrive, and CAP_MAX_REQ and CAP_NAME_MAX live here rather than in
 * cap.c so the derivation can see them -- a derived constant in one file reading
 * inputs in another is exactly how the two drifted apart. */
#define CAP_LS_MAX (CAP_MAX_REQ * (CAP_NAME_MAX + 1) + CAP_MAX_REQ)

/* Is the client still mid-negotiation, and therefore is registration held?
 * TRUE from the first `CAP LS` or `CAP REQ` until `CAP END`. This is the one
 * boolean the registration gate in commands.c asks, and it lives here so that the
 * thing that STARTS the negotiation and the thing that RELEASES it are in one
 * file. */
int cap_negotiating(const conn_t *c);

/* Has the client enabled `name`? 1 enabled, 0 not. Case-insensitive on the name,
 * because IRCv3 capability names are. */
int cap_enabled(const conn_t *c, const char *name);

/* multi-prefix specifically, because two modules need it and the bit index
 * should be written down once. */
int cap_multiprefix_enabled(const conn_t *c);

/* message-tags: the gate on whether this node writes ANY tag on an outbound line
 * to this client. Not the same question as draft/message-ids, which is the gate
 * on whether it writes a msgid -- but a client that asked for msgids without
 * asking for message-tags has asked for a tag inside a tag support it did not
 * enable, and gets nothing rather than a tag in a protocol it opted out of. */
int cap_message_tags_enabled(const conn_t *c);

/* draft/message-ids: whether this node writes a `msgid` on a delivered message
 * to this client. REQUIRES message-tags as well, and the two are not
 * interchangeable -- see cap.c for why a msgid without tag support is not a
 * best-effort thing to do. */
int cap_message_ids_enabled(const conn_t *c);

/* account-tag: whether this node writes an `account` tag naming the SENDER's
 * account on a line it delivers to this client. REQUIRES message-tags for
 * exactly the reason cap_message_ids_enabled() does, and the second half of the
 * emission is the account NAME -- which this node resolves from its own registry,
 * once per emission, and renders per destination.
 *
 * BOTH GATES ARE PER DESTINATION. That is the shape of the whole feature and it
 * is not a detail: two members of one channel are free to disagree about whether
 * they want to be told who sent a message, and a tag block written once for an
 * emission would put it on the line of the one who asked for none. */
int cap_account_tag_enabled(const conn_t *c);

/* account-notify: whether this node tells THIS client, unprompted, which account
 * it is associated with -- `ACCOUNT <account> PASS` when there is one and
 * `ACCOUNT *` when there is not.
 *
 * UNCONDITIONALLY AVAILABLE, and that is the difference from account-tag which is
 * worth spelling out. `account-tag` is withheld on a node with no registry
 * because there is nothing the tag could SAY, and a name is the only thing that
 * capability carries. `ACCOUNT *` is itself an answer -- "you are not associated
 * with an account" -- so a node with no account system can still be completely
 * honest about it, and withholding the name there would be a node that keeps a
 * fact from a client it does have. */
int cap_account_notify_enabled(const conn_t *c);

/* extended-join: whether this node extends the JOIN it echoes to this client with
 * the joining user's account and realname.
 *
 *   :nick!user@host JOIN #chan <account> :<realname>
 *   :nick!user@host JOIN #chan * :<realname>
 *
 * IT IS AVAILABLE ON A NODE WITH NO ACCOUNT SYSTEM, and that is deliberate rather
 * than an oversight. The specification's `*` form says "this user has not logged
 * in to an account prior to channel ingress", and a node with no registry has not
 * got one to log in to -- so `*` is not an absence of information here, it is the
 * information. Withholding the capability there would be refusing to tell a client
 * something true, and a client that wanted the channel roster with accounts has no
 * other way to ask for them. This is the opposite decision to `account-tag`'s, and
 * cap.h's paragraph above is the one to read for why two account capabilities
 * answer `cap_available()` differently.
 *
 * THE CHOICE IS PER DESTINATION, like every other capability in this file, and the
 * two JOIN forms are not interchangeable: a client that did not negotiate this one
 * receives `:nick!user@host JOIN #chan` and must not receive the two extra
 * parameters, which it would read as a topic and a reason. fanout.c decides which
 * shape a given destination gets; core/chan_verbs.c builds both. */
int cap_extended_join_enabled(const conn_t *c);

/* userhost-in-names: whether this node draws a `353` member as
 * `nick!user@host` for THIS client rather than as a bare nickname.
 *
 * ---------------------------------------------------------------------------
 * THIS ONE IS A PRIVACY CAPABILITY AND THE DOCUMENTATION IS THE POINT
 * ---------------------------------------------------------------------------
 * A `353` normally discloses a nickname and nothing else. With this one, it
 * discloses **every member's ident and observed host address to every other
 * member of the channel** -- including to clients the member has never spoken to,
 * and including to clients that joined after them. Nothing about it is scoped:
 * one client asking puts the whole roster's hostmasks on the wire to that client,
 * and there is no per-member consent.
 *
 * So it is opt-in in the strongest sense available: per DESTINATION, decided in
 * `chan_verbs.c`'s `send_names_list()` for the connection being answered, and two
 * clients on one channel may see two different roster SHAPES for the same member.
 * That is the same per-destination shape `multi-prefix` and `extended-join` use,
 * and for this one the reason is stronger than consistency: a node that decided
 * once per channel would disclose hostmasks to every member whether they asked or
 * not, which is a disclosure the member never agreed to.
 *
 * AVAILABLE ON EVERY NODE, unconditionally, because the question is whether the
 * data EXISTS and not whether some registry is loaded: `c->user` and `c->host` are
 * filled at accept() and by USER on every connection, and a remote member's pair
 * is carried by 4.3's SBURSTN. There is no configuration under which this node has
 * a `353` roster and no host in it, so there is no reason to withhold the name.
 *
 * WHAT IT DOES NOT CHANGE: `352` RPL_WHOREPLY and `311` RPL_WHOISREPLY already
 * carry `<user>` and `<host>` as their own RFC fields, so they were never the gap.
 * The gap was `353` alone, and that is the whole scope. */
int cap_userhost_in_names_enabled(const conn_t *c);

/* setname: whether this node will act on a `SETNAME` command from THIS client.
 *
 * THE GATE WORKS OPPOSITE TO THE OTHERS IN ONE RESPECTABLE WAY, and the asymmetry
 * is the specification's rather than this file's. `setname` says the server MUST
 * support the command **even while the capability is not negotiated**, and that a
 * `SETNAME` from a client that did not negotiate it SHOULD be handled **silently**
 * -- no response, no change. So:
 *
 *   - the NAME is advertised unconditionally, because the verb exists whatever the
 *     client asked for, and a client that saw `setname` in `CAP LS` and then got
 *     421 would read "this server has never heard of SETNAME", which would be a
 *     lie about a verb this dispatch table has a row for.
 *   - the GATE decides whether this connection's `SETNAME` changes anything. "Handled
 *     silently" IS the refusal, and it is observable: nothing arrives on the wire,
 *     and nothing changes. A client that wanted to try the command anyway, which
 *     the specification explicitly permits, gets silence rather than an error.
 *
 * It gates the CONFIRMATION too, which is the other half of the rule and the reason
 * this is not merely "whether the field changes": the server-to-client `SETNAME`
 * line MUST NOT be sent to a client that did not negotiate the capability. So a
 * client that asked cannot discover another member's realname change by watching
 * them, and this capability cannot become a disclosure channel by accident. */
int cap_setname_enabled(const conn_t *c);

/* echo-message: whether this node sends THIS client a copy of the `PRIVMSG` or
 * `NOTICE` it sent.
 *
 * ---------------------------------------------------------------------------
 * THE COPY IS NOT A SECOND DELIVERY, and that is the whole of the obligation
 * ---------------------------------------------------------------------------
 * A node that implements this naively sends the message once through the normal
 * path and then sends a SECOND copy to the sender, because the sender is not
 * obviously already in the audience. Every message a client that negotiated this
 * sends arrives twice, and a client that renders both shows the user their own
 * message twice -- which is the exact bug the capability is supposed to fix,
 * arrived at from the other direction.
 *
 * SO IT IS NOT A SEPARATE EMISSION. `msg_verbs.c`'s `send_message()` makes this
 * capability decide ONE thing: whether the sender stays in the audience of the one
 * delivery that is happening anyway. The specification's own example
 *
 *     --> PRIVMSG Attila :hi
 *     :example!ex@example.com PRIVMSG Attila :hi
 *
 * is byte-identical to what this node's normal path has produced for a channel
 * `PRIVMSG` since Phase 5, because `fanout.c` writes to every local member
 * INCLUDING the author -- which is why `exclude` is NULL for `PRIVMSG` and has
 * been since before this capability existed.
 *
 * The only verb whose RFC rule REMOVES the sender from the audience is `NOTICE`
 * (RFC 1459 2.4.2: "The NOTICE message is sent to a user or channel, whether or
 * not the sender is on the channel", and a NOTICE is never returned to the client
 * that sent it). So `echo-message` changes exactly one thing on this node: a sender
 * who negotiated it gets its own `NOTICE` back, with its own hostmask as the
 * source prefix.
 *
 * THE COST, and it is worth naming because it looks like nothing: nothing. There is
 * no second code path, no second stamp, no second message identity -- `fanout.c`
 * mints the emission's 2.4 identity once, above its switch, and the sender's copy
 * carries the SAME `msgid` as everyone else's, which is what the specification means
 * by "the final version of the message".
 *
 * ONE GATE AND NO AVAILABILITY CHECK: unlike `account-tag` there is nothing here
 * that depends on an operator file. */
int cap_echo_message_enabled(const conn_t *c);

/* standard-replies: whether this node renders its refusals as IRCv3's `FAIL`
 * line rather than as the legacy numeric, FOR THIS CLIENT.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS ONE IS DIFFERENT FROM EVERY OTHER GATE IN THIS FILE
 * ---------------------------------------------------------------------------
 * Every other capability here decides what the node DRAWS. This one decides
 * whether a refusal arrives as `417` or as
 *
 *     FAIL <command> <code> :<description>
 *
 * which is a different message with a different command word -- so a client that
 * did not negotiate it would read the second as an unknown verb. **The migration
 * is therefore strictly per destination and is decided in `reply.c`**, which is
 * the one place that says what an outbound message to a client may be. A
 * capability honoured per handler would be honoured on one path and forgotten on
 * the next, and the client would see both shapes from one server.
 *
 * ---------------------------------------------------------------------------
 * WHICH REFUSALS MIGRATE, AND WHY THE LIST IS SHORT
 * ---------------------------------------------------------------------------
 * `reply.c`'s table carries four numerics and no others. The rule is one
 * sentence: **a legacy numeric migrates where that numeric answers more than one
 * question on this node**, because then the number alone cannot tell a client
 * which refusal happened. `417` answers four (PRIVMSG text, AWAY, SETNAME realname,
 * KICK reason); `461` answers two and its text says "Not enough parameters" even
 * when the client sent too many; `482` answers three; `464` answers two. Every
 * other numeric on this node answers exactly one question and stays, because
 * replacing it would take away the only thing the client gets from it -- a name it
 * already handles -- in exchange for a line it must now learn.
 *
 * THE COST, and it is paid by the client that asked: after this, `417`, `461`,
 * `482` and `464` stop reaching a client that negotiated `standard-replies`, and a
 * client that pattern-matches `417` for "line too long" must read
 * `FAIL <cmd> ERR_INPUTTOOLONG` instead. Nothing that connected to an EARLIER
 * build is affected, because the capability did not exist to negotiate.
 *
 * AND THE TENSION WITH THE SPECIFICATION'S OWN SENTENCE, recorded rather than
 * glossed: the specification says servers "SHOULD NOT replace standardised error
 * numerics with standard replies, unless the replacement is explicitly described
 * by some other specification", and all four of these are standardised. What
 * makes the partial migration defensible here is that the exception's purpose is
 * served -- the complaint the specification's own introduction makes is that
 * "numerics themselves and the mapping of numerics to names can be unclear or
 * conflicting", and these four are unclear on THIS node -- and that the
 * replacement is per destination, so the ambiguity is fixed without taking the
 * number away from anybody who did not ask. `setname` is the one case the
 * exception clause covers outright, because its own specification names the
 * replacement. */
int cap_standard_replies_enabled(const conn_t *c);

/* away-notify: whether this node tells THIS client, unprompted, when a user it
 * shares a channel with sets, changes or removes their away state.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT SENDS, AND WHY THE CLEARED CASE IS THE INTERESTING ONE
 * ---------------------------------------------------------------------------
 * `:nick!user@host AWAY [:message]`. **The message is present when the user is
 * GOING away and ABSENT when they are removing their away state** -- one verb with
 * two shapes, decided by whether the value is there, and the absence is what makes
 * it a notification rather than an echo. `handle_away()` already produces exactly
 * those two states; this capability is what puts them on somebody else's wire.
 *
 * IT IS A NOTIFICATION AND NOT AN ECHO, and the difference is who gets it:
 * "clients will be sent an AWAY message when a user **sharing a channel with
 * them** sets, changes or removes their away state", and the specification is
 * explicit that the user themselves "SHOULD NOT be sent AWAY messages to notify
 * them of their own away status (as they can rely on `RPL_NOWAWAY` and
 * `RPL_UNAWAY`)" -- which is `305`/`306`, and this node answers both. So the
 * setter is EXCLUDED, and the exclusion is `exclude` rather than the gate: a member
 * who asked for the capability is still not told their own state, and a member who
 * did not ask is told nothing at all. Two different questions, two different
 * parameters.
 *
 * ONE GATE AND NO AVAILABILITY CHECK: `conn_t::away` exists on every connection,
 * so there is no configuration in which this node cannot honour the capability.
 * A node that advertised it and then sent nothing would be a client waiting for a
 * message that never comes, and one that withheld it whenever nobody happened to
 * be away would be a capability that appears and disappears with the traffic. */
int cap_away_notify_enabled(const conn_t *c);

/* `cap_away_notify_enabled()` in the shape `fanout.h`'s `fanout_gate_fn` wants --
 * `int (*)(const conn_t *, void *)` -- so the away notification can be handed to
 * `fanout_deliver_local_gated()` with no glue at the call site.
 *
 * IT LIVES HERE AND NOT IN msg_verbs.c, because the adaptation between this file's
 * one-argument predicates and the gate's two-argument signature is a fact about
 * this file, and one readable place is better than a wrapper per future caller. */
int cap_gate_away_notify(const conn_t *dst, void *ctx);

/* setname: `cap_setname_enabled()` in the shape `fanout.h`'s `fanout_gate_fn`
 * wants, for the COMMON-CHANNEL FAN-OUT rather than for the confirmation.
 *
 * THE GATE IS ASKED ABOUT THE DESTINATION, and this is the specification's own
 * condition rather than a choice: "The SETNAME message MUST NOT be sent to clients
 * which do not have the `setname` capability negotiated." A realname is personal
 * data, so who hears about a change is decided by the person hearing it -- and
 * `cap.h`'s rule for the confirmation above already decides it that way, so
 * gating the fan-out on the SENDER would make the two halves of one specification
 * answer opposite questions about the same field.
 *
 * THE COST, stated rather than discovered: a member who wants to watch realnames
 * change must ask for `setname` first, and a deployment whose operators want it
 * observed by default gets nothing -- which is the disclosure decision stated
 * plainly rather than a limitation. */
int cap_gate_setname(const conn_t *dst, void *ctx);

/* labeled-response: whether this node will stamp a `label=` tag on this client's
 * responses, and whether it will group a multi-line response in a
 * `labeled-response` batch and answer `ACK`.
 *
 * TWO QUESTIONS AND ONE ANSWER, and the reason they cannot be separated is the
 * specification: "Clients requesting this capability indicate that they are capable of
 * handling the message tag, batch type, and ACK response described below from servers."
 * A client that negotiated this has asked for all three; a client that did not has asked
 * for none of them, and a `BATCH` or an `ACK` on the wire to such a client is a command
 * word it was never told to expect -- the same objection 4.4.3 raises against a `FAIL`
 * reaching a client that negotiated nothing.
 *
 * IT IS ASKED ABOUT THE DESTINATION AND NOT ABOUT THE SENDER, for the reason every other
 * notification on this node is: what reaches a connection is a fact about that connection.
 * A client that labels a command gets its OWN responses labelled, and nothing about what
 * any other client is doing.
 *
 * THE CAPABILITY DOES NOT DEPEND ON `batch` BEING AVAILABLE, and it cannot: `batch` is a
 * separate capability this node advertises unconditionally, and the only thing
 * conditional here is whether the CLIENT negotiated this one. */
int cap_labeled_response_enabled(const conn_t *c);

/* invite-notify: whether this node tells THIS client, unprompted, that somebody was
 * invited to a channel they are on.
 *
 * THE AUDIENCE IS THE CHANNEL AND NOT THE INVITEE, and that is worth stating because
 * the specification is easy to misread as being about the invitee. It says: "allows a
 * client to specify that it would like to be notified when users are invited to
 * channels", and the format is `:<inviter> INVITE <target> <channel>` -- the SOURCE is
 * the inviter and the message is about a third party (the target) doing something to a
 * channel the recipient is on. RFC 2812 3.3.6's own rule is that "Other channel members
 * SHOULD NOT be notified"; this capability is the opt-in that permits it. Nothing here
 * concerns the invitee's connections, and the set of a user's OTHER connections is a
 * bouncer-shaped question this node does not have: exactly one connection may hold a
 * nickname, because the nick registry refuses a second with `433`.
 *
 * IT IS ASKED ABOUT THE DESTINATION, like every notification on this node, and for the
 * same reason: an unsolicited line is an assertion about a USER, so what reaches a
 * connection is a fact about that connection. The specification also says "The server is
 * not required to send the INVITE message ... to all clients supporting this capability
 * on a channel" and names a narrower audience as a permitted choice; this node's choice
 * is the one the capability names -- every member of the channel that negotiated it.
 *
 * NO AVAILABILITY CHECK, and there is nothing to check: the invitation is an event this
 * node produces whenever a channel operator issues an `INVITE`, and a node that
 * advertised the name and then sent nothing would be a client waiting for a message that
 * never comes.
 */
int cap_invite_notify_enabled(const conn_t *c);

/* The same predicate in `fanout.h`'s `fanout_gate_fn` shape, for the same reason
 * `cap_gate_away_notify()` and `cap_gate_setname()` exist: the adaptation between this
 * file's one-argument predicates and the gate's two-argument signature lives in ONE place
 * so that "every capability predicate here is one-argument, and the gate that adapts
 * them is this" stays a single readable claim. */
int cap_gate_invite_notify(const conn_t *dst, void *ctx);





/* Handle one `CAP` line. Returns 1 if it was handled, 0 if it was not a CAP at
 * all (which cannot happen: the caller has already dispatched on the verb). */
void cap_handle(server_t *s, conn_t *c, const message_t *m);

/* Release negotiation state. Called when a connection is torn down, so a
 * conn_t that is freed and re-used at the same descriptor cannot inherit a
 * capability it negotiated in a previous life. conn_t is calloc'd by conn_new()
 * and freed by conn_free(), so this is belt to those braces -- and it is on the
 * same list as "there is no per-connection message id" for the same reason: the
 * state must not outlive the connection that owns it. */
void cap_reset(conn_t *c);

#endif /* IRC_CORE_CAP_H */
