# RFC 2812 conformance

Every numeric RFC 2812 can define, and what this node does with each one. Written
by Phase 11, which swept `src/core/msg_verbs.c` and `src/core/commands.c` (and
`src/core/chan_verbs.c`, which owns the channel half) against RFC 2812 and RFC 1459
and fixed what it found.

**This document is the deliverable, not the code that accompanied it.** The point
of a table like this is that the next sweep does not have to be re-derived from
six source files, and the TLS work that follows touches the event loop and every
read/write path — so the wire behaviour is now pinned in one place rather than
recovered by reading.

## How to read a row

| Column | Meaning |
|---|---|
| **Code** | The three-digit numeric. |
| **Name** | The symbolic name from RFC 2812 section 5, or RFC 1459 section 4.4, or the de-facto registry the number actually comes from. |
| **Field list** | What the RFC writes. `<client>` is the target field `reply()` adds and is not shown. Middle parameters are shown bare and the trailing one is shown after a colon. **This column is what an arity check compares against.** |
| **Here** | `E` emitted, `A` absent, `—` N/A. |
| **Why** | For `A`: the RFC reference and the design consequence. For `E` that deviates: what deviates and why it is acceptable or what is open. |

`E (deviation)` means the numeric is emitted and something about it does not match
the RFC's field list or the RFC's choice of numeric for the condition. Those rows
are the ones to read carefully; they are collected in
[§5 Deviations](#5-deviations-emitted-and-not-quite-the-rfc) and
[§6 Open findings](#6-open-findings-this-phase-did-not-change).

## 1. The counts

RFC 2812 defines **160** distinct numerics: **84** in 5.1 (command responses), **53**
in 5.2 (error replies) and **23** in 5.3 (reserved, obsolete, or specific to one
server's non-generic features). Of those 160:

| | Count |
|---|---|
| **Emitted on this node** | **59** |
| Absent, and the absence is correct for this design | 91 |
| N/A — in RFC 2812 5.3 only, with no role on any server | 10 |
| **Defined in RFC 2812 and not accounted for** | **0** |

RFC 2812 5.3 prints `244` twice (RPL_STATSHLINE and RPL_STATSSLINE), which is a
typo in the RFC rather than two numerics; it is counted once, which is why 5.3
contributes 23 and not 24.

This node also emits **eight** numerics RFC 2812 does not define, all of them
de-facto or IRCv3. They are in [§4](#4-numerics-this-node-emits-that-rfc-2812-does-not-define).

Every row below is one of those four. There is no fifth category, and a numeric
with no row is a gap in this document rather than in the node — which is the one
failure mode a table like this has, and the reason the last column is mandatory.

### 1.1 How these three numbers were checked, and what that check cannot see

**Phase 11 wrote them by reading six source files. Phase 11b re-derived all three
mechanically**, because the two arity defects that table recorded as open findings
were both found by reading and both survived anyway. The method, so the next sweep
can repeat it:

1. **The 160 and its 84/53/23 split** come from parsing the RFC's own text for
   lines matching `^ {3,}<3 digits> {2,}<SYMBOLIC NAME>` and attributing each to the
   nearest preceding `5.x` heading. That gives 84 in 5.1 and 53 in 5.2. **§5.3 is a
   two-column table and cannot be read by line prefix** — nine of its 23 codes are on
   the table's *second* column and a prefix match misses every one of them — so it
   is read instead by pairing `<code> <NAME>` across the whole block: 25 pairs, of
   which one is `812`, the page number in a running header, leaving 24; and `244` is
   printed twice (`RPL_STATSHLINE`, `RPL_STATSSLINE`), leaving **23 distinct**. The
   three sections share no code, so `84 + 53 + 23 = 160` is the union and not merely
   the sum.
2. **The 59 emitted** comes from parsing every `reply()` and `reply_refused()` call
   in `src/` — **176 sites** — and collecting the three-digit literal each one names.
   That yields 65 distinct numerics; six of them (`265`, `266`, `329`, `330`,
   `333`, `417`) are §4's, and the remaining **59** are RFC 2812's.
   **Two more of §4's eight are not in that scan, and the reason is a macro rather
   than a gap in the sweep**: `410` and `908` are emitted as
   `RPL_INVALIDCAPSUBCOMMAND` and `RPL_SASLMECHS`, defined in `cap.h`, so the literal
   never appears at the call site. §4's other six appear inline, which is why the
   scan finds them and these two it does not. Anyone repeating this sweep should
   expand those two macros by hand rather than conclude the table is wrong.
3. **The 0 unaccounted for** is the set difference
   `RFC2812 − (§2 ∪ §3.1 ∪ §3.2 ∪ §4)`, with `413–415` style ranges expanded and
   only the FIRST column of each table read, so a cross-reference in a note cannot
   make a code look accounted for. It is empty.
4. **The arithmetic closes, and this is the form in which it closes.** §2's first
   column names **105** codes, of which **104** are RFC 2812's (`333` is not), and it
   splits them **59 emitted + 43 `A` + 2 `—`**. §3.1 lists 79 codes, **31 of which
   already have a row in §2**, so it contributes **48** new ones. §3.2 lists 10 codes,
   **2 of which already have a row in §2** (`384` and `492`), so it contributes **8**.
   `104 + 48 + 8 = 160`, and the ten N/A figures are §3.2's ten — which is why `477`
   can be `—` in §2 and still appear in §3.1's feature table: §2's mark is the
   verdict, §3.1's row is the reason.

**What the mechanical check cannot see, stated plainly.** Parsing call sites
verifies the *arity* of each numeric — how many middle parameters reach the wire —
and it cannot verify the *values*, the text, or whether the numeric is the right
answer to the question being asked. §5 is where the judgement calls live and they
are not mechanical: `317` carrying two numbers where the RFC names one is an arity
mismatch a scan finds, but `401` being used for `WHO <a b>` is a mapping question
no scan can reach. **The field-list re-vet was the arity half, run against all 176
call sites**, and it is what found the three new findings in §6.11 to §6.13 and the
two this document had recorded wrongly in §5.1 and §5.4.

## 2. Emitted, and conformant in field list

**Sixty rows here, of which fifty-nine are RFC 2812 numerics and one — `333` — is
one of §4's**, which is also why `333` appears in both tables. The other seven of
§4's eight (`265`, `266`, `329`, `330`, `410`, `417`, `908`) have no row here
because they are not RFC 2812 numerics and §2 is the RFC's table.

A `✓` in the last column means the field list was checked against the RFC and
matches; where it does not, the row says so and the numeric appears again in §5 or
§6. **Phase 11b re-checked all one hundred and three rows against the RFC
mechanically** — §1.1's method, run over all 176 `reply()` and `reply_refused()` call
sites — and that re-check is what corrected this column: **five rows below were
marked `✓` and were wrong** (`303`, `324`, `366`, `404`, `482`, each with exactly one
non-conformant call site), and one row's justification for its own deviation did not
hold (`324`, §5.4). `461` and `472` were the sixth and seventh, and both are now
conformant.

### Registration and server info (001–005)

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 001 | RPL_WELCOME | `:Welcome to the Internet Relay Network <nick>!<user>@<host>` | E | Host is the OBSERVED peer address, filled at accept. |
| 002 | RPL_YOURHOST | `:Your host is <servername>, running version <ver>` | E | ✓ |
| 003 | RPL_CREATED | `:This server was created <date>` | E | The one wall-clock read on the reply path. |
| 004 | RPL_MYINFO | `<servername> <version> <user modes> <channel modes>` | E | Four middle parameters, no trailing field consumed by them. |
| 005 | RPL_ISUPPORT | (free token list) | E | 11 tokens; see §7. |

### LUSERS and ADMIN (251–259)

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 251 | RPL_LUSERCLIENT | `:There are <users> and <services> on <servers> servers` | E | All five values are in the trailing text, which is free. |
| 252 | RPL_LUSEROP | `<integer> :operator(s) online` | A | Count is zero: no IRC operator exists on this node (258 says so, CHOPER is unconditionally refused). 3.4.2 makes it conditional on a non-zero count. |
| 253 | RPL_LUSERUNKNOWN | `<integer> :unknown connection(s)` | A | Count is zero: every accepted connection is a registered client or a peer link. |
| 254 | RPL_LUSERCHANNELS | `<integer> :channels formed` | E | **Added in Phase 11.** Required by 3.4.2 whenever the count is non-zero, which it is from the first JOIN. `server_chan_count()`, the same counter LIST walks. |
| 255 | RPL_LUSERME | `:I have <integer> clients and <integer> servers` | E | ✓ |
| 256 | RPL_ADMINME | `<server> :Administrative info` | E | RFC has `<server>` as a middle parameter; this node puts the server in the sentence. Free text, and the server name is in the prefix anyway. |
| 257 | RPL_ADMINLOC1 | `:<admin info>` | E | Carries facts about the node: name, network, version. |
| 258 | RPL_ADMINLOC2 | `:<admin info>` | E | Says there is no services and no operator flags. |
| 259 | RPL_ADMINEMAIL | `:<admin info>` | E | Says no contact address is configured. 3.4.2 makes an email address here REQUIRED; this node has none to give and says so rather than inventing a mailbox. |

### AWAY, USERHOST, ISON (301–306)

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 301 | RPL_AWAY | `<nick> :<away message>` | E | ✓ |
| 302 | RPL_USERHOST | `:<reply>` (one per nickname) | E | **deviation** — one middle parameter where the RFC has a trailing-only list, and it is a **duplicate** of the trailing one, so both readers are right. See §5.1. |
| 303 | RPL_ISON | `:<nick> *( " " <nick> )` | E | **✓ conformant as of Phase 11c.** The nick list is now ONE trailing parameter — RFC 2812 5.1's field list — instead of middle parameters with `"are online"` after them. The split across replies is unchanged and is not a deviation: it is forced by the wire, and a client that concatenates the chunks gets the whole list. §5.1 has the argument and what the change cost. |
| 305 | RPL_UNAWAY | `:You are no longer marked as being away` | E | ✓ |
| 306 | RPL_NOWAWAY | `:You have been marked as being away` | E | ✓ |

### WHO / WHOIS (311–319)

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 311 | RPL_WHOISUSER | `<nick> <user> <host> * :<real name>` | E | ✓ The `*` is a middle parameter. |
| 312 | RPL_WHOISSERVER | `<nick> <server> :<server info>` | E | ✓ |
| 313 | RPL_WHOISOPERATOR | `<nick> :is an IRC operator` | A | No IRC operators exist; 258 says so on the wire. |
| 314 | RPL_WHOWASUSER | `<nick> <user> <host> * :<real name>` | A | No WHOWAS command (421) and no nickname history: this node keeps none by design. |
| 315 | RPL_ENDOFWHO | `<name> :End of WHO list` | E | ✓ Always emitted, including after 403. |
| 317 | RPL_WHOISIDLE | `<nick> <integer> :seconds idle` | E | **deviation** — two middle parameters, §5.2. |
| 318 | RPL_ENDOFWHOIS | `<nick> :End of /WHOIS list` | E | ✓ Always emitted, including after 401. |
| 319 | RPL_WHOISCHANNELS | `<nick> :*( ( "@" / "+" ) <channel> " " )` | E | **Added in Phase 11.** Chunked at 400 bytes, which 3.3.4 sanctions in the sentence that defines the numeric. |

### LIST, MODE query, TOPIC, INVITE (321–341)

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 321 | RPL_LISTSTART | Obsolete. Not used. | E | Emitted as `"Channel" :Users  Name`, which is RFC 1459's form. RFC 2812 marks it obsolete, and RFC 1459 kept it; emitting both an obsolete and a modern form would be worse. **246/247 are the pre-1459 numbers and are absent — see §3.** |
| 322 | RPL_LIST | `<channel> <# visible> :<topic>` | E | ✓ |
| 323 | RPL_LISTEND | `:End of LIST` | E | ✓ |
| 324 | RPL_CHANNELMODEIS | `<channel> <mode> <mode params>` | E | **deviation** — two middle parameters and a trailing sentence, where the RFC has three fields and **no trailing parameter at all**. See §5.4. The missing `<mode params>` is honest (this node evaluates `b`, `o`, `v` and no mode takes an argument beyond `+b`'s mask), but Phase 11's justification — that the added text "is the RFC's free `<text>`" — was **wrong**: 324's entry in RFC 2812 5.1 contains no `:` and so names no free text. Corrected by the Phase 11b re-vet. |
| 325 | RPL_UNIQOPIS | `<channel> <nickname>` | A | No `+q`/`+a` mode exists on this node. |
| 331 | RPL_NOTOPIC | `<channel> :No topic is set` | E | ✓ |
| 332 | RPL_TOPIC | `<channel> :<topic>` | E | ✓ |
| 333 | RPL_TOPICWHYTIME | `<channel> <who> <time> :<topic>` | E | De-facto — RFC 2812 does not define it. See §4. |
| 341 | RPL_INVITING | `<channel> <nick>` | E | ✓ Goes to the inviter, never the invitee — 3's reply path makes that structural, not a convention. |

### WHO reply, NAMES, LINKS, NAMES end, ban list, INFO, MOTD (352–384)

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 352 | RPL_WHOREPLY | `<channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ] :<hopcount> <real name>` | E | ✓ `H`/`G` first letter, then the sigil. Honours `multi-prefix` when negotiated and says so in 005. |
| 353 | RPL_NAMREPLY | `( "=" / "*" / "@" ) <channel> :[ "@" / "+" ] <nick> *( … )` | E | ✓ Chunked at `CHAN_NAMES_LINE`. |
| 366 | RPL_ENDOFNAMES | `<channel> :End of /NAMES list` | E | ✓ **on every site as of Phase 11c**, and always last. The last non-conformant site — a bare `NAMES` on a node with **zero** channels, which answered with no `<channel>` at all — now sends `<channel>` = `*`. Every 366 on this node now goes through `send_end_of_names()`. The field list is conformant; the trailing TEXT is not, which is §6.14. |
| 367 | RPL_BANLIST | `<channel> <banmask>` | E | **Added in Phase 11.** Two middle parameters and no trailing field. |
| 368 | RPL_ENDOFBANLIST | `<channel> :End of channel ban list` | E | **deviation** on one path — see §5.3. |
| 369 | RPL_ENDOFWHOWAS | `<nick> :End of WHOWAS` | A | No WHOWAS command. |
| 371 | RPL_INFO | `:<string>` | E | One per line, terminated by 374. |
| 372 | RPL_MOTD | `:- <text>` | E | One per line. |
| 374 | RPL_ENDOFINFO | `:End of /INFO list` | E | ✓ |
| 375 | RPL_MOTDSTART | `:- <server> Message of the day -` | E | Free text. |
| 376 | RPL_ENDOFMOTD | `:End of MOTD command` | E | ✓ |
| 381 | RPL_YOUREOPER | `:You are now an IRC operator` | A | No OPER command; 421. |
| 382 | RPL_REHASHING | `<config file> :Rehashing` | A | No REHASH command; 421. |
| 383 | RPL_YOURESERVICE | `You are service <servicename>` | A | No SERVICE command and no services. |
| 384 | RPL_MYPORTIS | — | — | RFC 2812 5.3 only; belongs to BIND, which this node has no command for. Counted in §3.2 rather than §3.1. |

### Errors 4xx

| Code | Name | Field list | Here | Notes |
|---|---|---|---|---|
| 401 | ERR_NOSUCHNICK | `<nickname> :No such nick/channel` | E | ✓ |
| 402 | ERR_NOSUCHSERVER | `<server name> :No such server` | E | ✓ Used for a mask that does not name this node. |
| 403 | ERR_NOSUCHCHANNEL | `<channel name> :No such channel` | E | **deviation** on the `MODE <nick>` path — see §6.1. |
| 404 | ERR_CANNOTSENDTOCHAN | `<channel name> :Cannot send to channel` | E | ✓ on the site that answers the real condition — a channel the client is not on, with `t.name` as the field. **One site is not**: when the source hostmask itself will not render, the line carries no `<channel name>` and a different sentence. See §6.12. |
| 405 | ERR_TOOMANYCHANNELS | `<channel name> :You have joined too many channels` | A | **There is no per-client channel limit on this node**, so the condition cannot arise. That is a resource decision, not an oversight: channels are bounded only by the descriptor table. See §8. |
| 406 | ERR_WASNOSUCHNICK | `<nickname> :There was no such nickname` | A | No WHOWAS. |
| 407 | ERR_TOOMANYTARGETS | `<target> :<error code> recipients. <abort message>` | A | 005 advertises `MAXTARGETS=1`, so a multi-recipient line is refused as a parameter-count problem (461) rather than as too many recipients. The token is the honest disclosure. |
| 408 | ERR_NOSUCHSERVICE | `<service name> :No such service` | A | No services. |
| 409 | ERR_NOORIGIN | `:No origin specified` | A | No OPER, so there is no origin to be missing. |
| 411 | ERR_NORECIPIENT | `:No recipient given (<command>)` | A | **deviation** — see §6.2. |
| 412 | ERR_NOTEXTTOSEND | `:No text to send` | A | **deviation** — see §6.2. |
| 413–415 | ERR_NOTOPLEVEL / ERR_WILDTOPLEVEL / ERR_BADMASK | — | A | `PRIVMSG $<server>` and `PRIVMSG #<host>` forms. `$` is not a target sigil on this node, so `PRIVMSG $irc.test :hi` is a nickname lookup and answers 401. |
| 421 | ERR_UNKNOWNCOMMAND | `<command> :Unknown command` | E | ✓ |
| 422 | ERR_NOMOTD | `:MOTD File is missing` | A | **The MOTD is compiled in, not read from a file**, so this condition cannot occur. |
| 423 | ERR_NOADMININFO | `<server> :No administrative info available` | A | ADMIN always answers 256–259, including when asked about a foreign server (402). |
| 424 | ERR_FILEERROR | `:File error doing <file op> on <file>` | A | No runtime file operations. |
| 431 | ERR_NONICKNAMEGIVEN | `:No nickname given` | E | ✓ |
| 432 | ERR_ERRONEUSNICKNAME | `<nick> :Erroneous nickname` | E | **deviation** — the nick is in the trailing text, not a middle parameter. Forced: an illegal nickname may be empty or hold a space, and 3.2 refuses a value that is unrepresentable in a non-final position rather than reshaping it. |
| 433 | ERR_NICKNAMEINUSE | `<nick> :Nickname is already in use` | E | ✓ Client keeps the name it had and can immediately take another; verified on the wire in `test_query_surface.c`. |
| 436 | ERR_NICKCOLLISION | `<nick> :Nickname collision KILL from <user>@<host>` | A | A single node answers 433 to the requester and never KILLs. Over a mesh, `fed_nickreg_resolve_local()` renames the local loser without a 436. Documented design decision — see §9. |
| 437 | ERR_UNAVAILRESOURCE | `<nick/channel> :Nick/channel is temporarily unavailable` | E | Used for "this node may not manage that channel" and "that mode is the origin's to evaluate". |
| 441 | ERR_USERNOTINCHANNEL | `<nick> <channel> :They aren't on that channel` | E | ✓ |
| 442 | ERR_NOTONCHANNEL | `<channel> :You're not on that channel` | E | ✓ |
| 443 | ERR_USERONCHANNEL | `<user> <channel> :is already on channel` | A | **A second JOIN to a channel you are on re-answers the JOIN sequence and sends nothing.** Deliberate and idempotent; see §8. |
| 444 | ERR_NOLOGIN | `<user> :User not logged in` | A | Services numeric. This node has an account subsystem with its own refusals (`REGISTER`/`UNREGISTER` answered with 461/482 and the `ERR_ACCOUNTREGISTRATIONDISABLED` code). |
| 445 | ERR_SUMMONDISABLED | `:SUMMON has been disabled` | A | No SUMMON command; 421. |
| 446 | ERR_USERSDISABLED | `:USERS has been disabled` | A | No USERS command; 421. |
| 451 | ERR_NOTREGISTERED | `:You have not registered` | E | ✓ |
| 461 | ERR_NEEDMOREPARAMS | `<client> <command> :Not enough parameters` | E | **✓ conformant as of Phase 11b.** All 29 `reply_refused()` sites pass `NULL, 0`, and `reply_refused()` prepends its own `command` argument for this one numeric — see §6.3 for what was wrong, why the fix is in one place rather than 29, and what a `standard-replies` client gets instead. |
| 462 | ERR_ALREADYREGISTRED | `:Unauthorized command (already registered)` | E | ✓ |
| 463 | ERR_NOPERMFORHOST | `:Your host isn't among the privileged` | A | No host-based connection restriction. |
| 464 | ERR_PASSWDMISMATCH | `:Password incorrect` | E | **deviation** — see §6.4. |
| 465 | ERR_YOUREBANNEDCREEP | `:You are banned from this server` | A | No node-level ban list and no KILLLINE. |
| 466 | ERR_YOUWILLBEBANNED | — | A | Reserved by RFC 2812 5.3; same reasoning as 465. |
| 467 | ERR_KEYSET | `<channel> :Channel key already set` | A | `+k` is advertised in 004 and **not evaluated** — it is refused with 472 by name — so no key can ever be set. |
| 471 | ERR_CHANNELISFULL | `<channel> :Cannot join channel (+l)` | A | `+l` is advertised and not evaluated, so no channel can be full. |
| 472 | ERR_UNKNOWNMODE | `<client> <char> :is unknown mode char to me for <channel>` | E | **✓ conformant as of Phase 11b.** Both sites send the mode character as the middle parameter and name the channel in RFC 1459 4.4's sentence: `:irc.test 472 <client> k :is unknown mode char to me for channel #MO`. See §6.5 for the two faults this was. |
| 473 | ERR_INVITEONLYCHAN | `<channel> :Cannot join channel (+i)` | A | `+i` is advertised and not evaluated. |
| 474 | ERR_BANNEDFROMCHAN | `<channel> :Cannot join channel (+b)` | E | ✓ `+b` is the one channel mode this node evaluates. |
| 475 | ERR_BADCHANNELKEY | `<channel> :Cannot join channel (+k)` | A | `+k` is advertised and not evaluated. A `JOIN #chan <key>` argument is accepted and ignored. |
| 476 | ERR_BADCHANMASK | `<channel> :Bad Channel Mask` | A | **No mask validation.** `MODE #c +b <anything ≤63 bytes>` is stored and enforced. See §6.6. |
| 477 | ERR_NOCHANMODES | `<channel> :Channel doesn't support modes` | — | The node does support channel modes (`b`, and the prefix modes `o`/`v`). |
| 478 | ERR_BANLISTFULL | `<channel> <char> :Channel list is full` | E | **Added in Phase 11**, replacing 696. Both middle parameters. |
| 481 | ERR_NOPRIVILEGES | `:Permission Denied- You're not an IRC operator` | A | **deviation** — see §6.7. |
| 482 | ERR_CHANOPRIVSNEEDED | `<client> <channel> :You're not channel operator` | E | ✓ on the four channel sites, which name `ch->name`. **One site is not**: `REGISTER`/`UNREGISTER` refused by `account_refuse()` sends `482` with no `<channel>` and this node's own text, because neither verb has a channel and this node has no operator model to name instead. See §6.13. |
| 483 | ERR_CANTKILLSERVER | `:You can't kill a server!` | A | `KILL` is in the dispatch table with a NULL handler, so it answers 421. No operator model. |
| 484 | ERR_RESTRICTED | `:Your connection is restricted!` | A | No user mode `+r`. 004 advertises user modes `i` only. |
| 485 | ERR_UNIQOPPRIVSNEEDED | `:You're not the original channel operator` | A | No `+q`/`+a`. |
| 491 | ERR_NOOPERHOST | `:No O-lines for your host` | A | No OPER. |
| 492 | ERR_NOSERVICEHOST | — | A | Reserved by RFC 2812 5.3; services. |
| 501 | ERR_UMODEUNKNOWNFLAG | `:Unknown MODE flag` | A | **deviation** — see §6.8. |
| 502 | ERR_USERSDONTMATCH | `:Cannot change mode for other users` | A | **deviation** — see §6.8. |

## 3. Absent, and the absence is correct for this design

One hundred and one RFC 2812 numerics are not emitted. Ninety-one of them are
absent because the **feature** they report does not exist on this node, which is a
design decision with a stated consequence rather than a gap. The remaining ten are
in §3.2.

### 3.1 Absent because the feature is absent

| Codes | Feature | RFC | Design consequence |
|---|---|---|---|
| 200–210, 261, 262 | TRACE | 3.4.5 | No TRACE command; a client that runs `/TRACE` gets 421, which is the accurate answer — this server has never heard of the verb. The operator model has no diagnostic surface at all: no OPER, no STATS, no KILL. |
| 211–219, 240–244, 250 | STATS | 3.4.4 | Same. `242 RPL_STATSUPTIME` in particular is a thing clients ask for on connect; a client that asks gets 421 rather than a number. |
| 263 | RPL_TRYAGAIN | 3.4.2 | No throttle. The node's only back-pressure is a bounded write queue, and exceeding it drops the peer link rather than asking a client to wait — which is the correct answer for a *client*, since a client connection is not the thing under back-pressure. |
| 231–235 | SERVICES | 3.4.6 | No services. 258 says so on the wire, which is what makes CHOPER a refusal rather than a grant. |
| 221 | RPL_UMODEIS | 3.3.2 | This node evaluates **no** user modes (004 advertises `i`, and `MODE <nick>` never reaches a mode loop — §6.1). So there is no mode string to report. |
| 313 | RPL_WHOISOPERATOR | 3.3.4 | No IRC operators. |
| 314, 369, 406 | WHOWAS | 3.4.8 | No WHOWAS command and no nickname history. This node keeps none by design: a single process with no per-nick state that outlives a connection, so "was there a bob ten minutes ago" is not a question it can answer honestly. |
| 325, 485 | UNIQOP | 2.3.1 | No `+q` or `+a` mode exists. |
| 342, 445 | SUMMON | 3.4.9 | No SUMMON command; 421. |
| 346, 347, 348, 349 | INVITE / EXCEPTION / BAN lists | 2.3.2 | No `+e` and no `+I`. 2.2 reserves `{b, e, I}` to the origin and this node evaluates `b` alone, so `MODE #c +e` and `MODE #c +I` are refused with 472 by name. **The `+b` list (367/368) is implemented and these are not, and that is consistent: only `b` exists.** |
| 351 | RPL_VERSION | 3.4.3 | No VERSION command; 421. See §6.9 — this is the one absence in this table that reads as a gap. |
| 364, 365 | LINKS | 3.4.6 | No LINKS command; 421. |
| 381, 382 | YOUREOPER, REHASHING | 3.4.1, 3.4.4 | No OPER, no REHASH. |
| 383 | YOURESERVICE | 3.4.7 | No SERVICE command. |
| 391 | RPL_TIME | 3.4.4 | No TIME command; 421. See §6.10 for the CTCP half. |
| 392, 393, 394, 395 | USERS | 3.4.5 | No USERS command; 421. Also the numerics of a command RFC 1459 3.3.4 describes in the context of the *client's* host, so even a server that had it would answer with its own shell. |
| 405 | TOOMANYCHANNELS | 2.3.1 | No per-client channel limit exists, so the condition cannot arise. §8. |
| 408 | NOSUCHSERVICE | 3.4.6 | No services. |
| 409 | NOORIGIN | 3.4.1 | No OPER, so no origin. |
| 422 | NOMOTD | 3.4.5 | The MOTD is compiled in, not read from a file. |
| 423 | NOADMININFO | 3.4.6 | ADMIN always answers. |
| 424 | FILEERROR | 3.4.5 | No runtime file operations. |
| 436 | NICKCOLLISION | 3.3.4 | See §9. |
| 443 | USERONCHANNEL | 3.3.1 | A second JOIN re-answers and says nothing. Deliberate. §8. |
| 444 | NOLOGIN | 2.3.1 | Services numeric; the account subsystem has its own. |
| 446 | USERSDISABLED | 3.4.5 | No USERS command. |
| 463 | NOPERMFORHOST | 2.3 | No host-based restriction. |
| 465, 466 | Banned from the server | 2.3 | No KILLLINE, no node-level ban list. |
| 467, 471, 473, 475 | +k, +l, +i, +k | 2.3.1 | All four are advertised in 004's channel-mode set and **not evaluated** — 472 by name, which is the node's deliberate choice: a node that accepted a mode it does not act on would have a 324 that disagreed with its behaviour. Since none can be set, none of their refusals can arise. |
| 477 | NOCHANMODES | 2.3.1 | The node does support channel modes. |
| 481 | NOPRIVILEGES | 3.3.2 | See §6.7. |
| 483 | CANTKILLSERVER | 3.3.2 | `KILL` has a NULL handler; 421. |
| 484 | RESTRICTED | 2.3.2 | No user mode `+r`. |

### 3.2 N/A — reserved, obsolete, or a numeric no server ever sends

| Codes | Names | Why N/A |
|---|---|---|
| 246, 247 | RPL_STATSPING, RPL_STATSBLINE | RFC 2812 5.3 reserves them. They are **not** LIST's start/end: those are the pre-RFC-1459-draft numbers, and the pair every modern server sends is **321/323**, which this node does. |
| 300 | RPL_NONE | RFC 2812 5.3: "no longer in use". Nothing defines it. |
| 316 | RPL_WHOISCHANOP | RFC 2812 5.3 reserves it and 5.1 does not define it. It would report "this user is a channel operator in this channel", which is exactly what **319's `@` sigil now carries** — so emitting it as well would be a second spelling of a fact 319 states. |
| 361 | RPL_KILLDONE | Reserved. Part of the OPER/KILL family, which this node has no command for. |
| 362 | RPL_CLOSING | Reserved. Belongs to the *client's* connection lifecycle (TS/CLOSE), not a server reply. |
| 363 | RPL_CLOSEEND | As 362. |
| 373 | RPL_INFOSTART | Reserved. RFC 2812 3.4.6 defines INFO as 371 lines terminated by 374 and has no start marker; 375/376 are MOTD's, and reusing them for INFO would make the MOTD's terminator lie. |
| 384 | RPL_MYPORTIS | RFC 2812 5.3 only; belongs to BIND. |
| 492 | ERR_NOSERVICEHOST | RFC 2812 5.3 only; services. |

## 4. Numerics this node emits that RFC 2812 does not define

All eight come from the de-facto registry or from IRCv3. Every one of them is a
*convention every client understands*, which is the same argument the code makes
for `417` at each call site — and the reason to record them here is that "RFC 2812
does not define it" is not by itself a reason not to use it, but it IS a reason to
know where it came from.

| Code | Name | Origin | Why here |
|---|---|---|---|
| 265 | RPL_LOCALUSERS | ircdocs / common ircd practice | `<local> <max> :Current local users …`. Widely parsed by `/LUSERS` output. |
| 266 | RPL_GLOBALUSERS | as 265 | `<global> <max> :Current global users …`. On a single node `<global>` equals `<local>`, which is a fact and not a shortcut. |
| 329 | RPL_CREATIONTIME | ircdocs / ircd practice | `<channel> <time>`. Sent after a JOIN's names, as RFC 1459 2.3.1's JOIN sequence does. Carries `created_at` and nothing else — borrowing `topic_when` for it would be "a numeric that lies about what it is". |
| 330 | RPL_WHOISACCOUNT | ircd practice | `<nick> <account> :is logged in as`. Sent only when there is an account; absence is the RFC-conventional "not identified". The one place a person's account name reaches another user, and it is said so at the call site. |
| 333 | RPL_TOPICWHYTIME | ircd practice | `<channel> <who> <time> :<topic>`. Every client reads a topic's setter and time from here; without it the node has no way to report who set a topic. |
| 410 | ERR_INVALIDCAPSUBCOMMAND | IRCv3 `capability-negotiation` | `<cap> :Invalid CAP subcommand`. |
| 417 | ERR_INPUTTOOLONG | ircdocs / ircd practice | Not in RFC 2812 or RFC 1459 — **re-verified in Phase 11b** by parsing the RFC's own numeric table, which contains no 417 at all. Used for every over-long parameter: AWAY, PRIVMSG, SETNAME, KICK reason, TOPIC, channel name. 3.2 forbids delivering a silently shortened parameter, so *something* has to be said, and this is what clients already understand. A client that negotiated `standard-replies` gets `FAIL … ERR_INPUTTOOLONG` instead. |
| 908 | RPL_SASLMECHS | IRCv3 `sasl` | `<mechs> :are available SASL mechanisms`. |

## 5. Deviations: emitted, and not quite the RFC

**Six entries, covering six numerics.** Four are Phase 11's and were re-verified
against the RFC by the scan; **one is new** (`302`'s duplicated middle parameter),
and **one is gone** — `303` was recorded here through Phase 11c and is now conformant,
because the two numerics this section used to lump together are not the same shape.
§5.1 says so with the evidence. Two of the six are not fixable without a decision
that is not this document's to make.

| | Numeric | What |
|---|---|---|
| [§5.1](#51-302-puts-a-nick-list-in-a-middle-parameter-and-303-no-longer-does) | `302` | a nick list in a middle parameter the RFC does not have, plus the `+`/`-` spelling |
| [§5.2](#52-317-carries-two-numbers-where-the-rfcs-field-list-has-one) | `317` | two numbers where the RFC names one |
| [§5.3](#53-368-is-also-used-as-a-refusal-with-two-middle-parameters) | `368` | a refusal role the RFC does not give it |
| [§5.4](#54-324-adds-a-trailing-parameter-where-the-rfc-has-none) | `324` | a trailing sentence where the RFC's field list has no trailing parameter at all |
| [§5.5](#55-432-puts-the-nickname-in-the-trailing-text) | `432` | the nickname in the trailing text |
| [§5.6](#56-256-puts-the-server-name-in-the-sentence) | `256` | the server name in the sentence |

**`302`, `317`, `324`, `368`, `432` and `256` are deviations. `366`, `404` and
`482` are in §6 instead**, because each of those three is conformant on most of its
sites and the non-conformance is one call out of several — a different kind of thing
from a numeric this node always gets wrong. **`303` is on neither list now**: it was
a §5 deviation and §5.1 explains, with the wire lines, why keeping it would have meant
telling a client that an online user is offline.

### 5.1 `302` puts a nick list in a middle parameter, and `303` no longer does

**`302` — the spelling, unchanged and unchanged in kind.** RFC 2812 5.1 writes the
reply string as `nickname [ "*" ] "=" ( "+" / "-" ) hostname`. **Every deployed
server writes `nick+user@host` and `nick*user@host`**, and every client parses that.
Answering the RFC's literal form would be a different shape from what clients
expect, for a numeric whose entire purpose is the shape. Deviation kept; the RFC's
spelling is a known erratum in practice.

**`302`'s extra middle parameter, which Phase 11b missed.** RFC 2812 5.1 gives 302
**no** field before the trailing one: `302 RPL_USERHOST ":<reply>"`. This node sends
`<target> <reply> :<reply>` — the same value in **both** positions. That is an arity
mismatch the field-list scan finds, and it was not recorded until now. **It is inert,
and it is worth saying why rather than leaving it as a bare entry in the deviation
table**: because the value appears twice, a client reading the trailing parameter and
a client reading the middle parameter both get a correct answer. The duplication costs
`1 + strlen(reply)` bytes per reply and nothing else. It is not changed here because
the same reasoning that changed `303` does not apply — see below — and changing it
would remove the only reason the two readers agree.

**`303` — CONFORMANT as of Phase 11c.** This section previously recorded `303` as an
open deviation, alongside `302`, on the reasoning that *"both are the de-facto shape
and a client that dispatches on the numeric reads the first middle parameter as the
first nickname and the rest as continuation."* **That reasoning was false for `303`,
and conflating the two numerics is what hid it.** `302`'s middle parameter is a
**duplicate** of its trailing one, so a reader of either position is right. `303`'s
trailing parameter held `"are online"` — a sentence, not a duplicate — so the two
readers *disagreed*, and the disagreement was a false negative:

```
:alice ISON bob carol
:irc.test 303 alice bob carol :are online      <- before: nicks in the middle
:irc.test 303 alice :bob carol                  <- now: RFC 2812 5.1's shape
```

A client written to the RFC reads the trailing parameter — the only position the RFC
defines — and gets `"are online"`. It concludes the nick list is `["are", "online"]`,
and therefore that **`bob` and `carol` are OFFLINE**. ISON exists to answer exactly
that question, so this was not decoration: it was the worst failure a query reply can
have, on the most common case, and it was invisible to every needle in the suite
because those needles matched the defective shape.

**Conforming also costs no compatibility, which is the argument that settles it.**
Every deployed ircd sends `:irc.test 303 alice :bob carol`. There is no client in
existence that was written against this node's shape, because this node was the only
thing that sent it.

**The trailing text is gone, and it had to be.** The RFC's trailing parameter *is* the
list, so `"are online"` cannot be appended to it: a client splitting that parameter on
spaces would read `bob`, `carol`, `are`, `online` and report two phantom users as
online. `908 RPL_SASLMECHS` still says "are available SASL mechanisms", and that is
fine — 908's field list in RFC 2812 5.3 has no `<text>` at all, so there is nothing
there to collide with.

**THE SPLIT ACROSS REPLIES IS NOT A DEVIATION AND WAS NOT TOUCHED**, and this is the
part of the old §5.1 that was right. Both numerics chunk, and chunking cannot be
removed: a nick list too long for one line cannot be rendered in one line whatever the
parameter position, so some split is forced by the wire rather than chosen here. RFC
1459 2.4.3 anticipates it, and RFC 2812 5.1's own prose for 366 speaks of *"a series
of RPL_NAMEREPLY messages"*. **To the question of what chunking does to a client that
concatenates the chunks: it gives that client the whole list, which is precisely what
concatenation is for.** The alternative — truncating at the first reply — is strictly
worse, because a truncated list reports online users as offline, the same false
negative as the defect above. Truncation is not on the table.

**What conforming cost, and it was not free.** The bound moved from a *count* to a
*byte count*, and that is a real consequence rather than a detail:

| | before | now |
|---|---|---|
| what limits a chunk | `REPLY_MAX_MID` = 13 names | `ISON_CHUNK_MAX` = `REPLY_TEXT_MAX - 1` = 511 bytes |
| names per chunk | 13 always | 8 at the advertised maximum `NICKLEN` = 63 |

`reply()` renders trailing text into `char text[REPLY_TEXT_MAX]` and **refuses** a
write that would reach `sizeof text`, so with the list in one trailing parameter the
size of that parameter is the bound. Keeping the old count would have meant a chunk of
thirteen 63-byte nicknames — 895 bytes — being refused as `text_too_long`, which
`reply.c` documents as a bug report and which this project holds at zero. `ISON_CHUNK_MAX`
is derived from `REPLY_TEXT_MAX` so raising the buffer moves the bound with it.

**One new function, `reply_colon()`, and why a one-nickname 303 needed it.** RFC 1459
2.3 colons a trailing parameter only when it has to, and a list of exactly **one**
nickname has no space and no leading colon — so `message_format()` would render
`:irc.test 303 alice Bob` bare. That is **byte for byte the shape the middle-parameter
version sent**, so the conformance change would have been invisible on the single
most common case and visible only when two or more names matched. `reply_colon()` is
`reply()` with `force_colon` set, the numeric counterpart of the `send_line_colon()`
that already exists for IRCv3's `CAP`, and it is `message_format_ex()`'s existing
mechanism rather than a new one. Its reasoning is recorded at `reply.h` and at the
call site, which is where `302`'s does not apply: `302` can afford the duplicated
field precisely because both readers being right is worth `strlen(reply)` bytes, and
`303` cannot afford to be ambiguous about which of its two fields is the list.

### 5.2 `317` carries two numbers where the RFC's field list has one

RFC 2812 5.1: `<nick> <integer> :seconds idle`. This node sends
`<nick> <idle> <signon> :seconds idle`. See the call site for the full argument.
Short version: 317 is the only place a WHOIS reply carries a timestamp at all, the
two-number form is what clients parse, and `<signon>` had to be a *parameter*
rather than part of the sentence because 3.2 will not format a number into a
non-final position — so the trailing text stays exactly where the RFC puts it.
Re-verified by the Phase 11b scan: three middle parameters, where the RFC names two.

**The trailing text is left at the RFC's own literal `"seconds idle"`.** RFC 2812
3.3.4 makes it free text, so `"seconds idle, signon time"` would be equally
conformant and conformance cannot decide it. It is left alone because (1) it is the
specification's literal string and a client whose numeric table carries the RFC's
text matches this line byte for byte; (2) no client parses the trailing text of 317
— every one dispatches on the numeric and reads the middle parameters by position —
so rewriting decoration nothing reads buys no compatibility; and (3) an anchored
`:seconds idle` match is a real thing in the wild and a rewritten sentence does not
satisfy it. The trade is a hypothetical reader of decoration against a concrete
reader who matches it.

### 5.3 `368` is also used as a refusal, with two middle parameters

`MODE #c -b <mask>` where the mask is not set answers 368 with the channel **and
the mask**, and a text saying so. RFC 2812 gives 368 no such role: it is
`RPL_ENDOFBANLIST`, an end-of-list marker, and its field list has one middle
parameter.

Left unchanged, deliberately. RFC 2812 defines **no** numeric for "that ban is not
set", so the choice is between silence (which this node's own design rejects
everywhere — "4.4's numerics exist to prevent" the silence failure mode), a numeric
the RFC gives a different meaning, and this. This names the offending mask, so the
client's remedy is the same in all three cases: re-read the list, which
`MODE #c +b` now makes possible. A client that treats 368 as "list over" loses
nothing here, because it was not building a list from this line. Re-verified: one
site at one middle parameter and one at two.

### 5.4 `324` adds a trailing parameter where the RFC has none

**Phase 11b's finding, and the one place this document was wrong about itself in a
way that mattered** — not just an omission but a stated justification that does not
hold. RFC 2812 5.1 writes `324 RPL_CHANNELMODEIS "<channel> <mode> <mode params>"` —
**three fields and no `:`**, so the field list names no trailing parameter and no
free text. This node sends two middle parameters (`ch->name`, the mode string) and
`:Channel modes` as the trailing text:

```
:irc.test 324 moa #MO +b :Channel modes
```

Phase 11's row for `324` recorded this as conformant and gave a reason: "the
trailing text is the RFC's free `<text>`". That reason is false — there is no free
`<text>` in `324`'s entry, and the re-vet found it by counting the middle parameters
against the RFC and noticing that the RFC has three of them where the node has two.

**The two halves are different in kind, and only one of them is a defect.** The
missing `<mode params>` is honest: this node evaluates `b`, `o` and `v`, and `+b`'s
mask is carried in a `MODE` command rather than reported here, so there is no third
field to send. Adding a trailing sentence *is* the deviation, and it is the same
kind as §5.6's `256` — a value moved into the text so the line has something to say
— except that in `256`'s case the RFC names a field and in `324`'s case it does not.

**Why not changed.** Removing the sentence gives `:irc.test 324 moa #MO +b :`, and
`message_format()` is free to render the empty trailing parameter — so the change is
mechanical. It is not made here because this is a documentation commit and because
`324`'s trailing text is the only thing that tells a human reading a log which
numeric they are looking at. That is a weak argument and it is stated as weak: the
honest reason is that the sentence is not required and nobody has yet decided whether
removing it is an improvement. It is a one-line change with no test churn and it
belongs to whoever reads this next.

### 5.5 `432` puts the nickname in the trailing text

Forced, and argued at the call site. An illegal nickname may be empty, may start
with `:`, or may hold a space; 3.2's formatter **refuses** a value that cannot be
represented in a non-final position rather than reshaping it, so a middle parameter
would turn a nickname refusal into a `reply_refused` counter bump — a bug report
from ordinary client input. The trailing parameter is always representable.
Re-verified: zero middle parameters where the RFC names one.

### 5.6 `256` puts the server name in the sentence

RFC 2812 5.1: `<server> :Administrative info`. This node: `:Administrative info`,
with the server name in the message prefix. Free text, and the value is redundant
with the prefix. Re-verified: zero middle parameters where the RFC names one.

## 6. Open findings

Fourteen, and the count is now the number of subsections rather than a number
typed earlier. Each is a real deviation with a named client-visible symptom.

**Two of them were open findings in Phase 11 and were FIXED in Phase 11b** — §6.3
and §6.5, kept in place and rewritten as the record of what was wrong and what
replaced it, because a table that quietly deletes the defect it was written to
track loses the reason the fix looks the way it does. **Two more were fixed in
Phase 11c** — §6.11 and §6.12 — on the same terms. **§6.14 is new in Phase 11c**
and was found while fixing §6.11. The remaining ten are open, and each says why.

| | Numeric | Status |
|---|---|---|
| [§6.1](#61-mode-nick-is-answered-403-err_nosuchchannel) | `403` | open — needs a user-mode decision first |
| [§6.2](#62-privmsg-arity-is-461-not-411-and-412) | `461` for `PRIVMSG` | open — deliberate, and a real gap |
| [§6.3](#63-461-omitted-the-command-field--fixed-in-phase-11b) | `461` | **fixed** |
| [§6.4](#64-464-is-not-err_passwdmismatch-for-choper-or-authenticate) | `464` | open — a mapping choice |
| [§6.5](#65-472-sent-channel-where-the-rfc-sends-char--fixed-in-phase-11b) | `472` | **fixed** |
| [§6.6](#66-no-ban-mask-validation-so-476-cannot-happen) | `476` | open — needs a validator |
| [§6.7](#67-481-is-absent-the-not-privileged-family-answers-482-and-464) | `481` | open — needs an operator model |
| [§6.8](#68-501-and-502-are-unreachable) | `501`, `502` | open — same cause as §6.1 |
| [§6.9](#69-version-is-not-a-command) | `351` | open — needs a new verb |
| [§6.10](#610-time-ping-and-version-are-handled-as-commands-ctcp-is-not) | — | N/A, argued |
| [§6.11](#611-366-has-no-channel-when-names-is-asked-with-no-argument-and-there-are-no-channels--fixed-in-phase-11c) | `366` | **fixed** in Phase 11c — §6.11 |
| [§6.12](#612-404-has-no-channel-when-the-source-hostmask-will-not-render) | `404` | **fixed** in Phase 11c — §6.12 |
| [§6.13](#613-482-has-no-channel-for-register-and-unregister) | `482` | open — **blocked on §6.7** |
| [§6.14](#614-366s-trailing-text-is-end-of-names-list-the-rfcs-is-end-of-names-list) | `366` | open — **new in Phase 11c** |

### 6.1 `MODE <nick>` is answered 403 ERR_NOSUCHCHANNEL

RFC 2812 3.3.2: a MODE whose parameter is a **nickname** answers `221 RPL_UMODEIS`
for a query, or `501`/`502` for a change. This node canonicalises the first MODE
parameter as a channel name and refuses a nickname as an unknown channel:

```
:alice MODE alice
:irc.test 403 alice ALICE :No such channel
```

**Symptom.** A client that queries a user's modes — several do, and weechat does it
on connect — is told "no such channel" about a user that is demonstrably connected.
The answer is also self-contradicting: the *name* is echoed, upper-cased, which is
something only `canonical_channel()` does to a channel.

**Why not changed.** Fixing it means 221 or 501/502, and every one of them needs a
mode string this node does not have (004 advertises user modes `i` and evaluates
none of them). 221 with an empty string would be the RFC-shaped answer; 403 is the
answer that is already there and it is not *wrong* so much as misfiled. It needs a
decision about user modes before it needs a decision about numerics.

### 6.2 `PRIVMSG` arity is 461, not 411 and 412

RFC 2812 has a numeric for each: `411 ERR_NORECIPIENT` for no target and
`412 ERR_NOTEXTTOSEND` for no text. This node refuses both as parameter-count
problems:

```
:alice PRIVMSG :hi          ->  :irc.test 461 alice :Not enough parameters
:alice PRIVMSG #x           ->  :irc.test 461 alice :Not enough parameters
```

**Symptom.** Minor but real: a client that keys its "you forgot a message" handling
on 412 does not fire, and shows a generic parameter error instead. 411 and 412 are
both in RFC 2812 and both are free.

**Why not changed.** It is a deliberate single rule — `nparams != MSG_MAX_TARGETS + 1`
is one check and `MAXTARGETS=1` in 005 makes the arity public — and 461 is not
*false*. But the RFC names the two conditions and the node does not, which is a real
gap, not a style preference.

### 6.3 `461` omitted the `<command>` field — FIXED in Phase 11b

**What was wrong.** RFC 2812 5.2: `461 ERR_NEEDMOREPARAMS "<client> <command> :Not
enough parameters"`. All 29 `reply_refused()` sites passed `NULL, 0` for the middle
parameters, so `<command>` was absent from every one and the wire read:

```
:alice JOIN
:irc.test 461 alice :Not enough parameters
```

**Symptom, as recorded in Phase 11.** A client that echoes "wrong parameters for
*WHICH* command" cannot. Several clients parse 461's first middle parameter to
attribute the error; they got the trailing text where the command should be.

**Why Phase 11 did not change it, and why that was correct then.** The existing
tests asserted the current bytes, and correcting a conformance defect by correcting
the assertions that pin it is a decision with an owner, not a judgement call. Phase
11's own count of the damage was also **wrong**, which is worth recording because the
next reader would otherwise trust it: it said *"nine assertion sites across seven
files"*. The real figure is **eighteen sites across ten files** —
`test_account.c` ×1, `test_choper.c` ×4, `test_invite.c` ×2, `test_knock.c` ×2,
`test_messaging.c` ×2, `test_nick_rule.c` ×1, `test_serverinfo.c` ×1,
`test_standard_replies.c` ×3, `test_userhost.c` ×2. Phase 11 found the two examples it
named and generalised from them.

**What Phase 11b did, and the shape it chose.** The fix is in `reply_refused()`, not
at the 29 call sites: `command` is already an argument to that function and is already
used on the `FAIL` branch, so the value was present at exactly the point where the
legacy line was rendered and simply was not used. Three things bound it:

- **The legacy branch only.** A `FAIL` already carries `command` as its own required
  `<command>`, so prepending there would render
  `FAIL PRIVMSG PRIVMSG NEED_MORE_PARAMS …`.
- **461 only.** `451` has no `<command>` field and does not even route through
  `reply_refused()`; `462` and `464` have trailing text only; `482`'s field is the
  channel, which its callers already pass. `numeric_carries_command()` in `reply.c`
  names all four so the rule cannot drift into "every refusal names the verb".
- **A NULL or empty `command`, or a mid list already at `REPLY_MAX_MID`, falls
  through unchanged.** A refused reply is silence, and silence is the failure mode
  these numerics exist to prevent — reached by trying to be more conformant.

**On case and NULL.** Neither is reachable and both are guarded anyway. `message.c`'s
parser upper-cases the command word and `lookup()` compares with `strcmp`, so a
dispatch only succeeds on the exact uppercase spelling — which means the field is
byte-identical to what the client sent and cannot be NULL. The guards exist so that
property stays a fact about the callers rather than a hazard of the function.

**The tests, and why correcting eighteen needles was not enough.** All eighteen now
name the verb. That alone would not have caught the defect it fixes, and would not
catch it again: a needle of `461 alice :Not enough parameters` has no room for the
missing field, and a needle of `461 alice PRIVMSG :…` passes against a node that
**hardcoded** `PRIVMSG` — the same defect wearing a hat. So
`tests/integration/test_numeric_arity.c` is new and asserts the **field list**:
twenty-two probes over seventeen verbs, each decomposed into RFC 1459 2.3 fields and
checked positionally; `451` asserted to have three parameters; `482` asserted to keep
its channel as the field after `<client>`; a `standard-replies` client asserted to
carry the verb exactly once; one 461 per probe, counted.

### 6.4 `464` is not `ERR_PASSWDMISMATCH` for `CHOPER` or `AUTHENTICATE`

RFC 2812 5.1: `464 ERR_PASSWDMISMATCH — ":Password incorrect"`. This node uses 464
for three unrelated refusals: a `CHOPER` that cannot succeed (no operator model) and
two `AUTHENTICATE` failures. A client that maps 464 to "your password was wrong"
will tell a user their password was wrong when they used a correct one against a
server that has no operators.

**Symptom.** Only reachable by a client that sends `CHOPER` — which no real client
does, because `CHOPER` is this node's own non-RFC verb — or by a SASL client whose
AUTHENTICATE fails, and SASL's own error signalling carries the code. A client that
negotiated `standard-replies` gets `ERR_NOPRIVILEGES` / `ERR_AUTHENTICATIONFAILED`,
which is right.

**Why not changed.** The conventional mapping for this node's own verb is 481 (see
§6.7) and changing 464 to 481 would put it in the middle of a family this node uses
461 for. It is a mapping choice with no real client depending on it, and it is
recorded rather than churned.

### 6.5 `472` sent `<channel>` where the RFC sends `<char>` — FIXED in Phase 11b

**What was wrong.** RFC 2812 5.2: `472 ERR_UNKNOWNMODE "<client> <char> :is unknown
mode char to me for <channel>"`. Both sites sent `ch->name` as the single middle
parameter, so the channel was delivered where the character belongs and no
character was named anywhere:

```
:alice MODE #MO +k secret
:irc.test 472 alice #MO :Unknown mode character
```

**Symptom, as recorded in Phase 11.** Two, and the second is the worse one. (a) The
message named no character, so a user who mistyped `+k` was told "unknown mode
character" without being told which one. (b) A client parsing 472 by position read
`#MO` as the mode character it got wrong — it would conclude the node rejected the
sigil `#`.

**Why Phase 11 did not change it.** The same reason as §6.3, and the same shape of
problem: three assertion sites pinned the current bytes (`test_channels.c` ×2,
`test_serverinfo.c` ×1). That count was **correct**.

**What Phase 11b sends.** RFC 1459 4.4's sentence, which puts the channel in the text
and is the better of the two available wordings because it is the only one that
leaves the channel in the line at all:

```
:alice MODE #MO +k secret
:irc.test 472 alice k :is unknown mode char to me for channel #MO
```

**On the two sites.** They keep the same shape and the same comment rather than
sharing a helper, because the character is a different *expression* at each —
`m->params[1][0]` at the first (the byte that is neither `+` nor `-`) and the loop
variable `mode` at the second, one byte of a string like `+oks` — and what must not
vary between them is the field list. Each gets a `char[2]` because `message_format()`
refuses a value it cannot represent in a non-final position, and a bare `char` would
be one past the end of an object rather than a NUL-terminated string.

**The tests.** The three needles are corrected, and that alone was not enough: the old
needle had the channel in the same wrong slot, so it could not fail on a field-list
error. `expect_472_fields()` in `test_channels.c` now decomposes the line into RFC
1459 2.3 fields and asserts the character by position, the text whole, and the whole
line byte for byte — **three** cases, not two, because `+s` reaches the mode-loop
site and the first two never did.

### 6.6 No ban-mask validation, so `476` cannot happen

`MODE #c +b totalgarbage` is accepted, echoed, stored and enforced. RFC 2812 5.1
defines `476 ERR_BADCHANMASK — "<channel> :Bad Channel Mask"` for exactly this.

**Symptom.** A moderator who types a mask with a typo gets a ban that matches nothing,
and no indication of it. `chan_banned()` matches the stored string against nick,
host and the composite `nick!user@host`, so a malformed mask is a mask that matches
almost nothing — the failure is silent in the way this node tries hard not to be.

**Why not changed.** A mask validator is new code and new judgement (which
characters, which shapes, how much of RFC 2812 2.3.2's rather loose grammar), not a
conformance fix to a numeric this node emits. §8 lists it as the candidate.

### 6.7 `481` is absent; the "not privileged" family answers 482 and 464

RFC 2812 5.1: `481 ERR_NOPRIVILEGES — ":Permission Denied- You're not an IRC
operator"`. This node has no operator model, and refuses privilege with `482`
(channel operator, with the channel named — which is correct for KICK and MODE) and
`464` for `CHOPER`.

**Symptom.** A client whose "you must be an IRC operator" handling keys on 481 will
not recognise the refusal. Only a client that sends `CHOPER`, which is not an RFC
command, can reach it.

### 6.8 `501` and `502` are unreachable

They are RFC 2812's answers for a bad user-mode flag and for changing another user's
modes. This node never evaluates a user mode and never gets past 403 on the way
(§6.1), so neither can arise.

**Symptom.** Same as §6.1 — one symptom, three numerics that would fix it.

### 6.9 `VERSION` is not a command

RFC 2812 3.4.3: "The VERSION message is used to request a list of the current
version of the server." It is in the RFC's MUST-implement section. A client that
runs `/VERSION` gets `421 VERSION :Unknown command`.

**Symptom.** This is the one absence in this table that reads as a gap rather than
as a decision. Several clients send `VERSION` on connect to identify the server, and
the answer they get is an error. It is cheap to fix — one verb, one 351, and 002
already carries the version string — and it is not fixed here because it is a new
command, not a conformance repair.

### 6.10 `TIME`, `PING` and `VERSION` are handled as commands; CTCP is not

`PING` is a command and echoes its token verbatim (verified in
`test_query_surface.c`). `TIME` and `VERSION` are not commands, so §6.9's 421
applies to both.

**CTCP is a different question and the answer is N/A.** RFC 2812 defines no CTCP
numerics and no CTCP command: `\x01VERSION\x01` inside a PRIVMSG is *client*-to-
*client*, relayed verbatim, and this node relays it verbatim. A client that sends
CTCP `PING` to a nick is asking the *user* to answer, not the server, and a server
that answered would be impersonating a user. A client that sends CTCP `VERSION` to a
channel and gets no reply sees a timeout, which is the normal outcome for an
unanswered CTCP and not a protocol fault.

### 6.11 `366` has no `<channel>` when `NAMES` is asked with no argument and there are no channels — FIXED in Phase 11c

**What was wrong.** RFC 2812 5.2: `366 RPL_ENDOFNAMES "<client> <channel> :End of /NAMES list"`. Three of
this node's four `366` sites go through `send_end_of_names()` and name the channel
correctly. The fourth did not: `NAMES` with **no argument** on a node with **zero
channels** took a short-circuit that called `reply()` directly with `NULL, 0`:

```
:alice NAMES
:irc.test 366 alice :End of /NAMES list
```

**Symptom.** A client building its channel list from a bare `NAMES` closes it on 366
and has no channel name to label the window with. Every other 366 on this node — for
`NAMES #x`, and for the per-channel loop of a bare `NAMES` over a non-empty node —
carries the name, so a client that reads `<channel>` finds it absent exactly once and
in the one case where there was nothing to read.

**The decision: `<channel>` is `*`, and the line is now**

```
:alice NAMES
:irc.test 366 alice * :End of /NAMES list
```

RFC 2812 **defines no value here, and saying so is the whole of the first half of the
argument.** §5.1's field list is `"<channel> :End of NAMES list"` and its own prose for
the case says only *"If there is no channel found as in the query, then only
RPL_ENDOFNAMES is returned"* — it does not say what the channel field holds. So there
is no conformance argument available and this is a decision about what a client sees.

**What a client sees, either way.** The field is where a client looks for the channel a
list belongs to, and a client that splits the line into RFC 1459 2.3 fields gets three
of them from the old line where the RFC promises four:

| | old wire form | parameters a positional client parses |
|---|---|---|
| no field | `366 alice :End of /NAMES list` | `366`, `alice`, `End of /NAMES list` |
| `*` | `366 alice * :End of /NAMES list` | `366`, `alice`, `*`, `End of /NAMES list` |

On the old line the client reads **the trailing SENTENCE** as the channel name, or, if
it bounds its read by the expected field count, gets an out-of-range default and drops
the entry. Either way it has a channel *string* where the RFC says there is a channel
*field*, and nothing on the line distinguishes "there are no channels" from "the
server sent a malformed reply" — which is the one distinction this reply exists to
carry. With `*` the line is parseable and the client can label the answer "no
channels".

**Why `*` and not the empty string.** An empty field renders
`:irc.test 366 alice  :End of /NAMES list` — a doubled space — which
`message_format()` does not produce for an empty middle parameter and which a client
reading positionally sees as a missing parameter anyway. So the empty string buys a
different spelling of the same unparseable line. `*` is one byte, contains nothing
`message_format()` refuses in a non-final position, and is RFC 1459 2.3's own wildcard,
so it is also the value the rest of the protocol already uses for "the thing asked
for, which does not exist".

**The cost, stated.** A client that builds a window per 366 may open one titled `*` on
a channel-less node. That is one cosmetic artifact on a node with no channels, against
a mislabelled or absent field on every bare `NAMES` a client ever sends. The trade is
deliberate and one-sided.

**Where the change lives.** In the helper, not at the call site: `send_end_of_names()`
is now the only renderer of a 366 on this node, so "a 366 carries its channel field"
is a property of one function rather than of four call sites plus a short-circuit. The
value is named `NAMES_NO_CHANNEL` in `chan_verbs.c` so the decision is greppable.

**The test.** Section 5 of `tests/integration/test_numeric_arity.c`, and it is a
**field-count** assertion rather than a needle, because a needle cannot see this defect:
`:irc.test 366 alice :End of /NAMES list` is not a substring of either the old line or
the new one, and a needle written as `366 alice * :` would pass a node whose field was
absent only if the needle itself were wrong. It asserts four parameters, the value `*`
by position, the whole line byte for byte, **exactly one** 366, and **no 353** — RFC
2812 5.1's "only RPL_ENDOFNAMES is returned" being a statement about both. It runs
before the first JOIN in that binary, because a bare `NAMES` on a node that *has* a
channel answers with that channel's name and the check would pass for the wrong reason.

### 6.12 `404` has no `<channel>` when the source hostmask will not render

**New in Phase 11b.** RFC 2812 5.2: `404 ERR_CANNOTSENDTOCHAN "<client> <channel
name> :Cannot send to channel"`. One site gets it right — a channel the client is not
on, with `t.name` as the field and the RFC's own sentence. One does not:

```c
if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
    (void)reply(s, c, "404", NULL, 0, "Cannot send: unrenderable source");
```

Two deviations on that line: no `<channel name>`, and a sentence that is not the
RFC's.

**Symptom.** Small, and mostly for a log reader: a client sees 404 with no channel and
a sentence it has no mapping for. Ordinary client input cannot reach it —
`conn_hostmask()` fails only on a byte RFC 1459 2.3 will not put in a prefix, and
`accept()` cannot produce one — so this is a refusal on what `reply.c` calls a bug
report.

**Why not changed.** The channel name *is* available at this point (`m->params[0]`,
the arity check has already passed), so the field could be filled — but it has not
been resolved yet, and `params[0]` may be a nickname, in which case sending it as
`<channel name>` would be a new falsehood rather than a conformant answer. Resolving
the target first would mean running `fanout_resolve()` before the prefix check, which
reorders the handler around a path that exists to catch an internal fault. The
sentence could be aligned with the RFC's independently, but that leaves the line still
missing its field, so half a fix would be a cosmetic half. It needs the target-kind
decision, not a string edit.

### 6.13 `482` has no `<channel>` for `REGISTER` and `UNREGISTER`

**New in Phase 11b.** RFC 2812 5.2: `482 ERR_CHANOPRIVSNEEDED "<client> <channel>
:You're not channel operator"`. Four sites name `ch->name` and are conformant. The
fifth is `account_refuse()`, which answers a refused `REGISTER` or `UNREGISTER`:

```c
(void)reply_refused(s, s, c, verb, "ERR_ACCOUNTREGISTRATIONDISABLED", "482", NULL, 0,
                    "%s", text);
```

**Symptom.** A client that keys "you are not a channel operator" on 482 shows that
message for a `REGISTER` that was refused because the deployment has no open
registration — which is a different fact, and one the client's wording gets wrong in
a way that sends a user looking for a channel.

**Why not changed.** There is no channel to name: neither verb has one, and the
condition is not about a channel at all. So the honest options are §6.7's `481` — which
is absent because this node has no operator model — or `461`, which is what §6.2's
neighbouring choices do and which would be as wrong in a different way. `account_refuse()`
already passes its code as an override, so the fix is one argument; **which** argument
is the decision §6.7 has not made, and closing §6.13 without it would close it wrongly.
A client that negotiated `standard-replies` gets
`FAIL REGISTER ERR_ACCOUNTREGISTRATIONDISABLED`, which is correct and is the reason
this is a compatibility question rather than a correctness one.

### 6.14 `366`'s trailing text is "End of /NAMES list"; the RFC's is "End of NAMES list"

**New in Phase 11c, found while fixing §6.11, and recorded rather than changed.** RFC
2812 5.1 writes `366 RPL_ENDOFNAMES "<channel> :End of NAMES list"` — no forward slash.
This node sends `"End of /NAMES list"`, which is the spelling RFC 1459 2.3.1's prose
uses and the one clients' own strings are built from.

**Symptom.** Only for a reader of decoration: every client dispatches on the numeric
and reads the middle parameters by position, so nothing parses 366's trailing text. A
human or a log parser that anchors on the RFC's literal would not match.

**Why not changed here.** It is a one-line change with **no test churn that does not
churn** — thirteen assertion sites across `test_channels.c`, `test_userhost_in_names.c`
and `test_fed_burst.c` pin these bytes, and the correct text is a compatibility
question about which spelling clients' string tables carry, not a conformance repair.
Phase 11b's own reasoning for `317`'s trailing text (§5.2) applies almost verbatim and
is recorded there: the trade is a hypothetical reader of decoration against a concrete
reader who matches it, and here the concrete reader is the RFC's own literal. It
belongs to whoever reads this next, with the decision stated rather than assumed.

## 7. `005` completeness

Eleven tokens are emitted. Checked against what a modern client parses, and against
the eight documented absences:

| Token | Present | Note |
|---|---|---|
| `NETWORK` | ✓ | |
| `CHANTYPES=#&` | ✓ | Many real clients misbehave without it. |
| `PREFIX=(ov)@+` | ✓ | And without it. |
| `CASEMAPPING=ascii` | ✓ | True, and not a detail: `message.c`'s `up()` is ASCII-only, so `[]\~` and `{}|^` are **not** equivalent on this node. Advertising `rfc1459` would be a lie a client could act on. |
| `AWAYLEN`, `CHANNELLEN`, `KICKLEN`, `LINELEN`, `NAMELEN`, `NICKLEN`, `TOPICLEN` | ✓ | Each derived from the constant that **refuses** the over-long value, so raising a bound moves the token with it. `MAXTARGETS=1` matches `MSG_MAX_TARGETS`. |
| `BOT` | absent | Correct. No services, no bot accounts; nothing on this node would ever set a bot flag. |
| `EXTCBAN` | absent | Correct. The node has no extended ban mechanism, so there is no syntax to advertise. |
| `SAFELIST` | absent | Correct, and it is a claim this node can make. Channel ban lists are readable by any member (§5 of `send_ban_list()`) and there are no hidden channels. |
| `MONITOR` | absent | Correct. No MONITOR command; 421. |
| `MSGREFTYPES` | absent | Correct. No message-reference tags are parsed or emitted. |
| `ACCEPT` | absent | Correct. No ACCEPT. |
| `silence` | absent | Correct. No +s mode; `MODE #c +s` is 472. |
| `draft/CHATHISTORY` | absent | Correct, and separately **refused on design grounds**: history is a client-side store, and a server-side one would have to answer for what a client missed while disconnected. `docs/SPEC_TRACKING.md` §10.17 carries the full argument. |

Every one of the eight is still accurately absent. Three of them — `SAFELIST`,
`EXTCBAN`, `silence` — are absences this node could *earn* if a future phase adds
hidden channels, extended bans, or `+s`; they are correct now because the
corresponding features do not exist.

## 8. Behaviours the sweep found and deliberately did not change

Four, recorded because they are places where a client can be told something and a
reader of the code should know it is deliberate.

- **No per-client channel limit.** A client can join unboundedly many channels; the
  only bound is the descriptor table. `405 ERR_TOOMANYCHANNELS` is therefore
  unreachable, and is correctly absent. 005 advertises no `MAXCHANNELS`, which is
  the honest disclosure.
- **A second `JOIN` to a channel you are on re-answers and says nothing.** No 443.
  Idempotent, and the alternative would make a client's own reconnect path noisy.
- **A `JOIN` key argument is accepted and ignored.** `JOIN #chan <key>` is
  grammatical per RFC 2812 3.3.1; since `+k` is never evaluated there is no key to
  check it against, so 475 cannot arise.
- **Ban masks are not validated.** §6.6. `+b` is the one channel mode this node
  evaluates, and it evaluates the mask as an opaque string.

## 9. `436` and the duplicate-nickname policy

RFC 2812 3.3.4 defines `436 ERR_NICKCOLLISION` as the reply when a nickname
collision causes a server to KILL. This node does not KILL.

- On one node, `server_nick_claim()` is a lookup-and-insert: the loser never
  displaces the holder, nothing writes to the holder's connection, and the loser is
  answered **433** — which is the right numeric for "the name you asked for is
  taken", and what a client expects from a client-initiated `NICK`.
- On a mesh, `fed_nickreg_resolve_local()` renames the local loser without a 436 and
  without a KILL, and the policy converges because *both* nodes run the same
  function against the same two names.

So 436 is absent by design rather than by omission. The cost, stated: a node
watching a peer KILL a user for a collision sees something this node never does,
and an operator debugging a mesh has one fewer numeric to look for.

## 10. What changed, in one place

### 10.1 Phase 11

| Change | Kind | Test |
|---|---|---|
| `319 RPL_WHOISCHANNELS` added to `WHOIS` | the confirmed defect | `test_whois_channels.c` §1, §2 |
| `367`/`368` for `MODE #chan ±b` with no mask | gap with a client-visible symptom | `test_banlist.c` §2–§4 |
| `478` replaces `696` for a full ban list, with the RFC's `<char>` field | wrong numeric + wrong arity | `test_banlist.c` §5 |
| `CHAN_MAX_BANS` enforced in `chan_ban_add()` | documented bound was false | `test_banlist.c` §5 |
| `254` sent when the channel count is non-zero | required by 3.4.2, never sent | `test_query_surface.c` §1, §2 |
| `317`'s trailing text left at the RFC's literal string, argued at the call site | a decision, recorded | — |
| `msg_verbs.c`'s USERHOST comment corrected: `MODE <nick>` is 403, not 472 | a doc claim the sweep falsified | — |

### 10.2 Phase 11b

| Change | Kind | Test |
|---|---|---|
| `461` sends its `<command>` field, from `reply_refused()` rather than from 29 call sites | arity — §6.3 | eighteen corrected needles, plus the new `test_numeric_arity.c` (field-list, 22 probes over 17 verbs, plus `451`, `482` and the `FAIL` branch) |
| `472` sends the mode character as its middle field and names the channel in RFC 1459 4.4's sentence | arity — §6.5 | three corrected needles, plus `expect_472_fields()` in `test_channels.c` (positional, three cases) |
| §1's 84/53/23 split corrected from "130 in 5.1 and 30 in 5.3" | this document was wrong | §1.1 |
| `303`'s arity recorded — Phase 11 marked it `✓` | this document was wrong | §5.1 |
| `324`'s trailing parameter recorded — and Phase 11's justification for it retracted | this document was wrong | §5.4 |
| `366`, `404`, `482` rows corrected from `✓` — each has one non-conformant site | this document was wrong | §6.11, §6.12, §6.13 |
| §6's count corrected from "eight" to thirteen, and from "None was changed" | this document was wrong | §6 |
| §2's "fifty-nine rows" corrected to sixty, one of them a §4 numeric | this document was wrong | §2 |
| Phase 11's count of `461`'s assertion damage corrected from nine sites to eighteen | this document was wrong | §6.3 |

**The pattern is the point, and it is stated rather than buried.** Eight of the ten
corrections above are to *this document*, not to `src/` — the two code changes are the
first two rows and everything else is a claim this file made that turned out to be
wrong. Phase 11 read six source
files carefully and wrote 596 lines about them; Phase 11b parsed 176 call sites
against the RFC's own text and found that the table's `✓` column was wrong in five
places, its counts were wrong in four, and two of its deviation justifications did
not hold. Every `✓` in §2 is now backed by a mechanical arity comparison rather than
by a reading, which is the only reason to expect the column to survive the next
phase.

### 10.3 Phase 11c

| Change | Kind | Test |
|---|---|---|
| `366` sends `<channel>` = `*` on a channel-less node, through `send_end_of_names()` | field list — §6.11 | `test_numeric_arity.c` §5 (field count, `*` by position, whole line, one 366, no 353) |
| `303` sends the nick list as ONE trailing parameter, RFC 2812 5.1's shape | field list — §5.1 | nine corrected needles; `test_queries.c`'s chunking probe rebuilt around a 15 × 63-byte ISON, with per-chunk shape and whole-window name count |
| `reply_colon()` added: `reply()` with the trailing text always colonned | the mechanism §5.1 needs | the one-nick 303 needles, in `test_queries.c` and `test_nick_case.c` |
| `302`'s duplicated middle parameter recorded | this document was wrong — §5.1 | — |
| `366`'s trailing text recorded as a deviation | **new finding** — §6.14 | — |

## 11. What this document does not claim

- **It is not a claim of full conformance.** Fourteen findings are recorded in §6 —
  ten open, four fixed — and the deviations in §5; a server with all of them
  closed would still not be conformant to RFC 2812 section 3's "All commands
  described in this section MUST be implemented", which this node departs from
  deliberately in the operator, TRACE, STATS and diagnostics families.
- **The mechanical check verified arity, not sense.** §1.1 says what it can and
  cannot see. It compared *how many* middle parameters reach the wire against *how
  many* the RFC's field list names. It did not check that the values are right, that
  the text is the RFC's, or that the numeric answers the question being asked —
  which is why §5 and §6 are judgement and not output.
- **It does not claim the count in §1 stays right.** Nothing in CI reads this file,
  so a numeric added later does not decrement the "absent" figure. §1.1's method is
  written down so the next sweep can re-run it rather than re-derive it; what it
  cannot do is notice on its own.
- **It says nothing about numerics RFC 2812 does not define.** §4 covers the eight
  this node emits and the de-facto names they come from. The wider registry (the
  ISUPPORT `draft/` tokens, the `005` extensions other servers send) is out of
  scope and §7 is the boundary.
- **The "Here" column is about emission, not correctness.** A numeric marked `E` is
  emitted; whether its field list is right is the last column's job and, where the
  answer is "no", §5 or §6 says so. Nine rows are `E` and deviate in some way:
  `256`, `302`, `317`, `324`, `368`, `432` in §5, plus `366` (its trailing text,
  §6.14) and `482`, whose field-list deviation is one site out of several and is in
  §6. `303` was on that list until Phase 11c and is not any more.
- **It is a snapshot of `src/` at this commit.** A numeric added in a later phase
  does not appear here, and the check-skips and CI gates do not read this file — a
  stale row is invisible to the build.
