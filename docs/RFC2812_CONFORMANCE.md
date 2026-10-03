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

RFC 2812 section 5 defines **160** distinct numerics: 130 in 5.1 (command
responses) and 30 more in 5.3 (reserved, obsolete, or specific to one server's
non-generic features). Of those 160:

| | Count |
|---|---|
| **Emitted on this node** | **59** |
| Absent, and the absence is correct for this design | 91 |
| N/A — in RFC 2812 5.3 only, with no role on any server | 10 |
| **Defined in RFC 2812 and not accounted for** | **0** |

RFC 2812 5.3 prints `244` twice (RPL_STATSHLINE and RPL_STATSSLINE), which is a
typo in the RFC rather than two numerics; it is counted once.

This node also emits **eight** numerics RFC 2812 does not define, all of them
de-facto or IRCv3. They are in [§4](#4-numerics-this-node-emits-that-rfc-2812-does-not-define).

Every row below is one of those four. There is no fifth category, and a numeric
with no row is a gap in this document rather than in the node — which is the one
failure mode a table like this has, and the reason the last column is mandatory.

## 2. Emitted, and conformant in field list

Fifty-nine rows here; the eight numerics this node emits that RFC 2812 does not
define are in §4. A `✓` in the last column means the field list was checked against
the RFC and matches; where it does not, the row says so and the numeric appears
again in §5 or §6.

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
| 302 | RPL_USERHOST | `:<reply>` (one per nickname) | E | **deviation** — see §5.1. |
| 303 | RPL_ISON | `:<nick> *( " " <nick> )` | E | Chunked at `REPLY_MAX_MID`; RFC 1459 2.4.3 anticipates the split. |
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
| 324 | RPL_CHANNELMODEIS | `<channel> <mode> <mode params>` | E | Channel and mode are middle parameters; there are no mode params, and the trailing text is the RFC's free `<text>`. |
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
| 366 | RPL_ENDOFNAMES | `<channel> :End of /NAMES list` | E | ✓ Always last. |
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
| 404 | ERR_CANNOTSENDTOCHAN | `<channel name> :Cannot send to channel` | E | ✓ |
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
| 461 | ERR_NEEDMOREPARAMS | `<command> :Not enough parameters` | E | **deviation** — the `<command>` field is absent. See §6.3. |
| 462 | ERR_ALREADYREGISTRED | `:Unauthorized command (already registered)` | E | ✓ |
| 463 | ERR_NOPERMFORHOST | `:Your host isn't among the privileged` | A | No host-based connection restriction. |
| 464 | ERR_PASSWDMISMATCH | `:Password incorrect` | E | **deviation** — see §6.4. |
| 465 | ERR_YOUREBANNEDCREEP | `:You are banned from this server` | A | No node-level ban list and no KILLLINE. |
| 466 | ERR_YOUWILLBEBANNED | — | A | Reserved by RFC 2812 5.3; same reasoning as 465. |
| 467 | ERR_KEYSET | `<channel> :Channel key already set` | A | `+k` is advertised in 004 and **not evaluated** — it is refused with 472 by name — so no key can ever be set. |
| 471 | ERR_CHANNELISFULL | `<channel> :Cannot join channel (+l)` | A | `+l` is advertised and not evaluated, so no channel can be full. |
| 472 | ERR_UNKNOWNMODE | `<char> :is unknown mode char to me for <channel>` | E | **deviation** — the node sends `<channel>` where the RFC sends `<char>`, and names no mode character at all. See §6.5. |
| 473 | ERR_INVITEONLYCHAN | `<channel> :Cannot join channel (+i)` | A | `+i` is advertised and not evaluated. |
| 474 | ERR_BANNEDFROMCHAN | `<channel> :Cannot join channel (+b)` | E | ✓ `+b` is the one channel mode this node evaluates. |
| 475 | ERR_BADCHANNELKEY | `<channel> :Cannot join channel (+k)` | A | `+k` is advertised and not evaluated. A `JOIN #chan <key>` argument is accepted and ignored. |
| 476 | ERR_BADCHANMASK | `<channel> :Bad Channel Mask` | A | **No mask validation.** `MODE #c +b <anything ≤63 bytes>` is stored and enforced. See §6.6. |
| 477 | ERR_NOCHANMODES | `<channel> :Channel doesn't support modes` | — | The node does support channel modes (`b`, and the prefix modes `o`/`v`). |
| 478 | ERR_BANLISTFULL | `<channel> <char> :Channel list is full` | E | **Added in Phase 11**, replacing 696. Both middle parameters. |
| 481 | ERR_NOPRIVILEGES | `:Permission Denied- You're not an IRC operator` | A | **deviation** — see §6.7. |
| 482 | ERR_CHANOPRIVSNEEDED | `<channel> :You're not channel operator` | E | ✓ |
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
| 417 | ERR_INPUTTOOLONG | ircdocs / ircd practice | Not in RFC 2812 or RFC 1459. Used for every over-long parameter: AWAY, PRIVMSG, SETNAME, KICK reason, TOPIC, channel name. 3.2 forbids delivering a silently shortened parameter, so *something* has to be said, and this is what clients already understand. A client that negotiated `standard-replies` gets `FAIL … ERR_INPUTTOOLONG` instead. |
| 908 | RPL_SASLMECHS | IRCv3 `sasl` | `<mechs> :are available SASL mechanisms`. |

## 5. Deviations: emitted, and not quite the RFC

Five. Four are defensible and argued at the call site; the fifth is open.

### 5.1 `302` uses `nick+user@host`, not the RFC's `nick=+/user@host`

RFC 2812 5.1 writes the reply string as `nickname [ "*" ] "=" ( "+" / "-" )
hostname`. **Every deployed server writes `nick+user@host` and `nick*user@host`**, and
every client parses that. Answering the RFC's literal form would be a different
shape from what clients expect, for a numeric whose entire purpose is the shape.
Deviation kept; the RFC's spelling is a known erratum in practice.

### 5.2 `317` carries two numbers where the RFC's field list has one

RFC 2812 5.1: `<nick> <integer> :seconds idle`. This node sends
`<nick> <idle> <signon> :seconds idle`. See the call site for the full argument.
Short version: 317 is the only place a WHOIS reply carries a timestamp at all, the
two-number form is what clients parse, and `<signon>` had to be a *parameter*
rather than part of the sentence because 3.2 will not format a number into a
non-final position — so the trailing text stays exactly where the RFC puts it.

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
nothing here, because it was not building a list from this line.

### 5.4 `432` puts the nickname in the trailing text

Forced, and argued at the call site. An illegal nickname may be empty, may start
with `:`, or may hold a space; 3.2's formatter **refuses** a value that cannot be
represented in a non-final position rather than reshaping it, so a middle parameter
would turn a nickname refusal into a `reply_refused` counter bump — a bug report
from ordinary client input. The trailing parameter is always representable.

### 5.5 `256` puts the server name in the sentence

RFC 2812 5.1: `<server> :Administrative info`. This node: `:Administrative info`,
with the server name in the message prefix. Free text, and the value is redundant
with the prefix.

## 6. Open findings: this phase did not change these

Eight. Each is a real deviation with a named client-visible symptom. **None was
changed**, and the reasons are stated individually — this is the list the next
phase should read first.

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

### 6.3 `461` omits the `<command>` field

RFC 2812 5.1: `<command> :Not enough parameters`. This node sends
`:irc.test 461 alice :Not enough parameters` — **no command word**. Every one of its
~30 call sites passes `NULL, 0` for the middle parameters.

**Symptom.** A client that echoes "wrong parameters for *WHICH* command" cannot.
Several clients parse 461's first parameter to attribute the error; they get the
trailing text where the command should be.

**Why not changed.** This is the highest-value fix in the document and it was left
alone for a specific reason: **the existing tests assert the current bytes.** Nine
assertion sites across seven files pin `:irc.test 461 <nick> :Not enough parameters`
(`test_knock.c` ×2, `test_messaging.c` ×2, `test_invite.c` ×2,
`test_standard_replies.c` ×3, `test_account.c` ×1). Correcting the arity means
correcting all of them. See the handoff: this is the one decision the architect
needs to make.

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

### 6.5 `472` sends `<channel>` where the RFC sends `<char>`

RFC 2812 5.1: `472 ERR_UNKNOWNMODE — "<char> :is unknown mode char to me for
<channel>"`. **The `<char>` is a middle parameter and the channel is named in the
text.** This node sends the channel as the middle parameter and names no mode
character:

```
:alice MODE #MO +k secret
:irc.test 472 alice #MO :Unknown mode character
```

**Symptom.** Two, and the second is the worse one. (a) The message names no
character, so a user who mistyped `+k` is told "unknown mode character" without
being told which one. (b) A client parsing 472 by position reads `#MO` as the mode
character it got wrong — it will now believe the node rejected the sigil `#`.

**Why not changed.** The same reason as §6.3, and it is the same shape of problem:
three assertion sites pin the current bytes (`test_channels.c` ×2,
`test_serverinfo.c` ×1). The fix is `<char>` as the middle parameter with the
channel in the text, i.e. `:irc.test 472 alice k :is unknown mode char to me for
channel #MO` — and RFC 1459 4.4's own wording, which puts the channel in the text,
is the better of the two available sentences.

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

## 10. What Phase 11 changed, in one place

| Change | Kind | Test |
|---|---|---|
| `319 RPL_WHOISCHANNELS` added to `WHOIS` | the confirmed defect | `test_whois_channels.c` §1, §2 |
| `367`/`368` for `MODE #chan ±b` with no mask | gap with a client-visible symptom | `test_banlist.c` §2–§4 |
| `478` replaces `696` for a full ban list, with the RFC's `<char>` field | wrong numeric + wrong arity | `test_banlist.c` §5 |
| `CHAN_MAX_BANS` enforced in `chan_ban_add()` | documented bound was false | `test_banlist.c` §5 |
| `254` sent when the channel count is non-zero | required by 3.4.2, never sent | `test_query_surface.c` §1, §2 |
| `317`'s trailing text left at the RFC's literal string, argued at the call site | a decision, recorded | — |
| `msg_verbs.c`'s USERHOST comment corrected: `MODE <nick>` is 403, not 472 | a doc claim the sweep falsified | — |

## 11. What this document does not claim

- **It is not a claim of full conformance.** Eleven numerics are recorded as open
  findings and four as deviations; a server with all of them closed would still not
  be conformant to RFC 2812 section 3's "All commands described in this section MUST
  be implemented", which this node departs from deliberately in the operator, TRACE,
  STATS and diagnostics families.
- **It does not claim the count in §1 stays right.** Nothing in CI reads this file,
  so a numeric added later does not decrement the "absent" figure. The table is a
  snapshot; §11 says so again.
- **It says nothing about numerics RFC 2812 does not define.** §4 covers the eight
  this node emits and the de-facto names they come from. The wider registry (the
  ISUPPORT `draft/` tokens, the `005` extensions other servers send) is out of
  scope and §7 is the boundary.
- **The "Here" column is about emission, not correctness.** A numeric marked `E` is
  emitted; whether its field list is right is the last column's job and, where the
  answer is "no", §5 or §6 says so. Six rows are `E (deviation)`.
- **It is a snapshot of `src/` at this commit.** A numeric added in a later phase
  does not appear here, and the check-skips and CI gates do not read this file — a
  stale row is invisible to the build.
