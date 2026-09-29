/* verbs.c -- see verbs.h. The encode side of 4.3's S-verbs. */
#include "federation/verbs.h"

#include <stdio.h>
#include <string.h>

/* The map, once, in the order 4.3 lists the client verbs rather than in the
 * order of the S-verbs, so that a reader comparing this against the design does
 * it by eye and in the same sequence. A `switch` would be the other way to do
 * it and would be worse for a table this small: it duplicates the name of every
 * verb in the source, so a typo in one arm compiles cleanly and returns the
 * wrong thing at run time, and it makes "is this verb forwarded at all" a
 * question about a switch's coverage rather than about one array. */
static const struct {
    const char *client;
    const char *sverb;
} S_VERBS[] = {
    { "PRIVMSG", "SPRIVMSG" },
    { "NOTICE",  "SNOTICE"  },
    { "JOIN",    "SJOIN"    },
    { "PART",    "SPART"    },
    { "TOPIC",   "STOPIC"   },
    /* SMODES, not 4.3's SSMODE and not the obvious SMODE. See verbs.h. */
    { "MODE",    "SMODES"   },
    { "KICK",    "SKICK"    }
};

const char *fed_sverb_for(const char *client_verb)
{
    size_t i;

    if (client_verb == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof S_VERBS / sizeof S_VERBS[0]; i++) {
        if (strcmp(S_VERBS[i].client, client_verb) == 0) {
            return S_VERBS[i].sverb;
        }
    }
    return NULL;
}

int fed_send_sverb(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *client_verb, const char *prefix,
                   const char *target, const char *text)
{
    const char *sverb;
    const char *params[2];
    char block[IRC_MAX_TAG_OVERHEAD];
    char line[IRC_MAX_LINE + 2];
    message_t m;
    size_t blen;
    size_t len;

    /* The refusals are reported, not returned quietly, for the reason every
     * other [observable] refusal in this node is: a federated node that dropped
     * a forwarded message for want of a verb name would otherwise look exactly
     * like a node whose peers were silent, and the two have opposite fixes. */
    if (s == NULL || peer == NULL || client_verb == NULL || prefix == NULL ||
        target == NULL || text == NULL) {
        printf("[observable] fed_sverb_refused: verb=%s reason=bad_args\n",
               (client_verb != NULL) ? client_verb : "?");
        return -1;
    }
    sverb = fed_sverb_for(client_verb);
    if (sverb == NULL) {
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=NO_SVERB\n",
               client_verb, target);
        return -1;
    }
    if (tags == NULL || !irc_serve_tags_valid(tags)) {
        /* 2.4's tag grammar is enforced on receipt as well, so an invalid stamp
         * here is a caller that built one wrongly rather than a hostile peer. */
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=BAD_TAGS\n",
               client_verb, target);
        return -1;
    }

    /* IRC_MAX_TAG_OVERHEAD rather than a block-specific bound, and the two
     * numbers are related in a way worth stating: 179 is the '@' plus the one
     * separating space plus the block, so the block alone is at most 177 and the
     * buffer is 179. It is the right constant to name here precisely because it
     * is the constant 3.2 derived, and a second, block-only bound would be a
     * number nobody re-derives when a value limit moves.
     *
     * irc_serve_tags_format() returns 0 for a block that does not fit, which
     * cannot happen for a tag set it just validated -- so a 0 here means the
     * buffer is not big enough, which is a bug in this file. It is still checked
     * rather than assumed, because the alternative is writing a tagless line
     * onto a peer link: a message with no origin, which every node must then
     * guess about, and which defeats loop prevention entirely. */
    blen = irc_serve_tags_format(tags, block, sizeof block);
    if (blen == 0u) {
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=TAG_BLOCK_TOO_LONG\n",
               client_verb, target);
        return -1;
    }

    params[0] = target;
    params[1] = text;
    if (message_build(&m, block, prefix, sverb, params, 2) != 0) {
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=UNBUILDABLE\n",
               client_verb, target);
        return -1;
    }
    /* The +2 and the -2 are the same arithmetic reply.c does, and for the same
     * reason: IRC_MAX_LINE counts a legal line INCLUDING its CRLF and
     * message_format() reserves a byte for its NUL, so a maximal line plus its
     * terminator plus the NUL needs two more than IRC_MAX_LINE. */
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0) {
        /* All or nothing, never a partial line: 3.2 forbids truncating a
         * parameter, and a half-written S-verb on a peer link is not a shorter
         * message but a corrupted protocol stream the peer will misparse. */
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=UNRENDERABLE\n",
               client_verb, target);
        return -1;
    }
    /* RFC 1459 2.3: CRLF. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    if (server_queue(s, peer, line, len + 2u) != 0) {
        /* Already counted and already marked CLOSING by server_queue(): a
         * saturated peer link is dropped, not buffered (3.4). Not counted again
         * here. */
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=LINK_SATURATED\n",
               client_verb, target);
        return -1;
    }
    return 0;
}
