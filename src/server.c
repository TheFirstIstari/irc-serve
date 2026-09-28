/* Federated IRC server core
 *
 * server_init() intentionally does NOT simulate a peer response: it prepares
 * the protocol parser and arms the LOCAL side of the federation handshake
 * (INIT -> HANDSHAKE_SENT). The handshake context is caller-owned (static to
 * this module, single-thread, single-owner); it is only advanced to
 * ESTABLISHED by a genuine peer acknowledgement at runtime. This module
 * performs no memory-footprint/RSS accounting (see tests/benchmark for real
 * process measurement). */
#include <stddef.h>
#include <stdio.h>

#include "server.h"
#include "protocol_parse.h"
#include "federation_handshake.h"

/* Caller-owned handshake context: lives for the lifetime of the server core,
 * used from a single thread only. */
static handshake_ctx_t srv_handshake;

void server_init(void) {
    int handshake_rc = 0;
    int parsed = 0;
    int token_count = 0;
    int error_code = 0;

    printf("[observable] server core initializing...\n");

    /* Mode the local handshake: INIT -> HANDSHAKE_SENT. The peer has not yet
     * acknowledged, so state is HANDSHAKE_SENT, not ESTABLISHED. */
    handshake_init(&srv_handshake);
    handshake_rc = handshake_send(&srv_handshake);
    if (handshake_rc != 0) {
        printf("[observable] server_init: handshake_send failed (rc=%d)\n", handshake_rc);
        return;
    }
    printf("[observable] federation handshake armed: state=%d (local, awaiting peer ack)\n",
           (int)handshake_state(&srv_handshake));

    /* Prepare the protocol parser; do not claim readiness if it cannot parse. */
    parsed = parse_command("PING", &token_count, &error_code);
    if (parsed != 0) {
        printf("[observable] server_init: protocol parser prepare failed (rc=%d errors=%d)\n",
               parsed, error_code);
        return;
    }
    printf("[observable] protocol parser prepared: tokens=%d errors=%d\n",
           token_count, error_code);

    printf("[observable] server_init completed: initialized=1 "
           "handshake_state=%d (registered; federation pending peer ack)\n",
           (int)handshake_state(&srv_handshake));
}