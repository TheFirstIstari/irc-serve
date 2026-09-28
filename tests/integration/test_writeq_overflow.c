/* test_writeq_overflow.c -- the bounded queue drops the saturated connection
 * and nobody else.
 *
 * docs/SERVER_DESIGN.md 3.4: "Bounded write queues, ~256 KB per connection. A
 * saturated peer link is dropped, not buffered." Two properties are being
 * tested and they are different, which is why this is not the same test as
 * test_partial_write:
 *
 *   a) exceeding the cap does not grow the queue and does not block. The
 *      append is REFUSED, the connection is marked CLOSING, and the reaper
 *      closes it at the next fixed point.
 *   b) the drop is SCOPED. A second connection on the same node keeps working
 *      afterwards, before and after the flooder is reaped. "We dropped
 *      something" is not the requirement; "we dropped exactly the saturated
 *      connection" is.
 *
 * As in test_partial_write, Phase 2 has no command surface, so what each client
 * gets back is supplied through the dispatch seam 3.3 defines. Everything under
 * test -- the cap arithmetic, the refusal, the CLOSING mark, the reap, and the
 * isolation of the registry -- is production code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 30000

/* Two chunks that together exceed the 256 KB cap. The first is under it, so the
 * refusal is specifically the SECOND append crossing the bound rather than a
 * single append that is too large to ever fit. */
#define CHUNK_BYTES (200u * 1024u)
#define CHUNK_FILL 0x5a

/* The survivor's marker. Each OK line produces the next numbered one, so the
 * second marker can only arrive from a line parsed AFTER the flooder was
 * dropped -- which is what makes "the other client still works" a claim about
 * a later moment rather than a leftover from before. */
static int g_ok_count = 0;

static void overflow_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    char *chunk;
    const char *cmd = (m->command != NULL) ? m->command : "";

    if (strcmp(cmd, "FLOOD") == 0) {
        chunk = (char *)malloc(CHUNK_BYTES);
        if (chunk == NULL) {
            return;
        }
        memset(chunk, CHUNK_FILL, CHUNK_BYTES);
        /* Under the cap: accepted. */
        TF_CHECK_MSG(server_queue(s, c, chunk, CHUNK_BYTES) == 0,
                     "the first %u byte append should be under the cap",
                     CHUNK_BYTES);
        /* Over the cap: refused, connection marked CLOSING, counter bumped.
         * Nothing is buffered and nothing blocks. */
        TF_CHECK_MSG(server_queue(s, c, chunk, CHUNK_BYTES) != 0,
                     "the second %u byte append should exceed the 256 KB cap",
                     CHUNK_BYTES);
        TF_CHECK_MSG(c->state == CONN_CLOSING,
                     "an over-cap append must mark the connection CLOSING, "
                     "not close it: state=%d", c->state);
        TF_CHECK_MSG(c->fd >= 0,
                     "the send path must not have closed the descriptor");
        free(chunk);
        printf("[fixture] flooded fd=%d pending=%zu\n", c->fd,
               conn_write_pending(c));
        fflush(stdout);
        return;
    }

    if (strcmp(cmd, "OK") == 0) {
        char line[128];
        int n;

        g_ok_count++;
        n = snprintf(line, sizeof line,
                     ":irc.fixture NOTICE ok :ALIVE-%d\r\n", g_ok_count);
        TF_CHECK(n > 0 && (size_t)n < sizeof line);
        TF_CHECK_MSG(server_queue(s, c, line, (size_t)n) == 0,
                     "the survivor's marker was refused");
        (void)conn_pump(c);
        return;
    }
}

static void setup(server_t *s)
{
    s->dispatch = overflow_dispatch;
}

int main(void)
{
    nf_node_t node;
    test_client_t flooder;
    test_client_t survivor;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    /* The survivor connects FIRST, so it is already established when the
     * flooder is dropped. A drop that took the node down, or that closed the
     * wrong slot, shows up immediately. */
    tc_init(&survivor);
    TF_CHECK_MSG(tc_connect(&survivor, node.port) == 0, "survivor connect");
    TF_CHECK_MSG(tc_send(&survivor, "OK") == 0, "survivor send");
    TF_CHECK_MSG(tc_expect(&survivor, "ALIVE-1", T_IO_MS) == 0,
                 "survivor did not get its first marker");

    tc_init(&flooder);
    TF_CHECK_MSG(tc_connect(&flooder, node.port) == 0, "flooder connect");
    TF_CHECK_MSG(tc_send(&flooder, "FLOOD") == 0, "flooder send");

    /* The refusal is recorded, which is what "record it" in 3.4 means. */
    TF_CHECK_MSG(nf_expect(&node, "writeq_overflow", T_IO_MS) == 0,
                 "the node never reported a write-queue overflow");

    /* The flooder is dropped. A clean FIN, not a reset. */
    {
        int rc = tc_expect_eof(&flooder, T_IO_MS);

        TF_CHECK_MSG(rc == 0, "the flooded connection: expected a clean EOF, "
                     "got rc=%d (-3 is RST, -1/-2 timed out)", rc);
    }

    /* The survivor is untouched: the queue never refused for it, its
     * descriptor was never closed, and it still parses lines and gets answers
     * now that the flooder is gone. */
    TF_CHECK_MSG(tc_send(&survivor, "OK") == 0, "survivor second send");
    TF_CHECK_MSG(tc_expect(&survivor, "ALIVE-2", T_IO_MS) == 0,
                 "the surviving connection stopped working after the flooder "
                 "was dropped: it never got its second marker");

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "writeq_overflow=", 1, T_IO_MS) == 0,
                 "writeq_overflow should be 1: exactly one append was refused");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 2, T_IO_MS) == 0,
                 "accepted should be 2");
    /* Both connections are gone, and exactly one overflow: the survivor was
     * closed by the shutdown reap, not by the cap. */
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 2, T_IO_MS) == 0,
                 "closed should be 2");

    tc_close(&flooder);
    tc_close(&survivor);
    nf_free(&node);
    tf_done("writeq_overflow");
    return 0;
}
