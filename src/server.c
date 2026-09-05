/* Minimal stub: federated IRC node
 * Target spec: RFC 1459 + IRCv3 (tags, SASL, multi-prefix)
 * Memory footprint target: < 10MB base per node
 */
#include <stdio.h>

static void server_init(void) {
    printf("[irc-serve] federated node initializing...\n");
}
