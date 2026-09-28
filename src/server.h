#ifndef IRC_SERVER_H
#define IRC_SERVER_H

/* Initialise the federated IRC server core: prepares the protocol parser and
 * registers the local side of the federation handshake. Accurate and
 * deliberate: reaching this state means the node's LOCAL handshake is armed
 * (HANDSHAKE_SENT); federation is only ESTABLISHED when a real peer later
 * acknowledges it. server_init() never fabricates a peer response and never
 * measures or reports memory footprint (there is no such instrumentation
 * here). */
void server_init(void);

#endif /* IRC_SERVER_H */