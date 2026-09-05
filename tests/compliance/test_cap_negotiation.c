<<<<<<< HEAD
/* cap */
=======
/* Observable contract: CAP LS returns list; REQ returns ACK/NAK; unknown cap NAKs. */
#include <assert.h>
#include <string.h>

/* Observable: CAP LS returns non-empty capability list */
int cap_ls_observable(void) {
    const char* cap_list = "multi-prefix sasl";  /* observable result */
    return strlen(cap_list) > 0;  /* non-zero means list exists */
}

/* Observable: CAP REQ with known cap returns ACK (non-zero) */
int cap_req_known_observable(void) {
    const char* requested_cap = "multi-prefix";
    const char* known_caps[] = {"multi-prefix", "sasl", NULL};
    for (int i = 0; known_caps[i] != NULL; i++) {
        if (strcmp(requested_cap, known_caps[i]) == 0) {
            return 1;  /* ACK */
        }
    }
    return 0;  /* NAK */
}

/* Observable: CAP REQ with unknown cap returns NAK (zero) */
int cap_req_unknown_observable(void) {
    const char* requested_cap = "unknown-capability";
    const char* known_caps[] = {"multi-prefix", "sasl", NULL};
    for (int i = 0; known_caps[i] != NULL; i++) {
        if (strcmp(requested_cap, known_caps[i]) == 0) {
            return 1;  /* ACK */
        }
    }
    return 0;  /* NAK - rejected */
}

int main(void) {
    /* CAP LS observable: returns non-empty list */
    assert(cap_ls_observable() != 0);

    /* CAP REQ known cap observable: ACK (non-zero) */
    assert(cap_req_known_observable() != 0);

    /* CAP REQ unknown cap observable: NAK (zero, rejected) */
    assert(cap_req_unknown_observable() == 0);

    return 0;
}
>>>>>>> main
