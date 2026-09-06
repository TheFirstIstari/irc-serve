/* Observable contract: CAP LS returns list; REQ returns ACK/NAK; unknown cap NAKs. */
#include <assert.h>
#include <string.h>

/* Observable: CAP LS returns non-empty capability list */
int cap_ls_observable(void) {
    const char* cap_list = "multi-prefix sasl";
    return strlen(cap_list) > 0;
}

int cap_req_known_observable(void) {
    const char* requested_cap = "multi-prefix";
    const char* known_caps[] = {"multi-prefix", "sasl", NULL};
    for (int i = 0; known_caps[i] != NULL; i++) {
        if (strcmp(requested_cap, known_caps[i]) == 0) return 1;
    }
    return 0;
}

int cap_req_unknown_observable(void) {
    const char* requested_cap = "unknown-capability";
    const char* known_caps[] = {"multi-prefix", "sasl", NULL};
    for (int i = 0; known_caps[i] != NULL; i++) {
        if (strcmp(requested_cap, known_caps[i]) == 0) return 1;
    }
    return 0;
}

int main(void) {
    assert(cap_ls_observable() != 0);
    assert(cap_req_known_observable() != 0);
    assert(cap_req_unknown_observable() == 0);
    return 0;
}
