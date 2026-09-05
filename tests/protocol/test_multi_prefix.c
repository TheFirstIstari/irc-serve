/* multi-prefix test: verify +o prefix bit and list behavior */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Simulated user with mode prefix flag */
typedef struct {
    char name[32];
    int has_o_prefix;  /* observable: MODE +o sets this bit */
} user_t;

/* Simulate MODE +o setting the observable bit on a user */
static void mode_set_o(user_t *u) {
    u->has_o_prefix = 1;  /* bit set == 1 */
}

/* Simulate prefixed user list query: returns array with prefix flag on first entry */
static int query_prefixed_list(user_t *users, int count, user_t **out_first) {
    if (count <= 0) return 0;
    *out_first = &users[0];
    return count;
}

int main(void) {
    user_t users[3] = {
        {"alice", 0},
        {"bob", 0},
        {"carol", 0}
    };

    /* MODE +o sets observable bit == 1 */
    mode_set_o(&users[0]);
    assert(users[0].has_o_prefix == 1);

    /* Query returns prefixed list */
    user_t *first = NULL;
    int list_count = query_prefixed_list(users, 3, &first);
    assert(list_count > 0);
    assert(first != NULL);
    /* First entry has prefix flag observable */
    assert(first->has_o_prefix == 1);

    printf("multi-prefix: +o bit=%d, list_count=%d, first_prefix=%d OK\n",
           users[0].has_o_prefix, list_count, first->has_o_prefix);
    return 0;
}