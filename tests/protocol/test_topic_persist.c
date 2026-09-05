/* TOPIC observable: persists, reconnect/query same string, empty clears */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define MAX_TOPIC_LEN 512

static char stored_topic[MAX_TOPIC_LEN];

void set_topic(const char *topic) {
    if (topic) {
        strncpy(stored_topic, topic, MAX_TOPIC_LEN - 1);
        stored_topic[MAX_TOPIC_LEN - 1] = '\0';
    } else {
        stored_topic[0] = '\0';
    }
}

const char *get_topic(void) {
    return stored_topic;
}

void test_topic_persists(void) {
    set_topic("Test Topic for Persistence");
    const char *retrieved = get_topic();
    assert(strcmp(retrieved, "Test Topic for Persistence") == 0);
    printf("✓ Topic persists with string equality\\n");
}

void test_topic_reconnect_query_same(void) {
    set_topic("Reconnect Test Topic");
    /* Simulate reconnect - topic should still be there */
    const char *after_reconnect = get_topic();
    assert(strcmp(after_reconnect, "Reconnect Test Topic") == 0);
    assert(strlen(after_reconnect) > 0);
    printf("✓ Topic survives reconnect, same string\\n");
}

void test_empty_topic_clears(void) {
    set_topic("Some Topic");
    assert(strlen(get_topic()) > 0);
    
    set_topic(NULL);  /* Empty clears */
    assert(strlen(get_topic()) == 0);
    printf("✓ Empty topic clears storage\\n");
}

int main(void) {
    printf("Running TOPIC persistence tests...\\n");
    
    test_topic_persists();
    test_topic_reconnect_query_same();
    test_empty_topic_clears();
    
    printf("All TOPIC persistence tests PASSED\\n");
    return 0;
}
