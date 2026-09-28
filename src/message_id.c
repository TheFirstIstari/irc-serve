/* Observable message-id tracking (IRCv3). Minimal contract. */
#include <stdio.h>
#include <string.h>

static int msg_id_counter = 0;
static char last_msg_id[64] = {0};

int message_id_next(char* out, int max_len) {
    if (out == NULL || max_len <= 0) {
        printf("[observable] message_id_next: error=invalid_args\n");
        return -1;
    }
    msg_id_counter++;
    int written = snprintf(out, (size_t)max_len, "msg%d", msg_id_counter);
    if (written < 0 || written >= max_len) {
        printf("[observable] message_id_next: error=buffer_too_small\n");
        return -1;
    }
    strncpy(last_msg_id, out, sizeof(last_msg_id) - 1);
    last_msg_id[sizeof(last_msg_id) - 1] = '\0';
    printf("[observable] message_id_next: id=%s count=%d\n", out, msg_id_counter);
    return msg_id_counter;
}

int message_id_get_last(char* out, int max_len) {
    if (out == NULL || max_len <= 0) return -1;
    if (last_msg_id[0] == '\0') {
        printf("[observable] message_id_get_last: error=none_set\n");
        return -1;
    }
    int len = (int)strlen(last_msg_id);
    if (len >= max_len) return -1;
    memcpy(out, last_msg_id, (size_t)(len + 1));
    printf("[observable] message_id_get_last: id=%s\n", out);
    return len;
}
