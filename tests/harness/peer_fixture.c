/* peer_fixture.c -- see peer_fixture.h for what this is and why it is here.
 *
 * The socket code is deliberately plain: plain sockets, `select()`, `read()`,
 * `write()`. There is no non-blocking state machine and no buffer that outlives a
 * call, because a fixture that accumulated state would need its own teardown path
 * and its own bugs, and the only thing callers need is "read until this appeared"
 * and "give me what you have".
 */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "harness/peer_fixture.h"

void pf_peer_init(pf_peer_t *p)
{
    p->fd = -1;
    p->port = 0;
}

unsigned long long pf_now_ms(void)
{
    struct timeval tv;

    (void)gettimeofday(&tv, NULL);
    return (unsigned long long)tv.tv_sec * 1000ull +
           (unsigned long long)(tv.tv_usec / 1000);
}

int pf_listen_loopback(int *port_out)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        (void)close(fd);
        return -1;
    }
    *port_out = (int)ntohs(sa.sin_port);
    return fd;
}

int pf_accept_deadline(int listen_fd, int timeout_ms)
{
    unsigned long long deadline = pf_now_ms() + (unsigned long long)timeout_ms;

    for (;;) {
        struct timeval tv;
        unsigned long long now = pf_now_ms();
        unsigned long long left = (deadline > now) ? deadline - now : 0ull;
        fd_set rfds;
        int rc;

        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000ull);
        tv.tv_usec = (suseconds_t)((left % 1000ull) * 1000ull);
        rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            return -1;
        }
        return accept(listen_fd, NULL, NULL);
    }
}

int pf_read_until(int fd, const char *const *needles, size_t nneedles,
                  int timeout_ms)
{
    char buf[4096];
    char seen[8192];
    size_t used = 0;
    size_t got_all = 0;
    unsigned long long deadline = pf_now_ms() + (unsigned long long)timeout_ms;

    for (;;) {
        struct timeval tv;
        unsigned long long now = pf_now_ms();
        unsigned long long left = (deadline > now) ? deadline - now : 0ull;
        fd_set rfds;
        ssize_t got;
        int rc;

        if (got_all == nneedles) {
            return 0;
        }
        if (used >= sizeof seen - 1u) {
            break;
        }
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000ull);
        tv.tv_usec = (suseconds_t)((left % 1000ull) * 1000ull);
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) {
            break;
        }
        got = read(fd, buf, sizeof buf);
        if (got <= 0) {
            break;
        }
        if ((size_t)got >= sizeof seen - 1u - used) {
            got = (ssize_t)(sizeof seen - 1u - used);
        }
        memcpy(seen + used, buf, (size_t)got);
        used += (size_t)got;
        seen[used] = '\0';
        got_all = 0;
        for (size_t i = 0; i < nneedles; i++) {
            if (strstr(seen, needles[i]) != NULL) {
                got_all++;
            }
        }
    }
    return (got_all == nneedles) ? 0 : -1;
}

int pf_send_raw(int fd, const char *bytes, size_t n)
{
    size_t off = 0;

    while (off < n) {
        ssize_t got = write(fd, bytes + off, n - off);

        if (got <= 0) {
            return -1;
        }
        off += (size_t)got;
    }
    return 0;
}

int pf_send_line(int fd, const char *line)
{
    char framed[1024];
    int n = snprintf(framed, sizeof framed, "%s\r\n", line);

    if (n <= 0 || (size_t)n >= sizeof framed) {
        return -1;
    }
    return pf_send_raw(fd, framed, (size_t)n);
}

long pf_drain(int fd, char *dst, size_t cap)
{
    size_t used = 0;
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    for (;;) {
        ssize_t got;

        if (used + 1u >= cap) {
            break;
        }
        got = read(fd, dst + used, cap - used - 1u);
        if (got <= 0) {
            break;
        }
        used += (size_t)got;
    }
    dst[used] = '\0';
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags);
    }
    return (long)used;
}

size_t pf_times_seen(const char *buf, const char *needle)
{
    const char *p = buf;
    size_t n = 0;
    size_t len = strlen(needle);

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}
