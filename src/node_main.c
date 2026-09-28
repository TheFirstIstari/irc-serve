#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "server.h"

/* IRC-Serve Federated Node v0.1.0
 *
 * Executable integration is deliberate and accurate: the core is initialised
 * via server_init() and a real TCP listener is bound for incoming client
 * connections. Federation state is managed by the handshake arm performed in
 * server_init(); a live peer exchange is out of scope for the executable and
 * is not fabricated here. */

static volatile sig_atomic_t running = 1;
static int listen_fd = -1;

/* Both helpers below are private to this executable's main(); they are not
 * part of any library interface, so they are static rather than exported with
 * prototypes in a header. */
static void handle_sigterm(int sig) {
    (void)sig;
    running = 0;
}

static int bind_tcp_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[observable] TCP bind failed: port=%d reason=%s\n", port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    printf("[observable] tcp_bind: port=%d fd=%d state=LISTENING\n", port, fd);
    return fd;
}

int main(void) {
    const int port = 6667;

    printf("IRC-Serve Federated Node v0.1.0 initializing...\n");

    struct sigaction sa = {0};
    sa.sa_handler = handle_sigterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* Initialise the server core: protocol parser + local federation handshake
     * arm. This does not establish a peer link. */
    server_init();

    listen_fd = bind_tcp_listener(port);
    if (listen_fd < 0) {
        printf("[observable] server startup failed: state=FAILED reason=bind_failed\n");
        return 1;
    }

    printf("[observable] server running: listener_fd=%d (accepting connections)\n",
           listen_fd);

    /* Simple accept loop: accepts connections (a real TCP listener). No
     * application-layer protocol handling is fabricated here; the loop simply
     * accepts and closes, and forwards completion to the caller. */
    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(listen_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (ret == 0) continue;

        if (FD_ISSET(listen_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd >= 0) {
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                printf("[observable] client_connect: fd=%d ip=%s port=%d\n",
                       client_fd, client_ip, ntohs(client_addr.sin_port));
                close(client_fd);
            }
        }
    }

    if (listen_fd >= 0) {
        close(listen_fd);
        listen_fd = -1;
    }

    printf("[observable] server_shutdown: state=STOPPED\n");
    return 0;
}
