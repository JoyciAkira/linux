/*
 * r5-poll-probe.c — Guest-native Linux poll() loopback TCP probe.
 * Static x86-64 musl binary. No dynamic loader dependency.
 *
 * Exercises real Linux poll() on loopback TCP:
 *   1. AF_INET listen socket
 *   2. Nonblocking client connect → EINPROGRESS
 *   3. poll(POLLOUT) → connect completion
 *   4. getsockopt(SO_ERROR) → 0
 *   5. accept peer
 *   6. poll(POLLIN) before data → timeout (0)
 *   7. send payload → poll(POLLIN) → ready
 *   8. recv + verify payload
 *   9. shutdown(SHUT_WR) → poll → EOF/HUP
 *  10. recv → 0
 *  11. close all fds, exit 0
 *
 * Negative controls:
 *  - POLLNVAL on invalid fd
 *  - no-data timeout does not report POLLIN
 *  - payload mismatch fails
 *
 * Build: x86_64-linux-musl-gcc -static -O2 -o r5-poll-probe r5-poll-probe.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define PAYLOAD "R5V2_POLL_PROBE_PAYLOAD_0123456789"
#define PAYLOAD_LEN 34
#define LISTEN_PORT 19995
#define TIMEOUT_MS 5000
#define SHORT_TIMEOUT_MS 200

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL:%s (line %d)\n", msg, __LINE__); \
        failures++; \
    } else { \
        printf("OK:%s\n", msg); \
    } \
} while(0)

int main(void) {
    int lfd, cfd, afd;
    struct sockaddr_in addr;
    struct pollfd pfd;
    int ret, optval;
    socklen_t optlen;
    char buf[128];
    ssize_t n;

    printf("R5_POLL_PROBE_BEGIN\n");

    /* 1. Create AF_INET listening socket */
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(lfd >= 0, "socket(AF_INET,SOCK_STREAM)");
    if (lfd < 0) { printf("R5_POLL_PROBE_END:FAIL\n"); return 1; }

    optval = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LISTEN_PORT);

    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    CHECK(ret == 0, "bind(127.0.0.1:19995)");

    ret = listen(lfd, 1);
    CHECK(ret == 0, "listen");

    /* 2. Create nonblocking client socket */
    cfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(cfd >= 0, "socket(AF_INET,SOCK_NONBLOCK)");
    if (cfd < 0) { printf("R5_POLL_PROBE_END:FAIL\n"); return 1; }

    /* 3. Connect → EINPROGRESS */
    ret = connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
    CHECK(ret == -1 && errno == EINPROGRESS, "connect_EINPROGRESS");

    /* 4. poll(POLLOUT) → connect completion */
    pfd.fd = cfd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    ret = poll(&pfd, 1, TIMEOUT_MS);
    CHECK(ret == 1, "poll_POLLOUT_ready");
    CHECK(pfd.revents & POLLOUT, "revents_has_POLLOUT");

    /* 5. getsockopt(SO_ERROR) → 0 */
    optval = -1;
    optlen = sizeof(optval);
    ret = getsockopt(cfd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
    CHECK(ret == 0 && optval == 0, "SO_ERROR_zero");

    /* 6. Accept peer */
    afd = accept(lfd, NULL, NULL);
    CHECK(afd >= 0, "accept");
    if (afd < 0) { printf("R5_POLL_PROBE_END:FAIL\n"); return 1; }

    /* 7. poll(POLLIN) before data → timeout (0) */
    pfd.fd = afd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = poll(&pfd, 1, SHORT_TIMEOUT_MS);
    CHECK(ret == 0, "poll_no_data_timeout");
    CHECK(!(pfd.revents & POLLIN), "no_spurious_POLLIN");

    /* Negative control: POLLNVAL on invalid fd */
    pfd.fd = 9999;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = poll(&pfd, 1, 100);
    CHECK(pfd.revents & POLLNVAL, "POLLNVAL_invalid_fd");

    /* 8. Send deterministic payload */
    n = write(cfd, PAYLOAD, PAYLOAD_LEN);
    CHECK(n == PAYLOAD_LEN, "send_payload");

    /* 9. poll(POLLIN) → data ready */
    pfd.fd = afd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = poll(&pfd, 1, TIMEOUT_MS);
    CHECK(ret == 1, "poll_POLLIN_ready");
    CHECK(pfd.revents & POLLIN, "revents_has_POLLIN");

    /* 10. recv + verify payload */
    memset(buf, 0, sizeof(buf));
    n = read(afd, buf, sizeof(buf));
    CHECK(n == PAYLOAD_LEN, "recv_len");
    CHECK(memcmp(buf, PAYLOAD, PAYLOAD_LEN) == 0, "payload_match");

    /* 11. shutdown sender write side */
    ret = shutdown(cfd, SHUT_WR);
    CHECK(ret == 0, "shutdown_SHUT_WR");

    /* 12. poll receiver for EOF/HUP-readable transition */
    pfd.fd = afd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    ret = poll(&pfd, 1, TIMEOUT_MS);
    CHECK(ret == 1, "poll_EOF_ready");
    CHECK(pfd.revents & (POLLIN | POLLHUP), "revents_EOF_or_HUP");

    /* 13. recv → 0 (EOF) */
    n = read(afd, buf, sizeof(buf));
    CHECK(n == 0, "recv_EOF_zero");

    /* 14. Close all descriptors */
    close(afd);
    close(cfd);
    close(lfd);
    printf("OK:all_fds_closed\n");

    /* 15. Final verdict */
    if (failures == 0) {
        printf("R5_POLL_PROBE_END:PASS\n");
        return 0;
    } else {
        printf("R5_POLL_PROBE_END:FAIL:%d\n", failures);
        return 1;
    }
}
