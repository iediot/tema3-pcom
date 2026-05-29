#include <pthread.h>
#include <cstdlib>
#include <map>
#include <set>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
#include <sys/timerfd.h>
#include <cstring>
#include <unistd.h>
#include <algorithm>

using namespace std;

std::map<int, struct connection *> cons;
struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

static int  g_recv_buffer_size = 9 * 1024;
static int  g_listen_fd        = -1;
static int  g_next_handle      = 1;
static uint8_t g_next_conn_id  = 1;
static int  g_next_data_port   = 9000;

/* Track already-connected client addresses to ignore duplicate SYNs */
static uint64_t addr_key(const struct sockaddr_in &a)
{
    return ((uint64_t)a.sin_addr.s_addr << 32) | (uint64_t)a.sin_port;
}
static std::set<uint64_t> g_connected_addrs;

/* ------------------------------------------------------------------ */
/*                         CRC-16 / MODBUS                            */
/* ------------------------------------------------------------------ */
static uint16_t crc16(const uint8_t *data, int len)
{
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xA001;
            else
                crc >>= 1;
        }
    }
    return crc;
}

/* ------------------------------------------------------------------ */
/*  Helper: build and send a control packet                           */
/* ------------------------------------------------------------------ */
static void send_ctrl(int sockfd, const struct sockaddr_in *dest,
                      uint8_t conn_id, uint8_t type,
                      uint16_t ack_num, uint16_t recv_window)
{
    char buf[sizeof(poli_tcp_ctrl_hdr) + 2];
    poli_tcp_ctrl_hdr *h = (poli_tcp_ctrl_hdr *)buf;
    h->protocol_id = POLI_PROTOCOL_ID;
    h->conn_id     = conn_id;
    h->type        = type;
    h->ack_num     = ack_num;
    h->recv_window = recv_window;
    uint16_t c = crc16((uint8_t *)buf, sizeof(poli_tcp_ctrl_hdr));
    memcpy(buf + sizeof(poli_tcp_ctrl_hdr), &c, 2);
    sendto(sockfd, buf, sizeof(buf), 0,
           (const struct sockaddr *)dest, sizeof(*dest));
}

/* ------------------------------------------------------------------ */
/*                           recv_data                                */
/* ------------------------------------------------------------------ */
int recv_data(int conn_id, char *buffer, int len)
{
    struct connection *con = cons[conn_id];

    pthread_mutex_lock(&con->con_lock);

    /* Block until ordered data is available */
    while (con->ordered_count == 0) {
        pthread_cond_wait(&con->data_cond, &con->con_lock);
    }

    int to_copy = std::min(len, con->ordered_count);
    for (int i = 0; i < to_copy; i++) {
        buffer[i] = con->ordered_buf[con->ordered_head];
        con->ordered_head = (con->ordered_head + 1) % ORDERED_BUF_SIZE;
    }
    con->ordered_count -= to_copy;
    con->used_bytes    -= to_copy;

    pthread_mutex_unlock(&con->con_lock);
    return to_copy;
}

/* ------------------------------------------------------------------ */
/*                    receiver_handler (thread)                       */
/* ------------------------------------------------------------------ */
void *receiver_handler(void *arg)
{
    (void)arg;
    char segment[PKT_BUF_SIZE];

    DEBUG_PRINT("Starting receiver handler\n");

    while (1) {
        if (cons.size() == 0) {
            usleep(1000);
            continue;
        }

        int conn_id = -1;
        int res;
        do {
            res = recv_message_or_timeout(segment, PKT_BUF_SIZE, &conn_id);
        } while (res == -14);

        if (conn_id < 0 || cons.find(conn_id) == cons.end()) continue;

        pthread_mutex_lock(&cons[conn_id]->con_lock);
        struct connection *con = cons[conn_id];

        if (res > 0 && res >= (int)sizeof(poli_tcp_data_hdr)) {
            poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)segment;

            /* Basic validity */
            if (hdr->protocol_id != POLI_PROTOCOL_ID || hdr->type != PKT_DATA ||
                hdr->len < 2 || res < (int)sizeof(poli_tcp_data_hdr) + hdr->len) {
                goto send_ack;
            }

            {
                int user_data_len = hdr->len - 2;

                /* Verify CRC */
                uint16_t recv_crc;
                memcpy(&recv_crc,
                       segment + sizeof(poli_tcp_data_hdr) + user_data_len, 2);
                uint16_t calc_crc = crc16((uint8_t *)segment,
                                          (int)sizeof(poli_tcp_data_hdr) + user_data_len);
                if (recv_crc != calc_crc) goto send_ack; /* corrupted → drop */

                uint16_t seq = hdr->seq_num;

                /* Accept if within valid range and slot empty */
                if (seq >= con->next_expected &&
                    (uint16_t)(seq - con->next_expected) < RECV_OOO_SIZE) {
                    int idx = seq % RECV_OOO_SIZE;
                    if (!con->recv_ooo_valid[idx] &&
                        con->used_bytes + user_data_len <= con->max_recv_bytes) {
                        memcpy(con->recv_ooo_data[idx],
                               segment + sizeof(poli_tcp_data_hdr),
                               user_data_len);
                        con->recv_ooo_lens[idx]  = user_data_len;
                        con->recv_ooo_valid[idx] = 1;
                        con->used_bytes += user_data_len;
                    }
                }

                /* Advance: move consecutive in-order segments to ordered buf */
                while (1) {
                    int nidx = con->next_expected % RECV_OOO_SIZE;
                    if (!con->recv_ooo_valid[nidx]) break;
                    int dlen = con->recv_ooo_lens[nidx];
                    if (con->ordered_count + dlen > ORDERED_BUF_SIZE) break;

                    for (int i = 0; i < dlen; i++) {
                        con->ordered_buf[con->ordered_tail] =
                            con->recv_ooo_data[nidx][i];
                        con->ordered_tail =
                            (con->ordered_tail + 1) % ORDERED_BUF_SIZE;
                    }
                    con->ordered_count += dlen;
                    con->recv_ooo_valid[nidx] = 0;
                    /* used_bytes unchanged — data moved from ooo to ordered */
                    con->next_expected++;
                }

                pthread_cond_signal(&con->data_cond);
            }

send_ack:
            /* Always ACK with current state */
            {
                int remaining = con->max_recv_bytes - con->used_bytes;
                uint16_t win = remaining > 0 ? (uint16_t)remaining : 0;
                send_ctrl(con->sockfd, &con->servaddr,
                          (uint8_t)con->conn_id, PKT_ACK,
                          con->next_expected, win);
            }
        }
        /* timeout (res == -1): nothing to do on receiver side */

        pthread_mutex_unlock(&con->con_lock);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*                        wait4connect                                */
/* ------------------------------------------------------------------ */
int wait4connect(uint32_t ip, uint16_t port)
{
    /* Create listening socket on first call */
    if (g_listen_fd < 0) {
        g_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
        int opt = 1;
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = ip;
        addr.sin_port        = port;
        int ret = bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr));
        assert(ret >= 0);
    }

    char buf[PKT_BUF_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len;

    /* ---- Wait for a valid SYN from a new client ---- */
    while (1) {
        client_len = sizeof(client_addr);
        int n = recvfrom(g_listen_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&client_addr, &client_len);
        if (n < (int)(sizeof(poli_tcp_ctrl_hdr) + 2)) continue;

        poli_tcp_ctrl_hdr *ctrl = (poli_tcp_ctrl_hdr *)buf;
        uint16_t rc;
        memcpy(&rc, buf + sizeof(poli_tcp_ctrl_hdr), 2);
        uint16_t cc = crc16((uint8_t *)buf, sizeof(poli_tcp_ctrl_hdr));

        if (ctrl->protocol_id != POLI_PROTOCOL_ID || rc != cc) continue;
        if (ctrl->type != PKT_SYN) continue;

        /* Ignore duplicate SYNs from already-connected clients */
        uint64_t key = addr_key(client_addr);
        if (g_connected_addrs.count(key) > 0) continue;

        break;
    }

    /* ---- Allocate per-connection data socket ---- */
    int data_port = g_next_data_port++;
    int data_fd   = socket(AF_INET, SOCK_DGRAM, 0);
    {
        int opt = 1;
        setsockopt(data_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in da;
        memset(&da, 0, sizeof(da));
        da.sin_family      = AF_INET;
        da.sin_addr.s_addr = INADDR_ANY;
        da.sin_port        = htons(data_port);
        int ret = bind(data_fd, (struct sockaddr *)&da, sizeof(da));
        assert(ret >= 0);
    }

    uint8_t cid = g_next_conn_id++;

    /* ---- Send SYN-ACK & wait for ACK (with retries) ---- */
    {
        struct timeval tv = {0, 200000}; /* 200 ms */
        setsockopt(data_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    while (1) {
        /* SYN-ACK from listen socket; ack_num carries data_port (host order) */
        send_ctrl(g_listen_fd, &client_addr,
                  cid, PKT_SYN_ACK,
                  (uint16_t)data_port, (uint16_t)g_recv_buffer_size);

        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int n = recvfrom(data_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n < (int)sizeof(poli_tcp_ctrl_hdr)) continue;

        poli_tcp_ctrl_hdr *ctrl = (poli_tcp_ctrl_hdr *)buf;
        if (ctrl->protocol_id != POLI_PROTOCOL_ID) continue;

        /* Accept explicit ACK or implicit ACK via DATA */
        if (ctrl->type == PKT_ACK || ctrl->type == PKT_DATA)
            break;
    }

    /* Clear timeout */
    {
        struct timeval tv = {0, 0};
        setsockopt(data_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* ---- Build connection object ---- */
    struct connection *con = (struct connection *)calloc(1, sizeof(struct connection));
    con->sockfd       = data_fd;
    con->conn_id      = cid;
    con->servaddr     = client_addr;     /* replies go to client's addr */
    con->next_expected = 1;
    con->used_bytes    = 0;
    con->max_recv_bytes = g_recv_buffer_size;
    pthread_mutex_init(&con->con_lock, NULL);
    pthread_cond_init(&con->data_cond, NULL);

    int handle = g_next_handle++;
    g_connected_addrs.insert(addr_key(client_addr));

    /* Insert connection BEFORE bumping fdmax */
    cons.insert({handle, con});

    data_fds[fdmax].fd     = data_fd;
    data_fds[fdmax].events = POLLIN;

    /* Create a timerfd but don't arm it (receiver doesn't need timeout) */
    timer_fds[fdmax].fd     = timerfd_create(CLOCK_MONOTONIC, 0);
    timer_fds[fdmax].events = POLLIN;

    fdmax++;

    DEBUG_PRINT("Connection established! conn_id=%d handle=%d\n", cid, handle);
    return handle;
}

/* ------------------------------------------------------------------ */
/*                        init_receiver                               */
/* ------------------------------------------------------------------ */
void init_receiver(int recv_buffer_bytes)
{
    g_recv_buffer_size = recv_buffer_bytes;

    pthread_t thread1;
    int ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}
