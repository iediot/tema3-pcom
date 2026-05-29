#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <cstring>
#include <unistd.h>
#include <algorithm>

using namespace std;

std::map<int, struct connection *> cons;
struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

static int g_speed = 8;
static int g_delay = 2;
static int g_next_handle = 1;

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
/*  Helper: build and send a control packet (SYN / SYN-ACK / ACK)    */
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
/*                           send_data                                */
/* ------------------------------------------------------------------ */
int send_data(int conn_id, char *buffer, int len)
{
    struct connection *con = cons[conn_id];

    pthread_mutex_lock(&con->con_lock);

    int in_flight = (uint16_t)(con->next_seq - con->send_base);

    /* Window full? */
    if (in_flight >= con->max_window_seq) {
        pthread_mutex_unlock(&con->con_lock);
        return -1;
    }
    /* Receiver has no room? (but always allow at least one packet) */
    if (in_flight > 0 && con->rwnd < (MAX_DATA_SIZE - 2)) {
        pthread_mutex_unlock(&con->con_lock);
        return -1;
    }

    int data_len = std::min(len, (int)(MAX_DATA_SIZE - 2));
    int idx = con->next_seq % SEND_WINDOW_SIZE;

    /* Build DATA segment: [poli_tcp_data_hdr][user_data][crc16] */
    poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)con->send_segments[idx];
    hdr->protocol_id = POLI_PROTOCOL_ID;
    hdr->conn_id     = (uint8_t)con->conn_id;
    hdr->type        = PKT_DATA;
    hdr->seq_num     = con->next_seq;
    hdr->len         = (uint16_t)(data_len + 2);

    memcpy(con->send_segments[idx] + sizeof(poli_tcp_data_hdr), buffer, data_len);

    uint16_t checksum = crc16((uint8_t *)con->send_segments[idx],
                              (int)sizeof(poli_tcp_data_hdr) + data_len);
    memcpy(con->send_segments[idx] + sizeof(poli_tcp_data_hdr) + data_len,
           &checksum, 2);

    con->send_segment_lens[idx] = (int)sizeof(poli_tcp_data_hdr) + data_len + 2;

    sendto(con->sockfd, con->send_segments[idx], con->send_segment_lens[idx], 0,
           (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

    con->next_seq++;

    pthread_mutex_unlock(&con->con_lock);
    return data_len;
}

/* ------------------------------------------------------------------ */
/*                     sender_handler (thread)                        */
/* ------------------------------------------------------------------ */
void *sender_handler(void *arg)
{
    (void)arg;
    char buf[PKT_BUF_SIZE];

    while (1) {
        if (cons.size() == 0) {
            usleep(1000);
            continue;
        }

        int conn_id = -1;
        int res;
        do {
            res = recv_message_or_timeout(buf, PKT_BUF_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);
        struct connection *con = cons[conn_id];

        if (res > 0) {
            /* ----- Received a control packet (ACK or late SYN-ACK) ----- */
            if (res >= (int)sizeof(poli_tcp_ctrl_hdr) + 2) {
                poli_tcp_ctrl_hdr *ctrl = (poli_tcp_ctrl_hdr *)buf;

                uint16_t recv_crc;
                memcpy(&recv_crc, buf + sizeof(poli_tcp_ctrl_hdr), 2);
                uint16_t calc_crc = crc16((uint8_t *)buf, sizeof(poli_tcp_ctrl_hdr));

                if (ctrl->protocol_id == POLI_PROTOCOL_ID && recv_crc == calc_crc) {
                    if (ctrl->type == PKT_ACK) {
                        /* Cumulative ACK — advance send_base */
                        uint16_t advance = (uint16_t)(ctrl->ack_num - con->send_base);
                        uint16_t range   = (uint16_t)(con->next_seq - con->send_base);
                        if (advance > 0 && advance <= range)
                            con->send_base = ctrl->ack_num;
                        con->rwnd = ctrl->recv_window;
                    } else if (ctrl->type == PKT_SYN_ACK) {
                        /* Late SYN-ACK — resend final ACK */
                        send_ctrl(con->sockfd, &con->servaddr,
                                  (uint8_t)con->conn_id, PKT_ACK, 0, 0);
                    }
                }
            }
        } else if (res == -1) {
            /* ----- Timeout — retransmit if no progress since last fire ----- */
            if (con->send_base != con->next_seq &&
                con->send_base == con->last_timeout_base) {
                for (uint16_t s = con->send_base; s != con->next_seq; s++) {
                    if ((uint16_t)(s - con->send_base) >= SEND_WINDOW_SIZE) break;
                    int idx = s % SEND_WINDOW_SIZE;
                    sendto(con->sockfd,
                           con->send_segments[idx], con->send_segment_lens[idx], 0,
                           (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
                }
            }
            con->last_timeout_base = con->send_base;
        }

        pthread_mutex_unlock(&con->con_lock);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*                      setup_connection                              */
/* ------------------------------------------------------------------ */
int setup_connection(uint32_t ip, uint16_t port)
{
    struct connection *con = (struct connection *)calloc(1, sizeof(struct connection));
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    con->servaddr.sin_family      = AF_INET;
    con->servaddr.sin_addr.s_addr = ip;
    con->servaddr.sin_port        = port; /* network-order, initial SYN target */

    /* Handshake timeout */
    struct timeval tv = {0, 200000}; /* 200 ms */
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* ---------- Three-way handshake ---------- */
    char recv_buf[PKT_BUF_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen;

    while (1) {
        /* Send SYN */
        send_ctrl(con->sockfd, &con->servaddr, 0, PKT_SYN, 0, 0);

        fromlen = sizeof(from);
        int n = recvfrom(con->sockfd, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n < (int)(sizeof(poli_tcp_ctrl_hdr) + 2))
            continue;

        poli_tcp_ctrl_hdr *synack = (poli_tcp_ctrl_hdr *)recv_buf;
        uint16_t rc;
        memcpy(&rc, recv_buf + sizeof(poli_tcp_ctrl_hdr), 2);
        uint16_t cc = crc16((uint8_t *)recv_buf, sizeof(poli_tcp_ctrl_hdr));

        if (synack->protocol_id == POLI_PROTOCOL_ID &&
            synack->type == PKT_SYN_ACK && rc == cc) {
            con->conn_id = synack->conn_id;
            /* Data port is carried in ack_num (host order) */
            con->servaddr.sin_port = htons(synack->ack_num);
            con->rwnd = synack->recv_window;

            /* Send final ACK to data port */
            send_ctrl(con->sockfd, &con->servaddr,
                      (uint8_t)con->conn_id, PKT_ACK, 0, 0);
            break;
        }
    }

    /* Clear socket timeout */
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Init sender state */
    con->send_base        = 1;
    con->next_seq         = 1;
    con->last_timeout_base = 0;

    int bdp = g_speed * 125 * 2 * g_delay; /* bytes  (speed Mbps * 125000 B/Mb * RTT s) simplified */
    con->max_window_seq = (bdp * 4) / (MAX_DATA_SIZE - 2);
    if (con->max_window_seq < 4)  con->max_window_seq = 4;
    if (con->max_window_seq > SEND_WINDOW_SIZE - 1)
        con->max_window_seq = SEND_WINDOW_SIZE - 1;

    pthread_mutex_init(&con->con_lock, NULL);

    int handle = g_next_handle++;
    /* Insert in cons BEFORE bumping fdmax so handler thread never
       sees an fd without a matching connection entry. */
    cons.insert({handle, con});

    data_fds[fdmax].fd     = con->sockfd;
    data_fds[fdmax].events = POLLIN;

    int timeout_ms = TIMEOUT_SEND(g_delay);
    timer_fds[fdmax].fd     = timerfd_create(CLOCK_MONOTONIC, 0);
    timer_fds[fdmax].events = POLLIN;
    struct itimerspec spec = {};
    spec.it_value.tv_nsec    = timeout_ms * 1000000L;
    spec.it_interval.tv_nsec = timeout_ms * 1000000L;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);

    fdmax++;

    DEBUG_PRINT("Connection established! conn_id=%d handle=%d max_win=%d\n",
                con->conn_id, handle, con->max_window_seq);

    return handle;
}

/* ------------------------------------------------------------------ */
/*                         init_sender                                */
/* ------------------------------------------------------------------ */
void init_sender(int speed, int delay)
{
    g_speed = speed;
    g_delay = delay;

    pthread_t thread1;
    int ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
