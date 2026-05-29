
#pragma once

#include <cstdint>
#include "utils.h"
#include <arpa/inet.h>
#include <pthread.h>

/* Maximum payload size per segment. Set to 1026 so that 1024 bytes of user data
   + 2 bytes CRC fit in one segment. This ensures send_data(1024) succeeds in one
   call, avoiding the 500ms sleep in client.cpp's send loop. */
#define MAX_DATA_SIZE 1026
#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(poli_tcp_data_hdr))

/* Buffer size for storing packets (no dependency on protocol.h at struct-parse time) */
#define PKT_BUF_SIZE 1100

#define MAX_CONNECTIONS 32
#define SEND_WINDOW_SIZE 32
#define RECV_OOO_SIZE 64
#define ORDERED_BUF_SIZE 32768

/* Packet types */
#define PKT_SYN     1
#define PKT_SYN_ACK 2
#define PKT_ACK     3
#define PKT_DATA    4

/* Protocol control block. Used to track different parameters about a connection. */
struct connection {
    /* common */
    int sockfd; /* socket used for this connection */
    int conn_id; /* connection identifier */
    struct sockaddr_in servaddr; /* used to identify the destination */
    pthread_mutex_t con_lock;

    /* ---- Sender fields ---- */
    int max_window_seq;
    uint16_t send_base;
    uint16_t next_seq;
    uint16_t rwnd;              /* receiver-advertised window (bytes) */
    uint16_t last_timeout_base; /* send_base at last timeout, for stall detection */
    char     send_segments[SEND_WINDOW_SIZE][PKT_BUF_SIZE];
    int      send_segment_lens[SEND_WINDOW_SIZE];

    /* ---- Receiver fields ---- */
    uint16_t next_expected;
    int      used_bytes;
    int      max_recv_bytes;

    /* Out-of-order buffer */
    char recv_ooo_data[RECV_OOO_SIZE][MAX_DATA_SIZE];
    int  recv_ooo_lens[RECV_OOO_SIZE];
    int  recv_ooo_valid[RECV_OOO_SIZE];

    /* Ordered data buffer (circular) for recv_data consumption */
    char ordered_buf[ORDERED_BUF_SIZE];
    int  ordered_head;
    int  ordered_tail;
    int  ordered_count;

    pthread_cond_t data_cond;
};

/* ########## API that we expose to the application ########### */

int wait4connect(uint32_t ip, uint16_t port);
int setup_connection(uint32_t ip, uint16_t port);
int recv_data(int connectionid, char *buffer, int len);
int send_data(int conn_id, char *buffer, int len);
void init_receiver(int recv_buffer_bytes);
void init_sender(int speed, int delay);

/* ######### Internal API used by sender and receiver ########### */
int recv_message_or_timeout(char *buff, size_t len, int *conn_id);
