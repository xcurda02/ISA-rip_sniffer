/**
 * soubor: rip_defs.h
 * autor: Vojtech Curda, 3BIT
 *
 */

#ifndef PROJ_RIP_DEFS_H
#define PROJ_RIP_DEFS_H


#include <cstdint>
#include <zconf.h>
#include <netinet/in.h>

/* Headers */
#define IPV6_HEADER_LENGTH 40
#define ETH_HEADER_LENGTH 14
#define UDP_HEADER_LENGTH 8
#define RIP_HEADER_LENGTH 4

/* Entry length */
#define RIP_ENTRY_LENGTH 20

/* RIP command */
#define RIP_REQUEST 1
#define RIP_RESPONSE 2

/* RIP ports */
#define RIP_PORT 520
#define RIPNG_PORT 521

/* Multicast IPv6 address */
#define RIPNG_MULTICAST_ADDRESS "FF02::9"


/* Entry types */
typedef enum{ IP_ENTRY, NEXT_HOP_ENTRY, ROUTE_TABLE_ENTRY, SIMPLE_AUTH_ENTRY, MD5_AUTH_ENTRY, AUTH_DATA_TRAILER} entry_type;

/*
 * RIP header structure
 */
typedef struct rip_header {
    u_int8_t command;
    u_int8_t version;
    u_int16_t must_be_zero;
} rip_header;


/*
 * RIP entry structure
 * universal for all RIPv1/2 entries
 */
typedef struct rip_entry{
    uint16_t afi;                   // Address Family
    uint16_t route_tag;             // Route Tag
    union{
        struct{                     // Classic RIPv1/2 entry
            struct in_addr ip;
            struct in_addr mask;
            struct in_addr next_hop;
            uint32_t  metric;
        }simple_entry;

        struct {                    // Simple password authentification entry
            u_int8_t password[16];
        }auth_pass;

        struct{                     // MD5 authentification entry
            u_int16_t digest_offset;
            u_int8_t key_id;
            u_int8_t auth_data_len;
            u_int32_t seq_num;
        }md5_auth;

        struct {                    // MD5 data trailer entry
            u_int8_t data[16];
        }md5_data_trailer;

    } data;
} rip_entry;


/* RIPng entry */
typedef struct ripng_entry{
    struct in6_addr ip_prefix;
    uint16_t route_tag;
    u_int8_t prefix_length;
    u_int8_t metric;
} ripng_entry;

#endif //PROJ_RIP_DEFS_H
