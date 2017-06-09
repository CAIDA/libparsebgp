//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_PARSE_BMPV1_H
#define PARSE_LIB_PARSE_BMPV1_H

#include <iostream>
#include "parse_utils.h"
#include "parse_bgp.h"

/*
 * BMP Header lengths, not counting the version in the common hdr
 */
#define BMP_HDRv3_LEN 5             ///< BMP v3 header length, not counting the version
#define BMP_HDRv1v2_LEN  43
#define BMP_PEER_HDR_LEN 42         ///< BMP peer header length
#define BMP_INIT_MSG_LEN 4          ///< BMP init message header length, does not count the info field
#define BMP_TERM_MSG_LEN 4          ///< BMP term message header length, does not count the info field
#define BMP_PEER_UP_HDR_LEN 20      ///< BMP peer up event header size not including the recv/sent open param message
#define BMP_PACKET_BUF_SIZE 68000   ///< Size of the BMP packet buffer (memory)


using namespace std;

/**
 * BMP common header types
 */
enum bmp_type {
    TYPE_ROUTE_MON = 0, TYPE_STATS_REPORT, TYPE_PEER_DOWN, TYPE_PEER_UP, TYPE_INIT_MSG, TYPE_TERM_MSG
};

/**
 * BMP stats types
 */
enum bmp_stats {
    STATS_PREFIX_REJ = 0, STATS_DUP_PREFIX, STATS_DUP_WITHDRAW, STATS_INVALID_CLUSTER_LIST,
    STATS_INVALID_AS_PATH_LOOP, STATS_INVALID_ORIGINATOR_ID, STATS_INVALID_AS_CONFED_LOOP,
    STATS_NUM_ROUTES_ADJ_RIB_IN, STATS_NUM_ROUTES_LOC_RIB
};

/**
 * BMP Initiation Message Types
 */
enum bmp_init_types {
    INIT_TYPE_FREE_FORM_STRING = 0, INIT_TYPE_SYSDESCR, INIT_TYPE_SYSNAME, INIT_TYPE_ROUTER_BGP_ID = 65531
};

/**
 * BMP Termination Message Types
 */
enum bmp_term_types {
    TERM_TYPE_FREE_FORM_STRING = 0, TERM_TYPE_REASON
};

/**
 * BMP Termination Message reasons for type=1
 */
enum bmp_term_type1_reason {
    TERM_REASON_ADMIN_CLOSE = 0, TERM_REASON_UNSPECIFIED, TERM_REASON_OUT_OF_RESOURCES,
    TERM_REASON_REDUNDANT_CONN, TERM_REASON_OPENBMP_CONN_CLOSED = 65533, TERM_REASON_OPENBMP_CONN_ERR = 65534
};

/**
 * BMP peer header
 */
struct libparsebgp_parsed_peer_hdr_v3 {
    uint8_t         peer_type;            ///< 1 byte peer type
    uint8_t         peer_flags;           ///< 1 byte peer flags
    unsigned char   peer_dist_id[8];      ///< 8 byte peer route distinguisher
    unsigned char   peer_addr[16];        ///< 16 bytes IP address of peer
    uint32_t        peer_as;              ///< 4 byte peer AS number
    unsigned char   peer_bgp_id[4];       ///< 4 byte peer bgp id
    uint32_t        ts_secs;              ///< 4 byte timestamp in seconds
    uint32_t        ts_usecs;             ///< 4 byte timestamp microseconds
} __attribute__ ((__packed__));

/**
*  BMP headers for older versions (BMPv1)
*/
struct common_hdr_bmp_old {
    uint8_t         type;                ///< 1 byte message type
    uint8_t         peer_type;           ///< 1 byte peer type
    uint8_t         peer_flags;          ///< 1 byte peer flag
    unsigned char   peer_dist_id[8];     ///< 8 byte peer distinguisher
    unsigned char   peer_addr[16];       ///< 16 bytes peer IP address
    uint32_t        peer_as;             ///< 4 byte peer AS number
    unsigned char   peer_bgp_id[4];      ///< 4 byte peer bgp id
    uint32_t        ts_secs ;            ///< 4 byte timestamp in seconds
    uint32_t        ts_usecs ;           ///< 4 byte timestamp microseconds
    uint8_t         ver;                 ///< 1 byte -- At last since it's read before
} __attribute__ ((__packed__));

/**
 * BMP common header
 */
struct common_hdr_bmp_v3 {          ///< 6 bytes total length for the common header
    uint8_t     ver;                ///< 1 byte; version of BMP header
    uint32_t    len;                ///< 4 bytes; BMP msg length in bytes including all headers
    uint8_t     type;               ///< 1 byte; BMP Msg type
} __attribute__ ((__packed__));

/**
* BMP initiation message TLV
*/
typedef struct init_msg_v3_tlv {
    uint16_t    type;              ///< 2 bytes - Information type
    uint16_t    len;               ///< 2 bytes - Length of the information that follows
    char        info[4096];        ///< Information - variable
}init_msg_v3_tlv;

/**
* BMP initiation message: This can contain multiple init - tlvs
*/
typedef struct libparsebgp_parsed_bmp_init_msg {
    uint32_t         num_tlvs;
    init_msg_v3_tlv *init_msg_tlvs;    ///< list of init message tlvs
}libparsebgp_parsed_bmp_init_msg;

/**
 * BMP termination message
 */
typedef struct term_msg_v3_tlv {
    uint16_t type;              ///< 2 bytes - Information type
    uint16_t len;               ///< 2 bytes - Length of the information that follows
    char info[4096];            ///< Information - variable
}term_msg_v3_tlv;

/**
* BMP termination message: This can contain multiple term - tlvs
*/
typedef struct libparsebgp_parsed_bmp_term_msg {
    uint32_t         num_tlvs;
    term_msg_v3_tlv *term_msg_tlvs;    ///< list of term message tlvs
}libparsebgp_parsed_bmp_term_msg;

/**
 * OBJECT: peer_up_events
 *
 * Peer Up Events schema
 */
typedef struct libparsebgp_parsed_bmp_peer_up_event {
    char                                local_ip[16];           ///< IPv4 or IPv6 printed IP address
    uint16_t                            local_port;             ///< Local port number
    uint16_t                            remote_port;            ///< Remote port number
    libparsebgp_parse_bgp_parsed_data   sent_open_msg;          ///< sent open message
    libparsebgp_parse_bgp_parsed_data   received_open_msg;      ///< received open message
    //char                                info_data[4096];        ///< Inforamtional data for peer
}libparsebgp_parsed_bmp_peer_up_event;

/**
 * OBJECT: peer_down_events
 *
 * Peer Down Events schema
 */
typedef struct libparsebgp_parsed_bmp_peer_down_event {
    uint8_t         bmp_reason;                     ///< BMP notify reason
    libparsebgp_parse_bgp_parsed_data notify_msg;   ///< BGP notification message
}libparsebgp_parsed_bmp_peer_down_event;

/**
 * BMP stat counter
 */
typedef struct stat_counter {
    uint16_t    stat_type;              ///< 2 bytes - Information type
    uint16_t    stat_len;               ///< 2 bytes - Length of the information that follows
    char        stat_data[8];           ///< Information - variable
}stat_counter;

/**
 * OBJECT: stats_reports
 *
 * Stats Report schema
 */
typedef struct libparsebgp_parsed_bmp_stat_rep {
    uint32_t                stats_count;            ///< 4 bytes - Stats Count
    stat_counter*           total_stats_counter;    ///< 2 bytes - Information type
}libparsebgp_parsed_bmp_stat_rep;

u_char bmp_data[BMP_PACKET_BUF_SIZE + 1];
uint32_t    bmp_data_len;               ///< Length/size of data in the data buffer
uint32_t    bmp_len;                    ///< Length of the BMP message - does not include the common header size
uint8_t     bmp_type;                   ///< Type of the BMP message
uint8_t     ver;

/**
 * BMP Message Structure
 */
typedef struct libparsebgp_parsed_bmp_parsed_data{
    /**
     *  Union of BMP common header
     */
    struct libparsebgp_parsed_bmp_hdr {
        common_hdr_bmp_v3 c_hdr_v3;         ///< structure for bmp header version 3
        common_hdr_bmp_old c_hdr_old;       ///< structure for bmp header version 1 or 2
    }libparsebgp_parsed_bmp_hdr;

    libparsebgp_parsed_peer_hdr_v3 libparsebgp_parsed_peer_hdr;

    /**
     *  Union of BMP Message
     */
    struct libparsebgp_parsed_bmp_msg{
        libparsebgp_parsed_bmp_init_msg           parsed_init_msg;                  ///< structure for bmp init msg
        libparsebgp_parsed_bmp_term_msg           parsed_term_msg;                  ///< structure for bmp term msg
        libparsebgp_parsed_bmp_peer_up_event      parsed_peer_up_event_msg;         ///< structure for bmp peer up event msg
        libparsebgp_parsed_bmp_peer_down_event    parsed_peer_down_event_msg;       ///< structure for bmp peer down event msg
        libparsebgp_parse_bgp_parsed_data         parsed_rm_msg;                    ///< structure for bmp route monitoring msg
        libparsebgp_parsed_bmp_stat_rep           parsed_stat_rep;                  ///< structure for bmp stats report msg
    }libparsebgp_parsed_bmp_msg;
}libparsebgp_parsed_bmp_parsed_data;

/**
 * Parses a BMP message by its various types
 *
 * @details
 *  This function will parse the header of the message and according to the type of the BMP message, it parses the rest of the message.
 *
 * @param [in]     parsed_msg       Pointer to the BMP Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent overrun)
 * @param [out]    parsed_msg       Referenced to the updated bmp parsed message
 *
 * @returns Bytes that have been successfully read by the bmp parser.
 */
ssize_t libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int buf_len);

/**
 * Destructor function to free bmp_parsed_data
 *
 * @param parsed_data  Struct having parsed bmp data, that needs to be freed
 *
 */
void libparsebgp_parse_bmp_destructor(libparsebgp_parsed_bmp_parsed_data *parsed_data);

#endif //PARSE_LIB_PARSE_BMPV1_H
