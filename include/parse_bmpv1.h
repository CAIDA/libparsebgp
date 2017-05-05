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
#define BMP_HDRv1v2_LEN 43
#define BMP_PEER_HDR_LEN 42         ///< BMP peer header length
#define BMP_INIT_MSG_LEN 4          ///< BMP init message header length, does not count the info field
#define BMP_TERM_MSG_LEN 4          ///< BMP term message header length, does not count the info field
#define BMP_PEER_UP_HDR_LEN 20      ///< BMP peer up event header size not including the recv/sent open param message
#define BMP_PACKET_BUF_SIZE 68000   ///< Size of the BMP packet buffer (memory)

/**
 * \class   parseBMP
 *
 * \brief   Parser for BMP messages
 * \details This class can be used as needed to parse BMP messages. This
 *          class will read directly from the socket to read the BMP message.
 */

using namespace std;

/**
 * BMP common header types
 */
enum bmp_type {
    TYPE_ROUTE_MON = 0, TYPE_STATS_REPORT, TYPE_PEER_DOWN,
    TYPE_PEER_UP, TYPE_INIT_MSG, TYPE_TERM_MSG
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
    INIT_TYPE_FREE_FORM_STRING = 0, INIT_TYPE_SYSDESCR, INIT_TYPE_SYSNAME,
    INIT_TYPE_ROUTER_BGP_ID = 65531
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
    TERM_REASON_REDUNDANT_CONN,
    TERM_REASON_OPENBMP_CONN_CLOSED = 65533, TERM_REASON_OPENBMP_CONN_ERR = 65534
};
/**
 * BMP peer header
 */
struct libparsebgp_parsed_peer_hdr_v3 {
    uint8_t         peer_type;            ///< 1 byte
    uint8_t         peer_flags;           ///< 1 byte
    unsigned char   peer_dist_id[8];      ///< 8 byte peer route distinguisher
    unsigned char   peer_addr[16];        ///< 16 bytes
    uint32_t        peer_as;              ///< 4 byte
    unsigned char   peer_bgp_id[4];       ///< 4 byte peer bgp id
    uint32_t        ts_secs;              ///< 4 byte timestamp in seconds
    uint32_t        ts_usecs;             ///< 4 byte timestamp microseconds
} __attribute__ ((__packed__));

/**
*  BMP headers for older versions (BMPv1)
*/
struct common_hdr_bmp_old {
    //uint8_t ver;                 ///< 1 byte -- Not part of struct since it's read before
    uint8_t         type;                ///< 1 byte
    uint8_t         peer_type;            ///< 1 byte
    uint8_t         peer_flags;           ///< 1 byte
    unsigned char peer_dist_id[8];     ///< 8 byte peer distinguisher
    unsigned char peer_addr[16];       ///< 16 bytes
    uint32_t        peer_as[4];          ///< 4 byte
    unsigned char peer_bgp_id[4];      ///< 4 byte peer bgp id
    unsigned long ts_secs : 32;        ///< 4 byte timestamp in seconds
    unsigned long ts_usecs : 32;       ///< 4 byte timestamp microseconds
} __attribute__ ((__packed__));

/**
 * BMP common header
 */
struct common_hdr_bmp_v3 {          ///< 6 bytes total length for the common header
    uint8_t     ver;                ///< 1 byte;
    uint32_t    len;                ///< 4 bytes; BMP msg length in bytes including all headers
    uint8_t     type;               ///< BMP Msg type
} __attribute__ ((__packed__));


/**
* BMP initiation message TLV
*/
typedef struct init_msg_v3_tlv {
    uint16_t    type;              ///< 2 bytes - Information type
    uint16_t    len;               ///< 2 bytes - Length of the information that follows
    char        info[4096];                 ///< Information - variable
}init_msg_v3_tlv;

/**
* BMP initiation message: This can contain multiple init - tlvs
*/
typedef struct libparsebgp_parsed_bmp_init_msg {
    list<init_msg_v3_tlv> init_msg_tlvs;
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
    list<term_msg_v3_tlv> term_msg_tlvs;
}libparsebgp_parsed_bmp_term_msg;

/**
     * OBJECT: peer_up_events
     *
     * Peer Up Events schema
     *
     * \note    open_params are the decoded values in string/text format; e.g. "attr=value ..."
     *          Numeric values are converted to printed form.   The buffer itself is
     *          allocated by the caller and freed by the caller.
     */
typedef struct libparsebgp_parsed_bmp_peer_up_event {
    char                                local_ip[16];           ///< IPv4 or IPv6 printed IP address
    uint16_t                            local_port;             ///< Local port number
    uint16_t                            remote_port;            ///< Remote port number
    libparsebgp_parse_bgp_parsed_data   sent_open_msg;          ///< sent open message
    libparsebgp_parse_bgp_parsed_data   received_open_msg;      ///< received open message
    char                                info_data[4096];        ///< Inforamtional data for peer
}libparsebgp_parsed_bmp_peer_up_event;

/**
     * OBJECT: peer_down_events
     *
     * Peer Down Events schema
     */
typedef struct libparsebgp_parsed_bmp_peer_down_event {
    uint8_t         bmp_reason;         ///< BMP notify reason
    libparsebgp_parse_bgp_parsed_data notify_msg;
}libparsebgp_parsed_bmp_peer_down_event;

/**
 * BMP stat counter
 */
typedef struct stat_counter {
    uint16_t    stat_type;              ///< 2 bytes - Information type
    uint16_t    stat_len;               ///< 2 bytes - Length of the information that follows
    char        stat_data[8];              ///< Information - variable
}stat_counter;
/**
     * OBJECT: stats_reports
     *
     * Stats Report schema
     */
typedef struct libparsebgp_parsed_bmp_stat_rep {
    uint32_t                stats_count;
    list<stat_counter>    total_stats_counter;
}libparsebgp_parsed_bmp_stat_rep;

/**
     * OBJECT: stats_reports
     *
     * Stats Report schema
     */
typedef struct libparsebgp_parsed_bmp_rm_msg {
    libparsebgp_parse_bgp_parsed_data update_msg;
}libparsebgp_parsed_bmp_rm_msg;

u_char bmp_data[BMP_PACKET_BUF_SIZE + 1];
size_t bmp_data_len;              ///< Length/size of data in the data buffer
uint32_t bmp_len;                    ///< Length of the BMP message - does not include the common header size

/**
 * BMP Message Structure
 */
typedef struct libparsebgp_parsed_bmp_parsed_data{
    /**
     *  Union of BMP common header
     */
    struct libparsebgp_parsed_bmp_hdr {
        common_hdr_bmp_v3 c_hdr_v3;
        common_hdr_bmp_old c_hdr_old;
    }libparsebgp_parsed_bmp_hdr;

    libparsebgp_parsed_peer_hdr_v3 libparsebgp_parsed_peer_hdr;

    /**
     *  Union of BMP Message
     */
    struct libparsebgp_parsed_bmp_msg{
        libparsebgp_parsed_bmp_init_msg           parsed_init_msg;
        libparsebgp_parsed_bmp_term_msg           parsed_term_msg;
        libparsebgp_parsed_bmp_peer_up_event      parsed_peer_up_event_msg;
        libparsebgp_parsed_bmp_peer_down_event    parsed_peer_down_event_msg;
        libparsebgp_parsed_bmp_rm_msg             parsed_rm_msg;
        libparsebgp_parsed_bmp_stat_rep           parsed_stat_rep;
    }libparsebgp_parsed_bmp_msg;

//    uint32_t bmp_len;                    ///< Length of the BMP message - does not include the common header size

}libparsebgp_parsed_bmp_parsed_data;

uint32_t libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int buf_len);

#endif //PARSE_LIB_PARSE_BMPV1_H
