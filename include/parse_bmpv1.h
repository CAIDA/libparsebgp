//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_PARSE_BMPV1_H
#define PARSE_LIB_PARSE_BMPV1_H
#include <iostream>

using namespace std;
/**
 * BMP peer header
 */
struct libparsebgp_parsed_peer_hdr_v3 {
    unsigned char   peer_type;            ///< 1 byte
    unsigned char   peer_flags;           ///< 1 byte
    unsigned char   peer_dist_id[8];      ///< 8 byte peer route distinguisher
    unsigned char   peer_addr[16];        ///< 16 bytes
    unsigned char   peer_as[4];           ///< 4 byte
    unsigned char   peer_bgp_id[4];       ///< 4 byte peer bgp id
    uint32_t        ts_secs;              ///< 4 byte timestamp in seconds
    uint32_t        ts_usecs;             ///< 4 byte timestamp microseconds
} __attribute__ ((__packed__));

/**
*  BMP headers for older versions (BMPv1)
*/
struct common_hdr_bmp_old {
    unsigned char ver;                 ///< 1 byte -- Not part of struct since it's read before
    unsigned char type;                ///< 1 byte
    unsigned char peer_type;           ///< 1 byte
    unsigned char peer_flags;          ///< 1 byte
    unsigned char peer_dist_id[8];     ///< 8 byte peer distinguisher
    unsigned char peer_addr[16];       ///< 16 bytes
    unsigned char peer_as[4];          ///< 4 byte
    unsigned char peer_bgp_id[4];      ///< 4 byte peer bgp id
    unsigned long ts_secs : 32;        ///< 4 byte timestamp in seconds
    unsigned long ts_usecs : 32;       ///< 4 byte timestamp microseconds
} __attribute__ ((__packed__));

/**
 * BMP common header
 */
struct common_hdr_bmp_v3 {          ///< 6 bytes total length for the common header
    u_char      ver;                ///< 1 byte;
    uint32_t    len;                ///< 4 bytes; BMP msg length in bytes including all headers
    u_char      type;               ///< BMP Msg type
} __attribute__ ((__packed__));


/**
* BMP initiation message TLV
*/
struct init_msg_v3_tlv {
    uint16_t type;              ///< 2 bytes - Information type
    uint16_t len;               ///< 2 bytes - Length of the information that follows
    char *info;                 ///< Information - variable

} __attribute__ ((__packed__));

/**
* BMP initiation message: This can contain multiple init - tlvs
*/
struct lib_parse_bgp_parsed_bmp_init_msg {
    vector<init_msg_v3_tlv> init_msg_tlvs;
}lib_parse_bgp_parsed_bmp_init_msg;

/**
 * BMP termination message
 */
struct term_msg_v3_tlv {
    uint16_t type;              ///< 2 bytes - Information type
    uint16_t len;               ///< 2 bytes - Length of the information that follows

    char *info;              ///< Information - variable

} __attribute__ ((__packed__));
/**
* BMP termination message: This can contain multiple term - tlvs
*/
struct lib_parse_bgp_parsed_bmp_term_msg {
    vector<term_msg_v3_tlv> term_msg_tlvs;
}lib_parse_bgp_parsed_bmp_term_msg;

/**
     * OBJECT: peer_up_events
     *
     * Peer Up Events schema
     *
     * \note    open_params are the decoded values in string/text format; e.g. "attr=value ..."
     *          Numeric values are converted to printed form.   The buffer itself is
     *          allocated by the caller and freed by the caller.
     */
struct lib_parse_bgp_parsed_bmp_peer_up_event {
    char        local_ip[40];           ///< IPv4 or IPv6 printed IP address
    uint16_t    local_port;             ///< Local port number
    uint16_t    remote_port;            ///< Remote port number
//    lib_parse_bgp_parsed_bgp_open_msg   send_open_msg;
//    lib_parse_bgp_parsed_bgp_open_msg   received_open_msg;
    char        info_data[4096];        ///< Inforamtional data for peer

}lib_parse_bgp_parsed_bmp_peer_up_event;

/**
     * OBJECT: peer_down_events
     *
     * Peer Down Events schema
     */
struct lib_parse_bgp_parsed_bmp_peer_down_event {
    u_char          bmp_reason;         ///< BMP notify reason
    char            error_text[255];    ///< BGP error text string
}lib_parse_bgp_parsed_bmp_peer_down_event;

/**
 * BMP stat counter
 */
struct stat_counter {
    uint16_t    stat_type;              ///< 2 bytes - Information type
    uint16_t    stat_len;               ///< 2 bytes - Length of the information that follows
    char *      stat_data;              ///< Information - variable
};
/**
     * OBJECT: stats_reports
     *
     * Stats Report schema
     */
struct lib_parse_bgp_parsed_bmp_stat_rep {
    uint32_t                stats_count;
    vector<stat_counter>    stats_counter;
}lib_parse_bgp_parsed_bmp_stat_rep;

/**
     * OBJECT: stats_reports
     *
     * Stats Report schema
     */
struct lib_parse_bgp_parsed_bmp_rm_msg {
//    lib_parse_bgp_parsed_bgp_update_msg update_msg;
}lib_parse_bgp_parsed_bmp_rm_msg;


/**
 * BMP Message Structure
 */
typedef struct lib_parse_bgp_parsed_bmp{
    /**
     *  Union of BMP common header
     */
    union libparsebgp_parsed_bmp_hdr {
        common_hdr_bmp_v3 c_hdr_v3;
        common_hdr_bmp_old c_hdr_old;
    }libparsebgp_parsed_bmp_hdr;

    libparsebgp_parsed_peer_hdr_v3 libparsebgp_parsed_peer_hdr_v3;

    /**
     *  Union of BMP Message
     */
    union lib_parse_bgp_parsed_bmp_msg{
        lib_parse_bgp_parsed_bmp_init_msg           parsed_init_msg;
        lib_parse_bgp_parsed_bmp_term_msg           parsed_term_msg;
        lib_parse_bgp_parsed_bmp_peer_up_event      parsed_peer_up_event_msg;
        lib_parse_bgp_parsed_bmp_peer_down_event    parsed_peer_down_event_msg;
        lib_parse_bgp_parsed_bmp_rm_msg             parsed_rm_msg;
        lib_parse_bgp_parsed_bmp_stat_rep           parsed_stat_rep;
    }lib_parse_bgp_parsed_bmp_msg;
}lib_parse_bgp_parsed_bmp;

#endif //PARSE_LIB_PARSE_BMPV1_H
