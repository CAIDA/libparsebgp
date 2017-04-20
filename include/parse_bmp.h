/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */


#ifndef PARSEBMP_H_
#define PARSEBMP_H_

#include <string>
#include "add_path_data_container.h"
#include "parse_utils.h"
#include <list>
#include <vector>
#include <array>
#include "parse_common.h"

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
 * Persistent peer information structure
 *
 *   OPEN and other updates can add/change persistent peer information.
 */
struct peer_info {
    bool sent_four_octet_asn;                               ///< Indicates if 4 (true) or 2 (false) octet ASN is being used (sent cap)
    bool recv_four_octet_asn;                               ///< Indicates if 4 (true) or 2 (false) octet ASN is being used (recv cap)
    bool using_2_octet_asn;                                 ///< Indicates if peer is using two octet ASN format or not (true=2 octet, false=4 octet)
    bool checked_asn_octet_length;                          ///< Indicates if the ASN octet length has been checked or not
    libParseBGP_addpath_map add_path_capability;               ///< Stores data about Add Path capability
    string peer_group;                                      ///< Peer group name of defined
};

/**
 * BMP common header
 */
struct common_hdr_v3 {
    // 4 bytes total for the common header
    //u_char      ver;                // 1 byte; BMP version -- Not part of struct since it's read before

    uint32_t len;                ///< 4 bytes; BMP msg length in bytes including all headers

    /**
     * Type is defined by enum BMP_TYPE
     */
    u_char type;

} __attribute__ ((__packed__));

/**
 * BMP peer header
 */
struct peer_hdr_v3 {
    unsigned char peer_type;           ///< 1 byte
    unsigned char peer_flags;          ///< 1 byte

    unsigned char peer_dist_id[8];     ///< 8 byte peer route distinguisher
    unsigned char peer_addr[16];       ///< 16 bytes
    unsigned char peer_as[4];          ///< 4 byte
    unsigned char peer_bgp_id[4];      ///< 4 byte peer bgp id
    uint32_t ts_secs;             ///< 4 byte timestamp in seconds
    uint32_t ts_usecs;            ///< 4 byte timestamp microseconds

} __attribute__ ((__packed__));

/**
*  BMP headers for older versions (BMPv1)
*/
struct common_hdr_old {
    //unsigned char ver;               // 1 byte -- Not part of struct since it's read before
    unsigned char type;                // 1 byte
    unsigned char peer_type;           // 1 byte
    unsigned char peer_flags;          // 1 byte

    unsigned char peer_dist_id[8];     // 8 byte peer distinguisher
    unsigned char peer_addr[16];       // 16 bytes
    unsigned char peer_as[4];          // 4 byte
    unsigned char peer_bgp_id[4];      // 4 byte peer bgp id
    unsigned long ts_secs : 32;        // 4 byte timestamp in seconds
    unsigned long ts_usecs : 32;       // 4 byte timestamp microseconds
} __attribute__ ((__packed__));


struct libParseBGP_parse_bmp_parsed_data {
    /**
 * BMP message buffer (normally only contains the BGP message)
 *      BMP data message is read into this buffer so that it can be passed to the BGP parser for handling.
 *      Complete BGP message is read, otherwise error is generated.
 */
    u_char bmp_data[BMP_PACKET_BUF_SIZE + 1];
    size_t bmp_data_len;              ///< Length/size of data in the data buffer

    /**
     * BMP packet buffer - This is a copy of the BMP packet.
     *
     * Only BMPv3 messages get stored in the packet buffer since it wasn't until
     * BMPv3 that the length was specified.
     *
     * Length of packet is the common header message length (bytes)
     */
    u_char bmp_packet[BMP_PACKET_BUF_SIZE + 1];
    size_t bmp_packet_len;
    obj_bgp_peer p_entry;         ///< peer table entry - will be updated with BMP info
    obj_router r_entry;
    obj_peer_down_event down_event;
    obj_peer_up_event up_event;
    obj_stats_report stats;
    parsed_bgp_msg bgp_msg;
    common_hdr_v3 c_hdr_v3;
    common_hdr_old c_hdr_old;

    char bmp_type;                   ///< The BMP message type
    uint32_t bmp_len;                    ///< Length of the BMP message - does not include the common header size

    // Storage for the byte converted strings - This must match the MsgBusInterface bgp_peer struct
    char peer_addr[40];                         ///< Printed format of the peer address (Ipv4 and Ipv6)
    char peer_as[32];                           ///< Printed format of the peer ASN
    char peer_rd[32];                           ///< Printed format of the peer RD
    char peer_bgp_id[16];                       ///< Printed format of the peer bgp ID
    std::map<std::string, peer_info> peer_info_map;
};


//############################################################################
/**
* BMP initiation message
*/
struct init_msg_v3 {
    uint16_t type;              ///< 2 bytes - Information type
    uint16_t len;               ///< 2 bytes - Length of the information that follows

    char *info;              ///< Information - variable

} __attribute__ ((__packed__));


/**
 * BMP termination message
 */
struct term_msg_v3 {
    uint16_t type;              ///< 2 bytes - Information type
    uint16_t len;               ///< 2 bytes - Length of the information that follows

    char *info;              ///< Information - variable

} __attribute__ ((__packed__));

/**
 * Read messages from buffer
 *
 * BMP routers send BMP/BGP messages, this method reads and parses those.
 *
 * \param [in]  buffer       Buffer containing BMP message
 * \param [in]  buf_len       length of the buffer
 * \return true if more to read, false if the connection is done/closed
 */
uint8_t libParseBGP_parse_bmp_parse_msg(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char *&buffer,
                                     int buf_len);

//typedef std::map<std::string, bmp_message::peer_info>::iterator peer_info_map_iter;

libParseBGP_parse_bmp_parsed_data parse_bmp_wrapper(unsigned char *buffer, int buf_len);

#endif /* PARSEBMP_H_ */
