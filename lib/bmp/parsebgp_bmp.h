#ifndef __PARSEBGP_BMP_H
#define __PARSEBGP_BMP_H

#include "parsebgp_error.h" //< for parsebgp_error_t
#include "bgp/parsebgp_bgp.h" //< BMP encapsulates BGP messages
#include <inttypes.h>

/**
 * BMP common header types
 */
enum bmp_type {
  TYPE_ROUTE_MON = 0,
  TYPE_STATS_REPORT,
  TYPE_PEER_DOWN,
  TYPE_PEER_UP,
  TYPE_INIT_MSG,
  TYPE_TERM_MSG
};

/**
 * BMP stats types
 */
enum bmp_stats {
  STATS_PREFIX_REJ = 0,
  STATS_DUP_PREFIX,
  STATS_DUP_WITHDRAW,
  STATS_INVALID_CLUSTER_LIST,
  STATS_INVALID_AS_PATH_LOOP,
  STATS_INVALID_ORIGINATOR_ID,
  STATS_INVALID_AS_CONFED_LOOP,
  STATS_NUM_ROUTES_ADJ_RIB_IN,
  STATS_NUM_ROUTES_LOC_RIB
};

/**
 * BMP Initiation Message Types
 */
enum bmp_init_types {
  INIT_TYPE_FREE_FORM_STRING = 0,
  INIT_TYPE_SYSDESCR,
  INIT_TYPE_SYSNAME,
  INIT_TYPE_ROUTER_BGP_ID = 65531
};

/**
 * BMP Termination Message Types
 */
enum bmp_term_types { TERM_TYPE_FREE_FORM_STRING = 0, TERM_TYPE_REASON };

/**
 * BMP Termination Message reasons for type=1
 */
enum bmp_term_type1_reason {
  TERM_REASON_ADMIN_CLOSE = 0,
  TERM_REASON_UNSPECIFIED,
  TERM_REASON_OUT_OF_RESOURCES,
  TERM_REASON_REDUNDANT_CONN,
  TERM_REASON_OPENBMP_CONN_CLOSED = 65533,
  TERM_REASON_OPENBMP_CONN_ERR = 65534
};

/**
 * BMP peer header
 */
typedef struct libparsebgp_parsed_peer_hdr_v3 {
  uint8_t peer_type;             ///< 1 byte peer type
  uint8_t peer_flags;            ///< 1 byte peer flags
  unsigned char peer_dist_id[8]; ///< 8 byte peer route distinguisher
  unsigned char peer_addr[16];   ///< 16 bytes IP address of peer
  uint32_t peer_as;              ///< 4 byte peer AS number
  unsigned char peer_bgp_id[4];  ///< 4 byte peer bgp id
  uint32_t ts_secs;              ///< 4 byte timestamp in seconds
  uint32_t ts_usecs;             ///< 4 byte timestamp microseconds
} __attribute__((__packed__)) libparsebgp_parsed_peer_hdr_v3;

/**
 *  BMP headers for older versions (BMPv1)
 */
typedef struct __attribute__((__packed__)) common_hdr_bmp_old {
  uint8_t type;                  ///< 1 byte message type
  uint8_t peer_type;             ///< 1 byte peer type
  uint8_t peer_flags;            ///< 1 byte peer flag
  unsigned char peer_dist_id[8]; ///< 8 byte peer distinguisher
  unsigned char peer_addr[16];   ///< 16 bytes peer IP address
  uint32_t peer_as;              ///< 4 byte peer AS number
  unsigned char peer_bgp_id[4];  ///< 4 byte peer bgp id
  uint32_t ts_secs;              ///< 4 byte timestamp in seconds
  uint32_t ts_usecs;             ///< 4 byte timestamp microseconds
  uint8_t ver;                   ///< 1 byte -- At last since it's read before
} common_hdr_bmp_old;

/**
 * BMP common header
 */
typedef struct common_hdr_bmp_v3 { ///< 6 bytes total length for the common
                                   ///< header
  uint8_t ver;                     ///< 1 byte; version of BMP header
  uint32_t len; ///< 4 bytes; BMP msg length in bytes including all headers
  uint8_t type; ///< 1 byte; BMP Msg type
} common_hdr_bmp_v3;

/**
 * BMP initiation message TLV
 */
typedef struct init_msg_v3_tlv {
  uint16_t type;   ///< 2 bytes - Information type
  uint16_t len;    ///< 2 bytes - Length of the information that follows
  char info[4096]; ///< Information - variable
} init_msg_v3_tlv;

/**
 * BMP initiation message: This can contain multiple init - tlvs
 */
typedef struct libparsebgp_parsed_bmp_init_msg {
  uint32_t num_tlvs;
  init_msg_v3_tlv *init_msg_tlvs; ///< list of init message tlvs
} libparsebgp_parsed_bmp_init_msg;

/**
 * BMP termination message
 */
typedef struct term_msg_v3_tlv {
  uint16_t type;   ///< 2 bytes - Information type
  uint16_t len;    ///< 2 bytes - Length of the information that follows
  char info[4096]; ///< Information - variable
} term_msg_v3_tlv;

/**
 * BMP termination message: This can contain multiple term - tlvs
 */
typedef struct libparsebgp_parsed_bmp_term_msg {
  uint32_t num_tlvs;
  term_msg_v3_tlv *term_msg_tlvs; ///< list of term message tlvs
} libparsebgp_parsed_bmp_term_msg;

/**
 * OBJECT: peer_up_events
 *
 * Peer Up Events schema
 */
typedef struct libparsebgp_parsed_bmp_peer_up_event {
  char local_ip[16];    ///< IPv4 or IPv6 printed IP address
  uint16_t local_port;  ///< Local port number
  uint16_t remote_port; ///< Remote port number
  libparsebgp_parse_bgp_parsed_data sent_open_msg; ///< sent open message
  libparsebgp_parse_bgp_parsed_data
    received_open_msg; ///< received open message
} libparsebgp_parsed_bmp_peer_up_event;

/**
 * OBJECT: peer_down_events
 *
 * Peer Down Events schema
 */
typedef struct libparsebgp_parsed_bmp_peer_down_event {
  uint8_t bmp_reason;                           ///< BMP notify reason
  libparsebgp_parse_bgp_parsed_data notify_msg; ///< BGP notification message
} libparsebgp_parsed_bmp_peer_down_event;

/**
 * BMP stat counter
 */
typedef struct stat_counter {
  uint16_t stat_type;   ///< 2 bytes - Information type
  uint16_t stat_len;    ///< 2 bytes - Length of the information that follows
  uint8_t stat_data[8]; ///< Information - variable
} stat_counter;

/**
 * OBJECT: stats_reports
 *
 * Stats Report schema
 */
typedef struct libparsebgp_parsed_bmp_stat_rep {
  uint32_t stats_count;              ///< 4 bytes - Stats Count
  stat_counter *total_stats_counter; ///< 2 bytes - Information type
} libparsebgp_parsed_bmp_stat_rep;

/**
 * BMP Message Structure
 */
typedef struct libparsebgp_parsed_bmp_parsed_data {
  uint8_t version; ///< Version of BMP header
  uint8_t bmp_type;
  union libparsebgp_parsed_bmp_hdr {
    common_hdr_bmp_v3 c_hdr_v3;   ///< structure for bmp header version 3
    common_hdr_bmp_old c_hdr_old; ///< structure for bmp header version 1 or 2
  } libparsebgp_parsed_bmp_hdr;   ///< union of BMP common header

  libparsebgp_parsed_peer_hdr_v3
    libparsebgp_parsed_peer_hdr; ///< structure for BMP peer header

  union libparsebgp_parsed_bmp_msg {
    libparsebgp_parsed_bmp_init_msg
      parsed_init_msg; ///< structure for bmp init msg
    libparsebgp_parsed_bmp_term_msg
      parsed_term_msg; ///< structure for bmp term msg
    libparsebgp_parsed_bmp_peer_up_event
      parsed_peer_up_event_msg; ///< structure for bmp peer up event msg
    libparsebgp_parsed_bmp_peer_down_event
      parsed_peer_down_event_msg; ///< structure for bmp peer down event msg
    libparsebgp_parse_bgp_parsed_data
      parsed_rm_msg; ///< structure for bmp route monitoring msg
    libparsebgp_parsed_bmp_stat_rep
      parsed_stat_rep;          ///< structure for bmp stats report msg
  } libparsebgp_parsed_bmp_msg; ///< Union of BMP messages
} libparsebgp_parse_bmp_parsed_data;

/** Destroy the given BMP message structure
 *
 * @param msg           Pointer to message structure to destroy
 *
 * This function *does not* free the passed structure itself as it is assumed to
 * be a member of a parsebgp_msg_t structure.
 */
void parsebgp_bmp_destroy_msg(libparsebgp_parse_bmp_parsed_data *msg);

/**
 * Decode (parse) a single BMP message from the given buffer into the given BMP
 * message structure.
 *
 * @param [in] msg      Pointer to the BMP Message structure to fill
 * @param [in] buffer   Pointer to the start of a raw BGP message
 * @param [in,out] len  Length of the data buffer (used to prevent overrun).
 *                      Updated to the number of bytes read from the buffer.
 * @return OK (0) if a message was parsed successfully, or an error code
 * otherwise
 */
parsebgp_error_t parsebgp_bmp_decode(libparsebgp_parse_bmp_parsed_data *msg,
                                     uint8_t *buffer, size_t *len);

#endif /* __PARSEBGP_BMP_H */
