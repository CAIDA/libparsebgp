/*
 * Copyright (C) 2017 The Regents of the University of California.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PARSEBGP_BMP_H
#define __PARSEBGP_BMP_H

#include "parsebgp_bgp.h"   // BMP encapsulates BGP messages
#include "parsebgp_error.h" // for parsebgp_error_t
#include <inttypes.h>
#include <stddef.h>

/* -------------------- Info TLV -------------------- */

/**
 * BMP Info TLV Types
 */
typedef enum parsebgp_bmp_info_tlv_type {

  /** The information is a free form UTF-8 string (not nul-terminated). */
  PARSEBGP_BMP_INFO_TLV_TYPE_STRING = 0,

  /** The information is an ASCII string equal to the sysDescr MIB-II [RFC1213]
      object (not nul-terminated) */
  PARSEBGP_BMP_INFO_TLV_TYPE_SYSDESCR = 1,

  /** The information is an ASCII string equal to the sysName MIB-II [RFC1213]
      object (not nul-terminated) */
  PARSEBGP_BMP_INFO_TLV_TYPE_SYSNAME = 2,

} parsebgp_bmp_info_tlv_type_t;

/**
 * BMP Information TLV
 */
typedef struct parsebgp_bmp_info_tlv {

  /** Type of the information in the TLV (parsebgp_bmp_info_tlv_type_t) */
  uint16_t type;

  /** Length of the information in the following field */
  uint16_t len;

  /** Variable length information
   *
   * Note that while this is currently an ASCII or UTF-8 string, it is **not**
   * null terminated, so care should be taken with it (hence why it is a uint8_t
   * array and not a char array).
   */
  uint8_t *info;

  /** Length of the allocated info buffer (INTERNAL) */
  int _info_alloc_len;

} parsebgp_bmp_info_tlv_t;

/*  -------------------- Stats Report (Type 1) -------------------- */

/**
 * BMP stats types
 */
typedef enum parsebgp_bmp_stat_counter_type {

  /** Stat Type = 0: (32-bit Counter) Number of prefixes rejected by
      inbound policy. */
  PARSEBGP_BMP_STATS_PREFIX_REJECTS = 0,

  /** Stat Type = 1: (32-bit Counter) Number of (known) duplicate prefix
      advertisements. */
  PARSEBGP_BMP_STATS_PREFIX_DUPS = 1,

  /** Stat Type = 2: (32-bit Counter) Number of (known) duplicate
      withdraws. */
  PARSEBGP_BMP_STATS_WITHDRAW_DUP = 2,

  /** Stat Type = 3: (32-bit Counter) Number of updates invalidated due
      to CLUSTER_LIST loop. */
  PARSEBGP_BMP_STATS_INVALID_CLUSTER_LIST = 3,

  /** Stat Type = 4: (32-bit Counter) Number of updates invalidated due
      to AS_PATH loop. */
  PARSEBGP_BMP_STATS_INVALID_AS_PATH_LOOP = 4,

  /** Stat Type = 5: (32-bit Counter) Number of updates invalidated due
      to ORIGINATOR_ID. */
  PARSEBGP_BMP_STATS_INVALID_ORIGINATOR_ID = 5,

  /** Stat Type = 6: (32-bit Counter) Number of updates invalidated due
      to AS_CONFED loop. */
  PARSEBGP_BMP_STATS_INVALID_AS_CONFED_LOOP = 6,

  /** Stat Type = 7: (64-bit Gauge) Number of routes in Adj-RIBs-In. */
  PARSEBGP_BMP_STATS_ROUTES_ADJ_RIB_IN = 7,

  /** Stat Type = 8: (64-bit Gauge) Number of routes in Loc-RIB. */
  PARSEBGP_BMP_STATS_ROUTES_LOC_RIB = 8,

  /** Stat Type = 9: Number of routes in per-AFI/SAFI Adj-RIB-In.  The value is
      structured as: 2-byte Address Family Identifier (AFI), 1-byte Subsequent
      Address Family Identifier (SAFI), followed by a 64-bit Gauge. */
  PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_ADJ_RIB_IN = 9,

  /** Stat Type = 10: Number of routes in per-AFI/SAFI Loc-RIB.  The value is
      structured as: 2-byte AFI, 1-byte SAFI, followed by a 64-bit Gauge. */
  PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_LOC_RIB = 10,

  /** Stat Type = 11: (32-bit Counter) Number of updates subjected to
      treat-as-withdraw treatment [RFC7606]. */
  PARSEBGP_BMP_STATS_UPD_TREAT_AS_WITHDRAW = 11,

  /** Stat Type = 12: (32-bit Counter) Number of prefixes subjected to
      treat-as-withdraw treatment [RFC7606]. */
  PARSEBGP_BMP_STATS_PREFIX_TREAT_AS_WITHDRAW = 12,

  /** Stat Type = 13: (32-bit Counter) Number of duplicate update
      messages received. */
  PARSEBGP_BMP_STATS_DUP_UPD = 13,

} parsebgp_bmp_stat_counter_type_t;

typedef struct parsebgp_bmp_stats_counter_afi_safi_gauge {

  /** AFI */
  uint16_t afi;

  /** SAFI */
  uint8_t safi;

  /** Unsigned 64-bit gauge */
  uint64_t gauge_u64;

} parsebgp_bmp_stats_counter_afi_safi_gauge_t;

/**
 * BMP Stats Counter
 */
typedef struct stat_counter {

  /** Stat Counter Type (parsebgp_bmp_stat_counter_type_t) */
  uint16_t type;

  /** Length of the Stat Counter data field (either 4 or 8 in v3) */
  uint16_t len;

  union {

    /** Unsigned 32-bit counter */
    uint32_t counter_u32;

    /** Unsigned 64-bit gauge */
    uint64_t gauge_u64;

    /** Special AFI/SAFI Gauge used for Types 9 and 10 */
    parsebgp_bmp_stats_counter_afi_safi_gauge_t afi_safi_gauge;

  } data;

} parsebgp_bmp_stats_counter_t;

/**
 * BMP Stats Report
 */
typedef struct parsebgp_bmp_stats_report {

  /** Number of stats "counters" in this report */
  uint32_t stats_count;

  /** Array of stats counters (with stats_count elements) */
  parsebgp_bmp_stats_counter_t *counters;

  /** Number of allocated counters (INTERNAL) */
  int _counters_alloc_cnt;

} parsebgp_bmp_stats_report_t;

/*  -------------------- Peer Down (Type 2) -------------------- */

/** BMP Peer Down Notification Reason */
typedef enum {

  /** Reason 1: The local system closed the session. Following the Reason is a
      BGP PDU containing a BGP NOTIFICATION message that would have been sent to
      the peer. */
  PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF = 1,

  /** Reason 2: The local system closed the session.  No notification message
      was sent.  Following the reason code is a 2-byte field containing the code
      corresponding to the Finite State Machine (FSM) Event that caused the
      system to close the session (see Section 8.1 of [RFC4271]). */
  PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE = 2,

  /** Reason 3: The remote system closed the session with a notification
      message.  Following the Reason is a BGP PDU containing the BGP
      NOTIFICATION message as received from the peer. */
  PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF = 3,

  /** Reason 4: The remote system closed the session without a notification
      message.  This includes any unexpected termination of the transport
      session, so in some cases both the local and remote systems might consider
      this to apply. */
  PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE = 4,

  /** Reason 5: Information for this peer will no longer be sent to the
      monitoring station for configuration reasons.  This does not, strictly
      speaking, indicate that the peer has gone down, but it does indicate that
      the monitoring station will not receive updates for the peer. */
  PARSEBGP_BMP_PEER_DOWN_CONFIG = 5,

} parsebgp_bmp_peer_down_reason_t;

/**
 * BMP Peer Down Notification
 */
typedef struct parsebgp_bmp_peer_down {

  /** Reason why the session was closed (parsebgp_bmp_peer_down_reason_t) */
  uint8_t reason;

  struct {

    /** FSM Event that caused the system to close the connection */
    uint16_t fsm_code;

    /** BGP NOTIFICATION message (as sent-to, or recv-from the peer) */
    parsebgp_bgp_msg_t *notification;

  } data;

} parsebgp_bmp_peer_down_t;

/*  -------------------- Peer Up (Type 3) -------------------- */

/**
 * BMP Peer Up Notification
 */
typedef struct parsebgp_bmp_peer_up {

  /** Local IP address associated with the peering connection */
  uint8_t local_ip[16];

  /** (Inferred) Local IP Address AFI (based on peer header flags) */
  parsebgp_bgp_afi_t local_ip_afi;

  /** Local port associated with the connection */
  uint16_t local_port;

  /** Remote port number associated with the connection */
  uint16_t remote_port;

  /** OPEN Message sent to the peer (sent_open) */
  parsebgp_bgp_msg_t *sent_open;

  /** OPEN Message received from the peer (recv_open) */
  parsebgp_bgp_msg_t *recv_open;

  /** Array of TLVs present (may be empty) */
  parsebgp_bmp_info_tlv_t *tlvs;

  /** Number of allocated TLVs (INTERNAL) */
  int _tlvs_alloc_cnt;

  /** Number of TLVs present (may be zero) */
  int tlvs_cnt;

} parsebgp_bmp_peer_up_t;

/*  -------------------- Init Msg (Type 4) -------------------- */

/**
 * BMP initiation message: This can contain multiple information TLVs
 */
typedef struct parsebgp_bmp_init_msg {

  /** Array of TLVs present in the init message */
  parsebgp_bmp_info_tlv_t *tlvs;

  /** Number of allocated TLVs (INTERNAL) */
  int _tlvs_alloc_cnt;

  /** Number of TLVs present */
  int tlvs_cnt;

} parsebgp_bmp_init_msg_t;

/*  -------------------- Term Msg (Type 5) -------------------- */

typedef enum {

  /** Reason = 0: Session administratively closed.  The session might be
      re-initiated. */
  PARSEBGP_BMP_TERM_REASON_ADMIN_CLOSE = 0,

  /** Reason = 1: Unspecified reason. */
  PARSEBGP_BMP_TERM_REASON_UNSPEC = 1,

  /** Reason = 2: Out of resources.  The router has exhausted resources
      available for the BMP session. */
  PARSEBGP_BMP_TERM_REASON_RESOURCES = 2,

  /** Reason = 3: Redundant connection.  The router has determined that this
      connection is redundant with another one. */
  PARSEBGP_BMP_TERM_REASON_REDUNDANT_CONN = 3,

  /** Reason = 4: Session permanently administratively closed, will not be
      re-initiated. */
  PARSEBGP_BMP_TERM_REASON_ADMIN_CLOSE_PERM = 4,

} parsebgp_bmp_term_reason_t;

typedef enum {

  /** String: Free-form UTF-8 string (Type 0) */
  PARSEBGP_BMP_TERM_INFO_TYPE_STRING = 0,

  /** Reason: 2-byte reason code (Type 1) (parsebgp_bmp_term_reason_t) */
  PARSEBGP_BMP_TERM_INFO_TYPE_REASON = 1,

} parsebgp_bmp_term_info_type_t;

/** BMP Termination Information TLV */
typedef struct parsebgp_bmp_term_tlv {

  /** Information Type (parsebgp_bmp_term_info_type_t) */
  uint16_t type;

  /** Information Length */
  uint16_t len;

  struct {

    /** PARSEBGP_BMP_TERM_INFO_TYPE_STRING (nul-terminated) */
    char *string;

    /** Allocated length of "string" (INTERNAL) */
    int _string_alloc_len;

    /** PARSEBGP_BMP_TERM_INFO_TYPE_REASON */
    uint16_t reason;

  } info;

} parsebgp_bmp_term_tlv_t;

/**
 * BMP termination message: This can contain multiple information TLVs
 */
typedef struct parsebgp_bmp_term_msg {

  /** Array of TLVs present in the term message */
  parsebgp_bmp_term_tlv_t *tlvs;

  /** Number of allocated TLVs (INTERNAL) */
  int _tlvs_alloc_cnt;

  /** Number of TLVs present */
  int tlvs_cnt;

} parsebgp_bmp_term_msg_t;

/*  -------------------- Route Mirror (Type 6) -------------------- */

/** Route Mirror TLV Types */
typedef enum {

  /** BGP Message */
  PARSEBGP_BMP_ROUTE_MIRROR_TYPE_BGP_MSG = 0,

  /** Information */
  PARSEBGP_BMP_ROUTE_MIRROR_TYPE_INFO = 1,

} parsebgp_bmp_route_mirror_type_t;

/** Route Mirror Information Codes */
typedef enum {

  /** Errored PDU */
  PARSEBGP_BMP_ROUTE_MIRROR_INFO_ERROR_PDU = 0,

  /** Messages Lost */
  PARSEBGP_BMP_ROUTE_MIRROR_INFO_MSG_LOST = 1,

} parsebgp_bmp_route_mirror_info_code_t;

/** Route Mirror TLV */
typedef struct parsebgp_bmp_route_mirror_tlv {

  /** Type */
  uint16_t type;

  /** Length */
  uint16_t len;

  /** Values */
  struct {

    /** BGP PDU */
    parsebgp_bgp_msg_t *bgp_msg;

    /** Information Code (parsebgp_bmp_route_mirror_info_code_t) */
    uint16_t code;

  } values;

} parsebgp_bmp_route_mirror_tlv_t;

/** Route Mirror Message */
typedef struct parsebgp_bmp_route_mirror {

  /** Array of (tlvs_cnt) Route Mirroring TLVs */
  parsebgp_bmp_route_mirror_tlv_t *tlvs;

  /** Number of allocated TLVs (INTERNAL) */
  int _tlvs_alloc_cnt;

  /** (Inferred) number of TLVs */
  int tlvs_cnt;

} parsebgp_bmp_route_mirror_t;

/*  -------------------- Common Headers -------------------- */

/**
 * BMP Peer Flags
 */
typedef enum parsebgp_bmp_peer_flag {

  /** IPv6 Peer Address */
  PARSEBGP_BMP_PEER_FLAG_IPV6 = 0x80,

  /** Post-Policy Adj-RIB-In (i.e., not pre-policy) */
  PARSEBGP_BMP_PEER_FLAG_POST_POLICY = 0x40,

  /** Legacy 2-byte AS_PATH format */
  PARSEBGP_BMP_PEER_FLAG_2_BYTE_AS_PATH = 0x20,

} parsebgp_bmp_peer_flag_t;

/**
 * BMP peer header
 */
typedef struct parsebgp_bmp_peer_hdr {

  /** Peer Type */
  uint8_t type;

  /** Peer Flags */
  uint8_t flags;

  /** Peer Route Distinguisher */
  uint64_t dist_id;

  /** Peer IP Address */
  uint8_t addr[16];

  /** (Inferred) Peer IP AFI (based on flags) */
  parsebgp_bgp_afi_t afi;

  /** Peer ASN */
  uint32_t asn;

  /** Peer BGP ID */
  uint8_t bgp_id[4];

  /** Time (seconds portion) when the routes were received */
  uint32_t ts_sec;

  /** Time (microseconds portion) when the routes were received */
  uint32_t ts_usec;

} parsebgp_bmp_peer_hdr_t;

/**
 * BMP common header types
 */
typedef enum parsebgp_bmp_msg_type {

  /** Type = 0: Route Monitoring */
  PARSEBGP_BMP_TYPE_ROUTE_MON = 0,

  /** Type = 1: Statistics Report */
  PARSEBGP_BMP_TYPE_STATS_REPORT = 1,

  /** Type = 2: Peer Down Notification */
  PARSEBGP_BMP_TYPE_PEER_DOWN = 2,

  /** Type = 3: Peer Up Notification */
  PARSEBGP_BMP_TYPE_PEER_UP = 3,

  /** Type = 4: Initiation Message */
  PARSEBGP_BMP_TYPE_INIT_MSG = 4,

  /** Type = 5: Termination Message */
  PARSEBGP_BMP_TYPE_TERM_MSG = 5,

  /** Type = 6: Route Mirroring Message */
  PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG = 6,

} parsebgp_bmp_msg_type_t;

/*  -------------------- Main BMP Message -------------------- */

/**
 * BMP Message Structure
 *
 * This structure is based on BMP message format version 3, but the parser also
 * supports versions 1 and 2. In the case of a v1/v2 message, the length field
 * is filled with an inferred value once the entire message has been parsed.
 * parsed.
 */
typedef struct parsebgp_bmp_msg {

  /** BMP Version */
  uint8_t version;

  /** Message length including all headers */
  uint32_t len;

  /** Message Type (parsebgp_bmp_msg_type_t) */
  uint8_t type;

  /** Peer header (Not filled for TYPE_INIT_MSG and TYPE_TERM_MSG) */
  parsebgp_bmp_peer_hdr_t peer_hdr;

  /** Set if the message was fully parsed and the types structure can
   * be used. If this is not set, then only a shallow parse was
   * performed, so only the common header and peer header fields have
   * been populated. */
  int types_valid;

  /** Union of structures for all supported BMP message types */
  struct {

    /** 0: PARSEBGP_BMP_TYPE_ROUTE_MON: Route Monitoring */
    parsebgp_bgp_msg_t *route_mon;

    /** 1: PARSEBGP_BMP_TYPE_STATS_REPORT: Stats Report */
    parsebgp_bmp_stats_report_t *stats_report;

    /** 2: PARSEBGP_BMP_TYPE_PEER_DOWN: Peer Down Message */
    parsebgp_bmp_peer_down_t *peer_down;

    /** 3: PARSEBGP_BMP_TYPE_PEER_UP: Peer Up Message */
    parsebgp_bmp_peer_up_t *peer_up;

    /** 4: PARSEBGP_BMP_TYPE_INIT_MSG: Initiation Message */
    parsebgp_bmp_init_msg_t *init_msg;

    /** 5: PARSEBGP_BMP_TYPE_TERM_MSG: Termination Message */
    parsebgp_bmp_term_msg_t *term_msg;

    /** 6: PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG: Route Mirroring */
    parsebgp_bmp_route_mirror_t *route_mirror;

  } types;

} parsebgp_bmp_msg_t;

/**
 * Decode (parse) a single BMP message from the given buffer into the given BMP
 * message structure.
 *
 * @param [in] opts     Options for the parser
 * @param [in] msg      Pointer to the BMP Message structure to fill
 * @param [in] buffer   Pointer to the start of a raw BMP message
 * @param [in,out] len  Length of the data buffer (used to prevent overrun).
 *                      Updated to the number of bytes read from the buffer.
 * @return PARSEBGP_OK (0) if a message was parsed successfully, or an error
 * code otherwise
 */
parsebgp_error_t parsebgp_bmp_decode(parsebgp_opts_t *opts,
                                     parsebgp_bmp_msg_t *msg, const uint8_t *buffer,
                                     size_t *len);

/** Destroy the given BMP message structure
 *
 * @param msg           Pointer to message structure to destroy
 */
void parsebgp_bmp_destroy_msg(parsebgp_bmp_msg_t *msg);

/** Clear the given BMP message structure ready for reuse
 *
 * @param msg           Pointer to message structure to clear
 */
void parsebgp_bmp_clear_msg(parsebgp_bmp_msg_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed message to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bmp_dump_msg(const parsebgp_bmp_msg_t *msg, int depth);

#endif /* __PARSEBGP_BMP_H */
