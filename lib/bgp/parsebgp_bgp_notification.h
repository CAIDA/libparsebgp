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

#ifndef __PARSEBGP_BGP_NOTIFICATION_H
#define __PARSEBGP_BGP_NOTIFICATION_H

#include <inttypes.h>
#include "parsebgp_error.h"
#include "parsebgp_opts.h"

/**
 * BGP NOTIFICATION Error Codes
 */
typedef enum {

  /** Message Header Error */
  PARSEBGP_BGP_NOTIFY_MSG_HDR_ERR = 1,

  /** OPEN Message Error */
  PARSEBGP_BGP_NOTIFY_OPEN_MSG_ERR = 2,

  /** UPDATE Message Error */
  PARSEBGP_BGP_NOTIFY_UPDATE_MSG_ERR = 3,

  /** Hold Timer Expired */
  PARSEBGP_BGP_NOTIFY_HOLD_TIMER_EXPIRED = 4,

  /** Finite State MAchine Error */
  PARSEBGP_BGP_NOTIFY_FSM_ERR = 5,

  /** Cease */
  PARSEBGP_BGP_NOTIFY_CEASE = 6,

  /** ROUTE-REFRESH Message Error */
  PARSEBGP_BGP_NOTIFY_ROUTE_REFRESH = 7,

} parsebgp_bgp_notification_code_t;

/**
 * BGP NOTIFICATION Message Header Error Subcodes
 */
typedef enum {

  /** Connection Not Synchronized */
  PARSEBGP_BGP_NOTIFY_MSG_HDR_CONN_NOT_SYNC = 1,

  /** Bad Message Length */
  PARSEBGP_BGP_NOTIFY_MSG_HDR_BAD_MSG_LEN = 2,

  /** Bad Message Type */
  PARSEBGP_BGP_NOTIFY_MSG_HDR_BAD_MSG_TYPE = 3,

} parsebgp_bgp_notification_msg_hdr_subcode_t;

/**
 * BGP NOTIFICATION OPEN Message Error Subcodes
 */
typedef enum {

  /** Unsupported Version Number */
  PARSEBGP_BGP_NOTIFY_OPEN_UNSUPPORTED_VER = 1,

  /** Bad Peer AS */
  PARSEBGP_BGP_NOTIFY_OPEN_BAD_PEER_AS = 2,

  /** Bad BGP Identifier */
  PARSEBGP_BGP_NOTIFY_OPEN_BAD_BGP_ID = 3,

  /** Unsupported Optional Parameter */
  PARSEBGP_BGP_NOTIFY_OPEN_UNSUPPORTED_OPT_PARAM = 4,

  /** Code 5: DEPRECATED */

  /** Unacceptable Hold Time */
  PARSEBGP_BGP_NOTIFY_OPEN_UNACCEPTABLE_HOLD_TIME = 5,

} parsebgp_bgp_notification_open_msg_subcode_t;

/**
 * BGP NOTIFICATION UPDATE Message Error Subcodes
 */
typedef enum {

  /** Malformed Attribute List */
  PARSEBGP_BGP_NOTIFY_UPDATE_MALFORMED_ATTR_LIST = 1,

  /** Unrecognized Well-known Attribute */
  PARSEBGP_BGP_NOTIFY_UPDATE_UNRECOGNIZED_WELL_KNOWN_ATTR = 2,

  /** Missing Well-known Attribute */
  PARSEBGP_BGP_NOTIFY_UPDATE_MISSING_WELL_KNOWN_ATTR = 3,

  /** Attribute Flags Error */
  PARSEBGP_BGP_NOTIFY_UPDATE_ATTR_FLAGS_ERROR = 4,

  /** Attribute Length Error */
  PARSEBGP_BGP_NOTIFY_UPDATE_ATTR_LEN_ERROR = 5,

  /** Invalid ORIGIN Attribute */
  PARSEBGP_BGP_NOTIFY_UPDATE_ATTR_INVALID_ORIGIN_ATTR = 6,

  /** Code 7: DEPRECATED */

  /** Invalid NEXT_HOP Attribute */
  PARSEBGP_BGP_NOTIFY_UPDATE_INVALID_NEXT_HOP_ATTR = 8,

  /** Optional Attribute Error */
  PARSEBGP_BGP_NOTIFY_UPDATE_OPT_ATTR_ERROR = 9,

  /** Invalid Network Field */
  PARSEBGP_BGP_NOTIFY_UPDATE_INVALID_NET_FIELD = 10,

  /** Malformed AS_PATH */
  PARSEBGP_BGP_NOTIFY_UPDATE_MALFORMED_AS_PATH = 11,

} parsebgp_bgp_notification_update_msg_subcode_t;

/**
 * BGP NOTIFICATION Cease Subcodes [RFC4486]
 */
typedef enum {

  /** Maximum Number of Prefixes Reached */
  CEASE_MAX_PREFIXES = 1,

  /** Administrative Shutdown */
  CEASE_ADMIN_SHUTDOWN = 2,

  /** Peer De-configured */
  CEASE_PEER_DECONFIG = 3,

  /** Administrative Reset */
  CEASE_ADMIN_RESET = 4,

  /** Connection Rejected */
  CEASE_CONN_REJECT = 5,

  /** Other Configuration Change */
  CEASE_OTHER_CONFIG_CHANGE = 6,

  /** Connection Collision Resolution */
  CEASE_CONN_COLLISION_RES = 7,

  /** Out of Resources */
  CEASE_OUT_OF_RESOURCES = 8,

} parsebgp_bgp_notification_cease_subcode_t;

/**
 * BGP NOTIFICATION ROUTE-REFRESH Message Error Subcodes
 */
typedef enum {

  /** Invalid Message Length */
  PARSEBGP_BGP_NOTIFY_ROUTE_REFRESH_PARSEBGP_INVALID_MSG_LEN = 1,

} parsebgp_bgp_notification_route_refresh_msg_subcode_t;

/**
 * BGP NOTIFICATION Message
 */
typedef struct parsebgp_bgp_notification {

  /** Error Code (parsebgp_bgp_notification_code_t) */
  uint8_t code;

  /** Error Subcode */
  uint8_t subcode;

  /** Error Data */
  uint8_t *data;

  /** Allocated length of Error Data (INTERNAL) */
  int _data_alloc_len;

  /** Length of Error Data (in bytes) */
  int data_len;

} parsebgp_bgp_notification_t;

#endif /* __PARSEBGP_BGP_NOTIFICATION_H */
