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

#ifndef __PARSEBGP_BGP_H
#define __PARSEBGP_BGP_H

#include "parsebgp_bgp_notification.h"
#include "parsebgp_bgp_open.h"
#include "parsebgp_bgp_route_refresh.h"
#include "parsebgp_bgp_update.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * BGP Message Types
 */
typedef enum {

  /** OPEN Message */
  PARSEBGP_BGP_TYPE_OPEN = 1,

  /** UPDATE Message */
  PARSEBGP_BGP_TYPE_UPDATE = 2,

  /** NOTIFICATION Message */
  PARSEBGP_BGP_TYPE_NOTIFICATION = 3,

  /** KEEPALIVE Message */
  PARSEBGP_BGP_TYPE_KEEPALIVE = 4,

  /* ROUTE-REFRESH Message */
  PARSEBGP_BGP_TYPE_ROUTE_REFRESH = 5,

} parsebgp_bgp_msg_type_t;

/**
 * BGP Message
 */
typedef struct parsebgp_bgp_msg {

  /** Marker (always set to all ones) */
  uint8_t marker[16];

  /* Message length (total length of the message, including the header) */
  uint16_t len;

  /** Message type (parsebgp_bgp_msg_type_t) */
  uint8_t type;

  /** Union of structures for all supported BGP message types */
  struct {

    /** OPEN Message (Type 1) */
    parsebgp_bgp_open_t *open;

    /** UPDATE Message (Type 2) */
    parsebgp_bgp_update_t *update;

    /** NOTIFICATION message (Type 3) */
    parsebgp_bgp_notification_t *notification;

    /* KEEPALIVE has no extra data (Type 4) */

    /** ROUTE-REFRESH Message (Type 5) */
    parsebgp_bgp_route_refresh_t *route_refresh;

  } types;

} parsebgp_bgp_msg_t;

/**
 * Decode (parse) a single BGP message from the given buffer into the given BGP
 * message structure.
 *
 * @param [in] opts     Options for the parser
 * @param [in] msg      Pointer to the BGP Message structure to fill
 * @param [in] buffer   Pointer to the start of a raw BGP message
 * @param [in,out] len  Length of the data buffer (used to prevent overrun).
 *                      Updated to the number of bytes read from the buffer.
 * @return PARSEBGP_OK (0) if a message was parsed successfully, or an error
 * code otherwise
 */
parsebgp_error_t parsebgp_bgp_decode(parsebgp_opts_t *opts,
                                     parsebgp_bgp_msg_t *msg, uint8_t *buffer,
                                     size_t *len);

/** Destroy the given BGP message structure
 *
 * @param msg           Pointer to message structure to destroy
 */
void parsebgp_bgp_destroy_msg(parsebgp_bgp_msg_t *msg);

/** Clear the given BGP message structure ready for reuse
 *
 * @param msg           Pointer to message structure to clear
 */
void parsebgp_bgp_clear_msg(parsebgp_bgp_msg_t *msg);

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
void parsebgp_bgp_dump_msg(parsebgp_bgp_msg_t *msg, int depth);

#endif /* __PARSEBGP_BGP_H */
