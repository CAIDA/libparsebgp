#ifndef __PARSEBGP_BGP_H
#define __PARSEBGP_BGP_H

#include "parsebgp_bgp_notification.h"
#include "parsebgp_bgp_open.h"
#include "parsebgp_bgp_opts.h"
#include "parsebgp_bgp_route_refresh.h"
#include "parsebgp_bgp_update.h"
#include "parsebgp_error.h"
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
  union {

    /** OPEN Message (Type 1) */
    parsebgp_bgp_open_t open;

    /** UPDATE Message (Type 2) */
    parsebgp_bgp_update_t update;

    /** NOTIFICATION message (Type 3) */
    parsebgp_bgp_notification_t notification;

    /* KEEPALIVE has no extra data (Type 4) */

    /** ROUTE-REFRESH Message (Type 5) */
    parsebgp_bgp_route_refresh_t route_refresh;

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
 * @return OK (0) if a message was parsed successfully, or an error code
 * otherwise
 */
parsebgp_error_t parsebgp_bgp_decode(parsebgp_bgp_opts_t opts,
                                     parsebgp_bgp_msg_t *msg,
                                     uint8_t *buffer, size_t *len);

/** Destroy the given BGP message structure
 *
 * @param msg           Pointer to message structure to destroy
 *
 * This function *does not* free the passed structure itself as it is assumed to
 * be a member of a parsebgp_msg_t structure.
 */
void parsebgp_bgp_destroy_msg(parsebgp_bgp_msg_t *msg);

#endif /* __PARSEBGP_BGP_H */
