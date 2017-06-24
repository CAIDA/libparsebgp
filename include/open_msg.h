/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OPENMSG_H_
#define OPENMSG_H_

#include "../include/bgp_common.h"

/**
* Defines the BGP capabilities
*      http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
*/
enum bgp_cap_codes {
      BGP_CAP_MPBGP=1,
      BGP_CAP_ROUTE_REFRESH,
      BGP_CAP_OUTBOUND_FILTER,
      BGP_CAP_MULTI_ROUTES_DEST,

      BGP_CAP_EXT_NEXTHOP=5,                  // RFC 5549

      BGP_CAP_GRACEFUL_RESTART=64,
      BGP_CAP_4OCTET_ASN,

      BGP_CAP_DYN_CAP=67,
      BGP_CAP_MULTI_SESSION,
      BGP_CAP_ADD_PATH,
      BGP_CAP_ROUTE_REFRESH_ENHANCED,
      BGP_CAP_ROUTE_REFRESH_OLD=128
};

/**
* Defines the Add Path BGP capability's send/recieve code
*      https://tools.ietf.org/html/rfc7911#section-4
*/
enum bgp_cap_add_path_send_receive_codes {
      BGP_CAP_ADD_PATH_RECEIVE=1,
      BGP_CAP_ADD_PATH_SEND=2,
      BGP_CAP_ADD_PATH_SEND_RECEIVE=3
};

/**
 * Open message capability value
 */
typedef union capability_value {
    uint32_t asn;
    add_path_capability add_path_data;
    add_path_capability mpbgp_data;
}capability_value;

/**
 * Open message capabilities optional parameters
 */
typedef struct open_capabilities {
  uint8_t cap_code;             ///< Capability code, 1 octect
  uint8_t cap_len;              ///< Capability length, 1 octet
  capability_value cap_values;  ///< Capability values
}open_capabilities;

/**
 * Open message optional parameters
 */
typedef struct open_param {
  uint8_t param_type;                           ///< Parameter type, 1 octet
  uint8_t param_len;                            ///< Parameter length, 1 octet
  uint8_t count_param_val;
  open_capabilities *param_values;    ///< Parameter values
}open_param;

typedef struct libparsebgp_open_msg_data{
  uint8_t           ver;                 ///< Version, currently 4
  uint16_t          asn;                 ///< 2 byte ASN - AS_TRANS = 23456 to indicate 4-octet ASN
  uint16_t          hold_time;           ///< 2 byte hold time - can be zero or >= 3 seconds
  unsigned char     bgp_id[4];           ///< 4 byte bgp id of sender - router_id
  uint8_t           opt_param_len;       ///< optional parameter length - 0 means no params
  uint8_t           count_opt_param;     ///< number of optional parameters
  open_param        *opt_param;          ///< optional parameters
}libparsebgp_open_msg_data;

/**
* Parses an open message
*
* @details
*      Reads the open message from buffer.  The parsed data will be
*      returned via the out params.
*
* @param [in]   open_msg_data       Structure containing parsed open message
* @param [in]   data                Pointer to raw bgp payload data, starting at the notification message
* @param [in]   size                Size of the data parsed_msg.error_textfer, to prevent overrun when reading
* @param [in]   openMessageIsSent   If open message is sent. False if received
*
* @return negative values indicate error, otherwise a positive value indicating the number of bytes read
*/
ssize_t libparsebgp_open_msg_parse_open_msg(libparsebgp_open_msg_data *open_msg_data, u_char **data, size_t size, bool openMessageIsSent);

void libparsebgp_parse_open_msg_destructor(libparsebgp_open_msg_data *open_msg_data);

#endif /* OPENMSG_H_ */
