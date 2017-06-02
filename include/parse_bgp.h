/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

/**
 * @file   parse_bgp.cpp
 *
 * @brief   Parser for BGP messages
 * @details This file has functions that can be used as needed to parse a complete BGP message.
 *          BGP message can be read from a buffer
 */

#ifndef PARSEBGP_H_
#define PARSEBGP_H_

#include <vector>
#include <list>
#include "bgp_common.h"
#include "update_msg.h"
#include "open_msg.h"
#include "notification_msg.h"


using namespace std;

/**
 * Below defines the common BGP header per RFC4271
 */
enum bgp_msg_types { BGP_MSG_OPEN=1, BGP_MSG_UPDATE, BGP_MSG_NOTIFICATION, BGP_MSG_KEEPALIVE, BGP_MSG_ROUTE_REFRESH };

struct libparsebgp_common_bgp_hdr {
    uint8_t   marker[16];                           ///< 16-octet field is included for compatibility. All ones (required).
    uint16_t  len;                           ///< Total length of the message, including the header in octets. min length is 19, max is 4096
    uint8_t   type;                          ///< type code of the message
}__attribute__((__packed__));

/**
 * This struct holds the parsed BGP data according to RFC 4271
 */
typedef struct libparsebgp_parse_bgp_parsed_data {
    libparsebgp_common_bgp_hdr c_hdr;               ///< Has the bgp common header
    //union needed
    struct parsed_bgp_data {
        libparsebgp_open_msg_data open_msg;         ///< Stores the open message
        libparsebgp_update_msg_data update_msg;     ///< Stores update message
        libparsebgp_notify_msg notification_msg;    ///< Stores notification message
    }parsed_data;
    bool has_end_of_rib_marker;                     ///< Indicates whether this message has the end of rib marker
}libparsebgp_parse_bgp_parsed_data;

/**
 * Function to parse raw BGP message from data
 *
 * @param bgp_parsed_data   Struct holding BGP data
 * @param data              Buffer containing raw data
 * @param size              Size of buffer (data)
 * @param is_local_msg      Specifies if the message is local or remote
 *
 * @return the number of bytes read
 */
ssize_t libparsebgp_parse_bgp_parse_msg(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *&data, size_t size, bool is_local_msg = true);


/**
 * Handle BGP update message
 *
 * @details Parses the bgp update message.
 * @param [in]     bgp_update_msg   Struct to hold parsed BGP message
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent overrun)

 *
 * \returns number of bytes read
 */
ssize_t libparsebgp_parse_bgp_handle_update(libparsebgp_parse_bgp_parsed_data &bgp_update_msg, u_char *data, size_t size);

/**
 * handle BGP notify event
 *
 * @details
 *  Function to parse notification message
 *
 * @param [in]     data                 Pointer to the raw BGP message header
 * @param [in]     size                 length of the data buffer (used to prevent overrun)
 * @param [out]    bgp_parsed_data      Structure holding parsed BGP data
 *
 * @returns number of bytes read
 */
ssize_t libparsebgp_parse_bgp_handle_down_event(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *data, size_t size);

/**
 * Parses the BGP common header
 *
 * @details
 *      This method will parse the bgp common header and will upload the global
 *      c_hdr structure, instance data pointer.
 *      The return value of this method will be the BGP message type.
 *
 * @param [in]      data                Pointer to the raw BGP message header
 * @param [in]      size                length of the data buffer (used to prevent overrun)
 * @param [in]      c_hdr               Struct to store common bgp header
 *
 * @returns Bytes read in parsing the header
 */
ssize_t libparsebgp_parse_bgp_parse_header(libparsebgp_common_bgp_hdr &c_hdr, u_char *data, size_t size);

#endif /* PARSEBGP_H_ */
