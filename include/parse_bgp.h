/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef PARSEBGP_H_
#define PARSEBGP_H_

#include <vector>
#include <list>
#include "bgp_common.h"
#include "update_msg.h"


using namespace std;
/**
 * \class   parseBGP
 *
 * \brief   Parser for BGP messages
 * \details This class can be used as needed to parse a complete BGP message. This
 *          class will read directly from the socket to read the BGP message.
 */
  /**
     * Below defines the common BGP header per RFC4271
     */
    enum bgp_msg_types { BGP_MSG_OPEN=1, BGP_MSG_UPDATE, BGP_MSG_NOTIFICATION, BGP_MSG_KEEPALIVE,
        BGP_MSG_ROUTE_REFRESH
    };

struct libParseBGP_parse_bgp_parsed_data {
    /**
     * data_bytes_remaining is a counter that starts at the message size and then is
     * decremented as the message is read.
     *
     * This is used to ensure no buffer overruns on bgp data buffer
     */
    unsigned int data_bytes_remaining;

    /**
     * BGP data buffer for the raw BGP message to be parsed
     */
    unsigned char *data;                             ///< Pointer to the data buffer for the raw BGP message

    //common_bgp_hdr common_hdr;                       ///< Current/last pased bgp common header

    obj_bgp_peer *p_entry;       ///< peer table entry - will be updated with BMP info
    obj_path_attr base_attr;      ///< Base attribute object

    string router_addr;    ///< Router IP address - used for logging
    bmp_message::peer_info *p_info;        ///< Persistent Peer information

    unsigned char path_hash_id[16];                  ///< current path hash ID
};


    /**
     * Constructor for class -
     *
     * \details
     *    This class parses the BGP message and updates DB.  The
     *    'mysql_ptr' must be a pointer reference to an open mysql connection.
     *    'peer_entry' must be a pointer to the peer_entry table structure that
     *    has already been populated.
     *
     * \param [in]     logPtr      Pointer to existing Logger for app logging
     * \param [in]     mbus_ptr     Pointer to exiting dB implementation
     * \param [in,out] peer_entry  Pointer to peer entry
     * \param [in]     routerAddr  The router IP address - used for logging
     * \param [in,out] peer_info   Persistent peer information
     */
    void libParseBGP_parse_bgp_init(libParseBGP_parse_bgp_parsed_data *bgp_parsed_data, obj_bgp_peer *peer_entry,
                                    string router_addr, bmp_message::peer_info *peer_info);


    u_char libParseBGP_parse_bgp_parse_msg_from_mrt(libParseBGP_parse_bgp_parsed_data *bgp_parsed_data, u_char *data, size_t size, parsed_bgp_msg *bgp_msg,
                                                    obj_peer_up_event *up_event, obj_peer_down_event *down_event,
                                                    uint32_t asn, bool is_local_msg = false);


    /**
     * handle BGP update message and store in DB
     *
     * \details Parses the bgp update message and store it in the DB.
     *
     * \param [in]     data             Pointer to the raw BGP message header
     * \param [in]     size             length of the data buffer (used to prevent overrun)

     *
     * \returns True if error, false if no error.
     */
    bool libParseBGP_parse_bgp_handle_update(libParseBGP_parse_bgp_parsed_data *bgp_parsed_data, u_char *data, size_t size,
                                             parsed_bgp_msg *bgp_msg);

    /**
     * handle BGP notify event - updates the down event with parsed data
     *
     * \details
     *  The notify message does not directly add to Db, so the calling
     *  method/function must handle that.
     *
     * \param [in]     data             Pointer to the raw BGP message header
     * \param [in]     size             length of the data buffer (used to prevent overrun)
     * \param [out]    down_event       Reference to the down event/notification storage buffer
     *
     * \returns True if error, false if no error.
     */
    bool libParseBGP_parse_bgp_handle_down_event(libParseBGP_parse_bgp_parsed_data *bgp_parsed_data, u_char *data,
                                                 size_t size, obj_peer_down_event *down_event, parsed_bgp_msg *bgp_msg);

    /**
     * Handles the up event by parsing the BGP open messages - Up event will be updated
     *
     * \details
     *  This method will read the expected sent and receive open messages.
     *
     * \param [in]     data             Pointer to the raw BGP message header
     * \param [in]     size             length of the data buffer (used to prevent overrun)
     *
     * \returns True if error, false if no error.
     */
    bool libParseBGP_parse_bgp_handle_up_event(libParseBGP_parse_bgp_parsed_data *bgp_parsed_data, u_char *data, size_t size,
                                               obj_peer_up_event *up_event, parsed_bgp_msg *bgp_msg);

    /**
     * Parses the BGP common header
     *
     * \details
     *      This method will parse the bgp common header and will upload the global
     *      c_hdr structure, instance data pointer, and remaining bytes of message.
     *      The return value of this method will be the BGP message type.
     *
     * \param [in]      data            Pointer to the raw BGP message header
     * \param [in]      size            length of the data buffer (used to prevent overrun)
     *
     * \returns BGP message type
     */
    u_char libParseBGP_parse_bgp_parse_header(libParseBGP_parse_bgp_parsed_data *bgp_parsed_data, u_char *data, size_t size, common_bgp_hdr &common_hdr);

#endif /* PARSEBGP_H_ */
