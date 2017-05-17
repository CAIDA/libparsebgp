/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include <algorithm>
#include "../include/parse_bgp.h"
#include "../include/parse_utils.h"

using namespace std;

/**
 * parse BGP messages
 *
 * \param [in] data             Pointer to the raw BGP message header
 * \param [in] size             length of the data buffer (used to prevent overrun)
 * \param [in] bgp_msg           Structure to store the bgp messages
 * \returns bytes read
 */
ssize_t libparsebgp_parse_bgp_parse_msg(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *&data, size_t size,
                                               bool is_local_msg) {
    ssize_t read_size = 0;
    u_char  bgp_msg_type = libparsebgp_parse_bgp_parse_header(bgp_parsed_data, data, size);
    int data_bytes_remaining = bgp_parsed_data.c_hdr.len - BGP_MSG_HDR_LEN;
    data += BGP_MSG_HDR_LEN;
    switch (bgp_msg_type) {
        case BGP_MSG_UPDATE: {
            if ((read_size=libparsebgp_update_msg_parse_update_msg(&bgp_parsed_data.parsed_data.update_msg, data, data_bytes_remaining,
                                                                   bgp_parsed_data.has_end_of_rib_marker)) != (size - BGP_MSG_HDR_LEN)) {
                return ERR_READING_MSG; //throw "Failed to parse BGP update message";
            }
            break;
        }
        case BGP_MSG_NOTIFICATION: {
            libparsebgp_notify_msg parsed_msg;
            read_size= libparsebgp_notification_parse_notify(parsed_msg,data, data_bytes_remaining);
            if (read_size < 0)
            {
                //throw "Failed to parse the BGP notification message";
                return read_size;
            }
            else {
                read_size = 2;
                data += 2;                                                 // Move pointer past notification message
                data_bytes_remaining -= 2;

                bgp_parsed_data.parsed_data.notification_msg.error_code = parsed_msg.error_code;
                bgp_parsed_data.parsed_data.notification_msg.error_subcode = parsed_msg.error_subcode;
                strncpy(bgp_parsed_data.parsed_data.notification_msg.error_text, parsed_msg.error_text,
                        sizeof(bgp_parsed_data.parsed_data.notification_msg.error_text));
            }
            break;
        }
        case BGP_MSG_KEEPALIVE: {
            break;
        }
        case BGP_MSG_OPEN: {
            read_size = libparsebgp_open_msg_parse_open_msg(&bgp_parsed_data.parsed_data.open_msg,data, data_bytes_remaining, is_local_msg);
            if (!read_size) {
                return ERR_READING_MSG; //throw "Failed to read open message";
            }
            if (read_size < 0)
                return read_size;   // contains the error code
            break;
        }
        default: {
            return ABNORMAL_MSG; //throw "BGP message type does not match";
        }
    }
    data += read_size;
    data_bytes_remaining -= read_size;
    return read_size + BGP_MSG_HDR_LEN;
}

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
ssize_t libparsebgp_parse_bgp_handle_update(libparsebgp_parse_bgp_parsed_data &bgp_update_msg, u_char *data, size_t size) {
    int read_size = 0;

    if (libparsebgp_parse_bgp_parse_header(bgp_update_msg, data, size) == BGP_MSG_UPDATE) {
        int data_bytes_remaining = bgp_update_msg.c_hdr.len - BGP_MSG_HDR_LEN;
        data += BGP_MSG_HDR_LEN;
        read_size+=BGP_MSG_HDR_LEN;
       if ((read_size=libparsebgp_update_msg_parse_update_msg(&bgp_update_msg.parsed_data.update_msg, data, data_bytes_remaining,
                                                              bgp_update_msg.has_end_of_rib_marker)) != (size - BGP_MSG_HDR_LEN)) {
            throw "error in parsing update msg";
        }
        read_size+=(size - BGP_MSG_HDR_LEN);
    }
    return read_size;
}

/**
 * handle  BGP notify event - updates the down event with parsed data
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
ssize_t libparsebgp_parse_bgp_handle_down_event(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *data, size_t size) {
    ssize_t     read_size = 0, ret_val = 0;
    // Process the BGP message normally
    if (libparsebgp_parse_bgp_parse_header(bgp_parsed_data, data, size) == BGP_MSG_NOTIFICATION) {
        int data_bytes_remaining = bgp_parsed_data.c_hdr.len - BGP_MSG_HDR_LEN;
        data += BGP_MSG_HDR_LEN;
        read_size += BGP_MSG_HDR_LEN;

        libparsebgp_notify_msg notify_msg;
        ret_val = libparsebgp_notification_parse_notify(notify_msg,data, data_bytes_remaining);
        if (ret_val)
        {
            return ret_val;
            //throw "Failed to parse the BGP notification message";
        }
        else {
            data += 2;                                                 // Move pointer past notification message
            data_bytes_remaining -= 2;
            read_size += 2;

            bgp_parsed_data.parsed_data.notification_msg.error_code = notify_msg.error_code;
            bgp_parsed_data.parsed_data.notification_msg.error_subcode = notify_msg.error_subcode;
            strncpy(bgp_parsed_data.parsed_data.notification_msg.error_text, notify_msg.error_text,
                    sizeof(bgp_parsed_data.parsed_data.notification_msg.error_text));
        }
    }
    else {
        throw "ERROR: Invalid BGP MSG for BMP down event, expected NOTIFICATION message.";
    }
    return read_size;
}

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
u_char libparsebgp_parse_bgp_parse_header(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *data, size_t size) {
    /*
     * Error out if data size is not large enough for common header
     */
    if (size < BGP_MSG_HDR_LEN) {
 //       LOG_WARN("%s: rtr=%s: BGP message is being parsed is %d but expected at least %d in size",p_entry->peer_addr, router_addr.c_str(), size, BGP_MSG_HDR_LEN);
        return 0;
    }

    memcpy(&bgp_parsed_data.c_hdr, data, BGP_MSG_HDR_LEN);

    // Change length to host byte order
    SWAP_BYTES(&(bgp_parsed_data.c_hdr.len));
    SWAP_BYTES(&(bgp_parsed_data.c_hdr.type));

    /*
     * Error out if the remaining size of the BGP message is grater than passed bgp message buffer
     *      It is expected that the passed bgp message buffer holds the complete BGP message to be parsed
     */
//    if (common_hdr.len > size) {
//        LOG_WARN("%s: rtr=%s: BGP message size of %hu is greater than passed data buffer, cannot parse the BGP message",p_entry->peer_addr, router_addr.c_str(), common_hdr.len, size);
//    }

     return bgp_parsed_data.c_hdr.type;
}