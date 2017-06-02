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
 * function to parse BGP messages
 */
ssize_t libparsebgp_parse_bgp_parse_msg(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *&data, size_t size,
                                               bool is_local_msg) {
    ssize_t read_size = 0;

    /*
     * Parsing the bgp message header
     */
    ssize_t ret_val = libparsebgp_parse_bgp_parse_header(bgp_parsed_data.c_hdr, data, size);
    if (ret_val < 0)
        return ret_val;
    int data_bytes_remaining = bgp_parsed_data.c_hdr.len - BGP_MSG_HDR_LEN;
    data += BGP_MSG_HDR_LEN;

    /*
     * Parsing the bgp msg according to the type of the message
     */
    switch (bgp_parsed_data.c_hdr.type) {
        case BGP_MSG_UPDATE: {
            read_size = libparsebgp_update_msg_parse_update_msg(&bgp_parsed_data.parsed_data.update_msg, data, data_bytes_remaining,
                                                                bgp_parsed_data.has_end_of_rib_marker);
            if (read_size < 0)
                return read_size;
            if (read_size != (size - BGP_MSG_HDR_LEN)) {
                return ERR_READING_MSG; //throw "Failed to parse BGP update message";
            }
            break;
        }
        case BGP_MSG_NOTIFICATION: {
            read_size= libparsebgp_notification_parse_notify( bgp_parsed_data.parsed_data.notification_msg,data, data_bytes_remaining);
            if (read_size < 0)
                return read_size; //Failed to parse the BGP notification message

            else {
                read_size = 2;
                data += 2;                                                 // Move pointer past notification message
                data_bytes_remaining -= 2;
            }
            break;
        }
        case BGP_MSG_KEEPALIVE: {
            break;
        }
        case BGP_MSG_OPEN: {
            read_size = libparsebgp_open_msg_parse_open_msg(&bgp_parsed_data.parsed_data.open_msg,data, data_bytes_remaining, is_local_msg);
            if (!read_size)
                return ERR_READING_MSG; //Failed to read open message;

            if (read_size < 0)
                return read_size;   // contains the error code
            break;
        }
        default: {
            return INVALID_MSG; //Invalid bgp message type
        }
    }
    data += read_size;
    data_bytes_remaining -= read_size;
    return read_size + BGP_MSG_HDR_LEN;
}

/**
 * handle BGP update message and store in DB
 */
ssize_t libparsebgp_parse_bgp_handle_update(libparsebgp_parse_bgp_parsed_data &bgp_update_msg, u_char *data, size_t size) {
    ssize_t read_size = 0, bytes_read =0;
    //Process the BGP message header
    if((bytes_read = libparsebgp_parse_bgp_parse_header(bgp_update_msg.c_hdr, data, size))<0)
        return bytes_read;
    read_size += bytes_read;
    data += bytes_read;

    if (bgp_update_msg.c_hdr.type == BGP_MSG_UPDATE) {  //checking for proper message type
        ssize_t data_bytes_remaining = bgp_update_msg.c_hdr.len - BGP_MSG_HDR_LEN;
        if((bytes_read=libparsebgp_update_msg_parse_update_msg(&bgp_update_msg.parsed_data.update_msg, data, data_bytes_remaining,
                                                          bgp_update_msg.has_end_of_rib_marker))<0)
            return bytes_read;

        if (bytes_read != (size - BGP_MSG_HDR_LEN))
            return INVALID_MSG;

        read_size += bytes_read;
    } else
        return INVALID_MSG;

    return read_size;
}

/**
 * handle  BGP notify event - updates the down event with parsed data
 */
ssize_t libparsebgp_parse_bgp_handle_down_event(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *data, size_t size) {
    ssize_t     read_size = 0, ret_val = 0;
    // Process the BGP message normally
    ret_val = libparsebgp_parse_bgp_parse_header(bgp_parsed_data.c_hdr, data, size);
    if (ret_val < 0)
        return ret_val;
    if (bgp_parsed_data.c_hdr.type == BGP_MSG_NOTIFICATION) {   //checking for valid bgp message type
        int data_bytes_remaining = bgp_parsed_data.c_hdr.len - BGP_MSG_HDR_LEN;
        data += BGP_MSG_HDR_LEN;
        read_size += BGP_MSG_HDR_LEN;

        libparsebgp_notify_msg *notify_msg = (libparsebgp_notify_msg *)malloc(sizeof(libparsebgp_notify_msg));
        ret_val = libparsebgp_notification_parse_notify(bgp_parsed_data.parsed_data.notification_msg,data, data_bytes_remaining);
        if (ret_val < 0)
            return ret_val; //Error:Failed to parse the BGP notification message
        else {
            data += 2;                                                 // Move pointer past notification message
            data_bytes_remaining -= 2;
            read_size += 2;
        }
    }
    else {
        return INVALID_MSG; //ERROR: Invalid BGP MSG for BMP down event, expected NOTIFICATION message.
    }
    return read_size;
}

/**
 * Parses the BGP common header
 */
ssize_t libparsebgp_parse_bgp_parse_header(libparsebgp_common_bgp_hdr &c_hdr, u_char *data, size_t size) {
    /*
     * Error out if data size is not large enough for common header
     */
    if (size < BGP_MSG_HDR_LEN)
       return INCOMPLETE_MSG;

    memcpy(&c_hdr, data, BGP_MSG_HDR_LEN);

    // Change length to host byte order
    SWAP_BYTES(&(c_hdr.len));
    SWAP_BYTES(&(c_hdr.type));

    /*
     * Error out if the remaining size of the BGP message is grater than passed bgp message buffer
     *      It is expected that the passed bgp message buffer holds the complete BGP message to be parsed
     */
    if (c_hdr.len > size)
        return LARGER_MSG_LEN;

     return BGP_MSG_HDR_LEN;
}
/**
 * Destructor function to free the memory allocated in parse_bgp
 */
void libparsebgp_parse_bgp_destructor(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data) {
    free(&bgp_parsed_data.c_hdr);
//    libparsebgp_parse_open_msg_destructor(bgp_parsed_data.parsed_data.open_msg);
    free(&bgp_parsed_data.parsed_data.notification_msg);
//    libparsebgp_parse_update_msg_destructor(bgp_parsed_data.parsed_data.update_msg);
}