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

using namespace std;

/**
 * parse BGP messages in MRT
 *
 * \param [in] data             Pointer to the raw BGP message header
 * \param [in] size             length of the data buffer (used to prevent overrun)
 * \param [in] bgp_msg           Structure to store the bgp messages
 * \returns BGP message type
 */
void libparsebgp_parse_bgp_parse_msg_from_mrt(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *&data, size_t size,
                                               bool is_local_msg) {
    u_char  bgp_msg_type = libparsebgp_parse_bgp_parse_header(bgp_parsed_data, data, size);
    switch (bgp_msg_type) {
        case BGP_MSG_UPDATE: {
            int read_size = 0;
            data += BGP_MSG_HDR_LEN;

            if ((read_size=libparsebgp_update_msg_parse_update_msg(&bgp_parsed_data.parsed_data.update_msg, data,
                                                                   bgp_parsed_data.data_bytes_remaining,
                                                                   bgp_parsed_data.has_end_of_rib_marker)) != (size - BGP_MSG_HDR_LEN)) {
                throw "Failed to parse BGP update message";
            }
            bgp_parsed_data.data_bytes_remaining -= read_size;
            break;
        }
        case BGP_MSG_NOTIFICATION: {
            //bool rval;
            data += BGP_MSG_HDR_LEN;

            libparsebgp_notify_msg parsed_msg;
            if (libparsebgp_notification_parse_notify(parsed_msg,data, bgp_parsed_data.data_bytes_remaining))
            {
                throw "Failed to parse the BGP notification message";
            }
            else {
                data += 2;                                                 // Move pointer past notification message
                bgp_parsed_data.data_bytes_remaining -= 2;

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
            libparsebgp_open_msg_data *open_msg_data;
            int              read_size;

            data += BGP_MSG_HDR_LEN;
            read_size = libparsebgp_open_msg_parse_open_msg(open_msg_data,data, bgp_parsed_data.data_bytes_remaining, is_local_msg);

            if (!read_size) {
                //       LOG_ERR("%s: rtr=%s: Failed to read sent open message",  p_entry->peer_addr, router_addr.c_str());
                throw "Failed to read open message";
            }

            data += read_size;                                          // Move the pointer pase the sent open message
            bgp_parsed_data.data_bytes_remaining -= read_size;

//            if (is_local_msg) {
//                read_size = libparsebgp_open_msg_parse_open_msg(open_msg_data,data, bgp_parsed_data->data_bytes_remaining, true);
//
//                if (!read_size) {
//                    //       LOG_ERR("%s: rtr=%s: Failed to read sent open message",  p_entry->peer_addr, router_addr.c_str());
//                    throw "Failed to read sent open message";
//                }
//
//                data += read_size;                                          // Move the pointer pase the sent open message
//                bgp_parsed_data->data_bytes_remaining -= read_size;
//
//                //strncpy(up_event->local_bgp_id, local_bgp_id.c_str(), sizeof(up_event->local_bgp_id));
//
//                // Convert the list to string
//                //bzero(up_event->sent_cap, sizeof(up_event->sent_cap));
//
//                string cap_str;
//                for (list<string>::iterator it = cap_list.begin(); it != cap_list.end(); it++) {
//                    if ( it != cap_list.begin())
//                        cap_str.append(", ");
//
//                    // Check for 4 octet ASN support
//                    if ((*it).find("4 Octet ASN") != std::string::npos)
//                        bgp_parsed_data->p_info->sent_four_octet_asn = true;
//
//                    cap_str.append((*it));
//                }
//
//                //strncpy(up_event->sent_cap, cap_str.c_str(), sizeof(up_event->sent_cap));
//
//            }
//
//            /*
//             * Process the received open message
//             */
//
//            else {
//                read_size = libparsebgp_open_msg_parse_open_msg(open_msg_data,data, bgp_parsed_data->data_bytes_remaining, false);
//
//                if (!read_size) {
//                    //       LOG_ERR("%s: rtr=%s: Failed to read sent open message", p_entry->peer_addr, router_addr.c_str());
//                    throw "Failed to read received open message";
//                }
//
//                data += read_size;                                          // Move the pointer pase the sent open message
//                bgp_parsed_data->data_bytes_remaining -= read_size;
//
//                //strncpy(up_event->remote_bgp_id, remote_bgp_id.c_str(), sizeof(up_event->remote_bgp_id));
//
//                // Convert the list to string
//                //bzero(up_event->recv_cap, sizeof(up_event->recv_cap));
//
//                string cap_str;
//                for (list<string>::iterator it = cap_list.begin(); it != cap_list.end(); it++) {
//                    if ( it != cap_list.begin())
//                        cap_str.append(", ");
//
//                    // Check for 4 octet ASN support - reset to false if
//                    if ((*it).find("4 Octet ASN") != std::string::npos)
//                        bgp_parsed_data->p_info->recv_four_octet_asn = true;
//
//                    cap_str.append((*it));
//                }
//
//                //strncpy(up_event->recv_cap, cap_str.c_str(), sizeof(up_event->recv_cap));
//
//            }

            /*
            data += BGP_MSG_HDR_LEN;

            read_size = oMsg.parseOpenMsg(data, data_bytes_remaining, isLocalMsg, asn, up_event->local_hold_time, bgp_id, cap_list);

            if (!read_size) {
                //       LOG_ERR("%s: rtr=%s: Failed to read sent open message",  p_entry->peer_addr, router_addr.c_str());
                throw "Failed to read open message";
            }

            data += read_size;                                          // Move the pointer pase the sent open message
            data_bytes_remaining -= read_size;

            string cap_str;
            for (list<string>::iterator it = cap_list.begin(); it != cap_list.end(); it++) {
                if ( it != cap_list.begin())
                    cap_str.append(", ");

                // Check for 4 octet ASN support
                if ((*it).find("4 Octet ASN") != std::string::npos) {
                    if (isLocalMsg)
                        p_info->sent_four_octet_asn = true;
                    else
                        p_info->recv_four_octet_asn = true;
                }

                cap_str.append((*it));
            }*/

            break;
        }
        default: {
            throw "BGP message type does not match";
        }
    }
    //return bgp_msg_type;
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
int libparsebgp_parse_bgp_handle_update(libparsebgp_parse_bgp_parsed_data &update_msg, u_char *data, size_t size) {
    int read_size = 0;

    if (libparsebgp_parse_bgp_parse_header(update_msg, data, size) == BGP_MSG_UPDATE) {
        data += BGP_MSG_HDR_LEN;
        read_size+=BGP_MSG_HDR_LEN;
       if ((read_size=libparsebgp_update_msg_parse_update_msg(&update_msg.parsed_data.update_msg, data, update_msg.data_bytes_remaining,
                                                               update_msg.has_end_of_rib_marker)) != (size - BGP_MSG_HDR_LEN)) {
            //LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr, router_addr.c_str(), read_size, (size - read_size));
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
bool libparsebgp_parse_bgp_handle_down_event(libparsebgp_parse_bgp_parsed_data &bgp_parsed_data, u_char *data, size_t size) {
    bool        rval;

    // Process the BGP message normally
    if (libparsebgp_parse_bgp_parse_header(bgp_parsed_data, data, size) == BGP_MSG_NOTIFICATION) {

        data += BGP_MSG_HDR_LEN;

        libparsebgp_notify_msg notify_msg;
        if ( (rval=libparsebgp_notification_parse_notify(notify_msg,data, bgp_parsed_data.data_bytes_remaining)))
        {
            // LOG_ERR("%s: rtr=%s: Failed to parse the BGP notification message", p_entry->peer_addr, router_addr.c_str());
            throw "Failed to parse the BGP notification message";
        }
        else {
            data += 2;                                                 // Move pointer past notification message
            bgp_parsed_data.data_bytes_remaining -= 2;

            bgp_parsed_data.parsed_data.notification_msg.error_code = notify_msg.error_code;
            bgp_parsed_data.parsed_data.notification_msg.error_subcode = notify_msg.error_subcode;
            strncpy(bgp_parsed_data.parsed_data.notification_msg.error_text, notify_msg.error_text,
                    sizeof(bgp_parsed_data.parsed_data.notification_msg.error_text));
        }
    }
    else {
        //LOG_ERR("%s: rtr=%s: BGP message type is not a BGP notification, cannot parse the notification",
         //       p_entry->peer_addr, router_addr.c_str());
        throw "ERROR: Invalid BGP MSG for BMP down event, expected NOTIFICATION message.";
    }
    return rval;
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

    // Update remaining bytes left of the message
    bgp_parsed_data.data_bytes_remaining = bgp_parsed_data.c_hdr.len - BGP_MSG_HDR_LEN;

    /*
     * Error out if the remaining size of the BGP message is grater than passed bgp message buffer
     *      It is expected that the passed bgp message buffer holds the complete BGP message to be parsed
     */
//    if (common_hdr.len > size) {
//        LOG_WARN("%s: rtr=%s: BGP message size of %hu is greater than passed data buffer, cannot parse the BGP message",p_entry->peer_addr, router_addr.c_str(), common_hdr.len, size);
//    }

 //   SELF_DEBUG("%s: rtr=%s: BGP hdr len = %u, type = %d", p_entry->peer_addr, router_addr.c_str(), common_hdr.len, common_hdr.type);
    return bgp_parsed_data.c_hdr.type;
}

uint32_t libparsebgp_parse_bgp_parse_msg(libparsebgp_parse_bgp_parsed_data &parsed_bgp_msg, unsigned char *data, uint32_t size){
    int read_size;
    bool has_end_of_rib_marker = true;
    if (libparsebgp_parse_bgp_parse_header(parsed_bgp_msg, data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;
    } else throw "Failed to parse bgp header";

    switch (parsed_bgp_msg.c_hdr.type) {
        case BGP_MSG_UPDATE         :
            read_size = libparsebgp_update_msg_parse_update_msg(&parsed_bgp_msg.parsed_data.update_msg, data, size, has_end_of_rib_marker);
            break;

        case BGP_MSG_NOTIFICATION   : // Notification message
            read_size = libparsebgp_notification_parse_notify(parsed_bgp_msg.parsed_data.notification_msg, data, size);
            break;
        case BGP_MSG_OPEN           :
            read_size = libparsebgp_open_msg_parse_open_msg(&parsed_bgp_msg.parsed_data.open_msg, data, size, true);
            break;

        case BGP_MSG_ROUTE_REFRESH  : // Route Refresh message
            //           LOG_NOTICE("%s: rtr=%s: Received route refresh, nothing to do with this message currently.",p_entry->peer_addr, router_addr.c_str());
            break;

        default :
            //           LOG_WARN("%s: rtr=%s: Unsupported BGP message type = %d", p_entry->peer_addr, router_addr.c_str(), common_hdr.type);
            break;
    }
    return read_size + BGP_MSG_HDR_LEN;
}
