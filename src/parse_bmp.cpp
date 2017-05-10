//
// Created by ojas on 4/22/17.
//
#include "../include/parse_bgp.h"
#include "../include/parse_bmp.h"


/**
 * Buffer remaining BMP message
 *
 * \details This method will read the remaining amount of BMP data and store it in the instance variable bmp_data.
 *          Normally this is used to store the BGP message so that it can be parsed.
 *
 * \param [in]  sock       Socket to read the message from
 *
 * \returns true if successfully parsed the bmp peer down header, false otherwise
 *
 * \throws String error
 */
static void libparsebgp_parse_bmp_buffer_bmp_message(unsigned char*& buffer, int& buf_len) {
    if (bmp_len <= 0)
        return;

    if (bmp_len > sizeof(bmp_data)) {
        //       LOG_WARN("sock=%d: BMP message is invalid, length of %d is larger than max buffer size of %d",sock, bmp_len, sizeof(bmp_data));
        throw "BMP message length is too large for buffer, invalid BMP sender";
    }

    if ((bmp_data_len=extract_from_buffer(buffer, buf_len, bmp_data, bmp_len)) != bmp_len) {
        //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
        throw "Error while reading BMP data into buffer";
    }

    // Indicate no more data is left to read
    bmp_len = 0;

}
/**
 * Parse the v3 peer header
 */

static int libparsebgp_parse_bmp_parse_peer_hdr(libparsebgp_parsed_peer_hdr_v3 &parsed_peer_header, unsigned char *&buffer,
                                                 int &buf_len) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &parsed_peer_header, BMP_PEER_HDR_LEN)!= BMP_PEER_HDR_LEN) {
        //       LOG_ERR("sock=%d: Couldn't read all bytes, read %d bytes",sock, i);
        throw "Couldn't read all bytes";
    }
    read_size+=BMP_PEER_HDR_LEN;

    // Adjust the common header length to remove the peer header (as it's been read)
    bmp_len -= BMP_PEER_HDR_LEN;
    //   SELF_DEBUG("parsePeerHdr: sock=%d : Peer Type is %d", sock,p_hdr.peer_type);

    // Save the advertised timestamp
    SWAP_BYTES(&parsed_peer_header.peer_as);
    SWAP_BYTES(&parsed_peer_header.ts_secs);
    SWAP_BYTES(&parsed_peer_header.ts_usecs);
    return read_size;
}

/**
* Parse v1 and v2 BMP header
*
* \details
*      v2 uses the same common header, but adds the Peer Up message type.
*
* \param [in]  sock        Socket to read the message from
*/
static int libparsebgp_parse_bmp_parse_bmp_v2(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    int read_size=0;
    size_t i;
    char buf[256] = {0};

    bmp_len = 0;

    if (extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old, BMP_HDRv1v2_LEN)
        != BMP_HDRv1v2_LEN) {
        //     SELF_DEBUG("sock=%d: Couldn't read all bytes, read %zd bytes",sock, i);
        throw "ERROR: Cannot read v1/v2 BMP common header.";
    }
    read_size+=BMP_HDRv1v2_LEN;

    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.peer_as);

    // Save the advertised timestamp
    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ts_secs);
    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ts_usecs);


    // Process the message based on type
    switch (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type) {
        case 0: // Route monitoring

            // Get the length of the remaining message by reading the BGP length
            if ((i=extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
                uint16_t len;
                memcpy(&len, (buf+16), 2);
                SWAP_BYTES(&len);
                bmp_len = len;
                read_size+=i;

            } else {
                throw "Failed to read BGP message for BMP length";
            }
            break;

        case 1: // Statistics Report
            break;

        case 2: // Peer down notification
            // Get the length of the remaining message by reading the BGP length
            if ((i=extract_from_buffer(buffer, buf_len, buf, 1)) != 1) {

                // Is there a BGP message
                if (buf[0] == 1 or buf[0] == 3) {
                    if ((i = extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
                        memcpy(&bmp_len, buf + 16, 2);
                        SWAP_BYTES(&bmp_len);
                        read_size+=i;
                    } else
                        throw "Failed to read BGP message for BMP length";
                }
            } else
                throw "Failed to read BMP peer down reason";
            break;

        case 3: // Peer Up notification
            throw "ERROR: Will need to add support for peer up if it's really used.";
    }

    return read_size;
}


/**
 * Parse v3 BMP header
 *
 * \details
 *      v3 has a different header structure and changes the peer
 *      header format.
 */
static int libparsebgp_parse_bmp_parse_bmp_v3(libparsebgp_parsed_bmp_parsed_data *&parsed_msg, unsigned char *&buffer,
                                               int &buf_len) {

    int read_size = 0;
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len, 4)) != 4) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }
    read_size+=4;
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type, 1)) != 1) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }
    read_size+=1;

    // Change to host order
    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len);

    //   SELF_DEBUG("BMP v3: type = %x len=%d", parsed_msg->c_hdr_v3.type, parsed_msg->c_hdr_v3.len);

    // Adjust length to remove common header size
    bmp_len = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len - 1 - BMP_HDRv3_LEN;

    if (bmp_len > BGP_MAX_MSG_SIZE)
        throw "ERROR: BMP length is larger than max possible BGP size";

    switch (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type) {
        case TYPE_ROUTE_MON: // Route monitoring
        case TYPE_STATS_REPORT: // Statistics Report
        case TYPE_PEER_UP: // Peer Up notification
        case TYPE_PEER_DOWN: // Peer down notification
            read_size+=libparsebgp_parse_bmp_parse_peer_hdr(parsed_msg->libparsebgp_parsed_peer_hdr, buffer, buf_len);
            break;

        case TYPE_INIT_MSG:
        case TYPE_TERM_MSG:
            // Allowed
            break;

        default:
            //         LOG_ERR("ERROR: Unknown BMP message type of %d", parsed_msg->c_hdr_v3.type);
            throw "ERROR: BMP message type is not supported";
    }
    return read_size;
}

/**
 * Process the incoming BMP message
 *
 * \returns
 *      returns the BMP message type. A type of >= 0 is normal,
 *      < 0 indicates an error
 *
 * \param [in] sock     Socket to read the BMP message from
 *
 * //throws (const  char *) on error.   String will detail error message.
 */
static int libparsebgp_parse_bmp_handle_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int &buf_len) {
    uint8_t     ver;
    int         read_size = 0;
    // Get the version in order to determine what we read next
    //    As of Junos 10.4R6.5, it supports version 1
    read_size+= extract_from_buffer(buffer, buf_len, &ver, 1);

    if (read_size != 1)
        throw "Cannot read BMP version byte from buffer";

    // check the version
    if (ver == 3) { // draft-ietf-grow-bmp-04 - 07
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.ver = ver;
        read_size+=libparsebgp_parse_bmp_parse_bmp_v3(parsed_msg, buffer, buf_len);
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type;
    }

        // Handle the older versions
    else if (ver == 1 || ver == 2) {
        //TODO:
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ver=ver;
        read_size+=libparsebgp_parse_bmp_parse_bmp_v2(parsed_msg, buffer, buf_len);
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type;

    } else
        throw "ERROR: Unsupported BMP message version";

    return read_size;
}

/**
 * Parse the v3 peer down BMP header
 *
 * \details This method will update the db peer_down_event struct with BMP header info.
 *
 * \param [in]  sock       Socket to read the message from
 * \param [out] down_event Reference to the peer down event storage (will be updated with bmp info)
 *
 * \returns true if successfully parsed the bmp peer down header, false otherwise
 */
static bool libparsebgp_parse_bmp_parse_peer_down_event_hdr(libparsebgp_parsed_bmp_peer_down_event *down_event,
                                                            unsigned char*& buffer, int& buf_len) {
    if (extract_from_buffer(buffer, buf_len, &down_event->bmp_reason, 1) == 1) {
        //  LOG_NOTICE("sock=%d : %s: BGP peer down notification with reason code: %d", sock, p_entry->peer_addr, reason);
        return true;
    } else
        return false;
}

/**
 * handle the initiation message and update the router entry
 *
 * \param [in]     sock        Socket to read the init message from
 * \param [in/out] r_entry     Already defined router entry reference (will be updated)
 */
static void libparsebgp_parse_bmp_handle_init_msg(libparsebgp_parsed_bmp_init_msg *parsed_msg, unsigned char*& buffer, int& buf_len) {
    int info_len;

    // Buffer the init message for parsing
    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

    u_char *bufPtr = bmp_data;
    /*
     * Loop through the init message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_INIT_MSG_LEN) {
        init_msg_v3_tlv *init_msg;
        memcpy(&init_msg, bufPtr, BMP_INIT_MSG_LEN);

        memset(init_msg->info, 0, sizeof init_msg->info);
        SWAP_BYTES(&init_msg->len);
        SWAP_BYTES(&init_msg->type);

        bufPtr += BMP_INIT_MSG_LEN;                // Move pointer past the info header

        //       LOG_INFO("Init message type %hu and length %hu parsed", initMsg.type, initMsg.len);

        if (init_msg->len > 0) {
            info_len = sizeof(init_msg->info) < init_msg->len ? sizeof(init_msg->info) : init_msg->len;
            bzero(init_msg->info, sizeof(init_msg->info));
            memcpy(init_msg->info, bufPtr, info_len);
            bufPtr += info_len;                     // Move pointer past the info data
            i += info_len;                          // Update the counter past the info data
        }
        parsed_msg->init_msg_tlvs.push_back(*init_msg);
        delete init_msg;



//        /*
//         * Save the data based on info type
//         */
//        switch (init_msg.type) {
//            case INIT_TYPE_FREE_FORM_STRING :
//                info_len = sizeof(parsed_msg->r_entry.initiate_data) < (init_msg.len - 1) ? (sizeof(parsed_msg->r_entry.initiate_data) - 1) : init_msg.len;
//                memcpy(parsed_msg->r_entry.initiate_data, init_msg.info, info_len);
//                //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.initiate_data);
//
//                break;
//
//            case INIT_TYPE_SYSNAME :
//                info_len = sizeof(parsed_msg->r_entry.name) < (init_msg.len - 1) ? (sizeof(parsed_msg->r_entry.name) - 1) : init_msg.len;
//                strncpy((char *)parsed_msg->r_entry.name, init_msg.info, info_len);
//                //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.name);
//                break;
//
//            case INIT_TYPE_SYSDESCR :
//                info_len = sizeof(parsed_msg->r_entry.descr) < (init_msg.len - 1) ? (sizeof(parsed_msg->r_entry.descr) - 1) : init_msg.len;
//                strncpy((char *)parsed_msg->r_entry.descr, init_msg.info, info_len);
//                //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.descr);
//                break;
//
//            case INIT_TYPE_ROUTER_BGP_ID:
//                if (init_msg.len != sizeof(in_addr_t)) {
//                    //                   LOG_NOTICE("Init message type BGP ID not of IPv4 addr length");
//                    break;
//                }
//                inet_ntop(AF_INET, init_msg.info, parsed_msg->r_entry.bgp_id, sizeof(parsed_msg->r_entry.bgp_id));
////                LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.bgp_id);
//                break;
//
////            default:
//
////                LOG_NOTICE("Init message type %hu is unexpected per rfc7854", init_msg.type);
//        }
    }
}

/**
 * handle the termination message, router entry will be updated
 *
 * \param [in]     sock        Socket to read the term message from
 * \param [in/out] r_entry     Already defined router entry reference (will be updated)
 */
static void libparsebgp_parse_bmp_handle_term_msg(libparsebgp_parsed_bmp_term_msg *parsed_msg, unsigned char*& buffer, int& buf_len) {

//    char infoBuf[sizeof(parsed_msg->r_entry.term_data)];
    int infoLen;

    // Buffer the init message for parsing
    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

    u_char *bufPtr = bmp_data;

    /*
     * Loop through the term message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_TERM_MSG_LEN) {
        term_msg_v3_tlv term_msg;
        memcpy(&term_msg, bufPtr, BMP_TERM_MSG_LEN);
        memset(term_msg.info, 0, sizeof term_msg.info);
        SWAP_BYTES(&term_msg.len);
        SWAP_BYTES(&term_msg.type);

        bufPtr += BMP_TERM_MSG_LEN;                // Move pointer past the info header

        //       LOG_INFO("Term message type %hu and length %hu parsed", termMsg.type, termMsg.len);

        if (term_msg.len > 0) {
            infoLen = sizeof(term_msg.info) < term_msg.len ? sizeof(term_msg.info) : term_msg.len;
            bzero(term_msg.info, sizeof(term_msg.info));
            memcpy(term_msg.info, bufPtr, infoLen);
            bufPtr += infoLen;                     // Move pointer past the info data
            i += infoLen;                       // Update the counter past the info data

            //           LOG_INFO("Term message type %hu = %s", termMsg.type, termMsg.info);
        }
        parsed_msg->term_msg_tlvs.push_back(term_msg);

//        /*
//         * Save the data based on info type
//         */
//        switch (term_msg.type) {
//            case TERM_TYPE_FREE_FORM_STRING :
//                memcpy(parsed_msg->r_entry.term_data, term_msg.info, term_msg.len);
//                break;
//
//            case TERM_TYPE_REASON :
//            {
//                // Get the term reason code from info data (first 2 bytes)
//                uint16_t term_reason;
//                memcpy(&term_reason, term_msg.info, 2);
//                SWAP_BYTES(&term_reason);
//                parsed_msg->r_entry.term_reason_code = term_reason;
//
//                switch (term_reason) {
//                    case TERM_REASON_ADMIN_CLOSE :
//                        //                       LOG_INFO("%s BMP session closed by remote administratively", r_entry.ip_addr);
//                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
//                                 "Remote session administratively closed");
//                        break;
//
//                    case TERM_REASON_OUT_OF_RESOURCES:
//                        //                       LOG_INFO("%s BMP session closed by remote due to out of resources", r_entry.ip_addr);
//                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
//                                 "Remote out of resources");
//                        break;
//
//                    case TERM_REASON_REDUNDANT_CONN:
////                        LOG_INFO("%s BMP session closed by remote due to connection being redundant", r_entry.ip_addr);
//                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
//                                 "Remote considers connection redundant");
//                        break;
//
//                    case TERM_REASON_UNSPECIFIED:
//                        ///                       LOG_INFO("%s BMP session closed by remote as unspecified", r_entry.ip_addr);
//                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
//                                 "Remote closed with unspecified reason");
//                        break;
//
//                    default:
////                        LOG_INFO("%s closed with undefined reason code of %d", r_entry.ip_addr, term_reason);
//                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
//                                 "Unknown %d termination reason, which is not part of draft.", term_reason);
//                }
//
//                break;
//            }
//
////            default:
////                LOG_NOTICE("Term message type %hu is unexpected per draft", termMsg.type);
//        }
    }
}


/**
 * Parse and return back the stats report
 *
 * \param [in]  sock        Socket to read the stats message from
 * \param [out] stats       Reference to stats report data
 *
 * \return true if error, false if no error
 */
static int libparsebgp_parse_bmp_handle_stats_report(libparsebgp_parsed_bmp_stat_rep *parsed_msg, unsigned char * buffer, int buf_len) {
    char b[8];
    int read_size = 0;

    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->stats_count, 4)) != 4)
        throw "ERROR:  Cannot proceed since we cannot read the stats counter";

    SWAP_BYTES(&parsed_msg->stats_count);
    read_size+=4;
    // Loop through each stats object
    for (unsigned long i = 0; i < parsed_msg->stats_count; i++) {
        stat_counter stat_info;
        bzero(&stat_info, sizeof(stat_counter));
        bzero(b,8);
        if ((extract_from_buffer(buffer, buf_len, &stat_info, 4)) != 4)
            throw "ERROR: Cannot proceed since we cannot read the stats type.";
        read_size+=4;
//        if ((extract_from_buffer(buffer, buf_len, &stat_info.stat_len, 2)) != 2)
//            throw "ERROR: Cannot proceed since we cannot read the stats len.";
        // convert integer from network to host bytes
        SWAP_BYTES(&stat_info.stat_type);
        SWAP_BYTES(&stat_info.stat_len);

        //       SELF_DEBUG("sock=%d STATS: %lu : TYPE = %u LEN = %u", sock,
        //                   i, stat_type, stat_len);

        // check if this is a 32 bit number  (default)
        if (stat_info.stat_len == 4 or stat_info.stat_len == 8) {

            // Read the stats counter - 32/64 bits
            if ((extract_from_buffer(buffer, buf_len, b, stat_info.stat_len)) == stat_info.stat_len) {
                read_size+=stat_info.stat_len;
                // convert the bytes from network to host order
                SWAP_BYTES(b, stat_info.stat_len);
                memcpy(stat_info.stat_data, b, stat_info.stat_len);
            }

        } else { // stats len not expected, we need to skip it.
            //         SELF_DEBUG("sock=%d : skipping stats report '%u' because length of '%u' is not expected.",
            //                     sock, stat_type, stat_len);

            while (stat_info.stat_len-- > 0)
                extract_from_buffer(buffer, buf_len, &b[0], 1);
        }
        parsed_msg->total_stats_counter.push_back(stat_info);
//        delete stat_info;
    }
    return read_size;
}

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
static int libparsebgp_parse_bgp_handle_up_event(unsigned char *data, size_t size, libparsebgp_parsed_bmp_peer_up_event *up_event) {
    int              read_size;
    /*
    * Process the sent open message
    */
    if (libparsebgp_parse_bgp_parse_header(up_event->sent_open_msg, data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;
        size -= BGP_MSG_HDR_LEN;

        read_size = libparsebgp_open_msg_parse_open_msg(&up_event->sent_open_msg.parsed_data.open_msg, data, size, true);

        if (!read_size) {
            throw "Failed to read sent open message";
        }

        data += read_size;                                          // Move the pointer pase the sent open message
        size -= read_size;
    }

    if (libparsebgp_parse_bgp_parse_header(up_event->received_open_msg, data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;
        size -= BGP_MSG_HDR_LEN;
        read_size = libparsebgp_open_msg_parse_open_msg(&up_event->received_open_msg.parsed_data.open_msg,data, size, false);

        if (!read_size) {
            throw "Failed to read received open message";
        }

        data += read_size;                                          // Move the pointer pase the sent open message
        size -= read_size;

    } else {
        //      LOG_ERR("%s: rtr=%s: BGP message type is not BGP OPEN, cannot parse the open message",p_entry->peer_addr, router_addr.c_str());
        throw "ERROR: Invalid BGP MSG for BMP Received OPEN message, expected OPEN message.";
    }
    return false;
}

/**
 * Parse the v3 peer up BMP header
 *
 * \details This method will update the db peer_up_event struct with BMP header info.
 *
 * \param [in]  sock     Socket to read the message from
 * \param [out] up_event Reference to the peer up event storage (will be updated with bmp info)
 *
 * \returns true if successfully parsed the bmp peer up header, false otherwise
 */
static bool libparsebgp_parse_bmp_parse_peer_up_event_hdr(libparsebgp_parsed_bmp_peer_up_event *parsed_msg, unsigned char*& buffer, int& buf_len) {
    bool is_parse_good = true;
    int bytes_read = 0;

    // Get the local address
    if ( extract_from_buffer(buffer, buf_len, &parsed_msg->local_ip, 16) != 16)
        is_parse_good = false;
    else
        bytes_read += 16;

    // Get the local port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &parsed_msg->local_port, 2) != 2)
        is_parse_good = false;

    else if (is_parse_good) {
        bytes_read += 2;
        SWAP_BYTES(&parsed_msg->local_port);
    }

    // Get the remote port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &parsed_msg->remote_port, 2) != 2)
        is_parse_good = false;

    else if (is_parse_good) {
        bytes_read += 2;
        SWAP_BYTES(&parsed_msg->remote_port);
    }

    // Update bytes read
    bmp_len -= bytes_read;

    // Validate parse is still good, if not read the remaining bytes of the message so that the next msg will work
    if (!is_parse_good) {
        //       LOG_NOTICE("%s: PEER UP header failed to be parsed, read only %d bytes of the header",
        //              peer_addr, bytes_read);

        // Msg is invalid - Buffer and ignore
        libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
    }
    return is_parse_good;
}

int libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int buf_len) {
    string peer_info_key;
    int read_size = 0;
    bzero(bmp_data, sizeof(bmp_data));
    bmp_len=0;

    try {
        read_size+= libparsebgp_parse_bmp_handle_msg(parsed_msg, buffer, buf_len);

        /*
         * At this point we only have the BMP header message, what happens next depends
         *      on the BMP message type.
         */
        switch (bmp_type) {
            case TYPE_PEER_DOWN : { // Peer down type
                if (libparsebgp_parse_bmp_parse_peer_down_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg, buffer, buf_len)) {
                    //bufferBMPMessage(read_fd);
                    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

                    // Check if the reason indicates we have a BGP message that follows
                    switch (parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.bmp_reason) {
                        case 1 : { // Local system close with BGP notify
                            libparsebgp_parse_bgp_handle_down_event(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg, bmp_data, bmp_data_len);
                            break;
                        }
                        case 2 : // Local system close, no bgp notify
                        {
// Read two byte code corresponding to the FSM event
                            uint16_t fsm_event = 0 ;
                            memcpy(&fsm_event, bmp_data, 2);
                            SWAP_BYTES(&fsm_event);
                            break;
                        }
                        case 3 : { // remote system close with bgp notify
                            libparsebgp_parse_bgp_handle_down_event(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg, bmp_data, bmp_data_len);
                            break;
                        }
                    }
                } else
                    throw "BMPReader: Unable to read from client socket";
                break;
            }

            case TYPE_PEER_UP : // Peer up type
            {
                if (libparsebgp_parse_bmp_parse_peer_up_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg, buffer, buf_len)) {
                    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

                    // Parse the BGP sent/received open messages
                    read_size+=libparsebgp_parse_bgp_handle_up_event(bmp_data, bmp_data_len, &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg);
                }
                break;
            }

            case TYPE_ROUTE_MON : { // Route monitoring type
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                read_size+=libparsebgp_parse_bgp_handle_update(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_rm_msg.update_msg, bmp_data, bmp_data_len);
                break;
            }

            case TYPE_STATS_REPORT : { // Stats Report
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                read_size+=libparsebgp_parse_bmp_handle_stats_report(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_stat_rep, bmp_data, bmp_data_len);
                break;
            }

            case TYPE_INIT_MSG : { // Initiation Message
                libparsebgp_parse_bmp_handle_init_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_init_msg, buffer, buf_len);
                break;
            }

            case TYPE_TERM_MSG : { // Termination Message
                libparsebgp_parse_bmp_handle_term_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_term_msg, buffer, buf_len);
                break;
            }
            default:
                throw "invalid type";
                break;
        }
    } catch (char const *str) {
        // Mark the router as disconnected and update the error to be a local disconnect (no term message received)
        //  LOG_INFO("%s: Caught: %s", client->c_ip, str);
        throw str;
    }

    return read_size;
}