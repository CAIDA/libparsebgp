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
 * \param [in]  buffer       Buffer to read the message from
 * \param [in]  buf_len      Buffer length of the available buffer
 *
 */
static ssize_t libparsebgp_parse_bmp_buffer_bmp_message(unsigned char*& buffer, int& buf_len) {

    //TO DO:
    if (bmp_len <= 0)
        return 0;

    if (bmp_len > sizeof(bmp_data)) {
        return LARGER_MSG_LEN; //throw "BMP message length is too large for buffer, invalid BMP sender";
    }

    if ((bmp_data_len=extract_from_buffer(buffer, buf_len, bmp_data, bmp_len)) != bmp_len) {
        return ERR_READING_MSG; //throw "Error while reading BMP data into buffer";
    }

    // Indicate no more data is left to read
    bmp_len = 0;
}

/**
* Parse v3 BMP header
*
* \details
*      v3 uses the same common header, but adds the Peer Up message type.
*
* \param [in]  sock        Socket to read the message from
*/
static ssize_t libparsebgp_parse_bmp_parse_peer_hdr(libparsebgp_parsed_peer_hdr_v3 &parsed_peer_header, unsigned char *&buffer,
                                                 int &buf_len) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &parsed_peer_header, BMP_PEER_HDR_LEN)!= BMP_PEER_HDR_LEN)
        return ERR_READING_MSG;

    read_size+=BMP_PEER_HDR_LEN;

    // Adjust the common header length to remove the peer header (as it's been read)
    bmp_len -= BMP_PEER_HDR_LEN;

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
static ssize_t libparsebgp_parse_bmp_parse_bmp_v2(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    int read_size=0;
    size_t i;
    char buf[256] = {0};

    bmp_len = 0;

    if (extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old, BMP_HDRv1v2_LEN)
        != BMP_HDRv1v2_LEN)
        return ERR_READING_MSG;

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

            } else
                return ERR_READING_MSG;
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
                        return ERR_READING_MSG;
                }
            } else
                return ERR_READING_MSG;
            break;

        case 3: // Peer Up notification
            return NOT_YET_IMPLEMENTED; //throw "ERROR: Will need to add support for peer up if it's really used.";
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
static ssize_t libparsebgp_parse_bmp_parse_bmp_v3(libparsebgp_parsed_bmp_parsed_data *&parsed_msg, unsigned char *&buffer,
                                               int &buf_len) {

    ssize_t read_size = 0;
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len, 4)) != 4)
        return ERR_READING_MSG;

    read_size+=4;
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type, 1)) != 1)
        return ERR_READING_MSG;

    read_size+=1;

    // Change to host order
    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len);

    //   SELF_DEBUG("BMP v3: type = %x len=%d", parsed_msg->c_hdr_v3.type, parsed_msg->c_hdr_v3.len);

    // Adjust length to remove common header size
    bmp_len = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len - 1 - BMP_HDRv3_LEN;

    if (bmp_len > BGP_MAX_MSG_SIZE)
        return LARGER_MSG_LEN;

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
            return INVALID_MSG;     //throw "ERROR: BMP message type is not supported";
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
static ssize_t libparsebgp_parse_bmp_handle_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int &buf_len) {
    uint8_t     ver;
    ssize_t         read_size = 0;
    // Get the version in order to determine what we read next
    //    As of Junos 10.4R6.5, it supports version 1
    read_size+= extract_from_buffer(buffer, buf_len, &ver, 1);

    if (read_size != 1)
        return INVALID_MSG;

    // check the version
    if (ver == 3) { // draft-ietf-grow-bmp-04 - 07
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.ver = ver;
        read_size += libparsebgp_parse_bmp_parse_bmp_v3(parsed_msg, buffer, buf_len);
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type;
    }
        // Handle the older versions
    else if (ver == 1 || ver == 2) {
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ver=ver;
        read_size+=libparsebgp_parse_bmp_parse_bmp_v2(parsed_msg, buffer, buf_len);
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type;

    } else
        return INVALID_MSG;

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
        return true;
    } else
        return false;
}

/**
* Parse and return back the initiation message and update the init message structure
*
* \details
*        This method will read the init message tlvs and then store them in the init message structure.
*
* \param [in]     init_msg         Pointer to the initiation Message structure
* \param [in]     data             Pointer to the raw BGP message header
* \param [in]     size             length of the data buffer (used to prevent overrun)
* \param [out]    init_msg         Reference to the initiation message (will be updated with bmp message)
*
* \returns Bytes that have been successfully read by the handle initiation message.
*/
static ssize_t libparsebgp_parse_bmp_handle_init_msg(libparsebgp_parsed_bmp_init_msg *init_msg, unsigned char* buf_ptr, int buf_len) {
    int info_len;
    ssize_t read_bytes = 0;

    /*
     * Loop through the init message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_INIT_MSG_LEN) {
        init_msg_v3_tlv *init_msg_tlv;
        memcpy(&init_msg_tlv, buf_ptr, BMP_INIT_MSG_LEN);
        read_bytes+= BMP_INIT_MSG_LEN;

        memset(init_msg_tlv->info, 0, sizeof init_msg_tlv->info);
        SWAP_BYTES(&init_msg_tlv->len);
        SWAP_BYTES(&init_msg_tlv->type);

        buf_ptr += BMP_INIT_MSG_LEN;                // Move pointer past the info header

        if (init_msg_tlv->len > 0) {
            info_len = sizeof(init_msg_tlv->info) < init_msg_tlv->len ? sizeof(init_msg_tlv->info) : init_msg_tlv->len;
            bzero(init_msg_tlv->info, sizeof(init_msg_tlv->info));
            memcpy(init_msg_tlv->info, buf_ptr, info_len);
            read_bytes +=info_len;
            buf_ptr += info_len;                     // Move pointer past the info data
            i += info_len;                          // Update the counter past the info data
        }
        init_msg->init_msg_tlvs.push_back(*init_msg_tlv);
        delete init_msg_tlv;
    }
    return read_bytes;
}

/**
* Parse and return back the termination message and update the term message structure
*
* \details
        *  This method will read the expected stat counts and then parse the stat info messages.
*
* \param [in]     term_msg         Pointer to the termination Message structure
* \param [in]     data             Pointer to the raw BGP message header
* \param [in]     size             length of the data buffer (used to prevent overrun)
* \param [out]    term_msg         Reference to the termination message (will be updated with bmp message)
*
* \returns Bytes that have been successfully read by the handle termination message.
*/
static ssize_t libparsebgp_parse_bmp_handle_term_msg(libparsebgp_parsed_bmp_term_msg *term_msg, unsigned char *buf_ptr, int buf_len) {
    int info_len;
    ssize_t read_bytes = 0;

    /*
     * Loop through the term message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_TERM_MSG_LEN) {
        term_msg_v3_tlv *term_msg_tlv;
        memcpy(&term_msg_tlv, buf_ptr, BMP_TERM_MSG_LEN);
        read_bytes += BMP_TERM_MSG_LEN;

        memset(term_msg_tlv->info, 0, sizeof term_msg_tlv->info);
        SWAP_BYTES(&term_msg_tlv->len);
        SWAP_BYTES(&term_msg_tlv->type);

        buf_ptr += BMP_TERM_MSG_LEN;                // Move pointer past the info header

        if (term_msg_tlv->len > 0) {
            info_len = sizeof(term_msg_tlv->info) < term_msg_tlv->len ? sizeof(term_msg_tlv->info) : term_msg_tlv->len;
            bzero(term_msg_tlv->info, sizeof(term_msg_tlv->info));
            memcpy(term_msg_tlv->info, buf_ptr, info_len);
            read_bytes += info_len;
            buf_ptr += info_len;                     // Move pointer past the info data
            i += info_len;                       // Update the counter past the info data
        }
        term_msg->term_msg_tlvs.push_back(*term_msg_tlv);
        delete term_msg_tlv;
    }
    return read_bytes;
}

/**
 * Parse and return back the stats report and update the stat rep structure
 *
 * \details
 *  This method will read the expected stat counts and then parse the stat info messages.
 *
 * \param [in]     stat_rep_msg     Pointer to the stat report Message structure
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 * \param [out]    up_event         Reference to the stat report (will be updated with bmp message)
 *
 * \returns Bytes that have been successfully read by the handle stats report.
 */
static ssize_t libparsebgp_parse_bmp_handle_stats_report(libparsebgp_parsed_bmp_stat_rep *stat_rep_msg, unsigned char * buffer, int buf_len) {
    char b[8];
    ssize_t read_size = 0;

    if ((extract_from_buffer(buffer, buf_len, &stat_rep_msg->stats_count, 4)) != 4)
        return ERR_READING_MSG;

    SWAP_BYTES(&stat_rep_msg->stats_count);
    read_size+=4;

    // Loop through each stats object
    for (unsigned long i = 0; i < stat_rep_msg->stats_count; i++) {
        stat_counter stat_info;
        bzero(&stat_info, sizeof(stat_counter));
        bzero(b,8);
        if ((extract_from_buffer(buffer, buf_len, &stat_info.stat_type, 2)) != 2)
            return ERR_READING_MSG;

        read_size+=2;
        if ((extract_from_buffer(buffer, buf_len, &stat_info.stat_len, 2)) != 2)
            return ERR_READING_MSG;

        read_size+=2;
        // convert integer from network to host bytes
        SWAP_BYTES(&stat_info.stat_type);
        SWAP_BYTES(&stat_info.stat_len);

        // check if this is a 32 bit number  (default)
        if (stat_info.stat_len == 4 or stat_info.stat_len == 8) {

            // Read the stats counter - 32/64 bits
            if ((extract_from_buffer(buffer, buf_len, b, stat_info.stat_len)) == stat_info.stat_len) {
                read_size+=stat_info.stat_len;
                // convert the bytes from network to host order
                SWAP_BYTES(b, stat_info.stat_len);
                memcpy(stat_info.stat_data, b, stat_info.stat_len);
            }

        } else {

            while (stat_info.stat_len-- > 0)
                extract_from_buffer(buffer, buf_len, &b[0], 1);
        }
        stat_rep_msg->total_stats_counter.push_back(stat_info);
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
 * \param [in]     up_event         Pointer to the Up Event Message structure
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 * \param [out]    up_event         Reference to the peer up event storage (will be updated with bmp info)
 *
 * \returns Bytes that have been successfully read by the handle up event.
 */
static ssize_t libparsebgp_parse_bgp_handle_up_event(libparsebgp_parsed_bmp_peer_up_event *up_event, unsigned char *data, size_t size) {
    ssize_t    read_size = 0, bytes_read;
    /*
    * Process the sent open message
    */
    if (libparsebgp_parse_bgp_parse_header(up_event->sent_open_msg, data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;
        size -= BGP_MSG_HDR_LEN;
        read_size += BGP_MSG_HDR_LEN;

        bytes_read = libparsebgp_open_msg_parse_open_msg(&up_event->sent_open_msg.parsed_data.open_msg, data, size, true);

        if (!bytes_read) {
            return ERR_READING_MSG; //throw "Failed to read sent open message";
        }
        if (bytes_read < 0)
            return bytes_read;    // has the error codes

        data += bytes_read;                                          // Move the pointer pase the sent open message
        size -= bytes_read;
        read_size += bytes_read;
    } else
        return CORRUPT_MSG; //throw "ERROR: Invalid BGP MSG for BMP Received OPEN message, expected OPEN message.";

    if (libparsebgp_parse_bgp_parse_header(up_event->received_open_msg, data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;
        size -= BGP_MSG_HDR_LEN;
        read_size += BGP_MSG_HDR_LEN;

        bytes_read = libparsebgp_open_msg_parse_open_msg(&up_event->received_open_msg.parsed_data.open_msg,data, size, false);

        if (!bytes_read) {
            return ERR_READING_MSG; //throw "Failed to read received open message";
        }
        if (bytes_read < 0)
            return bytes_read;    // has the error codes

        data += bytes_read;                                          // Move the pointer pase the sent open message
        size -= bytes_read;
        read_size += bytes_read;
    } else
        return CORRUPT_MSG; //throw "ERROR: Invalid BGP MSG for BMP Received OPEN message, expected OPEN message.";

    return read_size;
}

/**
 * Parse the v3 peer up BMP header
 *
 * \details This method will update the peer_up_event struct with BMP header info.
 *
 * \param [in]     up_event         Pointer to the Up Event Message structure
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 * \param [out]    up_event         Reference to the peer up event storage (will be updated with bmp info)
 *
 * \returns Bytes that have been successfully read by the peer up header parser.
 */
static ssize_t libparsebgp_parse_bmp_parse_peer_up_event_hdr(libparsebgp_parsed_bmp_peer_up_event *up_event, unsigned char*& buffer, int& buf_len) {
    bool is_parse_good = true;
    ssize_t bytes_read = 0;

    // Get the local address
    if ( extract_from_buffer(buffer, buf_len, &up_event->local_ip, 16) != 16)
        is_parse_good = false;
    else
        bytes_read += 16;

    // Get the local port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &up_event->local_port, 2) != 2)
        is_parse_good = false;

    else if (is_parse_good) {
        bytes_read += 2;
        SWAP_BYTES(&up_event->local_port);
    }

    // Get the remote port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &up_event->remote_port, 2) != 2)
        is_parse_good = false;

    else if (is_parse_good) {
        bytes_read += 2;
        SWAP_BYTES(&up_event->remote_port);
    }

    // Update bytes read
    bmp_len -= bytes_read;

    // Validate parse is still good, if not read the remaining bytes of the message so that the next msg will work
    if (!is_parse_good) return CORRUPT_MSG;

    return bytes_read;
}

/**
 * Parses a BMP message by its various types
 *
 * \details
 *  This function will parse the header of the message and according to the type of the BMP message, it parses the rest of the message.
 *
 * \param [in]     parsed_msg       Pointer to the BMP Message structure
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 * \param [out]    parsed_msg       Referenced to the updated bmp parsed message
 *
 * \returns Bytes that have been successfully read by the bmp parser.
 */
ssize_t libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int buf_len) {
    string peer_info_key;
    ssize_t read_size = 0, bytes_read = 0;
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

                    read_size += 1;
                    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

                    // Check if the reason indicates we have a BGP message that follows
                    switch (parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.bmp_reason) {
                        case 1 : { // Local system close with BGP notify
                            read_size += libparsebgp_parse_bgp_handle_down_event(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg, bmp_data, bmp_data_len);
                            break;
                        }
                        case 2 : // Local system close, no bgp notify
                        {
                            // Read two byte code corresponding to the FSM event
                            uint16_t fsm_event = 0 ;
                            memcpy(&fsm_event, bmp_data, 2);
                            SWAP_BYTES(&fsm_event);
                            read_size += 2;
                            break;
                        }
                        case 3 : { // remote system close with bgp notify
                            read_size += libparsebgp_parse_bgp_handle_down_event(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg, bmp_data, bmp_data_len);
                            break;
                        }
                        default:
                            break;
                    }
                } else
                    return ERR_READING_MSG;
                break;
            }

            case TYPE_PEER_UP : // Peer up type
            {

                bytes_read = libparsebgp_parse_bmp_parse_peer_up_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg, buffer, buf_len);

                if(bytes_read<0) return bytes_read;
                read_size += bytes_read;

                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                bytes_read = libparsebgp_parse_bgp_handle_up_event(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg, bmp_data, bmp_data_len);

                if(bytes_read<0) return bytes_read;
                read_size += bytes_read;

                break;
            }

            case TYPE_ROUTE_MON : { // Route monitoring type
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                bytes_read = libparsebgp_parse_bgp_handle_update(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_rm_msg.update_msg, bmp_data, bmp_data_len);

                if(bytes_read<0) return bytes_read;
                read_size += bytes_read;
                break;
            }

            case TYPE_STATS_REPORT : { // Stats Report
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                bytes_read = libparsebgp_parse_bmp_handle_stats_report(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_stat_rep, bmp_data, bmp_data_len);

                if(bytes_read<0) return bytes_read;
                read_size += bytes_read;
                break;
            }

            case TYPE_INIT_MSG : { // Initiation Message
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                bytes_read = libparsebgp_parse_bmp_handle_init_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_init_msg, bmp_data, bmp_data_len);

                if(bytes_read<0) return bytes_read;
                read_size += bytes_read;
                break;
            }

            case TYPE_TERM_MSG : { // Termination Message
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                bytes_read = libparsebgp_parse_bmp_handle_term_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_term_msg, bmp_data, bmp_data_len);

                if(bytes_read<0) return bytes_read;
                read_size += bytes_read;
                break;
            }
            default:
                return CORRUPT_MSG;
        }
    } catch (char const *str) {
        // Mark the router as disconnected and update the error to be a local disconnect (no term message received)
        //  LOG_INFO("%s: Caught: %s", client->c_ip, str);
        throw str;
    }

    return read_size;
}