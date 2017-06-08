//
// Created by ojas on 4/22/17.
//
#include "../include/parse_bgp.h"
#include "../include/parse_bmp.h"

/**
 * Buffer remaining BMP message
 *
 * @details This method will read the remaining amount of BMP data and store it in the instance variable bmp_data.
 *          Normally this is used to store the BGP message so that it can be parsed.
 *
 * @param [in]  buffer       Buffer to read the message from
 * @param [in]  buf_len      Buffer length of the available buffer
 *
 * @return Returns the error code in buffering the message
 *
 */
static ssize_t libparsebgp_parse_bmp_buffer_bmp_message(unsigned char*& buffer, int& buf_len) {

    bmp_data_len=0;
    //TO DO:
    if (bmp_len <= 0)
        return 0;

    if (bmp_len > sizeof(bmp_data))
        return LARGER_MSG_LEN;      //BMP message length is too large for buffer, invalid BMP sender

    if ((bmp_data_len=extract_from_buffer(buffer, buf_len, bmp_data, bmp_len)) != bmp_len)
        return ERR_READING_MSG;     //Error while reading BMP data into buffer

    // Indicate no more data is left to read
    bmp_len = 0;

    return 0;       //No error
}

/**
* Parse v3 BMP header
*
* @details
*      v3 uses the same common header, but adds the Peer Up message type.
*
* @param [in]     parsed_peer_header    Reference to the peer header Message structure
* @param [in]     buffer                Pointer to the raw BMP Message header
* @param [in]     buf_len               length of the data buffer (used to prevent overrun)
*
* @returns  Bytes that have been successfully read by bmp parse peer header.
*
*/
static ssize_t libparsebgp_parse_bmp_parse_peer_hdr(libparsebgp_parsed_peer_hdr_v3 &parsed_peer_header, unsigned char *&buffer, int &buf_len) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &parsed_peer_header, BMP_PEER_HDR_LEN)!= BMP_PEER_HDR_LEN)
        return ERR_READING_MSG;

    // Adding the peer header len to the read_size
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
* @details
*      v2 uses the same common header, but adds the Peer Up message type.
*
* @param [in]     parsed_msg       Pointer to the bmp parsed data structure
* @param [in]     buffer           Pointer to the raw BMP Message header
* @param [in]     buf_len          length of the data buffer (used to prevent overrun)
*
* @returns Bytes that have been successfully read by the parse bmp v2.
*/
static ssize_t libparsebgp_parse_bmp_parse_bmp_v2(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int& buf_len) {
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
                return ERR_READING_MSG;     //error in reading bgp length
            break;

        case 3: // Peer Up notification
            return NOT_YET_IMPLEMENTED;     //ERROR: Will need to add support for peer up if it's really used.
    }
    return read_size;
}

/**
 * Parse v3 BMP header
 *
 * @details
 *      v3 has a different header structure and changes the peer
 *      header format.
 *
 * @param [in]     parsed_msg    Pointer to the bmp parsed data structure
 * @param [in]     buffer        Pointer to the raw BMP Message header
 * @param [in]     buf_len       length of the data buffer (used to prevent overrun)
 *
 * @return Bytes that have been successfully read by the parse bmp v3.
 */
static ssize_t libparsebgp_parse_bmp_parse_bmp_v3(libparsebgp_parsed_bmp_parsed_data *&parsed_msg, unsigned char *&buffer, int &buf_len) {

    ssize_t read_size = 0;
    //reading the length in the header
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len, 4)) != 4)
        return ERR_READING_MSG;

    read_size+=4;

    //reading the bmp type in the header
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type, 1)) != 1)
        return ERR_READING_MSG;

    read_size+=1;

    // Change to host order
    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len);

    // Adjust length to remove common header size
    bmp_len = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len - 1 - BMP_HDRv3_LEN;

    if (bmp_len > BGP_MAX_MSG_SIZE)
        return LARGER_MSG_LEN;

    //Parsing per peer header for every type except init and term since these messages doesn't contain peer headers
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
            return INVALID_MSG;     //ERROR: BMP message type is not supported
    }
    return read_size;
}

/**
 * Process the incoming BMP message's header
 *
 * @details
 *      This function parses the header in a bmp message and further parses it according to the version in the header
 *
 * @param [in]     parsed_msg    Pointer to the bmp parsed data structure
 * @param [in]     buffer        Pointer to the raw BMP Message header
 * @param [in]     buf_len       length of the data buffer (used to prevent overrun)
 *
 * @return Bytes that have been successfully read by the parse bmp v3.
 *
 */
static ssize_t libparsebgp_parse_bmp_msg_header(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int &buf_len) {
//    uint8_t         ver = 0;
    ver = 0;
    ssize_t         read_size = 0, bytes_read = 0;

    // Reading the version to parse the header accordingly
    if(extract_from_buffer(buffer, buf_len, &ver, 1)!=1)
        return INVALID_MSG;

    read_size += 1;

    // check the version
    if (ver == 3) { // draft-ietf-grow-bmp-04 - 07
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.ver = ver;
        //parsing the rest of the message as per the version
        bytes_read =  libparsebgp_parse_bmp_parse_bmp_v3(parsed_msg, buffer, buf_len);
        if(bytes_read<0) return bytes_read;

        read_size+=bytes_read;
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type;
    }
        // Handle the older versions
    else if (ver == 1 || ver == 2) {
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ver = ver;
        //parsing the rest of the message as per the version
        bytes_read = libparsebgp_parse_bmp_parse_bmp_v2(parsed_msg, buffer, buf_len);
        if(bytes_read<0) return bytes_read;

        read_size+=bytes_read;
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type;

    } else
        return INVALID_MSG;     //Invalid version in the message header

    return read_size;
}

/**
* Parse and return back the initiation message and update the init message structure
*
* @details
*        This method will read the init message tlvs and then store them in the init message structure.
*
* @param [in]     init_msg         Pointer to the initiation Message structure
* @param [in]     data             Pointer to the raw BGP message header
* @param [in]     size             length of the data buffer (used to prevent overrun)
* @param [out]    init_msg         Reference to the initiation message (will be updated with bmp message)
*
* @returns Bytes that have been successfully read by the handle initiation message.
*/
static ssize_t libparsebgp_parse_bmp_handle_init_msg(libparsebgp_parsed_bmp_init_msg *init_msg, unsigned char *buf_ptr, int buf_len) {
    int info_len = 0;
    ssize_t read_bytes = 0;

    int num_tlvs = bmp_data_len/BMP_INIT_MSG_LEN, curr_tlv = 0;

    init_msg->init_msg_tlvs = (init_msg_v3_tlv *)malloc(num_tlvs*sizeof(init_msg_v3_tlv));
    init_msg_v3_tlv *init_msg_tlv = (init_msg_v3_tlv *)malloc(sizeof(init_msg_v3_tlv));

    /*
     * Loop through the init message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_INIT_MSG_LEN) {
        memset(init_msg_tlv, 0, sizeof(init_msg_v3_tlv));

        memcpy(&init_msg_tlv->type, buf_ptr, 2);
        read_bytes+= 2;
        buf_ptr+= 2;

        memcpy(&init_msg_tlv->len, buf_ptr, 2);
        read_bytes+= 2;
        buf_ptr+= 2;

        memset(init_msg_tlv->info, 0, sizeof(init_msg_tlv->info));
        SWAP_BYTES(&init_msg_tlv->len);
        SWAP_BYTES(&init_msg_tlv->type);

        if (init_msg_tlv->len > 0) {
            info_len = sizeof(init_msg_tlv->info) < init_msg_tlv->len ? sizeof(init_msg_tlv->info) : init_msg_tlv->len;
            bzero(init_msg_tlv->info, sizeof(init_msg_tlv->info));
            memcpy(init_msg_tlv->info, buf_ptr, info_len);
            read_bytes +=info_len;
            buf_ptr += info_len;                     // Move pointer past the info data
            i += info_len;                          // Update the counter past the info data
        }

        init_msg->init_msg_tlvs[curr_tlv++] = *init_msg_tlv;
    }
    delete init_msg_tlv;
    return read_bytes;
}

/**
* Parse and return back the termination message and update the term message structure
*
* @details
        *  This method will read the expected stat counts and then parse the stat info messages.
*
* @param [in]     term_msg         Pointer to the termination Message structure
* @param [in]     data             Pointer to the raw BGP message header
* @param [in]     size             length of the data buffer (used to prevent overrun)
* @param [out]    term_msg         Reference to the termination message (will be updated with bmp message)
*
* @returns Bytes that have been successfully read by the handle termination message.
*/
static ssize_t libparsebgp_parse_bmp_handle_term_msg(libparsebgp_parsed_bmp_term_msg *term_msg, unsigned char *buf_ptr, int buf_len) {
    int info_len;
    ssize_t read_bytes = 0;

    uint32_t num_tlvs = bmp_data_len/BMP_TERM_MSG_LEN, curr_tlv = 0;
    term_msg->term_msg_tlvs = (term_msg_v3_tlv *)malloc(num_tlvs*sizeof(term_msg_v3_tlv));
    /*
     * Loop through the term message (in buffer) to parse each TLV
     */
    term_msg_v3_tlv *term_msg_tlv = (term_msg_v3_tlv *)malloc(sizeof(term_msg_v3_tlv));

    for (int i=0; i < bmp_data_len; i += BMP_TERM_MSG_LEN) {
        memset(term_msg_tlv, 0, sizeof(term_msg_v3_tlv));

        memcpy(&term_msg_tlv->type, buf_ptr, 2);
        buf_ptr+=2;

        memcpy(&term_msg_tlv->len, buf_ptr, 2);
        buf_ptr+=2;

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
        term_msg->term_msg_tlvs[curr_tlv++] = *term_msg_tlv;
    }
    delete(term_msg_tlv);
    return read_bytes;
}

/**
 * Parse and return back the stats report and update the stat rep structure
 *
 * @details
 *  This method will read the expected stat counts and then parse the stat info messages.
 *
 * @param [in]     stat_rep_msg     Pointer to the stat report Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent overrun)
 * @param [out]    up_event         Reference to the stat report (will be updated with bmp message)
 *
 * @returns Bytes that have been successfully read by the handle stats report.
 */
static ssize_t libparsebgp_parse_bmp_handle_stats_report(libparsebgp_parsed_bmp_stat_rep *stat_rep_msg, unsigned char *buffer, int buf_len) {
    char b[8];
    ssize_t read_size = 0;

    if ((extract_from_buffer(buffer, buf_len, &stat_rep_msg->stats_count, 4)) != 4)
        return ERR_READING_MSG;

    SWAP_BYTES(&stat_rep_msg->stats_count);
    read_size+=4;

    stat_rep_msg->total_stats_counter = (stat_counter *)malloc(stat_rep_msg->stats_count*sizeof(stat_counter));
    stat_counter *stat_info = (stat_counter *)malloc(sizeof(stat_counter));

    // Loop through each stats object
    for (unsigned long i = 0; i < stat_rep_msg->stats_count; i++) {
        memset(stat_info, 0, sizeof(stat_counter));

        bzero(b,8);
        if ((extract_from_buffer(buffer, buf_len, &stat_info->stat_type, 2)) != 2)
            return ERR_READING_MSG;

        read_size+=2;
        if ((extract_from_buffer(buffer, buf_len, &stat_info->stat_len, 2)) != 2)
            return ERR_READING_MSG;

        read_size+=2;
        // convert integer from network to host bytes
        SWAP_BYTES(&stat_info->stat_type);
        SWAP_BYTES(&stat_info->stat_len);

        // check if this is a 32 bit number  (default)
        if (stat_info->stat_len == 4 or stat_info->stat_len == 8) {

            // Read the stats counter - 32/64 bits
            if ((extract_from_buffer(buffer, buf_len, b, stat_info->stat_len)) == stat_info->stat_len) {
                read_size+=stat_info->stat_len;
                // convert the bytes from network to host order
                SWAP_BYTES(b, stat_info->stat_len);
                memcpy(stat_info->stat_data, b, stat_info->stat_len);
            }

        } else {

            while (stat_info->stat_len-- > 0)
                extract_from_buffer(buffer, buf_len, &b[0], 1);
        }
        stat_rep_msg->total_stats_counter[i]=*stat_info;
//        delete stat_info;
    }
    delete(stat_info);
    return read_size;
}

/**
 * Handles the up event by parsing the BGP open messages - Up event will be updated
 *
 * @details
 *  This method will read the expected sent and receive open messages.
 *
 * @param [in]     up_event         Pointer to the Up Event Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent overrun)
 * @param [out]    up_event         Reference to the peer up event storage (will be updated with bmp info)
 *
 * @returns Bytes that have been successfully read by the handle up event.
 */
static ssize_t libparsebgp_parse_bgp_handle_up_event(libparsebgp_parsed_bmp_peer_up_event *up_event, unsigned char *data, size_t size) {
    ssize_t    read_size = 0, bytes_read = 0;
    /*
    * Process the sent open message
    */
    if((bytes_read = libparsebgp_parse_bgp_parse_header(up_event->sent_open_msg.c_hdr, data, size))>0)
    {
        if(up_event->sent_open_msg.c_hdr.type == BGP_MSG_OPEN) {
            data += BGP_MSG_HDR_LEN;
            size -= BGP_MSG_HDR_LEN;
            read_size += BGP_MSG_HDR_LEN;

            bytes_read = libparsebgp_open_msg_parse_open_msg(&up_event->sent_open_msg.parsed_data.open_msg, data, size, true);

            if (!bytes_read)
                return ERR_READING_MSG; //throw "Failed to read sent open message";

            if (bytes_read < 0)
                return bytes_read;    // has the error codes

            data += bytes_read;                                          // Move the pointer pase the sent open message
            size -= bytes_read;
            read_size += bytes_read;
        }
        else
            return CORRUPT_MSG;
    }
    else
        return bytes_read; //throw "ERROR: Invalid BGP MSG for BMP Received OPEN message, expected OPEN message.";

    if((bytes_read = libparsebgp_parse_bgp_parse_header(up_event->sent_open_msg.c_hdr, data, size))>0)
    {
        if (up_event->sent_open_msg.c_hdr.type == BGP_MSG_OPEN) {
            data += BGP_MSG_HDR_LEN;
            size -= BGP_MSG_HDR_LEN;
            read_size += BGP_MSG_HDR_LEN;

            bytes_read = libparsebgp_open_msg_parse_open_msg(&up_event->received_open_msg.parsed_data.open_msg, data,
                                                             size, false);

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
    }
    else
        return bytes_read;
    return read_size;
}

/**
 * Parse the v3 peer up BMP header
 *
 * @details This method will update the peer_up_event struct with BMP header info.
 *
 * @param [in]     up_event         Pointer to the Up Event Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent overrun)
 * @param [out]    up_event         Reference to the peer up event storage (will be updated with bmp info)
 *
 * @returns Bytes that have been successfully read by the peer up header parser.
 */
static ssize_t libparsebgp_parse_bmp_parse_peer_up_event_hdr(libparsebgp_parsed_bmp_peer_up_event *up_event, unsigned char *&buffer, int& buf_len) {
    bool is_parse_good = true;
    ssize_t read_size = 0;

    // Get the local address
    if (extract_from_buffer(buffer, buf_len, &up_event->local_ip, 16) != 16)
        is_parse_good = false;
    else
        read_size += 16;

    // Get the local port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &up_event->local_port, 2) != 2)
        is_parse_good = false;
    else if (is_parse_good) {
        read_size += 2;
        SWAP_BYTES(&up_event->local_port);
    }

    // Get the remote port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &up_event->remote_port, 2) != 2)
        is_parse_good = false;
    else if (is_parse_good) {
        read_size += 2;
        SWAP_BYTES(&up_event->remote_port);
    }

    // Update bytes read
    bmp_len -= read_size;

    // Validate parse is still good, if not read the remaining bytes of the message so that the next msg will work
    if (!is_parse_good) return CORRUPT_MSG;

    return read_size;
}

/**
 * Parses a BMP message by its various types
 *
 * @details
 *  This function will parse the header of the message and according to the type of the BMP message, it parses the rest of the message.
 *
 * @param [in]     parsed_msg       Pointer to the BMP Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent overrun)
 * @param [out]    parsed_msg       Referenced to the updated bmp parsed message
 *
 * @returns Bytes that have been successfully read by the bmp parser.
 */
ssize_t libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int buf_len) {
    ssize_t read_size = 0, bytes_read = 0;
    bzero(bmp_data, sizeof(bmp_data));
    bmp_len=0;

    /*
     * Parsing the bmp message header: Version 1, 2, 3 are supported
     */
    if((bytes_read= libparsebgp_parse_bmp_msg_header(parsed_msg, buffer, buf_len))<0)
        return bytes_read;      //checking for the error code returned in parsing bmp header.

    read_size += bytes_read;    //adding the bytes read from parsing the header

    /*
     * Parsing BMP message based on bmp type retrieved from the header
     */
    switch (bmp_type) {
        case TYPE_PEER_DOWN : { // Parsing Peer down type
            if (extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.bmp_reason, 1) == 1) {
                read_size += 1;
                bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);
                if(bytes_read<0) return bytes_read;

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

        case TYPE_PEER_UP : // Parsing Peer up type
        {
            /*
             * Parsing the up event header except open messages
             */
            if((bytes_read = libparsebgp_parse_bmp_parse_peer_up_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg, buffer, buf_len))<0)
                return bytes_read;

            read_size += bytes_read;

            /*
             * Reading the message into buffer bmp_data
             */
            if((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len))<0)
                return bytes_read;

            /*
             * Parsing the received and sent open message in the up event message
             */
            if((bytes_read = libparsebgp_parse_bgp_handle_up_event(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg, bmp_data, bmp_data_len))<0)
                return bytes_read;

            read_size += bytes_read;
            break;
        }

        case TYPE_ROUTE_MON : { // Route monitoring type
            /*
             * Reading the message into buffer bmp_data
             */
            if((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len))<0)
                return bytes_read;

            /*
             * Parsing the bgp update message
             */
            if((bytes_read = libparsebgp_parse_bgp_handle_update(parsed_msg->libparsebgp_parsed_bmp_msg.parsed_rm_msg, bmp_data, bmp_data_len))<0)
                return bytes_read;

            read_size += bytes_read;
            break;
        }

        case TYPE_STATS_REPORT : { // Stats Report
            /*
             * Reading the message into buffer bmp_data
             */
            if((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len))<0)
                return bytes_read;

            /*
             * Parsing the stats report message
             */
            if((bytes_read = libparsebgp_parse_bmp_handle_stats_report(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_stat_rep, bmp_data, bmp_data_len))<0)
                return bytes_read;

            read_size += bytes_read;
            break;
        }

        case TYPE_INIT_MSG : { // Initiation Message
            /*
             * Reading the message into buffer bmp_data
             */
            if((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len))<0)
                return bytes_read;

            /*
             * Parsing the init message tlvs
             */
            if((bytes_read = libparsebgp_parse_bmp_handle_init_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_init_msg, bmp_data, bmp_data_len))<0)
                return bytes_read;

            read_size += bytes_read;
            break;
        }

        case TYPE_TERM_MSG : { // Termination Message
            /*
             * Reading the message into buffer bmp_data
             */
            if((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len))<0)
                return bytes_read;

            /*
             * Parsing the term message tlvs
             */
            if((bytes_read = libparsebgp_parse_bmp_handle_term_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_term_msg, bmp_data, bmp_data_len))<0)
                return bytes_read;

            read_size += bytes_read;
            break;
        }
        default:
            return CORRUPT_MSG;     //Invalid BMP message type
    }
    return read_size;
}

/**
 * Destructor function to free bmp_parsed_data
 */
void libparsebgp_parse_bmp_destructor(libparsebgp_parsed_bmp_parsed_data *parsed_data) {
    switch (bmp_type) {
        case TYPE_INIT_MSG : {
//            int num_tlvs = bmp_data_len / BMP_INIT_MSG_LEN;
//            for (int i = 0; i < num_tlvs; i++) {
//                free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_init_msg.init_msg_tlvs[i]);
//            }
            free(parsed_data->libparsebgp_parsed_bmp_msg.parsed_init_msg.init_msg_tlvs);
            parsed_data->libparsebgp_parsed_bmp_msg.parsed_init_msg.init_msg_tlvs = NULL;
//            free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_init_msg);
            break;
        }
        case TYPE_PEER_DOWN: {
            libparsebgp_parse_bgp_destructor(parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg);
//            free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg);
            break;
        }
        case TYPE_PEER_UP: {
            libparsebgp_parse_bgp_destructor(parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg.received_open_msg);
            libparsebgp_parse_bgp_destructor(parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg.sent_open_msg);
//            free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg);
            break;
        }
        case TYPE_ROUTE_MON: {
            libparsebgp_parse_bgp_destructor(parsed_data->libparsebgp_parsed_bmp_msg.parsed_rm_msg);
//            free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_rm_msg);
            break;
        }
        case TYPE_STATS_REPORT: {
//            for (int i = 0; i < parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep.stats_count; i++) {
//                free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep.total_stats_counter[i]);
//            }
            free(parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep.total_stats_counter);
            parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep.total_stats_counter = NULL;
//            free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep);
            break;
        }
        case TYPE_TERM_MSG: {
//            uint32_t num_tlvs = bmp_data_len/BMP_TERM_MSG_LEN;
//            for (int i = 0; i < num_tlvs; i++) {
//                free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_term_msg.term_msg_tlvs[i]);
//            }
            free(parsed_data->libparsebgp_parsed_bmp_msg.parsed_term_msg.term_msg_tlvs);
            parsed_data->libparsebgp_parsed_bmp_msg.parsed_term_msg.term_msg_tlvs = NULL;
//            free(&parsed_data->libparsebgp_parsed_bmp_msg.parsed_term_msg);
            break;
        }
    }
}

//int main() {
///*    u_char temp[] = {0x58, 0xb6, 0x12, 0x84, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0xe4, 0x8f,
//                     0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x00, 0x01, 0x67, 0xf7, 0x03, 0x2d, 0x80, 0xdf, 0x33, 0x66,
//                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//                     0x00, 0x43, 0x02, 0x00, 0x04, 0x18, 0xa8, 0xb5, 0x24, 0x00, 0x24, 0x40, 0x01, 0x01, 0x00, 0x40,
//                     0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0xe4, 0x8f, 0x00, 0x00, 0x1b, 0x1b, 0x00, 0x04, 0x01, 0x04,
//                     0x00, 0x00, 0x6e, 0xb7, 0x00, 0x04, 0x05, 0x73, 0x40, 0x03, 0x04, 0x67, 0xf7, 0x03, 0x2d, 0x18,
//                     0xbf, 0x05, 0xaa};
//
//
///*u_char temp[] = {0x58, 0x67, 0xb5, 0x31, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x07, 0x2c,
//                     0x00, 0x00, 0x31, 0x6e, 0x00, 0x00, 0x00, 0x02, 0x2a, 0x01, 0x02, 0xa8, 0x00, 0x00, 0x00, 0x00,
//                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x06, 0x7c, 0x02, 0xe8, 0x00, 0x02,
//                     0xff, 0xff, 0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04};*//*
//*/
///*
//*/
//    int len = 0;
//    //unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0x06, 0x04};
////len = 186;
////unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xdf, 0x33, 0x67, 0xd0, 0x40, 0x00, 0xb3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x41, 0x01, 0x04, 0x19, 0x2f, 0x02, 0x58, 0x80, 0xdf, 0x33, 0x67, 0x24, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x19, 0x2f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x35, 0x01, 0x04, 0x0d, 0x1c, 0x00, 0xb4, 0x04, 0x45, 0xb8, 0xc1, 0x18, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00};
////len = 228;
////unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0xe4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x92, 0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x92, 0x03, 0x7f, 0xff, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xeb, 0x80, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xeb, 0x80, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x80, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x80, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x80, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xb4};
////len = 870;
////unsigned char temp[] = {0x03, 0x00, 0x00, 0x03, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03, 0x36, 0x02, 0x00, 0x00, 0x00, 0x44, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x08, 0x02, 0x03, 0x0d, 0x1c, 0x0b, 0x62, 0x40, 0x7d, 0x40, 0x03, 0x04, 0x04, 0x45, 0xb8, 0xc1, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x08, 0x24, 0x0b, 0x62, 0x01, 0x9a, 0x0b, 0x62, 0x04, 0xb3, 0x0b, 0x62, 0x08, 0x99, 0x0b, 0x62, 0x0c, 0x80, 0x0d, 0x1c, 0x00, 0x03, 0x0d, 0x1c, 0x00, 0x56, 0x0d, 0x1c, 0x02, 0x3f, 0x0d, 0x1c, 0x02, 0x9a, 0x0d, 0x1c, 0x07, 0xdc, 0x17, 0x36, 0xe7, 0x82, 0x16, 0x34, 0xda, 0x40, 0x15, 0x34, 0xda, 0x38, 0x16, 0x34, 0xda, 0x34, 0x18, 0x36, 0xb6, 0xf4, 0x18, 0x34, 0xde, 0xf2, 0x17, 0x34, 0xde, 0xf0, 0x18, 0x34, 0xde, 0xef, 0x17, 0x34, 0xde, 0xec, 0x17, 0x34, 0xde, 0xe8, 0x16, 0x34, 0xde, 0xe4, 0x17, 0x34, 0xde, 0xe2, 0x18, 0x34, 0x54, 0x49, 0x18, 0x36, 0xef, 0x27, 0x18, 0x36, 0xef, 0x25, 0x18, 0x36, 0xef, 0x22, 0x18, 0x36, 0xef, 0x20, 0x18, 0x36, 0xe7, 0x9f, 0x18, 0x36, 0xe7, 0x9e, 0x18, 0x36, 0xe7, 0x9d, 0x18, 0x36, 0xe7, 0x9a, 0x18, 0x36, 0xe7, 0x99, 0x18, 0x36, 0xe7, 0x98, 0x18, 0x36, 0xe7, 0x97, 0x18, 0x36, 0xe7, 0x94, 0x18, 0x36, 0xe7, 0x93, 0x18, 0x36, 0xe7, 0x92, 0x18, 0x36, 0xe7, 0x91, 0x18, 0x36, 0xe7, 0x8e, 0x18, 0x36, 0xe7, 0x8d, 0x18, 0x36, 0xe7, 0x8b, 0x18, 0x36, 0xe7, 0x8a, 0x18, 0x36, 0xe7, 0x89, 0x18, 0x36, 0xe7, 0x87, 0x18, 0x36, 0xe7, 0x86, 0x18, 0x36, 0xe7, 0x84, 0x18, 0x36, 0xe7, 0x83, 0x18, 0x36, 0xe7, 0x81, 0x13, 0x36, 0xe7, 0x80, 0x18, 0x36, 0xe7, 0x80, 0x16, 0x36, 0xe6, 0x1c, 0x11, 0x36, 0xe5, 0x80, 0x11, 0x36, 0xe5, 0x00, 0x10, 0x36, 0xe4, 0x10, 0x36, 0xdc, 0x0f, 0x36, 0xd8, 0x10, 0x36, 0xc3, 0x10, 0x36, 0xc2, 0x16, 0x36, 0xc0, 0x1c, 0x17, 0x36, 0xb6, 0xf0, 0x18, 0x36, 0xb6, 0xc8, 0x18, 0x36, 0xb6, 0xc7, 0x18, 0x36, 0xb6, 0xc6, 0x17, 0x36, 0xb6, 0x90, 0x17, 0x36, 0xb6, 0x8e, 0x17, 0x36, 0xb6, 0x8c, 0x10, 0x36, 0xab, 0x10, 0x36, 0xaa, 0x10, 0x36, 0x9b, 0x10, 0x36, 0x9a, 0x10, 0x36, 0x4e, 0x0f, 0x36, 0x4c, 0x0f, 0x36, 0x4a, 0x10, 0x36, 0x49, 0x10, 0x36, 0x48, 0x18, 0x34, 0xda, 0x4f, 0x18, 0x34, 0xda, 0x4e, 0x18, 0x34, 0xda, 0x4b, 0x18, 0x34, 0xda, 0x4a, 0x18, 0x34, 0xda, 0x49, 0x18, 0x34, 0xda, 0x48, 0x18, 0x34, 0xda, 0x45, 0x18, 0x34, 0xda, 0x44, 0x18, 0x34, 0xda, 0x43, 0x18, 0x34, 0xda, 0x42, 0x18, 0x34, 0xda, 0x3f, 0x18, 0x34, 0xda, 0x3c, 0x18, 0x34, 0xda, 0x3b, 0x18, 0x34, 0xda, 0x3a, 0x18, 0x34, 0xda, 0x39, 0x18, 0x34, 0xda, 0x36, 0x18, 0x34, 0xda, 0x35, 0x18, 0x34, 0xda, 0x34, 0x18, 0x34, 0xda, 0x33, 0x18, 0x34, 0xda, 0x30, 0x18, 0x34, 0xda, 0x2d, 0x18, 0x34, 0xda, 0x2c, 0x18, 0x34, 0xda, 0x2b, 0x18, 0x34, 0xda, 0x2a, 0x18, 0x34, 0xda, 0x27, 0x18, 0x34, 0xda, 0x26, 0x18, 0x34, 0xda, 0x25, 0x18, 0x34, 0xda, 0x24, 0x18, 0x34, 0xda, 0x21, 0x18, 0x34, 0xda, 0x20, 0x18, 0x34, 0xda, 0x1e, 0x18, 0x34, 0xda, 0x1d, 0x18, 0x34, 0xda, 0x1c, 0x18, 0x34, 0xda, 0x1b, 0x18, 0x34, 0xda, 0x18, 0x18, 0x34, 0xda, 0x17, 0x18, 0x34, 0xda, 0x16, 0x18, 0x34, 0xda, 0x15, 0x18, 0x34, 0xda, 0x12, 0x18, 0x34, 0xda, 0x11, 0x18, 0x34, 0xda, 0x10, 0x18, 0x34, 0xda, 0x0f, 0x18, 0x34, 0xda, 0x0e, 0x18, 0x34, 0xda, 0x0d, 0x18, 0x34, 0xda, 0x0c, 0x18, 0x34, 0xda, 0x09, 0x18, 0x34, 0xda, 0x08, 0x18, 0x34, 0xda, 0x07, 0x18, 0x34, 0xda, 0x06, 0x18, 0x34, 0xda, 0x03, 0x18, 0x34, 0xda, 0x02, 0x18, 0x34, 0xda, 0x01, 0x11, 0x34, 0xda, 0x00, 0x18, 0x34, 0xda, 0x00, 0x0d, 0x34, 0xd0, 0x18, 0x34, 0x5f, 0xfd, 0x18, 0x34, 0x5f, 0xf4, 0x18, 0x34, 0x5f, 0x96, 0x18, 0x34, 0x5f, 0x95, 0x17, 0x34, 0x5f, 0x94, 0x18, 0x34, 0x5f, 0x94, 0x16, 0x34, 0x5f, 0x68, 0x15, 0x34, 0x5e, 0xd8, 0x16, 0x34, 0x5e, 0x70, 0x14, 0x34, 0x5e, 0x30, 0x14, 0x34, 0x5e, 0x20, 0x17, 0x34, 0x5e, 0x18, 0x18, 0x34, 0x5e, 0x0f, 0x18, 0x34, 0x5e, 0x05, 0x18, 0x34, 0x5c, 0x5b, 0x18, 0x34, 0x5c, 0x5a, 0x18, 0x34, 0x5c, 0x59, 0x16, 0x34, 0x5c, 0x58, 0x18, 0x34, 0x5c, 0x58, 0x15, 0x34, 0x5c, 0x28, 0x18, 0x34, 0x55, 0xc6, 0x17, 0x34, 0x55, 0xc4, 0x10, 0x34, 0x38, 0x0e, 0x34, 0x30, 0x0f, 0x34, 0x1e, 0x0f, 0x34, 0x12, 0x0f, 0x34, 0x10, 0x12, 0x2e, 0x89, 0x80, 0x11, 0x2e, 0x89, 0x00, 0x14, 0x2e, 0x33, 0xc0, 0x12, 0x2e, 0x33, 0x80, 0x18, 0xd8, 0x89, 0x39, 0x18, 0xd8, 0x89, 0x38, 0x18, 0xcc, 0xf6, 0xbd, 0x18, 0xb9, 0x8f, 0x10, 0x16, 0xb9, 0x30, 0x78, 0x14, 0xb2, 0xec, 0x00, 0x12, 0xb0, 0x22, 0xc0, 0x13, 0xb0, 0x22, 0xa0, 0x14, 0xb0, 0x22, 0x90, 0x14, 0xb0, 0x22, 0x80, 0x12, 0xb0, 0x22, 0x40, 0x15, 0xb0, 0x20, 0x68, 0x15, 0x57, 0xee, 0x50, 0x11, 0x4f, 0x7d, 0x00, 0x12, 0x4f, 0x7d, 0x00, 0x12, 0x36, 0xf7, 0xc0, 0x12, 0x36, 0xf7, 0x80, 0x11, 0x36, 0xf7, 0x00, 0x11, 0x36, 0xf6, 0x80, 0x11, 0x36, 0xf6, 0x00, 0x16, 0x36, 0xf0, 0xdc, 0x18, 0x36, 0xf0, 0xc5, 0x18, 0x36, 0xf0, 0x38, 0x16, 0x36, 0xf0, 0x34, 0x17, 0x36, 0xf0, 0x32, 0x15, 0x36, 0xf0, 0x00, 0x18, 0x36, 0xef, 0xdf, 0x18, 0x36, 0xef, 0xa6, 0x17, 0x36, 0xef, 0xa4, 0x18, 0x36, 0xef, 0x63, 0x15, 0x36, 0xef, 0x20, 0x16, 0x36, 0xe6, 0xc4, 0x16, 0x36, 0xc0, 0xc4, 0x18, 0x34, 0x55, 0x3f, 0x17, 0x34, 0x55, 0x3c, 0x17, 0x34, 0x55, 0x3a, 0x0d, 0x22, 0xf8};
//
//    u_char *tmp;
//    tmp = temp;
//    libparsebgp_parsed_bmp_parsed_data bmp_data;
//    int read_size = libparsebgp_parse_bmp_parse_msg(&bmp_data, tmp, len);
//    cout << "Hello Ojas and Induja"<<endl;
//    cout << read_size;
//
////    cout << "Peer Address" << int(.peer_index_tbl.peer_entries.begin()->peer_type);
//    //cout<<"Peer Address "<<int(p->peer_index_table.peer_entries.begin()->peer_type);
////    cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
////    cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
//    return 1;
//}