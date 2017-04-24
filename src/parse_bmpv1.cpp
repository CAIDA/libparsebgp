//
// Created by ojas on 4/22/17.
//
#include "../include/parse_bgp.h"
#include "../include/parse_bmpv1.h"
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


/**
 * Parse the v3 peer header
 *
 * \param [in]  sock        Socket to read the message from
 */
//void parseBMP::parsePeerHdr(int sock) {
static void libparsebgp_parse_bmp_parse_peer_hdr(libparsebgp_parsed_peer_hdr_v3 *parsed_peer_header, unsigned char *&buffer,
                                                 int &buf_len) {
    parsed_peer_header = {0};
    bzero(&parsed_peer_header, sizeof(parsed_peer_header));

    /*if ((i = Recv(sock, &p_hdr, BMP_PEER_HDR_LEN, MSG_WAITALL))
        != BMP_PEER_HDR_LEN) {
        //       LOG_ERR("sock=%d: Couldn't read all bytes, read %d bytes",sock, i);
    }*/
    if (extract_from_buffer(buffer, buf_len, &parsed_peer_header, BMP_PEER_HDR_LEN)!= BMP_PEER_HDR_LEN) {
        //       LOG_ERR("sock=%d: Couldn't read all bytes, read %d bytes",sock, i);
        throw "Couldn't read all bytes";
    }

    // Adjust the common header length to remove the peer header (as it's been read)
TODO:
//    parsed_peer_header->bmp_len -= BMP_PEER_HDR_LEN;

    //   SELF_DEBUG("parsePeerHdr: sock=%d : Peer Type is %d", sock,p_hdr.peer_type);

//    if (p_hdr.peer_flags & 0x80) { // V flag of 1 means this is IPv6
//        parsed_peer_header->p_entry.is_ipv4 = false;
//
//        inet_ntop(AF_INET6, p_hdr.peer_addr, parsed_peer_header->peer_addr, sizeof(parsed_peer_header->peer_addr));
//
//        //       SELF_DEBUG("sock=%d : Peer address is IPv6 %s", sock,peer_addr);
//
//    } else {
//        parsed_peer_header->p_entry.is_ipv4 = true;
//
//        snprintf(parsed_peer_header->peer_addr, sizeof(parsed_peer_header->peer_addr), "%d.%d.%d.%d",
//                 p_hdr.peer_addr[12], p_hdr.peer_addr[13], p_hdr.peer_addr[14],
//                 p_hdr.peer_addr[15]);
//        //       SELF_DEBUG("sock=%d : Peer address is IPv4 %s", sock,peer_addr);
//    }
//
//    if (p_hdr.peer_flags & 0x10) { // O flag of 1 means this is Adj-Rib-Out
////        SELF_DEBUG("sock=%d : Msg is for Adj-RIB-Out", sock);
//        parsed_peer_header->p_entry.is_pre_policy = false;
//        parsed_peer_header->p_entry.is_adj_in = false;
//    } else if (p_hdr.peer_flags & 0x40) { // L flag of 1 means this is post-policy of Adj-RIB-In
////        SELF_DEBUG("sock=%d : Msg is for POST-POLICY Adj-RIB-In", sock);
//        parsed_peer_header->p_entry.is_pre_policy = false;
//        parsed_peer_header->p_entry.is_adj_in = true;
//    } else {
//        //       SELF_DEBUG("sock=%d : Msg is for PRE-POLICY Adj-RIB-In", sock);
//        parsed_peer_header->p_entry.is_pre_policy = true;
//        parsed_peer_header->p_entry.is_adj_in = true;
//    }
//
//    // convert the BMP byte messages to human readable strings
//    snprintf(parsed_peer_header->peer_as, sizeof(parsed_peer_header->peer_as), "0x%04x%04x",
//             p_hdr.peer_as[0] << 8 | p_hdr.peer_as[1],
//             p_hdr.peer_as[2] << 8 | p_hdr.peer_as[3]);
//
//    inet_ntop(AF_INET, p_hdr.peer_bgp_id, parsed_peer_header->peer_bgp_id, sizeof(parsed_peer_header->peer_bgp_id));
////    SELF_DEBUG("sock=%d : Peer BGP-ID %x.%x.%x.%x (%s)", sock, p_hdr.peer_bgp_id[0],p_hdr.peer_bgp_id[1],p_hdr.peer_bgp_id[2],p_hdr.peer_bgp_id[3], peer_bgp_id);
//
//    // Format based on the type of RD
////    SELF_DEBUG("sock=%d : Peer RD type = %d %d", sock, p_hdr.peer_dist_id[0], p_hdr.peer_dist_id[1]);
//    switch (p_hdr.peer_dist_id[1]) {
//        case 1: // admin = 4bytes (IP address), assign number = 2bytes
//            snprintf(parsed_peer_header->peer_rd, sizeof(parsed_peer_header->peer_rd), "%d.%d.%d.%d:%d",
//                     p_hdr.peer_dist_id[2], p_hdr.peer_dist_id[3],
//                     p_hdr.peer_dist_id[4], p_hdr.peer_dist_id[5],
//                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
//            break;
//
//        case 2: // admin = 4bytes (ASN), sub field 2bytes
//            snprintf(parsed_peer_header->peer_rd, sizeof(parsed_peer_header->peer_rd), "%lu:%d",
//                     (unsigned long) (p_hdr.peer_dist_id[2] << 24
//                                      | p_hdr.peer_dist_id[3] << 16
//                                      | p_hdr.peer_dist_id[4] << 8 | p_hdr.peer_dist_id[5]),
//                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
//            break;
//        default: // Type 0:  // admin = 2 bytes, sub field = 4 bytes
//            snprintf(parsed_peer_header->peer_rd, sizeof(parsed_peer_header->peer_rd), "%d:%lu",
//                     p_hdr.peer_dist_id[2] << 8 | p_hdr.peer_dist_id[3],
//                     (unsigned long) (p_hdr.peer_dist_id[4] << 24
//                                      | p_hdr.peer_dist_id[5] << 16
//                                      | p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]));
//            break;
//    }
//
//    // Update the peer entry struct in parse bmp
//    strncpy(parsed_peer_header->p_entry.peer_addr, parsed_peer_header->peer_addr, sizeof(parsed_peer_header->p_entry.peer_addr));
//    parsed_peer_header->p_entry.peer_as = strtoll(parsed_peer_header->peer_as, NULL, 16);
//    strncpy(parsed_peer_header->p_entry.peer_bgp_id, parsed_peer_header->peer_bgp_id, sizeof(parsed_peer_header->p_entry.peer_bgp_id));
//    strncpy(parsed_peer_header->p_entry.peer_rd, parsed_peer_header->peer_rd, sizeof(parsed_peer_header->p_entry.peer_rd));
//

    // Save the advertised timestamp
    SWAP_BYTES(&parsed_peer_header->ts_secs);
    SWAP_BYTES(&parsed_peer_header->ts_usecs);

//    if (p_hdr.ts_secs != 0) {
//        parsed_peer_header->p_entry.timestamp_secs = p_hdr.ts_secs;
//        parsed_peer_header->p_entry.timestamp_us = p_hdr.ts_usecs;
//
//    } else {
//        timeval tv;
//
//        gettimeofday(&tv, NULL);
//        parsed_peer_header->p_entry.timestamp_secs = tv.tv_sec;
//        parsed_peer_header->p_entry.timestamp_us = tv.tv_usec;
//    }


//    // Is peer type L3VPN peer or global instance
//    if (p_hdr.peer_type == 1) // L3VPN
//        parsed_peer_header->p_entry.is_l3vpn = 1;
//
//    else
//        // Global Instance
//        parsed_peer_header->p_entry.is_l3vpn = 0;

//    SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
    //   SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock,
    //               p_hdr.peer_as[0], p_hdr.peer_as[1], p_hdr.peer_as[2],
    //               p_hdr.peer_as[3]);
//    SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
}

/**
* Parse v1 and v2 BMP header
*
* \details
*      v2 uses the same common header, but adds the Peer Up message type.
*
* \param [in]  sock        Socket to read the message from
*/
//static void libparsebgp_parse_bmp_parse_bmp_v2(libparsebgp_parsed_bmp *parsed_msg, unsigned char*& buffer, int& buf_len) {
//    parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old = { 0 };
//    size_t i;
//    char buf[256] = {0};
//
////    SELF_DEBUG("parseBMP: sock=%d: Reading %d bytes", sock, BMP_HDRv1v2_LEN);
//
////    parsed_msg->bmp_len = 0;
//
//    if (extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old, BMP_HDRv1v2_LEN)
//        != BMP_HDRv1v2_LEN) {
//        //     SELF_DEBUG("sock=%d: Couldn't read all bytes, read %zd bytes",sock, i);
//        throw "ERROR: Cannot read v1/v2 BMP common header.";
//    }
//
//    // Process the message based on type
//    //parsed_msg->bmp_type = parsed_msg->c_hdr_old.type;
//    switch (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type) {
//        case 0: // Route monitoring
//            //          SELF_DEBUG("sock=%d : BMP MSG : route monitor", sock);
//
//            // Get the length of the remaining message by reading the BGP length
//            //if ((i=Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
//            if ((i=extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
//                uint16_t len;
//                memcpy(&len, (buf+16), 2);
//                SWAP_BYTES(&len);
//                parsed_msg->bmp_len = len;
//
//            } else {
////                LOG_ERR("sock=%d: Failed to read BGP message to get length of BMP message", sock);
//                throw "Failed to read BGP message for BMP length";
//            }
//            break;
//
//        case 1: // Statistics Report
//            //           SELF_DEBUG("sock=%d : BMP MSG : stats report", sock);
////            LOG_INFO("sock=%d : BMP MSG : stats report", sock);
//            break;
//
//        case 2: // Peer down notification
////            LOG_INFO("sock=%d: BMP MSG: Peer down", sock);
//
//            // Get the length of the remaining message by reading the BGP length
//            if ((i=extract_from_buffer(buffer, buf_len, buf, 1)) != 1) {
//
//                // Is there a BGP message
//                if (buf[0] == 1 or buf[0] == 3) {
//                    //if ((i = Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
//                    if ((i = extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
//                        memcpy(&parsed_msg->bmp_len, buf + 16, 2);
//                        SWAP_BYTES(&parsed_msg->bmp_len);
//
//                    } else {
////                        LOG_ERR("sock=%d: Failed to read peer down BGP message to get length of BMP message", sock);
//                        throw "Failed to read BGP message for BMP length";
//                    }
//                }
//            } else {
////                LOG_ERR("sock=%d: Failed to read peer down reason", sock);
//                throw "Failed to read BMP peer down reason";
//            }
//
//            //           SELF_DEBUG("sock=%d : BMP MSG : peer down", sock);
//            break;
//
//        case 3: // Peer Up notification
////            LOG_ERR("sock=%d: Peer UP not supported with older BMP version since no one has implemented it", sock);
//
//            //           SELF_DEBUG("sock=%d : BMP MSG : peer up", sock);
//            throw "ERROR: Will need to add support for peer up if it's really used.";
//            break;
//    }
//
////    //   SELF_DEBUG("sock=%d : Peer Type is %d", sock, c_hdr_old.peer_type);
////
////    if (parsed_msg->c_hdr_old.peer_flags & 0x80) { // V flag of 1 means this is IPv6
////        parsed_msg->p_entry.is_ipv4 = false;
////        inet_ntop(AF_INET6, parsed_msg->c_hdr_old.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr));
////
////        //      SELF_DEBUG("sock=%d : Peer address is IPv6", sock);
////
////    } else {
////        parsed_msg->p_entry.is_ipv4 = true;
////        snprintf(parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr), "%d.%d.%d.%d",
////                 parsed_msg->c_hdr_old.peer_addr[12], parsed_msg->c_hdr_old.peer_addr[13], parsed_msg->c_hdr_old.peer_addr[14],
////                 parsed_msg->c_hdr_old.peer_addr[15]);
////
////        //       SELF_DEBUG("sock=%d : Peer address is IPv4", sock);
////    }
//
//    /* if (c_hdr.peer_flags & 0x40) { // L flag of 1 means this is Loc-RIP and not Adj-RIB-In
//         //       SELF_DEBUG("sock=%d : Msg is for Loc-RIB", sock);
//     } else {
//         //      SELF_DEBUG("sock=%d : Msg is for Adj-RIB-In", sock);
//     }*/
//
////    // convert the BMP byte messages to human readable strings
////    snprintf(parsed_msg->peer_as, sizeof(parsed_msg->peer_as), "0x%04x%04x",
////             parsed_msg->c_hdr_old.peer_as[0] << 8 | parsed_msg->c_hdr_old.peer_as[1],
////             parsed_msg->c_hdr_old.peer_as[2] << 8 | parsed_msg->c_hdr_old.peer_as[3]);
////    snprintf(parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id), "%d.%d.%d.%d",
////             parsed_msg->c_hdr_old.peer_bgp_id[0], parsed_msg->c_hdr_old.peer_bgp_id[1], parsed_msg->c_hdr_old.peer_bgp_id[2],
////             parsed_msg->c_hdr_old.peer_bgp_id[3]);
////
////    // Format based on the type of RD
////    switch (parsed_msg->c_hdr_old.peer_dist_id[0] << 8 | parsed_msg->c_hdr_old.peer_dist_id[1]) {
////        case 1: // admin = 4bytes (IP address), assign number = 2bytes
////            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d.%d.%d.%d:%d",
////                     parsed_msg->c_hdr_old.peer_dist_id[2], parsed_msg->c_hdr_old.peer_dist_id[3],
////                     parsed_msg->c_hdr_old.peer_dist_id[4], parsed_msg->c_hdr_old.peer_dist_id[5],
////                     parsed_msg->c_hdr_old.peer_dist_id[6] << 8 | parsed_msg->c_hdr_old.peer_dist_id[7]);
////            break;
////        case 2: // admin = 4bytes (ASN), assing number = 2bytes
////            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%lu:%d",
////                     (unsigned long) (parsed_msg->c_hdr_old.peer_dist_id[2] << 24
////                                      | parsed_msg->c_hdr_old.peer_dist_id[3] << 16
////                                      | parsed_msg->c_hdr_old.peer_dist_id[4] << 8 | parsed_msg->c_hdr_old.peer_dist_id[5]),
////                     parsed_msg->c_hdr_old.peer_dist_id[6] << 8 | parsed_msg->c_hdr_old.peer_dist_id[7]);
////            break;
////        default: // admin = 2 bytes, sub field = 4 bytes
////            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d:%lu",
////                     parsed_msg->c_hdr_old.peer_dist_id[1] << 8 | parsed_msg->c_hdr_old.peer_dist_id[2],
////                     (unsigned long) (parsed_msg->c_hdr_old.peer_dist_id[3] << 24
////                                      | parsed_msg->c_hdr_old.peer_dist_id[4] << 16
////                                      | parsed_msg->c_hdr_old.peer_dist_id[5] << 8 | parsed_msg->c_hdr_old.peer_dist_id[6]
////                                      | parsed_msg->c_hdr_old.peer_dist_id[7]));
////            break;
////    }
////
////    // Update the MySQL peer entry struct
////    strncpy(parsed_msg->p_entry.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr));
////    parsed_msg->p_entry.peer_as = strtoll(parsed_msg->peer_as, NULL, 16);
////    strncpy(parsed_msg->p_entry.peer_bgp_id, parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id));
////    strncpy(parsed_msg->p_entry.peer_rd, parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd));
////
////    // Save the advertised timestamp
////    uint32_t ts = parsed_msg->c_hdr_old.ts_secs;
////    SWAP_BYTES(&ts);
////
////
////    if (ts != 0)
////        parsed_msg->p_entry.timestamp_secs = ts;
////    else
////        parsed_msg->p_entry.timestamp_secs = time(NULL);
////
////    // Is peer type L3VPN peer or global instance
////    if (parsed_msg->c_hdr_old.type == 1) // L3VPN
////        parsed_msg->p_entry.is_l3vpn = 1;
////    else
////        // Global Instance
////        parsed_msg->p_entry.is_l3vpn = 0;
//
//    //   SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
////    SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock, c_hdr.peer_as[0], c_hdr.peer_as[1], c_hdr.peer_as[2], c_hdr.peer_as[3]);
//    //   SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
//}


/**
 * Parse v3 BMP header
 *
 * \details
 *      v3 has a different header structure and changes the peer
 *      header format.
 *
 * \param [in]  sock        Socket to read the message from
 */
//void parseBMP::parseBMPv3(int sock) {
static void libParseBGP_parse_bmp_parse_bmp_v3(libparsebgp_parsed_bmp *parsed_msg, unsigned char*& buffer, int& buf_len) {
    parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3 = { 0 };
    //   SELF_DEBUG("Parsing BMP version 3 (rfc7854)");

    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len, 4)) != 4) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type, 1)) != 1) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }

    // Change to host order
    SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len);

    //   SELF_DEBUG("BMP v3: type = %x len=%d", parsed_msg->c_hdr_v3.type, parsed_msg->c_hdr_v3.len);

    // Adjust length to remove common header size
    parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len -= 1 + BMP_HDRv3_LEN;

    if (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len > BGP_MAX_MSG_SIZE)
        throw "ERROR: BMP length is larger than max possible BGP size";

//    // Parse additional headers based on type
//    parsed_msg->bmp_type = parsed_msg->c_hdr_v3.type;
//    parsed_msg->bmp_len = parsed_msg->c_hdr_v3.len;

    switch (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type) {
        case TYPE_ROUTE_MON: // Route monitoring
            //          SELF_DEBUG("BMP MSG : route monitor");
            //parsePeerHdr(sock);
            libparsebgp_parse_bmp_parse_peer_hdr(&parsed_msg->libparsebgp_parsed_peer_hdr, buffer, buf_len);
            break;

        case TYPE_STATS_REPORT: // Statistics Report
            //          SELF_DEBUG("BMP MSG : stats report");
            //parsePeerHdr(sock);
            libparsebgp_parse_bmp_parse_peer_hdr(&parsed_msg->libparsebgp_parsed_peer_hdr, buffer, buf_len);
            break;

        case TYPE_PEER_UP: // Peer Up notification
        {
            //           SELF_DEBUG("BMP MSG : peer up");
            //parsePeerHdr(sock);
            libparsebgp_parse_bmp_parse_peer_hdr(&parsed_msg->libparsebgp_parsed_peer_hdr, buffer, buf_len);
            break;
        }
        case TYPE_PEER_DOWN: // Peer down notification
            //           SELF_DEBUG("BMP MSG : peer down");
            //parsePeerHdr(sock);
            libparsebgp_parse_bmp_parse_peer_hdr(&parsed_msg->libparsebgp_parsed_peer_hdr, buffer, buf_len);
            break;

        case TYPE_INIT_MSG:
        case TYPE_TERM_MSG:
            // Allowed
            break;

        default:
            //         LOG_ERR("ERROR: Unknown BMP message type of %d", parsed_msg->c_hdr_v3.type);
            throw "ERROR: BMP message type is not supported";
            break;
    }
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
static char libparsebgp_parse_bmp_handle_msg(libparsebgp_parsed_bmp *parsed_msg, unsigned char *&buffer, int &buf_len) {
    uint8_t     ver;
    ssize_t     bytes_read;
    uint8_t     bmp_type;
    // Get the version in order to determine what we read next
    //    As of Junos 10.4R6.5, it supports version 1
    bytes_read = extract_from_buffer(buffer, buf_len, &ver, 1);

    if (bytes_read != 1)
        throw "Cannot read BMP version byte from buffer";

    // check the version
    if (ver == 3) { // draft-ietf-grow-bmp-04 - 07
        //parseBMPv3(sock);
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.ver = ver;
        libParseBGP_parse_bmp_parse_bmp_v3(parsed_msg, buffer, buf_len);
        bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type;
    }

        // Handle the older versions
    else if (ver == 1 || ver == 2) {
        //       SELF_DEBUG("Older BMP version of %d, consider upgrading the router to support BMPv3", ver);
        //parseBMPv2(sock);
//        libparsebgp_parse_bmp_parse_bmp_v2(parsed_msg, buffer, buf_len);
        parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type;

    } else
        throw "ERROR: Unsupported BMP message version";

    //   SELF_DEBUG("BMP version = %d\n", ver);

    return bmp_type;
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

//        // Indicate that data has been read
//        parsed_msg->bmp_len--;
//
//        // Initialize the down_event struct
//        parsed_msg->down_event.bmp_reason = reason;
        return true;
    } else
        return false;
}

//uint8_t libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp *parsed_msg, unsigned char *&buffer, int buf_len) {
//    string peer_info_key;
//    int initial_buffer_len = buf_len;
//
//    char bmp_type = 0;
//    libParseBGP_parse_bgp_parsed_data pBGP;
//
//    try {
//        bmp_type = libparsebgp_parse_bmp_handle_msg(parsed_msg, buffer, buf_len);
//
////        if (bmp_type < 4) {
////            peer_info_key =  parsed_msg->p_entry.peer_addr;
////            peer_info_key += parsed_msg->p_entry.peer_rd;
////        }
//        /*
//         * At this point we only have the BMP header message, what happens next depends
//         *      on the BMP message type.
//         */
//        switch (bmp_type) {
//            case TYPE_PEER_DOWN : { // Peer down type
//                if (libparsebgp_parse_bmp_parse_peer_down_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg, buffer, buf_len)) {
//                    //bufferBMPMessage(read_fd);
//                    libparsebgp_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);
//
//                    // Prepare the BGP parser
//                    libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);
//
//                    // Check if the reason indicates we have a BGP message that follows
//                    switch (parsed_msg->down_event.bmp_reason) {
//                        case 1 : { // Local system close with BGP notify
//                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
//                                     "Local close by (%s) for peer (%s) : ", parsed_msg->r_entry.ip_addr,
//                                     parsed_msg->p_entry.peer_addr);
//                            libParseBGP_parse_bgp_handle_down_event(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len,&parsed_msg->down_event,&parsed_msg->bgp_msg);
//                            break;
//                        }
//                        case 2 : // Local system close, no bgp notify
//                        {
//// Read two byte code corresponding to the FSM event
//                            uint16_t fsm_event = 0 ;
//                            memcpy(&fsm_event, parsed_msg->bmp_data, 2);
//                            SWAP_BYTES(&fsm_event);
//
//                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
//                                     "Local (%s) closed peer (%s) session: fsm_event=%d, No BGP notify message.",
//                                     parsed_msg->r_entry.ip_addr,parsed_msg->p_entry.peer_addr, fsm_event);
//                            break;
//                        }
//                        case 3 : { // remote system close with bgp notify
//                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
//                                     "Remote peer (%s) closed local (%s) session: ", parsed_msg->r_entry.ip_addr,
//                                     parsed_msg->p_entry.peer_addr);
//
//                            libParseBGP_parse_bgp_handle_down_event(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len, &parsed_msg->down_event,&parsed_msg->bgp_msg);
//                            break;
//                        }
//                    }
//
//
//                } else {
//                    //       LOG_ERR("Error with client socket %d", read_fd);
//                    // Make sure to free the resource
//                    throw "BMPReader: Unable to read from client socket";
//                }
//                break;
//            }
//
//            case TYPE_PEER_UP : // Peer up type
//            {
//                if (libParseBGP_parse_bmp_parse_peer_up_event_hdr(parsed_msg, buffer, buf_len)) {
//                    //     LOG_INFO("%s: PEER UP Received, local addr=%s:%hu remote addr=%s:%hu", client->c_ip,up_event.local_ip, up_event.local_port, p_entry.peer_addr, up_event.remote_port);
//
//                    libparsebgp_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);
//
//                    // Prepare the BGP parser
//                    libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);
//
//
//// Parse the BGP sent/received open messages
//                    libParseBGP_parse_bgp_handle_up_event(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len, &parsed_msg->up_event,&parsed_msg->bgp_msg);
//                } //else {
//                //   LOG_NOTICE("%s: PEER UP Received but failed to parse the BMP header.", client->c_ip);
//                // }
//                break;
//            }
//
//            case TYPE_ROUTE_MON : { // Route monitoring type
//                libparsebgp_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);
//
//                /*
//                 * Read and parse the the BGP message from the client.
//                 *     parseBGP will update mysql directly
//                 */
//                libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);
//
//                libParseBGP_parse_bgp_handle_update(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len, &parsed_msg->bgp_msg);
//
//                break;
//            }
//
//            case TYPE_STATS_REPORT : { // Stats Report
//                libParseBGP_parse_bmp_handle_stats_report(parsed_msg, buffer, buf_len);
//                break;
//            }
//
//            case TYPE_INIT_MSG : { // Initiation Message
//                // LOG_INFO("%s: Init message received with length of %u", client->c_ip, pBMP->getBMPLength());
//
//                libParseBGP_parse_bmp_handle_init_msg(parsed_msg, buffer, buf_len);
//
//                break;
//            }
//
//            case TYPE_TERM_MSG : { // Termination Message
//                // LOG_INFO("%s: Term message received with length of %u", client->c_ip, pBMP->getBMPLength());
//
//                libParseBGP_parse_bmp_handle_term_msg(parsed_msg, buffer, buf_len);
//
//                // LOG_INFO("Proceeding to disconnect router");
//                break;
//            }
//
//        }
//
//    } catch (char const *str) {
//        // Mark the router as disconnected and update the error to be a local disconnect (no term message received)
//        //  LOG_INFO("%s: Caught: %s", client->c_ip, str);
//        throw str;
//    }
//
//    return initial_buffer_len-buf_len;
//}