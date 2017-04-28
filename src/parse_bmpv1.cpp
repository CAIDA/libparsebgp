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
// void parseBMP::bufferBMPMessage(int sock) {

static void libparsebgp_parse_bmp_buffer_bmp_message(unsigned char*& buffer, int& buf_len) {
    if (bmp_len <= 0)
        return;

    if (bmp_len > sizeof(bmp_data)) {
        //       LOG_WARN("sock=%d: BMP message is invalid, length of %d is larger than max buffer size of %d",sock, bmp_len, sizeof(bmp_data));
        throw "BMP message length is too large for buffer, invalid BMP sender";
    }

//    SELF_DEBUG("sock=%d: Buffering %d from socket", sock, bmp_len);
    /*if ((bmp_data_len=Recv(sock, bmp_data, bmp_len, MSG_WAITALL)) != bmp_len) {
 //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
         throw "Error while reading BMP data into buffer";
    }*/
    if ((bmp_data_len=extract_from_buffer(buffer, buf_len, bmp_data, bmp_len)) != bmp_len) {
        //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
        throw "Error while reading BMP data into buffer";
    }

    // Indicate no more data is left to read
    bmp_len = 0;

}
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
//    // convert the BMP byte messages to human readable strings
//    snprintf(parsed_msg->peer_as, sizeof(parsed_msg->peer_as), "0x%04x%04x",
//             parsed_msg->c_hdr_old.peer_as[0] << 8 | parsed_msg->c_hdr_old.peer_as[1],
//             parsed_msg->c_hdr_old.peer_as[2] << 8 | parsed_msg->c_hdr_old.peer_as[3]);
//    snprintf(parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id), "%d.%d.%d.%d",
//             parsed_msg->c_hdr_old.peer_bgp_id[0], parsed_msg->c_hdr_old.peer_bgp_id[1], parsed_msg->c_hdr_old.peer_bgp_id[2],
//             parsed_msg->c_hdr_old.peer_bgp_id[3]);
//
//    // Format based on the type of RD
//    switch (parsed_msg->c_hdr_old.peer_dist_id[0] << 8 | parsed_msg->c_hdr_old.peer_dist_id[1]) {
//        case 1: // admin = 4bytes (IP address), assign number = 2bytes
//            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d.%d.%d.%d:%d",
//                     parsed_msg->c_hdr_old.peer_dist_id[2], parsed_msg->c_hdr_old.peer_dist_id[3],
//                     parsed_msg->c_hdr_old.peer_dist_id[4], parsed_msg->c_hdr_old.peer_dist_id[5],
//                     parsed_msg->c_hdr_old.peer_dist_id[6] << 8 | parsed_msg->c_hdr_old.peer_dist_id[7]);
//            break;
//        case 2: // admin = 4bytes (ASN), assing number = 2bytes
//            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%lu:%d",
//                     (unsigned long) (parsed_msg->c_hdr_old.peer_dist_id[2] << 24
//                                      | parsed_msg->c_hdr_old.peer_dist_id[3] << 16
//                                      | parsed_msg->c_hdr_old.peer_dist_id[4] << 8 | parsed_msg->c_hdr_old.peer_dist_id[5]),
//                     parsed_msg->c_hdr_old.peer_dist_id[6] << 8 | parsed_msg->c_hdr_old.peer_dist_id[7]);
//            break;
//        default: // admin = 2 bytes, sub field = 4 bytes
//            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d:%lu",
//                     parsed_msg->c_hdr_old.peer_dist_id[1] << 8 | parsed_msg->c_hdr_old.peer_dist_id[2],
//                     (unsigned long) (parsed_msg->c_hdr_old.peer_dist_id[3] << 24
//                                      | parsed_msg->c_hdr_old.peer_dist_id[4] << 16
//                                      | parsed_msg->c_hdr_old.peer_dist_id[5] << 8 | parsed_msg->c_hdr_old.peer_dist_id[6]
//                                      | parsed_msg->c_hdr_old.peer_dist_id[7]));
//            break;
//    }
//
//    // Update the MySQL peer entry struct
//    strncpy(parsed_msg->p_entry.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr));
//    parsed_msg->p_entry.peer_as = strtoll(parsed_msg->peer_as, NULL, 16);
//    strncpy(parsed_msg->p_entry.peer_bgp_id, parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id));
//    strncpy(parsed_msg->p_entry.peer_rd, parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd));
//
//    // Save the advertised timestamp
//    uint32_t ts = parsed_msg->c_hdr_old.ts_secs;
//    SWAP_BYTES(&ts);
//
//
//    if (ts != 0)
//        parsed_msg->p_entry.timestamp_secs = ts;
//    else
//        parsed_msg->p_entry.timestamp_secs = time(NULL);
//
//    // Is peer type L3VPN peer or global instance
//    if (parsed_msg->c_hdr_old.type == 1) // L3VPN
//        parsed_msg->p_entry.is_l3vpn = 1;
//    else
//        // Global Instance
//        parsed_msg->p_entry.is_l3vpn = 0;

    //   SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
//    SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock, c_hdr.peer_as[0], c_hdr.peer_as[1], c_hdr.peer_as[2], c_hdr.peer_as[3]);
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

/**
 * handle the initiation message and update the router entry
 *
 * \param [in]     sock        Socket to read the init message from
 * \param [in/out] r_entry     Already defined router entry reference (will be updated)
 */
static void libparsebgp_parse_bmp_handle_init_msg(libparsebgp_parsed_bmp_init_msg *parsed_msg, unsigned char*& buffer, int& buf_len) {
    //char infoBuf[4096];
    int info_len;

    // Buffer the init message for parsing
    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

    u_char *bufPtr = bmp_data;
    /*
     * Loop through the init message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_INIT_MSG_LEN) {
        init_msg_v3_tlv init_msg;
        memcpy(&init_msg, bufPtr, BMP_INIT_MSG_LEN);
//        init_msg.info=NULL;
        memset(init_msg.info, 0, sizeof init_msg.info);
        SWAP_BYTES(&init_msg.len);
        SWAP_BYTES(&init_msg.type);

        bufPtr += BMP_INIT_MSG_LEN;                // Move pointer past the info header

        //       LOG_INFO("Init message type %hu and length %hu parsed", initMsg.type, initMsg.len);

        if (init_msg.len > 0) {
            info_len = sizeof(init_msg.info) < init_msg.len ? sizeof(init_msg.info) : init_msg.len;
            bzero(init_msg.info, sizeof(init_msg.info));
            memcpy(init_msg.info, bufPtr, info_len);
            bufPtr += info_len;                     // Move pointer past the info data
            i += info_len;                          // Update the counter past the info data
        }
        parsed_msg->init_msg_tlvs.push_back(init_msg);
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
//void parseBMP::handleTermMsg(int sock) {
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
//            term_msg.info = infoBuf;

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
static bool libparsebgp_parse_bmp_handle_stats_report(libparsebgp_parsed_bmp_stat_rep *parsed_msg, unsigned char*& buffer, int& buf_len) {
    char b[8];

    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->stats_count, 4)) != 4)
        throw "ERROR:  Cannot proceed since we cannot read the stats counter";

    bmp_len -= 4;

//    // Reverse the bytes and update int
//    SWAP_BYTES(b, 4);
//    memcpy((void*) &parsed_msg->stats_count, (void*) b, 4);

    //   SELF_DEBUG("sock = %d : STATS REPORT Count: %u (%d %d %d %d)",
    //               sock, stats_cnt, b[0], b[1], b[2], b[3]);

//    // Vars used per counter object
//    unsigned short stat_type = 0;
//    unsigned short stat_len = 0;

    // Loop through each stats object
    for (unsigned long i = 0; i < parsed_msg->stats_count; i++) {
        stat_counter stat_info;
        //if ((Recv(sock, &stat_type, 2, MSG_WAITALL)) != 2)
        if ((extract_from_buffer(buffer, buf_len, &stat_info, 4)) != 4)
            throw "ERROR: Cannot proceed since we cannot read the stats type.";
        //if ((Recv(sock, &stat_len, 2, MSG_WAITALL)) != 2)
//        if ((extract_from_buffer(buffer, buf_len, &stat_info.stat_len, 2)) != 2)
//            throw "ERROR: Cannot proceed since we cannot read the stats len.";

        bmp_len -= 4;

        // convert integer from network to host bytes
        SWAP_BYTES(&stat_info.stat_type);
        SWAP_BYTES(&stat_info.stat_len);

        //       SELF_DEBUG("sock=%d STATS: %lu : TYPE = %u LEN = %u", sock,
        //                   i, stat_type, stat_len);

        // check if this is a 32 bit number  (default)
        if (stat_info.stat_len == 4 or stat_info.stat_len == 8) {

            // Read the stats counter - 32/64 bits
            if ((extract_from_buffer(buffer, buf_len, b, stat_info.stat_len)) == stat_info.stat_len) {
                bmp_len -= stat_info.stat_len;

                // convert the bytes from network to host order
                SWAP_BYTES(b, stat_info.stat_len);
                memcpy(stat_info.stat_data, b, stat_info.stat_len);

                // Update the table structure based on the stats counter type
//                switch (stat_info.stat_type) {
//                    case STATS_PREFIX_REJ:
//                        memcpy((void*) &parsed_msg->stats.prefixes_rej, (void*) b, stat_len);
//                        break;
//                    case STATS_DUP_PREFIX:
//                        memcpy((void*) &parsed_msg->stats.known_dup_prefixes, (void*) b, stat_len);
//                        break;
//                    case STATS_DUP_WITHDRAW:
//                        memcpy((void*) &parsed_msg->stats.known_dup_withdraws, (void*) b, stat_len);
//                        break;
//                    case STATS_INVALID_CLUSTER_LIST:
//                        memcpy((void*) &parsed_msg->stats.invalid_cluster_list, (void*) b, stat_len);
//                        break;
//                    case STATS_INVALID_AS_PATH_LOOP:
//                        memcpy((void*) &parsed_msg->stats.invalid_as_path_loop, (void*) b, stat_len);
//                        break;
//                    case STATS_INVALID_ORIGINATOR_ID:
//                        memcpy((void*) &parsed_msg->stats.invalid_originator_id, (void*) b, stat_len);
//                        break;
//                    case STATS_INVALID_AS_CONFED_LOOP:
//                        memcpy((void*) &parsed_msg->stats.invalid_as_confed_loop, (void*) b, stat_len);
//                        break;
//                    case STATS_NUM_ROUTES_ADJ_RIB_IN:
//                        memcpy((void*) &parsed_msg->stats.routes_adj_rib_in, (void*) b, stat_len);
//                        break;
//                    case STATS_NUM_ROUTES_LOC_RIB:
//                        memcpy((void*) &parsed_msg->stats.routes_loc_rib, (void*) b, stat_len);
//                        break;
//
//                    default:
//                    {
//                        uint32_t value32bit;
//                        uint64_t value64bit;
//
//                        if (stat_info.stat_len == 8) {
//                            memcpy((void*)&value64bit, (void *)b, 8);
//
//                            //                         SELF_DEBUG("%s: sock=%d: stat type %d length of %d value of %lu is not yet implemented",
//                            //                                 p_entry.peer_addr, sock, stat_type, stat_len, value64bit);
//                        } else {
//                            memcpy((void*)&value32bit, (void *)b, 4);
//
//                            //                         SELF_DEBUG("%s: sock=%d: stat type %d length of %d value of %lu is not yet implemented",
//                            //                                  p_entry.peer_addr, sock, stat_type, stat_len, value32bit);
//                        }
//                    }
//                }

                //             SELF_DEBUG("VALUE is %u",
                //                         b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]);
            }

        } else { // stats len not expected, we need to skip it.
            //         SELF_DEBUG("sock=%d : skipping stats report '%u' because length of '%u' is not expected.",
            //                     sock, stat_type, stat_len);

            while (stat_info.stat_len-- > 0)
                extract_from_buffer(buffer, buf_len, &b[0], 1);
        }
        parsed_msg->total_stats_counter.push_back(stat_info);
        delete stat_info;
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
    unsigned char local_addr[16];
    bool is_parse_good = true;
    int bytes_read = 0;

    // Get the local address
    if ( extract_from_buffer(buffer, buf_len, &parsed_msg->local_ip, 16) != 16)
        is_parse_good = false;
    else
        bytes_read += 16;

//    if (is_parse_good and parsed_msg->p_entry.is_ipv4) {
//        snprintf(parsed_msg->up_event.local_ip, sizeof(parsed_msg->up_event.local_ip), "%d.%d.%d.%d",
//                 local_addr[12], local_addr[13], local_addr[14],
//                 local_addr[15]);
//        //       SELF_DEBUG("%s : Peer UP local address is IPv4 %s", peer_addr, up_event.local_ip);
//
//    } else if (is_parse_good) {
//        inet_ntop(AF_INET6, local_addr, parsed_msg->up_event.local_ip, sizeof(parsed_msg->up_event.local_ip));
//        //       SELF_DEBUG("%s : Peer UP local address is IPv6 %s", peer_addr, up_event.local_ip);
//    }

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

uint8_t libparsebgp_parse_bmp_parse_msg(libparsebgp_parsed_bmp *parsed_msg, unsigned char *&buffer, int buf_len) {
    string peer_info_key;
    int initial_buffer_len = buf_len;

    char bmp_type = 0;
    libparsebgp_parse_bgp_parsed_data pBGP;

    try {
        bmp_type = libparsebgp_parse_bmp_handle_msg(parsed_msg, buffer, buf_len);

//        if (bmp_type < 4) {
//            peer_info_key =  parsed_msg->p_entry.peer_addr;
//            peer_info_key += parsed_msg->p_entry.peer_rd;
//        }
        /*
         * At this point we only have the BMP header message, what happens next depends
         *      on the BMP message type.
         */
        switch (bmp_type) {
            case TYPE_PEER_DOWN : { // Peer down type
                if (libparsebgp_parse_bmp_parse_peer_down_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg, buffer, buf_len)) {
                    //bufferBMPMessage(read_fd);
                    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

                    // Prepare the BGP parser
//                    libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);

                    // Check if the reason indicates we have a BGP message that follows
                    switch (parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.bmp_reason) {
                        case 1 : { // Local system close with BGP notify
//                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
//                                     "Local close by (%s) for peer (%s) : ", parsed_msg->r_entry.ip_addr,
//                                     parsed_msg->p_entry.peer_addr);
                            libparsebgp_parse_bgp_handle_down_event(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg, bmp_data, bmp_data_len);
                            break;
                        }
                        case 2 : // Local system close, no bgp notify
                        {
// Read two byte code corresponding to the FSM event
                            uint16_t fsm_event = 0 ;
                            memcpy(&fsm_event, bmp_data, 2);
                            SWAP_BYTES(&fsm_event);

//                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
//                                     "Local (%s) closed peer (%s) session: fsm_event=%d, No BGP notify message.",
//                                     parsed_msg->r_entry.ip_addr,parsed_msg->p_entry.peer_addr, fsm_event);
                            break;
                        }
                        case 3 : { // remote system close with bgp notify
//                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
//                                     "Remote peer (%s) closed local (%s) session: ", parsed_msg->r_entry.ip_addr,
//                                     parsed_msg->p_entry.peer_addr);

                            libparsebgp_parse_bgp_handle_down_event(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg.notify_msg, bmp_data, bmp_data_len);
                            break;
                        }
                    }


                } else {
                    //       LOG_ERR("Error with client socket %d", read_fd);
                    // Make sure to free the resource
                    throw "BMPReader: Unable to read from client socket";
                }
                break;
            }

            case TYPE_PEER_UP : // Peer up type
            {
                if (libparsebgp_parse_bmp_parse_peer_up_event_hdr(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg, buffer, buf_len)) {
                    //     LOG_INFO("%s: PEER UP Received, local addr=%s:%hu remote addr=%s:%hu", client->c_ip,up_event.local_ip, up_event.local_port, p_entry.peer_addr, up_event.remote_port);

                    libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

//                    // Prepare the BGP parser
//                    libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);


// Parse the BGP sent/received open messages
                    libparsebgp_parse_bgp_handle_up_event(bmp_data, bmp_data_len, &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg);
                } //else {
                //   LOG_NOTICE("%s: PEER UP Received but failed to parse the BMP header.", client->c_ip);
                // }
                break;
            }

            case TYPE_ROUTE_MON : { // Route monitoring type
                libparsebgp_parse_bmp_buffer_bmp_message(buffer, buf_len);

                /*
                 * Read and parse the the BGP message from the client.
                 *     parseBGP will update mysql directly
                 */
//                libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);

                libparsebgp_parse_bgp_handle_update(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_rm_msg,bmp_data, bmp_data_len);

                break;
            }

            case TYPE_STATS_REPORT : { // Stats Report
                libparsebgp_parse_bmp_handle_stats_report(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_stat_rep, buffer, buf_len);
                break;
            }

            case TYPE_INIT_MSG : { // Initiation Message
                // LOG_INFO("%s: Init message received with length of %u", client->c_ip, pBMP->getBMPLength());

                libparsebgp_parse_bmp_handle_init_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_init_msg, buffer, buf_len);

                break;
            }

            case TYPE_TERM_MSG : { // Termination Message
                // LOG_INFO("%s: Term message received with length of %u", client->c_ip, pBMP->getBMPLength());

                libparsebgp_parse_bmp_handle_term_msg(&parsed_msg->libparsebgp_parsed_bmp_msg.parsed_term_msg, buffer, buf_len);

                // LOG_INFO("Proceeding to disconnect router");
                break;
            }

        }

    } catch (char const *str) {
        // Mark the router as disconnected and update the error to be a local disconnect (no term message received)
        //  LOG_INFO("%s: Caught: %s", client->c_ip, str);
        throw str;
    }

    return initial_buffer_len-buf_len;
}