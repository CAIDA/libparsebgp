/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parse_bmp.h"
#include "../include/parse_bgp.h"
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

libParseBGP_parse_bmp_parsed_data parse_bmp_wrapper(unsigned char *buffer, int buf_len) {

    uint8_t read_size;
    libParseBGP_parse_bmp_parsed_data parsed_data;
    read_size=libParseBGP_parse_bmp_parse_msg(&parsed_data, buffer, buf_len);
    return parsed_data;
}

/**
 * Constructor for class
 *
 * \note
 *  This class will allocate via 'new' the bgp_peers variables
 *        as needed.  The calling method/class/function should check each var
 *        in the structure for non-NULL pointers.  Non-NULL pointers need to be
 *        freed with 'delete'
 *
 * \param [in]     logPtr      Pointer to existing Logger for app logging
 * \param [in,out] peer_entry  Pointer to the peer entry
 */

//libParseBGP_parse_bgp_parsed_data pBGP;
//bool parseBMP::parseMsg(int read_fd)

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
static void libParseBGP_parse_bmp_buffer_bmp_message(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    if (parsed_msg->bmp_len <= 0)
        return;

    if (parsed_msg->bmp_len > sizeof(parsed_msg->bmp_data)) {
        //       LOG_WARN("sock=%d: BMP message is invalid, length of %d is larger than max buffer size of %d",sock, bmp_len, sizeof(bmp_data));
        throw "BMP message length is too large for buffer, invalid BMP sender";
    }

//    SELF_DEBUG("sock=%d: Buffering %d from socket", sock, bmp_len);
    /*if ((bmp_data_len=Recv(sock, bmp_data, bmp_len, MSG_WAITALL)) != bmp_len) {
 //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
         throw "Error while reading BMP data into buffer";
    }*/
    if ((parsed_msg->bmp_data_len=extract_from_buffer(buffer, buf_len, parsed_msg->bmp_data, parsed_msg->bmp_len)) != parsed_msg->bmp_len) {
        //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
        throw "Error while reading BMP data into buffer";
    }

    // Indicate no more data is left to read
    parsed_msg->bmp_len = 0;

}

/**
* Parse v1 and v2 BMP header
*
* \details
*      v2 uses the same common header, but adds the Peer Up message type.
*
* \param [in]  sock        Socket to read the message from
*/
//void parseBMP::parseBMPv2(int sock) {
static void libParseBGP_parse_bmp_parse_bmp_v2(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    parsed_msg->c_hdr_old = { 0 };
    ssize_t i = 0;
    char buf[256] = {0};

//    SELF_DEBUG("parseBMP: sock=%d: Reading %d bytes", sock, BMP_HDRv1v2_LEN);

    parsed_msg->bmp_len = 0;

    if ((i = extract_from_buffer(buffer, buf_len, &parsed_msg->c_hdr_old, BMP_HDRv1v2_LEN))
        != BMP_HDRv1v2_LEN) {
        //     SELF_DEBUG("sock=%d: Couldn't read all bytes, read %zd bytes",sock, i);
        throw "ERROR: Cannot read v1/v2 BMP common header.";
    }

    // Process the message based on type
    parsed_msg->bmp_type = parsed_msg->c_hdr_old.type;
    switch (parsed_msg->c_hdr_old.type) {
        case 0: // Route monitoring
            //          SELF_DEBUG("sock=%d : BMP MSG : route monitor", sock);

            // Get the length of the remaining message by reading the BGP length
            //if ((i=Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
            if ((i=extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
                uint16_t len;
                memcpy(&len, (buf+16), 2);
                bgp::SWAP_BYTES(&len);
                parsed_msg->bmp_len = len;

            } else {
//                LOG_ERR("sock=%d: Failed to read BGP message to get length of BMP message", sock);
                throw "Failed to read BGP message for BMP length";
            }
            break;

        case 1: // Statistics Report
            //           SELF_DEBUG("sock=%d : BMP MSG : stats report", sock);
//            LOG_INFO("sock=%d : BMP MSG : stats report", sock);
            break;

        case 2: // Peer down notification
//            LOG_INFO("sock=%d: BMP MSG: Peer down", sock);

            // Get the length of the remaining message by reading the BGP length
            if ((i=extract_from_buffer(buffer, buf_len, buf, 1)) != 1) {

                // Is there a BGP message
                if (buf[0] == 1 or buf[0] == 3) {
                    //if ((i = Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
                    if ((i = extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
                        memcpy(&parsed_msg->bmp_len, buf + 16, 2);
                        bgp::SWAP_BYTES(&parsed_msg->bmp_len);

                    } else {
//                        LOG_ERR("sock=%d: Failed to read peer down BGP message to get length of BMP message", sock);
                        throw "Failed to read BGP message for BMP length";
                    }
                }
            } else {
//                LOG_ERR("sock=%d: Failed to read peer down reason", sock);
                throw "Failed to read BMP peer down reason";
            }

            //           SELF_DEBUG("sock=%d : BMP MSG : peer down", sock);
            break;

        case 3: // Peer Up notification
//            LOG_ERR("sock=%d: Peer UP not supported with older BMP version since no one has implemented it", sock);

            //           SELF_DEBUG("sock=%d : BMP MSG : peer up", sock);
            throw "ERROR: Will need to add support for peer up if it's really used.";
            break;
    }

    //   SELF_DEBUG("sock=%d : Peer Type is %d", sock, c_hdr_old.peer_type);

    if (parsed_msg->c_hdr_old.peer_flags & 0x80) { // V flag of 1 means this is IPv6
        parsed_msg->p_entry.is_ipv4 = false;
        inet_ntop(AF_INET6, parsed_msg->c_hdr_old.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr));

        //      SELF_DEBUG("sock=%d : Peer address is IPv6", sock);

    } else {
        parsed_msg->p_entry.is_ipv4 = true;
        snprintf(parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr), "%d.%d.%d.%d",
                 parsed_msg->c_hdr_old.peer_addr[12], parsed_msg->c_hdr_old.peer_addr[13], parsed_msg->c_hdr_old.peer_addr[14],
                 parsed_msg->c_hdr_old.peer_addr[15]);

        //       SELF_DEBUG("sock=%d : Peer address is IPv4", sock);
    }

    /* if (c_hdr.peer_flags & 0x40) { // L flag of 1 means this is Loc-RIP and not Adj-RIB-In
         //       SELF_DEBUG("sock=%d : Msg is for Loc-RIB", sock);
     } else {
         //      SELF_DEBUG("sock=%d : Msg is for Adj-RIB-In", sock);
     }*/

    // convert the BMP byte messages to human readable strings
    snprintf(parsed_msg->peer_as, sizeof(parsed_msg->peer_as), "0x%04x%04x",
             parsed_msg->c_hdr_old.peer_as[0] << 8 | parsed_msg->c_hdr_old.peer_as[1],
             parsed_msg->c_hdr_old.peer_as[2] << 8 | parsed_msg->c_hdr_old.peer_as[3]);
    snprintf(parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id), "%d.%d.%d.%d",
             parsed_msg->c_hdr_old.peer_bgp_id[0], parsed_msg->c_hdr_old.peer_bgp_id[1], parsed_msg->c_hdr_old.peer_bgp_id[2],
             parsed_msg->c_hdr_old.peer_bgp_id[3]);

    // Format based on the type of RD
    switch (parsed_msg->c_hdr_old.peer_dist_id[0] << 8 | parsed_msg->c_hdr_old.peer_dist_id[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d.%d.%d.%d:%d",
                     parsed_msg->c_hdr_old.peer_dist_id[2], parsed_msg->c_hdr_old.peer_dist_id[3],
                     parsed_msg->c_hdr_old.peer_dist_id[4], parsed_msg->c_hdr_old.peer_dist_id[5],
                     parsed_msg->c_hdr_old.peer_dist_id[6] << 8 | parsed_msg->c_hdr_old.peer_dist_id[7]);
            break;
        case 2: // admin = 4bytes (ASN), assing number = 2bytes
            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%lu:%d",
                     (unsigned long) (parsed_msg->c_hdr_old.peer_dist_id[2] << 24
                                      | parsed_msg->c_hdr_old.peer_dist_id[3] << 16
                                      | parsed_msg->c_hdr_old.peer_dist_id[4] << 8 | parsed_msg->c_hdr_old.peer_dist_id[5]),
                     parsed_msg->c_hdr_old.peer_dist_id[6] << 8 | parsed_msg->c_hdr_old.peer_dist_id[7]);
            break;
        default: // admin = 2 bytes, sub field = 4 bytes
            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d:%lu",
                     parsed_msg->c_hdr_old.peer_dist_id[1] << 8 | parsed_msg->c_hdr_old.peer_dist_id[2],
                     (unsigned long) (parsed_msg->c_hdr_old.peer_dist_id[3] << 24
                                      | parsed_msg->c_hdr_old.peer_dist_id[4] << 16
                                      | parsed_msg->c_hdr_old.peer_dist_id[5] << 8 | parsed_msg->c_hdr_old.peer_dist_id[6]
                                      | parsed_msg->c_hdr_old.peer_dist_id[7]));
            break;
    }

    // Update the MySQL peer entry struct
    strncpy(parsed_msg->p_entry.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr));
    parsed_msg->p_entry.peer_as = strtoll(parsed_msg->peer_as, NULL, 16);
    strncpy(parsed_msg->p_entry.peer_bgp_id, parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id));
    strncpy(parsed_msg->p_entry.peer_rd, parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd));

    // Save the advertised timestamp
    uint32_t ts = parsed_msg->c_hdr_old.ts_secs;
    bgp::SWAP_BYTES(&ts);


    if (ts != 0)
        parsed_msg->p_entry.timestamp_secs = ts;
    else
        parsed_msg->p_entry.timestamp_secs = time(NULL);

    // Is peer type L3VPN peer or global instance
    if (parsed_msg->c_hdr_old.type == 1) // L3VPN
        parsed_msg->p_entry.is_l3vpn = 1;
    else
        // Global Instance
        parsed_msg->p_entry.is_l3vpn = 0;

    //   SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
//    SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock, c_hdr.peer_as[0], c_hdr.peer_as[1], c_hdr.peer_as[2], c_hdr.peer_as[3]);
    //   SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
}

/**
 * Parse the v3 peer header
 *
 * \param [in]  sock        Socket to read the message from
 */
//void parseBMP::parsePeerHdr(int sock) {
static void libParseBGP_parse_bmp_parse_peer_hdr(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    peer_hdr_v3 p_hdr = {0};
    int i;

    bzero(&p_hdr, sizeof(p_hdr));

    /*if ((i = Recv(sock, &p_hdr, BMP_PEER_HDR_LEN, MSG_WAITALL))
        != BMP_PEER_HDR_LEN) {
        //       LOG_ERR("sock=%d: Couldn't read all bytes, read %d bytes",sock, i);
    }*/
    if ((i = extract_from_buffer(buffer, buf_len, &p_hdr, BMP_PEER_HDR_LEN))
        != BMP_PEER_HDR_LEN) {
        //       LOG_ERR("sock=%d: Couldn't read all bytes, read %d bytes",sock, i);
        throw "Couldn't read all bytes";
    }

    // Adjust the common header length to remove the peer header (as it's been read)
    parsed_msg->bmp_len -= BMP_PEER_HDR_LEN;

    //   SELF_DEBUG("parsePeerHdr: sock=%d : Peer Type is %d", sock,p_hdr.peer_type);

    if (p_hdr.peer_flags & 0x80) { // V flag of 1 means this is IPv6
        parsed_msg->p_entry.is_ipv4 = false;

        inet_ntop(AF_INET6, p_hdr.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr));

        //       SELF_DEBUG("sock=%d : Peer address is IPv6 %s", sock,peer_addr);

    } else {
        parsed_msg->p_entry.is_ipv4 = true;

        snprintf(parsed_msg->peer_addr, sizeof(parsed_msg->peer_addr), "%d.%d.%d.%d",
                 p_hdr.peer_addr[12], p_hdr.peer_addr[13], p_hdr.peer_addr[14],
                 p_hdr.peer_addr[15]);
        //       SELF_DEBUG("sock=%d : Peer address is IPv4 %s", sock,peer_addr);
    }

    if (p_hdr.peer_flags & 0x10) { // O flag of 1 means this is Adj-Rib-Out
//        SELF_DEBUG("sock=%d : Msg is for Adj-RIB-Out", sock);
        parsed_msg->p_entry.is_pre_policy = false;
        parsed_msg->p_entry.is_adj_in = false;
    } else if (p_hdr.peer_flags & 0x40) { // L flag of 1 means this is post-policy of Adj-RIB-In
//        SELF_DEBUG("sock=%d : Msg is for POST-POLICY Adj-RIB-In", sock);
        parsed_msg->p_entry.is_pre_policy = false;
        parsed_msg->p_entry.is_adj_in = true;
    } else {
        //       SELF_DEBUG("sock=%d : Msg is for PRE-POLICY Adj-RIB-In", sock);
        parsed_msg->p_entry.is_pre_policy = true;
        parsed_msg->p_entry.is_adj_in = true;
    }

    // convert the BMP byte messages to human readable strings
    snprintf(parsed_msg->peer_as, sizeof(parsed_msg->peer_as), "0x%04x%04x",
             p_hdr.peer_as[0] << 8 | p_hdr.peer_as[1],
             p_hdr.peer_as[2] << 8 | p_hdr.peer_as[3]);

    inet_ntop(AF_INET, p_hdr.peer_bgp_id, parsed_msg->peer_bgp_id, sizeof(parsed_msg->peer_bgp_id));
//    SELF_DEBUG("sock=%d : Peer BGP-ID %x.%x.%x.%x (%s)", sock, p_hdr.peer_bgp_id[0],p_hdr.peer_bgp_id[1],p_hdr.peer_bgp_id[2],p_hdr.peer_bgp_id[3], peer_bgp_id);

    // Format based on the type of RD
//    SELF_DEBUG("sock=%d : Peer RD type = %d %d", sock, p_hdr.peer_dist_id[0], p_hdr.peer_dist_id[1]);
    switch (p_hdr.peer_dist_id[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d.%d.%d.%d:%d",
                     p_hdr.peer_dist_id[2], p_hdr.peer_dist_id[3],
                     p_hdr.peer_dist_id[4], p_hdr.peer_dist_id[5],
                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
            break;

        case 2: // admin = 4bytes (ASN), sub field 2bytes
            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%lu:%d",
                     (unsigned long) (p_hdr.peer_dist_id[2] << 24
                                      | p_hdr.peer_dist_id[3] << 16
                                      | p_hdr.peer_dist_id[4] << 8 | p_hdr.peer_dist_id[5]),
                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
            break;
        default: // Type 0:  // admin = 2 bytes, sub field = 4 bytes
            snprintf(parsed_msg->peer_rd, sizeof(parsed_msg->peer_rd), "%d:%lu",
                     p_hdr.peer_dist_id[2] << 8 | p_hdr.peer_dist_id[3],
                     (unsigned long) (p_hdr.peer_dist_id[4] << 24
                                      | p_hdr.peer_dist_id[5] << 16
                                      | p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]));
            break;
    }

    // Update the peer entry struct in parse bmp
    strncpy(parsed_msg->p_entry.peer_addr, parsed_msg->peer_addr, sizeof(parsed_msg->p_entry.peer_addr));
    parsed_msg->p_entry.peer_as = strtoll(parsed_msg->peer_as, NULL, 16);
    strncpy(parsed_msg->p_entry.peer_bgp_id, parsed_msg->peer_bgp_id, sizeof(parsed_msg->p_entry.peer_bgp_id));
    strncpy(parsed_msg->p_entry.peer_rd, parsed_msg->peer_rd, sizeof(parsed_msg->p_entry.peer_rd));


    // Save the advertised timestamp
    bgp::SWAP_BYTES(&p_hdr.ts_secs);
    bgp::SWAP_BYTES(&p_hdr.ts_usecs);

    if (p_hdr.ts_secs != 0) {
        parsed_msg->p_entry.timestamp_secs = p_hdr.ts_secs;
        parsed_msg->p_entry.timestamp_us = p_hdr.ts_usecs;

    } else {
        timeval tv;

        gettimeofday(&tv, NULL);
        parsed_msg->p_entry.timestamp_secs = tv.tv_sec;
        parsed_msg->p_entry.timestamp_us = tv.tv_usec;
    }


    // Is peer type L3VPN peer or global instance
    if (p_hdr.peer_type == 1) // L3VPN
        parsed_msg->p_entry.is_l3vpn = 1;

    else
        // Global Instance
        parsed_msg->p_entry.is_l3vpn = 0;

//    SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
    //   SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock,
    //               p_hdr.peer_as[0], p_hdr.peer_as[1], p_hdr.peer_as[2],
    //               p_hdr.peer_as[3]);
//    SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
}

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
static void libParseBGP_parse_bmp_parse_bmp_v3(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    parsed_msg->c_hdr_v3 = { 0 };
    //   SELF_DEBUG("Parsing BMP version 3 (rfc7854)");
    if ((extract_from_buffer(buffer, buf_len, &parsed_msg->c_hdr_v3, BMP_HDRv3_LEN)) != BMP_HDRv3_LEN) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }

    //memcpy(&parsed_msg->c_hdr_v3, buffer, BMP_HDRv3_LEN);
    // Change to host order
    bgp::SWAP_BYTES(&parsed_msg->c_hdr_v3.len);

    //   SELF_DEBUG("BMP v3: type = %x len=%d", parsed_msg->c_hdr_v3.type, parsed_msg->c_hdr_v3.len);

    // Adjust length to remove common header size
    parsed_msg->c_hdr_v3.len -= 1 + BMP_HDRv3_LEN;

    if (parsed_msg->c_hdr_v3.len > BGP_MAX_MSG_SIZE)
        throw "ERROR: BMP length is larger than max possible BGP size";

    // Parse additional headers based on type
    parsed_msg->bmp_type = parsed_msg->c_hdr_v3.type;
    parsed_msg->bmp_len = parsed_msg->c_hdr_v3.len;

    switch (parsed_msg->c_hdr_v3.type) {
        case TYPE_ROUTE_MON: // Route monitoring
            //          SELF_DEBUG("BMP MSG : route monitor");
            //parsePeerHdr(sock);
            libParseBGP_parse_bmp_parse_peer_hdr(parsed_msg, buffer, buf_len);
            break;

        case TYPE_STATS_REPORT: // Statistics Report
            //          SELF_DEBUG("BMP MSG : stats report");
            //parsePeerHdr(sock);
            libParseBGP_parse_bmp_parse_peer_hdr(parsed_msg, buffer, buf_len);
            break;

        case TYPE_PEER_UP: // Peer Up notification
        {
            //           SELF_DEBUG("BMP MSG : peer up");
            //parsePeerHdr(sock);
            libParseBGP_parse_bmp_parse_peer_hdr(parsed_msg, buffer, buf_len);
            break;
        }
        case TYPE_PEER_DOWN: // Peer down notification
            //           SELF_DEBUG("BMP MSG : peer down");
            //parsePeerHdr(sock);
            libParseBGP_parse_bmp_parse_peer_hdr(parsed_msg, buffer, buf_len);
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
static char libParseBGP_parse_bmp_handle_msg(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int &buf_len) {
    unsigned char ver;
    ssize_t bytes_read;

    // Get the version in order to determine what we read next
    //    As of Junos 10.4R6.5, it supports version 1
    bytes_read = extract_from_buffer(buffer, buf_len, &ver, 1);
    //memcpy(&ver,buffer,1);
    //*buffer++;
    //buf_len-=1;
//    if (bytes_read < 0)
//        throw "(1) Failed to read from socket.";
//    else if (bytes_read == 0)
//        throw "(2) Connection closed";
//    else if (bytes_read != 1)
//        throw "(3) Cannot read the BMP version byte from socket";
    if (bytes_read != 1)
        throw "Cannot read BMP version byte from buffer";

    // check the version
    if (ver == 3) { // draft-ietf-grow-bmp-04 - 07
        //parseBMPv3(sock);
        libParseBGP_parse_bmp_parse_bmp_v3(parsed_msg, buffer, buf_len);
    }

        // Handle the older versions
    else if (ver == 1 || ver == 2) {
        //       SELF_DEBUG("Older BMP version of %d, consider upgrading the router to support BMPv3", ver);
        //parseBMPv2(sock);
        libParseBGP_parse_bmp_parse_bmp_v2(parsed_msg, buffer, buf_len);

    } else
        throw "ERROR: Unsupported BMP message version";

    //   SELF_DEBUG("BMP version = %d\n", ver);

    return parsed_msg->bmp_type;
}

/**
 * Parse and return back the stats report
 *
 * \param [in]  sock        Socket to read the stats message from
 * \param [out] stats       Reference to stats report data
 *
 * \return true if error, false if no error
 */
static bool libParseBGP_parse_bmp_handle_stats_report(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    unsigned long stats_cnt = 0; // Number of counter stat objects to follow
    unsigned char b[8];

    if ((extract_from_buffer(buffer, buf_len, b, 4)) != 4)
        throw "ERROR:  Cannot proceed since we cannot read the stats mon counter";

    parsed_msg->bmp_len -= 4;

    // Reverse the bytes and update int
    bgp::SWAP_BYTES(b, 4);
    memcpy((void*) &stats_cnt, (void*) b, 4);

    //   SELF_DEBUG("sock = %d : STATS REPORT Count: %u (%d %d %d %d)",
    //               sock, stats_cnt, b[0], b[1], b[2], b[3]);

    // Vars used per counter object
    unsigned short stat_type = 0;
    unsigned short stat_len = 0;

    // Loop through each stats object
    for (unsigned long i = 0; i < stats_cnt; i++) {

        //if ((Recv(sock, &stat_type, 2, MSG_WAITALL)) != 2)
        if ((extract_from_buffer(buffer, buf_len, &stat_type, 2)) != 2)
            throw "ERROR: Cannot proceed since we cannot read the stats type.";
        //if ((Recv(sock, &stat_len, 2, MSG_WAITALL)) != 2)
        if ((extract_from_buffer(buffer, buf_len, &stat_len, 2)) != 2)
            throw "ERROR: Cannot proceed since we cannot read the stats len.";

        parsed_msg->bmp_len -= 4;

        // convert integer from network to host bytes
        bgp::SWAP_BYTES(&stat_type);
        bgp::SWAP_BYTES(&stat_len);

        //       SELF_DEBUG("sock=%d STATS: %lu : TYPE = %u LEN = %u", sock,
        //                   i, stat_type, stat_len);

        // check if this is a 32 bit number  (default)
        if (stat_len == 4 or stat_len == 8) {

            // Read the stats counter - 32/64 bits
            if ((extract_from_buffer(buffer, buf_len, b, stat_len)) == stat_len) {
                parsed_msg->bmp_len -= stat_len;

                // convert the bytes from network to host order
                bgp::SWAP_BYTES(b, stat_len);

                // Update the table structure based on the stats counter type
                switch (stat_type) {
                    case STATS_PREFIX_REJ:
                        memcpy((void*) &parsed_msg->stats.prefixes_rej, (void*) b, stat_len);
                        break;
                    case STATS_DUP_PREFIX:
                        memcpy((void*) &parsed_msg->stats.known_dup_prefixes, (void*) b, stat_len);
                        break;
                    case STATS_DUP_WITHDRAW:
                        memcpy((void*) &parsed_msg->stats.known_dup_withdraws, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_CLUSTER_LIST:
                        memcpy((void*) &parsed_msg->stats.invalid_cluster_list, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_AS_PATH_LOOP:
                        memcpy((void*) &parsed_msg->stats.invalid_as_path_loop, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_ORIGINATOR_ID:
                        memcpy((void*) &parsed_msg->stats.invalid_originator_id, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_AS_CONFED_LOOP:
                        memcpy((void*) &parsed_msg->stats.invalid_as_confed_loop, (void*) b, stat_len);
                        break;
                    case STATS_NUM_ROUTES_ADJ_RIB_IN:
                        memcpy((void*) &parsed_msg->stats.routes_adj_rib_in, (void*) b, stat_len);
                        break;
                    case STATS_NUM_ROUTES_LOC_RIB:
                        memcpy((void*) &parsed_msg->stats.routes_loc_rib, (void*) b, stat_len);
                        break;

                    default:
                    {
                        uint32_t value32bit;
                        uint64_t value64bit;

                        if (stat_len == 8) {
                            memcpy((void*)&value64bit, (void *)b, 8);

                            //                         SELF_DEBUG("%s: sock=%d: stat type %d length of %d value of %lu is not yet implemented",
                            //                                 p_entry.peer_addr, sock, stat_type, stat_len, value64bit);
                        } else {
                            memcpy((void*)&value32bit, (void *)b, 4);

                            //                         SELF_DEBUG("%s: sock=%d: stat type %d length of %d value of %lu is not yet implemented",
                            //                                  p_entry.peer_addr, sock, stat_type, stat_len, value32bit);
                        }
                    }
                }

                //             SELF_DEBUG("VALUE is %u",
                //                         b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]);
            }

        } else { // stats len not expected, we need to skip it.
            //         SELF_DEBUG("sock=%d : skipping stats report '%u' because length of '%u' is not expected.",
            //                     sock, stat_type, stat_len);

            while (stat_len-- > 0)
                extract_from_buffer(buffer, buf_len, &b[0], 1);
        }
    }

    return false;
}

/**
 * handle the initiation message and update the router entry
 *
 * \param [in]     sock        Socket to read the init message from
 * \param [in/out] r_entry     Already defined router entry reference (will be updated)
 */
static void libParseBGP_parse_bmp_handle_init_msg(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    init_msg_v3 init_msg;
    char infoBuf[sizeof(parsed_msg->r_entry.initiate_data)];
    int infoLen;

    // Buffer the init message for parsing
    libParseBGP_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);

    u_char *bufPtr = parsed_msg->bmp_data;

    /*
     * Loop through the init message (in buffer) to parse each TLV
     */
    for (int i=0; i < parsed_msg->bmp_data_len; i += BMP_INIT_MSG_LEN) {
        memcpy(&init_msg, bufPtr, BMP_INIT_MSG_LEN);
        init_msg.info = NULL;
        bgp::SWAP_BYTES(&init_msg.len);
        bgp::SWAP_BYTES(&init_msg.type);

        bufPtr += BMP_INIT_MSG_LEN;                // Move pointer past the info header

        //       LOG_INFO("Init message type %hu and length %hu parsed", initMsg.type, initMsg.len);

        if (init_msg.len > 0) {
            infoLen = sizeof(infoBuf) < init_msg.len ? sizeof(infoBuf) : init_msg.len;
            bzero(infoBuf, sizeof(infoBuf));
            memcpy(infoBuf, bufPtr, infoLen);
            bufPtr += infoLen;                     // Move pointer past the info data
            i += infoLen;                          // Update the counter past the info data

            init_msg.info = infoBuf;

        }

        /*
         * Save the data based on info type
         */
        switch (init_msg.type) {
            case INIT_TYPE_FREE_FORM_STRING :
                infoLen = sizeof(parsed_msg->r_entry.initiate_data) < (init_msg.len - 1) ? (sizeof(parsed_msg->r_entry.initiate_data) - 1) : init_msg.len;
                memcpy(parsed_msg->r_entry.initiate_data, init_msg.info, infoLen);
                //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.initiate_data);

                break;

            case INIT_TYPE_SYSNAME :
                infoLen = sizeof(parsed_msg->r_entry.name) < (init_msg.len - 1) ? (sizeof(parsed_msg->r_entry.name) - 1) : init_msg.len;
                strncpy((char *)parsed_msg->r_entry.name, init_msg.info, infoLen);
                //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.name);
                break;

            case INIT_TYPE_SYSDESCR :
                infoLen = sizeof(parsed_msg->r_entry.descr) < (init_msg.len - 1) ? (sizeof(parsed_msg->r_entry.descr) - 1) : init_msg.len;
                strncpy((char *)parsed_msg->r_entry.descr, init_msg.info, infoLen);
                //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.descr);
                break;

            case INIT_TYPE_ROUTER_BGP_ID:
                if (init_msg.len != sizeof(in_addr_t)) {
                    //                   LOG_NOTICE("Init message type BGP ID not of IPv4 addr length");
                    break;
                }
                inet_ntop(AF_INET, init_msg.info, parsed_msg->r_entry.bgp_id, sizeof(parsed_msg->r_entry.bgp_id));
//                LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.bgp_id);
                break;

//            default:

//                LOG_NOTICE("Init message type %hu is unexpected per rfc7854", init_msg.type);
        }
    }
}

/**
 * handle the termination message, router entry will be updated
 *
 * \param [in]     sock        Socket to read the term message from
 * \param [in/out] r_entry     Already defined router entry reference (will be updated)
 */
//void parseBMP::handleTermMsg(int sock) {
static void libParseBGP_parse_bmp_handle_term_msg(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char*& buffer, int& buf_len) {
    term_msg_v3 termMsg;
    char infoBuf[sizeof(parsed_msg->r_entry.term_data)];
    int infoLen;

    // Buffer the init message for parsing
    libParseBGP_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);

    u_char *bufPtr = parsed_msg->bmp_data;

    /*
     * Loop through the term message (in buffer) to parse each TLV
     */
    for (int i=0; i < parsed_msg->bmp_data_len; i += BMP_TERM_MSG_LEN) {
        memcpy(&termMsg, bufPtr, BMP_TERM_MSG_LEN);
        termMsg.info = NULL;
        bgp::SWAP_BYTES(&termMsg.len);
        bgp::SWAP_BYTES(&termMsg.type);

        bufPtr += BMP_TERM_MSG_LEN;                // Move pointer past the info header

        //       LOG_INFO("Term message type %hu and length %hu parsed", termMsg.type, termMsg.len);

        if (termMsg.len > 0) {
            infoLen = sizeof(infoBuf) < termMsg.len ? sizeof(infoBuf) : termMsg.len;
            bzero(infoBuf, sizeof(infoBuf));
            memcpy(infoBuf, bufPtr, infoLen);
            bufPtr += infoLen;                     // Move pointer past the info data
            i += infoLen;                       // Update the counter past the info data

            termMsg.info = infoBuf;

            //           LOG_INFO("Term message type %hu = %s", termMsg.type, termMsg.info);
        }

        /*
         * Save the data based on info type
         */
        switch (termMsg.type) {
            case TERM_TYPE_FREE_FORM_STRING :
                memcpy(parsed_msg->r_entry.term_data, termMsg.info, termMsg.len);
                break;

            case TERM_TYPE_REASON :
            {
                // Get the term reason code from info data (first 2 bytes)
                uint16_t term_reason;
                memcpy(&term_reason, termMsg.info, 2);
                bgp::SWAP_BYTES(&term_reason);
                parsed_msg->r_entry.term_reason_code = term_reason;

                switch (term_reason) {
                    case TERM_REASON_ADMIN_CLOSE :
                        //                       LOG_INFO("%s BMP session closed by remote administratively", r_entry.ip_addr);
                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
                                 "Remote session administratively closed");
                        break;

                    case TERM_REASON_OUT_OF_RESOURCES:
                        //                       LOG_INFO("%s BMP session closed by remote due to out of resources", r_entry.ip_addr);
                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
                                 "Remote out of resources");
                        break;

                    case TERM_REASON_REDUNDANT_CONN:
//                        LOG_INFO("%s BMP session closed by remote due to connection being redundant", r_entry.ip_addr);
                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
                                 "Remote considers connection redundant");
                        break;

                    case TERM_REASON_UNSPECIFIED:
                        ///                       LOG_INFO("%s BMP session closed by remote as unspecified", r_entry.ip_addr);
                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
                                 "Remote closed with unspecified reason");
                        break;

                    default:
//                        LOG_INFO("%s closed with undefined reason code of %d", r_entry.ip_addr, term_reason);
                        snprintf(parsed_msg->r_entry.term_reason_text, sizeof(parsed_msg->r_entry.term_reason_text),
                                 "Unknown %d termination reason, which is not part of draft.", term_reason);
                }

                break;
            }

//            default:
//                LOG_NOTICE("Term message type %hu is unexpected per draft", termMsg.type);
        }
    }
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
static bool libParseBGP_parse_bmp_parse_peer_down_event_hdr(libParseBGP_parse_bmp_parsed_data *parsed_msg,
                                                     unsigned char*& buffer, int& buf_len) {
    char reason;
    //if (Recv(sock, &reason, 1, 0) == 1) {
    if (extract_from_buffer(buffer, buf_len, &reason, 1) == 1) {
        //  LOG_NOTICE("sock=%d : %s: BGP peer down notification with reason code: %d", sock, p_entry->peer_addr, reason);

        // Indicate that data has been read
        parsed_msg->bmp_len--;

        // Initialize the down_event struct
        parsed_msg->down_event.bmp_reason = reason;

    } else {
        return false;
    }

    return true;
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
static bool libParseBGP_parse_bmp_parse_peer_up_event_hdr(libParseBGP_parse_bmp_parsed_data *parsed_msg,
                                                   unsigned char*& buffer, int& buf_len) {
    unsigned char local_addr[16];
    bool is_parse_good = true;
    int bytes_read = 0;

    // Get the local address
    if ( extract_from_buffer(buffer, buf_len, &local_addr, 16) != 16)
        is_parse_good = false;
    else
        bytes_read += 16;

    if (is_parse_good and parsed_msg->p_entry.is_ipv4) {
        snprintf(parsed_msg->up_event.local_ip, sizeof(parsed_msg->up_event.local_ip), "%d.%d.%d.%d",
                 local_addr[12], local_addr[13], local_addr[14],
                 local_addr[15]);
        //       SELF_DEBUG("%s : Peer UP local address is IPv4 %s", peer_addr, up_event.local_ip);

    } else if (is_parse_good) {
        inet_ntop(AF_INET6, local_addr, parsed_msg->up_event.local_ip, sizeof(parsed_msg->up_event.local_ip));
        //       SELF_DEBUG("%s : Peer UP local address is IPv6 %s", peer_addr, up_event.local_ip);
    }

    // Get the local port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &parsed_msg->up_event.local_port, 2) != 2)
        is_parse_good = false;

    else if (is_parse_good) {
        bytes_read += 2;
        bgp::SWAP_BYTES(&parsed_msg->up_event.local_port);
    }

    // Get the remote port
    if (is_parse_good and extract_from_buffer(buffer, buf_len, &parsed_msg->up_event.remote_port, 2) != 2)
        is_parse_good = false;

    else if (is_parse_good) {
        bytes_read += 2;
        bgp::SWAP_BYTES(&parsed_msg->up_event.remote_port);
    }

    // Update bytes read
    parsed_msg->bmp_len -= bytes_read;

    // Validate parse is still good, if not read the remaining bytes of the message so that the next msg will work
    if (!is_parse_good) {
        //       LOG_NOTICE("%s: PEER UP header failed to be parsed, read only %d bytes of the header",
        //              peer_addr, bytes_read);

        // Msg is invalid - Buffer and ignore
        libParseBGP_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);
    }

    return is_parse_good;
}

uint8_t libParseBGP_parse_bmp_parse_msg(libParseBGP_parse_bmp_parsed_data *parsed_msg, unsigned char *&buffer, int buf_len) {
    string peer_info_key;
    int initial_buffer_len = buf_len;

    char bmp_type = 0;
    libParseBGP_parse_bgp_parsed_data pBGP;

    try {
        bmp_type = libParseBGP_parse_bmp_handle_msg(parsed_msg, buffer, buf_len);

        if (bmp_type < 4) {
            peer_info_key =  parsed_msg->p_entry.peer_addr;
            peer_info_key += parsed_msg->p_entry.peer_rd;

        }
        /*
         * At this point we only have the BMP header message, what happens next depends
         *      on the BMP message type.
         */
        switch (bmp_type) {
            case TYPE_PEER_DOWN : { // Peer down type
                if (libParseBGP_parse_bmp_parse_peer_down_event_hdr(parsed_msg, buffer, buf_len)) {
                    //bufferBMPMessage(read_fd);
                    libParseBGP_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);


                    // Prepare the BGP parser
                    libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);

                    // Check if the reason indicates we have a BGP message that follows
                    switch (parsed_msg->down_event.bmp_reason) {
                        case 1 : { // Local system close with BGP notify
                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
                                    "Local close by (%s) for peer (%s) : ", parsed_msg->r_entry.ip_addr,
                                     parsed_msg->p_entry.peer_addr);
                            libParseBGP_parse_bgp_handle_down_event(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len,&parsed_msg->down_event,&parsed_msg->bgp_msg);
                            break;
                        }
                        case 2 : // Local system close, no bgp notify
                        {
// Read two byte code corresponding to the FSM event
                            uint16_t fsm_event = 0 ;
                            memcpy(&fsm_event, parsed_msg->bmp_data, 2);
                            bgp::SWAP_BYTES(&fsm_event);

                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
                                    "Local (%s) closed peer (%s) session: fsm_event=%d, No BGP notify message.",
                                     parsed_msg->r_entry.ip_addr,parsed_msg->p_entry.peer_addr, fsm_event);
                            break;
                        }
                        case 3 : { // remote system close with bgp notify
                            snprintf(parsed_msg->down_event.error_text, sizeof(parsed_msg->down_event.error_text),
                                    "Remote peer (%s) closed local (%s) session: ", parsed_msg->r_entry.ip_addr,
                                     parsed_msg->p_entry.peer_addr);

                            libParseBGP_parse_bgp_handle_down_event(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len, &parsed_msg->down_event,&parsed_msg->bgp_msg);
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
                if (libParseBGP_parse_bmp_parse_peer_up_event_hdr(parsed_msg, buffer, buf_len)) {
               //     LOG_INFO("%s: PEER UP Received, local addr=%s:%hu remote addr=%s:%hu", client->c_ip,up_event.local_ip, up_event.local_port, p_entry.peer_addr, up_event.remote_port);

                    libParseBGP_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);

                    // Prepare the BGP parser
                    libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);


// Parse the BGP sent/received open messages
                    libParseBGP_parse_bgp_handle_up_event(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len, &parsed_msg->up_event,&parsed_msg->bgp_msg);
                } //else {
                 //   LOG_NOTICE("%s: PEER UP Received but failed to parse the BMP header.", client->c_ip);
               // }
                break;
            }

            case TYPE_ROUTE_MON : { // Route monitoring type
                libParseBGP_parse_bmp_buffer_bmp_message(parsed_msg, buffer, buf_len);

                /*
                 * Read and parse the the BGP message from the client.
                 *     parseBGP will update mysql directly
                 */
                libParseBGP_parse_bgp_init(&pBGP, &parsed_msg->p_entry, (char *)parsed_msg->r_entry.ip_addr, &parsed_msg->peer_info_map[peer_info_key]);

                libParseBGP_parse_bgp_handle_update(&pBGP, parsed_msg->bmp_data, parsed_msg->bmp_data_len, &parsed_msg->bgp_msg);

                break;
            }

            case TYPE_STATS_REPORT : { // Stats Report
                libParseBGP_parse_bmp_handle_stats_report(parsed_msg, buffer, buf_len);
                break;
            }

            case TYPE_INIT_MSG : { // Initiation Message
               // LOG_INFO("%s: Init message received with length of %u", client->c_ip, pBMP->getBMPLength());

                libParseBGP_parse_bmp_handle_init_msg(parsed_msg, buffer, buf_len);

                break;
            }

            case TYPE_TERM_MSG : { // Termination Message
               // LOG_INFO("%s: Term message received with length of %u", client->c_ip, pBMP->getBMPLength());

                libParseBGP_parse_bmp_handle_term_msg(parsed_msg, buffer, buf_len);

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

/*int main() {
   /* fstream infile;
    infile.open("C:/Users/Induja/CLionProjects/openbmp-bmpparser/file.txt", fstream::in);
    if (infile.is_open()) {
        char b[1] = "";
        //infile >> std::hex >> a;
        infile.read(b, 2);
        cout << b[1] << endl;
        infile.close();
    } * /
    unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0x06, 0x04};
    //unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xdf, 0x33, 0x67, 0xd0, 0x40, 0x00, 0xb3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x41, 0x01, 0x04, 0x19, 0x2f, 0x02, 0x58, 0x80, 0xdf, 0x33, 0x67, 0x24, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x19, 0x2f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x35, 0x01, 0x04, 0x0d, 0x1c, 0x00, 0xb4, 0x04, 0x45, 0xb8, 0xc1, 0x18, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00};
    //unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0xe4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //unsigned char temp[] = {0x03, 0x00, 0x00, 0x03, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03, 0x36, 0x02, 0x00, 0x00, 0x00, 0x44, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x08, 0x02, 0x03, 0x0d, 0x1c, 0x0b, 0x62, 0x40, 0x7d, 0x40, 0x03, 0x04, 0x04, 0x45, 0xb8, 0xc1, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x08, 0x24, 0x0b, 0x62, 0x01, 0x9a, 0x0b, 0x62, 0x04, 0xb3, 0x0b, 0x62, 0x08, 0x99, 0x0b, 0x62, 0x0c, 0x80, 0x0d, 0x1c, 0x00, 0x03, 0x0d, 0x1c, 0x00, 0x56, 0x0d, 0x1c, 0x02, 0x3f, 0x0d, 0x1c, 0x02, 0x9a, 0x0d, 0x1c, 0x07, 0xdc, 0x17, 0x36, 0xe7, 0x82, 0x16, 0x34, 0xda, 0x40, 0x15, 0x34, 0xda, 0x38, 0x16, 0x34, 0xda, 0x34, 0x18, 0x36, 0xb6, 0xf4, 0x18, 0x34, 0xde, 0xf2, 0x17, 0x34, 0xde, 0xf0, 0x18, 0x34, 0xde, 0xef, 0x17, 0x34, 0xde, 0xec, 0x17, 0x34, 0xde, 0xe8, 0x16, 0x34, 0xde, 0xe4, 0x17, 0x34, 0xde, 0xe2, 0x18, 0x34, 0x54, 0x49, 0x18, 0x36, 0xef, 0x27, 0x18, 0x36, 0xef, 0x25, 0x18, 0x36, 0xef, 0x22, 0x18, 0x36, 0xef, 0x20, 0x18, 0x36, 0xe7, 0x9f, 0x18, 0x36, 0xe7, 0x9e, 0x18, 0x36, 0xe7, 0x9d, 0x18, 0x36, 0xe7, 0x9a, 0x18, 0x36, 0xe7, 0x99, 0x18, 0x36, 0xe7, 0x98, 0x18, 0x36, 0xe7, 0x97, 0x18, 0x36, 0xe7, 0x94, 0x18, 0x36, 0xe7, 0x93, 0x18, 0x36, 0xe7, 0x92, 0x18, 0x36, 0xe7, 0x91, 0x18, 0x36, 0xe7, 0x8e, 0x18, 0x36, 0xe7, 0x8d, 0x18, 0x36, 0xe7, 0x8b, 0x18, 0x36, 0xe7, 0x8a, 0x18, 0x36, 0xe7, 0x89, 0x18, 0x36, 0xe7, 0x87, 0x18, 0x36, 0xe7, 0x86, 0x18, 0x36, 0xe7, 0x84, 0x18, 0x36, 0xe7, 0x83, 0x18, 0x36, 0xe7, 0x81, 0x13, 0x36, 0xe7, 0x80, 0x18, 0x36, 0xe7, 0x80, 0x16, 0x36, 0xe6, 0x1c, 0x11, 0x36, 0xe5, 0x80, 0x11, 0x36, 0xe5, 0x00, 0x10, 0x36, 0xe4, 0x10, 0x36, 0xdc, 0x0f, 0x36, 0xd8, 0x10, 0x36, 0xc3, 0x10, 0x36, 0xc2, 0x16, 0x36, 0xc0, 0x1c, 0x17, 0x36, 0xb6, 0xf0, 0x18, 0x36, 0xb6, 0xc8, 0x18, 0x36, 0xb6, 0xc7, 0x18, 0x36, 0xb6, 0xc6, 0x17, 0x36, 0xb6, 0x90, 0x17, 0x36, 0xb6, 0x8e, 0x17, 0x36, 0xb6, 0x8c, 0x10, 0x36, 0xab, 0x10, 0x36, 0xaa, 0x10, 0x36, 0x9b, 0x10, 0x36, 0x9a, 0x10, 0x36, 0x4e, 0x0f, 0x36, 0x4c, 0x0f, 0x36, 0x4a, 0x10, 0x36, 0x49, 0x10, 0x36, 0x48, 0x18, 0x34, 0xda, 0x4f, 0x18, 0x34, 0xda, 0x4e, 0x18, 0x34, 0xda, 0x4b, 0x18, 0x34, 0xda, 0x4a, 0x18, 0x34, 0xda, 0x49, 0x18, 0x34, 0xda, 0x48, 0x18, 0x34, 0xda, 0x45, 0x18, 0x34, 0xda, 0x44, 0x18, 0x34, 0xda, 0x43, 0x18, 0x34, 0xda, 0x42, 0x18, 0x34, 0xda, 0x3f, 0x18, 0x34, 0xda, 0x3c, 0x18, 0x34, 0xda, 0x3b, 0x18, 0x34, 0xda, 0x3a, 0x18, 0x34, 0xda, 0x39, 0x18, 0x34, 0xda, 0x36, 0x18, 0x34, 0xda, 0x35, 0x18, 0x34, 0xda, 0x34, 0x18, 0x34, 0xda, 0x33, 0x18, 0x34, 0xda, 0x30, 0x18, 0x34, 0xda, 0x2d, 0x18, 0x34, 0xda, 0x2c, 0x18, 0x34, 0xda, 0x2b, 0x18, 0x34, 0xda, 0x2a, 0x18, 0x34, 0xda, 0x27, 0x18, 0x34, 0xda, 0x26, 0x18, 0x34, 0xda, 0x25, 0x18, 0x34, 0xda, 0x24, 0x18, 0x34, 0xda, 0x21, 0x18, 0x34, 0xda, 0x20, 0x18, 0x34, 0xda, 0x1e, 0x18, 0x34, 0xda, 0x1d, 0x18, 0x34, 0xda, 0x1c, 0x18, 0x34, 0xda, 0x1b, 0x18, 0x34, 0xda, 0x18, 0x18, 0x34, 0xda, 0x17, 0x18, 0x34, 0xda, 0x16, 0x18, 0x34, 0xda, 0x15, 0x18, 0x34, 0xda, 0x12, 0x18, 0x34, 0xda, 0x11, 0x18, 0x34, 0xda, 0x10, 0x18, 0x34, 0xda, 0x0f, 0x18, 0x34, 0xda, 0x0e, 0x18, 0x34, 0xda, 0x0d, 0x18, 0x34, 0xda, 0x0c, 0x18, 0x34, 0xda, 0x09, 0x18, 0x34, 0xda, 0x08, 0x18, 0x34, 0xda, 0x07, 0x18, 0x34, 0xda, 0x06, 0x18, 0x34, 0xda, 0x03, 0x18, 0x34, 0xda, 0x02, 0x18, 0x34, 0xda, 0x01, 0x11, 0x34, 0xda, 0x00, 0x18, 0x34, 0xda, 0x00, 0x0d, 0x34, 0xd0, 0x18, 0x34, 0x5f, 0xfd, 0x18, 0x34, 0x5f, 0xf4, 0x18, 0x34, 0x5f, 0x96, 0x18, 0x34, 0x5f, 0x95, 0x17, 0x34, 0x5f, 0x94, 0x18, 0x34, 0x5f, 0x94, 0x16, 0x34, 0x5f, 0x68, 0x15, 0x34, 0x5e, 0xd8, 0x16, 0x34, 0x5e, 0x70, 0x14, 0x34, 0x5e, 0x30, 0x14, 0x34, 0x5e, 0x20, 0x17, 0x34, 0x5e, 0x18, 0x18, 0x34, 0x5e, 0x0f, 0x18, 0x34, 0x5e, 0x05, 0x18, 0x34, 0x5c, 0x5b, 0x18, 0x34, 0x5c, 0x5a, 0x18, 0x34, 0x5c, 0x59, 0x16, 0x34, 0x5c, 0x58, 0x18, 0x34, 0x5c, 0x58, 0x15, 0x34, 0x5c, 0x28, 0x18, 0x34, 0x55, 0xc6, 0x17, 0x34, 0x55, 0xc4, 0x10, 0x34, 0x38, 0x0e, 0x34, 0x30, 0x0f, 0x34, 0x1e, 0x0f, 0x34, 0x12, 0x0f, 0x34, 0x10, 0x12, 0x2e, 0x89, 0x80, 0x11, 0x2e, 0x89, 0x00, 0x14, 0x2e, 0x33, 0xc0, 0x12, 0x2e, 0x33, 0x80, 0x18, 0xd8, 0x89, 0x39, 0x18, 0xd8, 0x89, 0x38, 0x18, 0xcc, 0xf6, 0xbd, 0x18, 0xb9, 0x8f, 0x10, 0x16, 0xb9, 0x30, 0x78, 0x14, 0xb2, 0xec, 0x00, 0x12, 0xb0, 0x22, 0xc0, 0x13, 0xb0, 0x22, 0xa0, 0x14, 0xb0, 0x22, 0x90, 0x14, 0xb0, 0x22, 0x80, 0x12, 0xb0, 0x22, 0x40, 0x15, 0xb0, 0x20, 0x68, 0x15, 0x57, 0xee, 0x50, 0x11, 0x4f, 0x7d, 0x00, 0x12, 0x4f, 0x7d, 0x00, 0x12, 0x36, 0xf7, 0xc0, 0x12, 0x36, 0xf7, 0x80, 0x11, 0x36, 0xf7, 0x00, 0x11, 0x36, 0xf6, 0x80, 0x11, 0x36, 0xf6, 0x00, 0x16, 0x36, 0xf0, 0xdc, 0x18, 0x36, 0xf0, 0xc5, 0x18, 0x36, 0xf0, 0x38, 0x16, 0x36, 0xf0, 0x34, 0x17, 0x36, 0xf0, 0x32, 0x15, 0x36, 0xf0, 0x00, 0x18, 0x36, 0xef, 0xdf, 0x18, 0x36, 0xef, 0xa6, 0x17, 0x36, 0xef, 0xa4, 0x18, 0x36, 0xef, 0x63, 0x15, 0x36, 0xef, 0x20, 0x16, 0x36, 0xe6, 0xc4, 0x16, 0x36, 0xc0, 0xc4, 0x18, 0x34, 0x55, 0x3f, 0x17, 0x34, 0x55, 0x3c, 0x17, 0x34, 0x55, 0x3a, 0x0d, 0x22, 0xf8};
    unsigned char *tmp;
    tmp = temp;
    parseBMP *p = new parseBMP();
    int len = 6;
    try {
        if (p->parseMsg(tmp, len))
            cout << "Hello Ojas and Induja"<<endl;
        else
            cout << "Oh no!"<<endl;
    }
    catch (char const *str) {
        cout << "Crashed!" << str<<endl;
    }
  //  cout<<"Peer Address "<<p->p_entry.peer_addr<<" "<<p->p_entry.timestamp_secs<<" "<<p->p_entry.isPrePolicy<<endl;
  //  cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
 //   cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
    return 1;
}*/