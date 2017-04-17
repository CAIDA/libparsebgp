/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parseBMP.h"
#include "../include/parseBGP.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/bgp_common.h"
#include "../include/parse_common.h"

parseBMP parseBMPwrapper(unsigned char *buffer, int buf_len) {
    parseBMP pBMP;
    pBMP.parseMsg(buffer, buf_len);
    return pBMP;
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
//parseBMP::parseBMP(MsgBusInterface::obj_bgp_peer *peer_entry) {
parseBMP::parseBMP() {
    //debug = false;
    bmp_type = -1; // Initially set to error
    bmp_len = 0;
    bmp_data_len = 0;
    bzero(bmp_data, sizeof(bmp_data));

    bmp_packet_len = 0;
    bzero(bmp_packet, sizeof(bmp_packet));

    bgp_msg.has_end_of_rib_marker = false;

    //parseMsg(buffer, buf_len);
    // Set the passed storage for the router entry items.
//    p_entry = peer_entry;
    bzero(&p_entry, sizeof(parse_common::obj_bgp_peer));
}

parseBMP::~parseBMP() {
    // clean up
}

libParseBGP_parse_bgp_parsed_data *pBGP;
//bool parseBMP::parseMsg(int read_fd)
bool parseBMP::parseMsg(unsigned char *&buffer, int& buf_len)
{
    //bool rval = true;
    string peer_info_key;
    // MsgBusInterface::obj_bgp_peer p_entry;

    char bmp_type = 0;

    try {
        bmp_type = handle_message(buffer, buf_len);

        if (bmp_type < 4) {
            //memcpy(p_entry.router_hash_id, r_entry.hash_id, sizeof(r_entry.hash_id));
            peer_info_key =  p_entry.peer_addr;
            peer_info_key += p_entry.peer_rd;

        }
        /*
         * At this point we only have the BMP header message, what happens next depends
         *      on the BMP message type.
         */
        switch (bmp_type) {
            case parseBMP::TYPE_PEER_DOWN : { // Peer down type

                //MsgBusInterface::obj_peer_down_event down_event = {};

                //if (parsePeerDownEventHdr(read_fd)) {
                if (parse_peer_down_event_hdr(buffer, buf_len)) {
                    //bufferBMPMessage(read_fd);
                    buffer_bmp_message(buffer, buf_len);


                    // Prepare the BGP parser
                    libParseBGP_parse_bgp_init(pBGP, &p_entry, (char *)r_entry.ip_addr, &peer_info_map[peer_info_key]);
                    //pBGP = new parseBGP(&p_entry, (char *)r_entry.ip_addr, &peer_info_map[peer_info_key]);

      //              if (cfg->debug_bgp)
      //                 pBGP->enableDebug();

                    // Check if the reason indicates we have a BGP message that follows
                    switch (down_event.bmp_reason) {
                        case 1 : { // Local system close with BGP notify
                            snprintf(down_event.error_text, sizeof(down_event.error_text),
                                    "Local close by (%s) for peer (%s) : ", r_entry.ip_addr,
                                    p_entry.peer_addr);
                            libParseBGP_parse_bgp_handle_down_event(pBGP, bmp_data, bmp_data_len,&down_event,&bgp_msg);
                            //pBGP->handleDownEvent(bmp_data, bmp_data_len,&down_event,&bgp_msg);
                            break;
                        }
                        case 2 : // Local system close, no bgp notify
                        {
// Read two byte code corresponding to the FSM event
                            uint16_t fsm_event = 0 ;
                            memcpy(&fsm_event, bmp_data, 2);
                            bgp::SWAP_BYTES(&fsm_event);

                            snprintf(down_event.error_text, sizeof(down_event.error_text),
                                    "Local (%s) closed peer (%s) session: fsm_event=%d, No BGP notify message.",
                                    r_entry.ip_addr,p_entry.peer_addr, fsm_event);
                            break;
                        }
                        case 3 : { // remote system close with bgp notify
                            snprintf(down_event.error_text, sizeof(down_event.error_text),
                                    "Remote peer (%s) closed local (%s) session: ", r_entry.ip_addr,
                                    p_entry.peer_addr);

                            libParseBGP_parse_bgp_handle_down_event(pBGP, bmp_data, bmp_data_len, &down_event,&bgp_msg);
                            //pBGP->handleDownEvent(bmp_data, bmp_data_len, &down_event,&bgp_msg);
                            break;
                        }
                    }

              //      delete pBGP;            // Free the bgp parser after each use.

                    // Add event to the database
                    //mbus_ptr->update_Peer(p_entry, NULL, &down_event, mbus_ptr->PEER_ACTION_DOWN);

                } else {
             //       LOG_ERR("Error with client socket %d", read_fd);
                    // Make sure to free the resource
                    throw "BMPReader: Unable to read from client socket";
                }
                break;
            }

            case parseBMP::TYPE_PEER_UP : // Peer up type
            {
            //    MsgBusInterface::obj_peer_up_event up_event = {};

                //if (parsePeerUpEventHdr(read_fd)) {
                if (parse_peer_up_event_hdr(buffer, buf_len)) {
               //     LOG_INFO("%s: PEER UP Received, local addr=%s:%hu remote addr=%s:%hu", client->c_ip,up_event.local_ip, up_event.local_port, p_entry.peer_addr, up_event.remote_port);

                    buffer_bmp_message(buffer, buf_len);

                    // Prepare the BGP parser
                    //pBGP = new parseBGP(&p_entry, (char *)r_entry.ip_addr, &peer_info_map[peer_info_key]);
                    libParseBGP_parse_bgp_init(pBGP, &p_entry, (char *)r_entry.ip_addr, &peer_info_map[peer_info_key]);

        //            if (cfg->debug_bgp)
        //               pBGP->enableDebug();

// Parse the BGP sent/received open messages
                    libParseBGP_parse_bgp_handle_up_event(pBGP, bmp_data, bmp_data_len, &up_event,&bgp_msg);
                    //pBGP->handleUpEvent(bmp_data, bmp_data_len, &up_event,&bgp_msg);

                    // Free the bgp parser
                    //delete pBGP;

                    // Add the up event to the DB
                    //mbus_ptr->update_Peer(p_entry, &up_event, NULL, mbus_ptr->PEER_ACTION_UP);

                } //else {
                 //   LOG_NOTICE("%s: PEER UP Received but failed to parse the BMP header.", client->c_ip);
               // }
                break;
            }

            case parseBMP::TYPE_ROUTE_MON : { // Route monitoring type
                //bufferBMPMessage(read_fd);
                buffer_bmp_message(buffer, buf_len);

                /*
                 * Read and parse the the BGP message from the client.
                 *     parseBGP will update mysql directly
                 */
                //pBGP = new parseBGP(&p_entry, (char *)r_entry.ip_addr,
                //                    &peer_info_map[peer_info_key]);
                libParseBGP_parse_bgp_init(pBGP, &p_entry, (char *)r_entry.ip_addr, &peer_info_map[peer_info_key]);

               // if (cfg->debug_bgp)
               //     pBGP->enableDebug();

                //pBGP->handleUpdate(bmp_data, bmp_data_len, &bgp_msg);
                libParseBGP_parse_bgp_handle_update(pBGP, bmp_data, bmp_data_len, &bgp_msg);
                //delete pBGP;

                break;
            }

            case parseBMP::TYPE_STATS_REPORT : { // Stats Report
       //         MsgBusInterface::obj_stats_report stats = {};
                //if (! pBMP->handleStatsReport(read_fd))
                //handleStatsReport(read_fd);
                handle_stats_report(buffer, buf_len);
                    // Add to mysql
                    //mbus_ptr->add_StatReport(p_entry, stats);

                break;
            }

            case parseBMP::TYPE_INIT_MSG : { // Initiation Message
               // LOG_INFO("%s: Init message received with length of %u", client->c_ip, pBMP->getBMPLength());
                //handleInitMsg(read_fd);
                handle_init_msg(buffer, buf_len);

// Update the router entry with the details
                //mbus_ptr->update_Router(r_object, mbus_ptr->ROUTER_ACTION_INIT);
                break;
            }

            case parseBMP::TYPE_TERM_MSG : { // Termination Message
               // LOG_INFO("%s: Term message received with length of %u", client->c_ip, pBMP->getBMPLength());

                //handleTermMsg(read_fd);
                handle_term_msg(buffer, buf_len);

               // LOG_INFO("Proceeding to disconnect router");
                //mbus_ptr->update_Router(r_object, mbus_ptr->ROUTER_ACTION_TERM);
         //       close(client->c_sock);

                //rval = false;                           // Indicate connection is closed
                break;
            }

        }

    } catch (char const *str) {
        // Mark the router as disconnected and update the error to be a local disconnect (no term message received)
      //  LOG_INFO("%s: Caught: %s", client->c_ip, str);
       // disconnect(client, mbus_ptr, parseBMP::TERM_REASON_OPENBMP_CONN_ERR, str);
        //cout<<str;
        delete pBGP;                    // Make sure to free the resource
        throw str;
    }

    // Send BMP RAW packet data
    //mbus_ptr->send_bmp_raw(router_hash_id, p_entry, pBMP->bmp_packet, pBMP->bmp_packet_len);

    // Free the bmp parser
    //delete pBMP;

    //return rval;
    return true;
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
//char parseBMP::handleMessage(int sock) {
char parseBMP::handle_message(unsigned char*& buffer, int& buf_len) {
    unsigned char ver;
    ssize_t bytes_read;

    // Get the version in order to determine what we read next
    //    As of Junos 10.4R6.5, it supports version 1
    //bytes_read = Recv(sock, &ver, 1, MSG_WAITALL);
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
        parse_bmp_v3(buffer, buf_len);
    }

    // Handle the older versions
    else if (ver == 1 || ver == 2) {
        //       SELF_DEBUG("Older BMP version of %d, consider upgrading the router to support BMPv3", ver);
        //parseBMPv2(sock);
        parse_bmp_v2(buffer, buf_len);

    } else
        throw "ERROR: Unsupported BMP message version";

    //   SELF_DEBUG("BMP version = %d\n", ver);

    return bmp_type;
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
void parseBMP::parse_bmp_v2(unsigned char*& buffer, int& buf_len) {
    struct common_hdr_old c_hdr = { 0 };
    ssize_t i = 0;
    char buf[256] = {0};

//    SELF_DEBUG("parseBMP: sock=%d: Reading %d bytes", sock, BMP_HDRv1v2_LEN);

    bmp_len = 0;

    /*if ((i = Recv(sock, &c_hdr, BMP_HDRv1v2_LEN, MSG_WAITALL))
            != BMP_HDRv1v2_LEN) {
        //     SELF_DEBUG("sock=%d: Couldn't read all bytes, read %zd bytes",sock, i);
        throw "ERROR: Cannot read v1/v2 BMP common header.";
    }*/
    if ((i = extract_from_buffer(buffer, buf_len, &c_hdr, BMP_HDRv1v2_LEN))
        != BMP_HDRv1v2_LEN) {
        //     SELF_DEBUG("sock=%d: Couldn't read all bytes, read %zd bytes",sock, i);
        throw "ERROR: Cannot read v1/v2 BMP common header.";
    }

    // Process the message based on type
    bmp_type = c_hdr.type;
    switch (c_hdr.type) {
        case 0: // Route monitoring
            //          SELF_DEBUG("sock=%d : BMP MSG : route monitor", sock);

            // Get the length of the remaining message by reading the BGP length
            //if ((i=Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
            if ((i=extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
                uint16_t len;
                memcpy(&len, (buf+16), 2);
                bgp::SWAP_BYTES(&len);
                bmp_len = len;

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
            //if ((i=Recv(sock, buf, 1, MSG_PEEK)) != 1) {
            if ((i=extract_from_buffer(buffer, buf_len, buf, 1)) != 1) {

                // Is there a BGP message
                if (buf[0] == 1 or buf[0] == 3) {
                    //if ((i = Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
                    if ((i = extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
                        memcpy(&bmp_len, buf + 16, 2);
                        bgp::SWAP_BYTES(&bmp_len);

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

    //   SELF_DEBUG("sock=%d : Peer Type is %d", sock, c_hdr.peer_type);

    if (c_hdr.peer_flags & 0x80) { // V flag of 1 means this is IPv6
        p_entry.is_ipv4 = false;
        inet_ntop(AF_INET6, c_hdr.peer_addr, peer_addr, sizeof(peer_addr));

        //      SELF_DEBUG("sock=%d : Peer address is IPv6", sock);

    } else {
        p_entry.is_ipv4 = true;
        snprintf(peer_addr, sizeof(peer_addr), "%d.%d.%d.%d",
                c_hdr.peer_addr[12], c_hdr.peer_addr[13], c_hdr.peer_addr[14],
                c_hdr.peer_addr[15]);

        //       SELF_DEBUG("sock=%d : Peer address is IPv4", sock);
    }

   /* if (c_hdr.peer_flags & 0x40) { // L flag of 1 means this is Loc-RIP and not Adj-RIB-In
        //       SELF_DEBUG("sock=%d : Msg is for Loc-RIB", sock);
    } else {
        //      SELF_DEBUG("sock=%d : Msg is for Adj-RIB-In", sock);
    }*/

    // convert the BMP byte messages to human readable strings
    snprintf(peer_as, sizeof(peer_as), "0x%04x%04x",
            c_hdr.peer_as[0] << 8 | c_hdr.peer_as[1],
            c_hdr.peer_as[2] << 8 | c_hdr.peer_as[3]);
    snprintf(peer_bgp_id, sizeof(peer_bgp_id), "%d.%d.%d.%d",
            c_hdr.peer_bgp_id[0], c_hdr.peer_bgp_id[1], c_hdr.peer_bgp_id[2],
            c_hdr.peer_bgp_id[3]);

    // Format based on the type of RD
    switch (c_hdr.peer_dist_id[0] << 8 | c_hdr.peer_dist_id[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d.%d.%d.%d:%d",
                    c_hdr.peer_dist_id[2], c_hdr.peer_dist_id[3],
                    c_hdr.peer_dist_id[4], c_hdr.peer_dist_id[5],
                    c_hdr.peer_dist_id[6] << 8 | c_hdr.peer_dist_id[7]);
            break;
        case 2: // admin = 4bytes (ASN), assing number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%lu:%d",
                    (unsigned long) (c_hdr.peer_dist_id[2] << 24
                            | c_hdr.peer_dist_id[3] << 16
                            | c_hdr.peer_dist_id[4] << 8 | c_hdr.peer_dist_id[5]),
                    c_hdr.peer_dist_id[6] << 8 | c_hdr.peer_dist_id[7]);
            break;
        default: // admin = 2 bytes, sub field = 4 bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d:%lu",
                    c_hdr.peer_dist_id[1] << 8 | c_hdr.peer_dist_id[2],
                    (unsigned long) (c_hdr.peer_dist_id[3] << 24
                            | c_hdr.peer_dist_id[4] << 16
                            | c_hdr.peer_dist_id[5] << 8 | c_hdr.peer_dist_id[6]
                            | c_hdr.peer_dist_id[7]));
            break;
    }

    // Update the MySQL peer entry struct
    strncpy(p_entry.peer_addr, peer_addr, sizeof(peer_addr));
    p_entry.peer_as = strtoll(peer_as, NULL, 16);
    strncpy(p_entry.peer_bgp_id, peer_bgp_id, sizeof(peer_bgp_id));
    strncpy(p_entry.peer_rd, peer_rd, sizeof(peer_rd));

    // Save the advertised timestamp
    uint32_t ts = c_hdr.ts_secs;
    bgp::SWAP_BYTES(&ts);
   

    if (ts != 0)
        p_entry.timestamp_secs = ts;
    else
        p_entry.timestamp_secs = time(NULL);

    // Is peer type L3VPN peer or global instance
    if (c_hdr.type == 1) // L3VPN
        p_entry.is_l3vpn = 1;
    else
        // Global Instance
        p_entry.is_l3vpn = 0;

    //   SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
//    SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock, c_hdr.peer_as[0], c_hdr.peer_as[1], c_hdr.peer_as[2], c_hdr.peer_as[3]);
    //   SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
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
void parseBMP::parse_bmp_v3(unsigned char*& buffer, int& buf_len) {
    struct common_hdr_v3 c_hdr = { 0 };
    //   SELF_DEBUG("Parsing BMP version 3 (rfc7854)");
    /*if ((Recv(sock, &c_hdr, BMP_HDRv3_LEN, MSG_WAITALL)) != BMP_HDRv3_LEN) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }*/
    if ((extract_from_buffer(buffer, buf_len, &c_hdr, BMP_HDRv3_LEN)) != BMP_HDRv3_LEN) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }

    //memcpy(&c_hdr, buffer, BMP_HDRv3_LEN);
    // Change to host order
    bgp::SWAP_BYTES(&c_hdr.len);

    //   SELF_DEBUG("BMP v3: type = %x len=%d", c_hdr.type, c_hdr.len);

    // Adjust length to remove common header size
    c_hdr.len -= 1 + BMP_HDRv3_LEN;

    if (c_hdr.len > BGP_MAX_MSG_SIZE)
        throw "ERROR: BMP length is larger than max possible BGP size";

    // Parse additional headers based on type
    bmp_type = c_hdr.type;
    bmp_len = c_hdr.len;

    switch (c_hdr.type) {
        case TYPE_ROUTE_MON: // Route monitoring
            //          SELF_DEBUG("BMP MSG : route monitor");
            //parsePeerHdr(sock);
            parse_peer_hdr(buffer, buf_len);
            break;

        case TYPE_STATS_REPORT: // Statistics Report
            //          SELF_DEBUG("BMP MSG : stats report");
            //parsePeerHdr(sock);
            parse_peer_hdr(buffer, buf_len);
            break;

        case TYPE_PEER_UP: // Peer Up notification
        {
            //           SELF_DEBUG("BMP MSG : peer up");
            //parsePeerHdr(sock);
            parse_peer_hdr(buffer, buf_len);
            break;
        }
        case TYPE_PEER_DOWN: // Peer down notification
            //           SELF_DEBUG("BMP MSG : peer down");
            //parsePeerHdr(sock);
            parse_peer_hdr(buffer, buf_len);
            break;

        case TYPE_INIT_MSG:
        case TYPE_TERM_MSG:
            // Allowed
            break;

        default:
            //         LOG_ERR("ERROR: Unknown BMP message type of %d", c_hdr.type);
            throw "ERROR: BMP message type is not supported";
            break;
    }
}

/**
 * Parse the v3 peer header
 *
 * \param [in]  sock        Socket to read the message from
 */
//void parseBMP::parsePeerHdr(int sock) {
void parseBMP::parse_peer_hdr(unsigned char*& buffer, int& buf_len) {
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
    bmp_len -= BMP_PEER_HDR_LEN;

    //   SELF_DEBUG("parsePeerHdr: sock=%d : Peer Type is %d", sock,p_hdr.peer_type);

    if (p_hdr.peer_flags & 0x80) { // V flag of 1 means this is IPv6
        p_entry.is_ipv4 = false;

        inet_ntop(AF_INET6, p_hdr.peer_addr, peer_addr, sizeof(peer_addr));

        //       SELF_DEBUG("sock=%d : Peer address is IPv6 %s", sock,peer_addr);

    } else {
        p_entry.is_ipv4 = true;

        snprintf(peer_addr, sizeof(peer_addr), "%d.%d.%d.%d",
                 p_hdr.peer_addr[12], p_hdr.peer_addr[13], p_hdr.peer_addr[14],
                 p_hdr.peer_addr[15]);
        //       SELF_DEBUG("sock=%d : Peer address is IPv4 %s", sock,peer_addr);
    }

    if (p_hdr.peer_flags & 0x10) { // O flag of 1 means this is Adj-Rib-Out
//        SELF_DEBUG("sock=%d : Msg is for Adj-RIB-Out", sock);
        p_entry.is_pre_policy = false;
        p_entry.is_adj_in = false;
    } else if (p_hdr.peer_flags & 0x40) { // L flag of 1 means this is post-policy of Adj-RIB-In
//        SELF_DEBUG("sock=%d : Msg is for POST-POLICY Adj-RIB-In", sock);
        p_entry.is_pre_policy = false;
        p_entry.is_adj_in = true;
    } else {
        //       SELF_DEBUG("sock=%d : Msg is for PRE-POLICY Adj-RIB-In", sock);
        p_entry.is_pre_policy = true;
        p_entry.is_adj_in = true;
    }

    // convert the BMP byte messages to human readable strings
    snprintf(peer_as, sizeof(peer_as), "0x%04x%04x",
             p_hdr.peer_as[0] << 8 | p_hdr.peer_as[1],
             p_hdr.peer_as[2] << 8 | p_hdr.peer_as[3]);

    inet_ntop(AF_INET, p_hdr.peer_bgp_id, peer_bgp_id, sizeof(peer_bgp_id));
//    SELF_DEBUG("sock=%d : Peer BGP-ID %x.%x.%x.%x (%s)", sock, p_hdr.peer_bgp_id[0],p_hdr.peer_bgp_id[1],p_hdr.peer_bgp_id[2],p_hdr.peer_bgp_id[3], peer_bgp_id);

    // Format based on the type of RD
//    SELF_DEBUG("sock=%d : Peer RD type = %d %d", sock, p_hdr.peer_dist_id[0], p_hdr.peer_dist_id[1]);
    switch (p_hdr.peer_dist_id[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d.%d.%d.%d:%d",
                     p_hdr.peer_dist_id[2], p_hdr.peer_dist_id[3],
                     p_hdr.peer_dist_id[4], p_hdr.peer_dist_id[5],
                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
            break;

        case 2: // admin = 4bytes (ASN), sub field 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%lu:%d",
                     (unsigned long) (p_hdr.peer_dist_id[2] << 24
                                      | p_hdr.peer_dist_id[3] << 16
                                      | p_hdr.peer_dist_id[4] << 8 | p_hdr.peer_dist_id[5]),
                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
            break;
        default: // Type 0:  // admin = 2 bytes, sub field = 4 bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d:%lu",
                     p_hdr.peer_dist_id[2] << 8 | p_hdr.peer_dist_id[3],
                     (unsigned long) (p_hdr.peer_dist_id[4] << 24
                                      | p_hdr.peer_dist_id[5] << 16
                                      | p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]));
            break;
    }

    // Update the peer entry struct in parse bmp
    strncpy(p_entry.peer_addr, peer_addr, sizeof(p_entry.peer_addr));
    p_entry.peer_as = strtoll(peer_as, NULL, 16);
    strncpy(p_entry.peer_bgp_id, peer_bgp_id, sizeof(p_entry.peer_bgp_id));
    strncpy(p_entry.peer_rd, peer_rd, sizeof(p_entry.peer_rd));


    // Save the advertised timestamp
    bgp::SWAP_BYTES(&p_hdr.ts_secs);
    bgp::SWAP_BYTES(&p_hdr.ts_usecs);

    if (p_hdr.ts_secs != 0) {
        p_entry.timestamp_secs = p_hdr.ts_secs;
        p_entry.timestamp_us = p_hdr.ts_usecs;

    } else {
        timeval tv;

        gettimeofday(&tv, NULL);
        p_entry.timestamp_secs = tv.tv_sec;
        p_entry.timestamp_us = tv.tv_usec;
    }


    // Is peer type L3VPN peer or global instance
    if (p_hdr.peer_type == 1) // L3VPN
        p_entry.is_l3vpn = 1;

    else
        // Global Instance
        p_entry.is_l3vpn = 0;

//    SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
    //   SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock,
    //               p_hdr.peer_as[0], p_hdr.peer_as[1], p_hdr.peer_as[2],
    //               p_hdr.peer_as[3]);
//    SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
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
//bool parseBMP::parsePeerDownEventHdr(int sock) {
bool parseBMP::parse_peer_down_event_hdr(unsigned char*& buffer, int& buf_len) {

    char reason;
    //if (Recv(sock, &reason, 1, 0) == 1) {
    if (extract_from_buffer(buffer, buf_len, &reason, 1) == 1) {
      //  LOG_NOTICE("sock=%d : %s: BGP peer down notification with reason code: %d", sock, p_entry->peer_addr, reason);

        // Indicate that data has been read
        bmp_len--;

        // Initialize the down_event struct
        down_event.bmp_reason = reason;

    } else {
        return false;
    }

    return true;
}

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
void parseBMP::buffer_bmp_message(unsigned char*& buffer, int& buf_len) {
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
 * Parse the v3 peer up BMP header
 *
 * \details This method will update the db peer_up_event struct with BMP header info.
 *
 * \param [in]  sock     Socket to read the message from
 * \param [out] up_event Reference to the peer up event storage (will be updated with bmp info)
 *
 * \returns true if successfully parsed the bmp peer up header, false otherwise
 */
//bool parseBMP::parsePeerUpEventHdr(int sock) {
bool parseBMP::parse_peer_up_event_hdr(unsigned char*& buffer, int& buf_len) {
    unsigned char local_addr[16];
    bool isParseGood = true;
    int bytes_read = 0;

    // Get the local address
    //if ( Recv(sock, &local_addr, 16, MSG_WAITALL) != 16)
    if ( extract_from_buffer(buffer, buf_len, &local_addr, 16) != 16)
        isParseGood = false;
    else
        bytes_read += 16;

    if (isParseGood and p_entry.is_ipv4) {
        snprintf(up_event.local_ip, sizeof(up_event.local_ip), "%d.%d.%d.%d",
                    local_addr[12], local_addr[13], local_addr[14],
                    local_addr[15]);
 //       SELF_DEBUG("%s : Peer UP local address is IPv4 %s", peer_addr, up_event.local_ip);

    } else if (isParseGood) {
        inet_ntop(AF_INET6, local_addr, up_event.local_ip, sizeof(up_event.local_ip));
 //       SELF_DEBUG("%s : Peer UP local address is IPv6 %s", peer_addr, up_event.local_ip);
    }

    // Get the local port
    //if (isParseGood and Recv(sock, &up_event.local_port, 2, MSG_WAITALL) != 2)
    if (isParseGood and extract_from_buffer(buffer, buf_len, &up_event.local_port, 2) != 2)
            isParseGood = false;

    else if (isParseGood) {
        bytes_read += 2;
        bgp::SWAP_BYTES(&up_event.local_port);
    }

    // Get the remote port
    //if (isParseGood and Recv(sock, &up_event.remote_port, 2, MSG_WAITALL) != 2)
    if (isParseGood and extract_from_buffer(buffer, buf_len, &up_event.remote_port, 2) != 2)
        isParseGood = false;

    else if (isParseGood) {
        bytes_read += 2;
        bgp::SWAP_BYTES(&up_event.remote_port);
    }

    // Update bytes read
    bmp_len -= bytes_read;

    // Validate parse is still good, if not read the remaining bytes of the message so that the next msg will work
    if (!isParseGood) {
 //       LOG_NOTICE("%s: PEER UP header failed to be parsed, read only %d bytes of the header",
  //              peer_addr, bytes_read);

        // Msg is invalid - Buffer and ignore
        //bufferBMPMessage(sock);
        buffer_bmp_message(buffer, buf_len);
    }

    return isParseGood;
}


/**
 * Parse and return back the stats report
 *
 * \param [in]  sock        Socket to read the stats message from
 * \param [out] stats       Reference to stats report data
 *
 * \return true if error, false if no error
 */
//bool parseBMP::handleStatsReport(int sock) {
bool parseBMP::handle_stats_report(unsigned char*& buffer, int& buf_len) {
    unsigned long stats_cnt = 0; // Number of counter stat objects to follow
    unsigned char b[8];

    //if ((Recv(sock, b, 4, MSG_WAITALL)) != 4)
    if ((extract_from_buffer(buffer, buf_len, b, 4)) != 4)
        throw "ERROR:  Cannot proceed since we cannot read the stats mon counter";

    bmp_len -= 4;

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

        bmp_len -= 4;

        // convert integer from network to host bytes
        bgp::SWAP_BYTES(&stat_type);
        bgp::SWAP_BYTES(&stat_len);

 //       SELF_DEBUG("sock=%d STATS: %lu : TYPE = %u LEN = %u", sock,
 //                   i, stat_type, stat_len);

        // check if this is a 32 bit number  (default)
        if (stat_len == 4 or stat_len == 8) {

            // Read the stats counter - 32/64 bits
            //if ((Recv(sock, b, stat_len, MSG_WAITALL)) == stat_len) {
            if ((extract_from_buffer(buffer, buf_len, b, stat_len)) == stat_len) {
                bmp_len -= stat_len;

                // convert the bytes from network to host order
                bgp::SWAP_BYTES(b, stat_len);

                // Update the table structure based on the stats counter type
                switch (stat_type) {
                    case STATS_PREFIX_REJ:
                        memcpy((void*) &stats.prefixes_rej, (void*) b, stat_len);
                        break;
                    case STATS_DUP_PREFIX:
                        memcpy((void*) &stats.known_dup_prefixes, (void*) b, stat_len);
                        break;
                    case STATS_DUP_WITHDRAW:
                        memcpy((void*) &stats.known_dup_withdraws, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_CLUSTER_LIST:
                        memcpy((void*) &stats.invalid_cluster_list, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_AS_PATH_LOOP:
                        memcpy((void*) &stats.invalid_as_path_loop, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_ORIGINATOR_ID:
                        memcpy((void*) &stats.invalid_originator_id, (void*) b, stat_len);
                        break;
                    case STATS_INVALID_AS_CONFED_LOOP:
                        memcpy((void*) &stats.invalid_as_confed_loop, (void*) b, stat_len);
                        break;
                    case STATS_NUM_ROUTES_ADJ_RIB_IN:
                        memcpy((void*) &stats.routes_adj_rib_in, (void*) b, stat_len);
                        break;
                    case STATS_NUM_ROUTES_LOC_RIB:
                        memcpy((void*) &stats.routes_loc_rib, (void*) b, stat_len);
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
                //Recv(sock, &b[0], 1, 0);
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
//void parseBMP::handleInitMsg(int sock) {
void parseBMP::handle_init_msg(unsigned char*& buffer, int& buf_len) {
    init_msg_v3 init_msg;
    char infoBuf[sizeof(r_entry.initiate_data)];
    int infoLen;

    // Buffer the init message for parsing
    //bufferBMPMessage(sock);
    buffer_bmp_message(buffer, buf_len);

    u_char *bufPtr = bmp_data;

    /*
     * Loop through the init message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_INIT_MSG_LEN) {
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
                infoLen = sizeof(r_entry.initiate_data) < (init_msg.len - 1) ? (sizeof(r_entry.initiate_data) - 1) : init_msg.len;
                memcpy(r_entry.initiate_data, init_msg.info, infoLen);
 //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.initiate_data);

                break;

            case INIT_TYPE_SYSNAME :
                infoLen = sizeof(r_entry.name) < (init_msg.len - 1) ? (sizeof(r_entry.name) - 1) : init_msg.len;
                strncpy((char *)r_entry.name, init_msg.info, infoLen);
 //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.name);
                break;

            case INIT_TYPE_SYSDESCR :
                infoLen = sizeof(r_entry.descr) < (init_msg.len - 1) ? (sizeof(r_entry.descr) - 1) : init_msg.len;
                strncpy((char *)r_entry.descr, init_msg.info, infoLen);
 //               LOG_INFO("Init message type %hu = %s", init_msg.type, r_entry.descr);
                break;

            case INIT_TYPE_ROUTER_BGP_ID:
                if (init_msg.len != sizeof(in_addr_t)) {
 //                   LOG_NOTICE("Init message type BGP ID not of IPv4 addr length");
                    break;
                }
                inet_ntop(AF_INET, init_msg.info, r_entry.bgp_id, sizeof(r_entry.bgp_id));
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
void parseBMP::handle_term_msg(unsigned char*& buffer, int& buf_len) {
    term_msg_v3 termMsg;
    char infoBuf[sizeof(r_entry.term_data)];
    int infoLen;

    // Buffer the init message for parsing
    //bufferBMPMessage(sock);
    buffer_bmp_message(buffer, buf_len);

    u_char *bufPtr = bmp_data;

    /*
     * Loop through the term message (in buffer) to parse each TLV
     */
    for (int i=0; i < bmp_data_len; i += BMP_TERM_MSG_LEN) {
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
                memcpy(r_entry.term_data, termMsg.info, termMsg.len);
                break;

            case TERM_TYPE_REASON :
            {
                // Get the term reason code from info data (first 2 bytes)
                uint16_t term_reason;
                memcpy(&term_reason, termMsg.info, 2);
                bgp::SWAP_BYTES(&term_reason);
                r_entry.term_reason_code = term_reason;

                switch (term_reason) {
                    case TERM_REASON_ADMIN_CLOSE :
 //                       LOG_INFO("%s BMP session closed by remote administratively", r_entry.ip_addr);
                        snprintf(r_entry.term_reason_text, sizeof(r_entry.term_reason_text),
                               "Remote session administratively closed");
                        break;

                    case TERM_REASON_OUT_OF_RESOURCES:
 //                       LOG_INFO("%s BMP session closed by remote due to out of resources", r_entry.ip_addr);
                        snprintf(r_entry.term_reason_text, sizeof(r_entry.term_reason_text),
                                "Remote out of resources");
                        break;

                    case TERM_REASON_REDUNDANT_CONN:
//                        LOG_INFO("%s BMP session closed by remote due to connection being redundant", r_entry.ip_addr);
                        snprintf(r_entry.term_reason_text, sizeof(r_entry.term_reason_text),
                                "Remote considers connection redundant");
                        break;

                    case TERM_REASON_UNSPECIFIED:
 ///                       LOG_INFO("%s BMP session closed by remote as unspecified", r_entry.ip_addr);
                        snprintf(r_entry.term_reason_text, sizeof(r_entry.term_reason_text),
                                "Remote closed with unspecified reason");
                        break;

                    default:
//                        LOG_INFO("%s closed with undefined reason code of %d", r_entry.ip_addr, term_reason);
                        snprintf(r_entry.term_reason_text, sizeof(r_entry.term_reason_text),
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
 * get current BMP message type
 */
char parseBMP::get_bmp_type() {
    return bmp_type;
}

/**
 * get current BMP message length
 *
 * The length returned does not include the version 3 common header length
 */
uint32_t parseBMP::get_bmp_length() {
    return bmp_len;
}

/**
 * Enable/Disable debug
 */
/*void parseBMP::enableDebug() {
    debug = true;
}
void parseBMP::disableDebug() {
    debug = false;
}*/

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