/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include "../include/open_msg.h"
#include "../include/bgp_common.h"
#include <arpa/inet.h>

//namespace bgp_msg {

/**
 * Constructor for class
 *
 * \details Handles bgp open messages
 *
 * \param [in]     peerAddr        Printed form of peer address used for logging
 * \param [in]     peer_info       Persistent peer information
 * \param [in]     enable_debug    Debug true to enable, false to disable
 */
void libparsebgp_open_msg_init(libparsebgp_open_msg_data *open_msg_data,std::string peer_addr, peer_info *peer_info) {
    open_msg_data->peer_inf = peer_info;
    open_msg_data->peer_addr = peer_addr;
}

    /**
 * Parses capabilities from buffer
 *
 * \details
 *      Reads the capabilities from buffer.  The parsed data will be
 *      returned via the out params.
 *
 * \param [in]   data               Pointer to raw bgp payload data, starting at the open/cap message
 * \param [in]   size               Size of the data available to read; prevent overrun when reading
 * \param [in]   openMessageIsSent  If open message is sent. False if received
 * \param [out]  asn                Reference to the ASN that was discovered
 * \param [out]  capabilities       Reference to the capabilities list<string> (decoded values)
 *
 * \return ZERO is error, otherwise a positive value indicating the number of bytes read
 */
static size_t libparsebgp_open_msg_parse_capabilities(libparsebgp_open_msg_data *open_msg_data,u_char *data, size_t size, bool openMessageIsSent) {
    size_t      read_size   = 0;
    u_char      *bufPtr     = data;

    /*
     * Loop through the capabilities (will set the 4 byte ASN)
     */
    char        capStr[200];
    //open_param_hdr  *param;
    //cap_param   *cap;

    for (int i=0; i < size; ) {
        //param = (open_param_hdr *)bufPtr;
        memcpy(&open_msg_data->opt_param, bufPtr, 2);  //reading type and length
//        SELF_DEBUG("%s: Open param type=%d len=%d", peer_addr.c_str(), param->type, param->len);
        if (open_msg_data->opt_param.param_type != BGP_CAP_PARAM_TYPE) {
//            LOG_NOTICE("%s: Open param type %d is not supported, expected type %d", peer_addr.c_str(),param->type, BGP_CAP_PARAM_TYPE);
        }

            /*
             * Process the capabilities if present
             */
        else if (open_msg_data->opt_param.param_len >= 2 and (read_size + 2 + open_msg_data->opt_param.param_len) <= size) {
            u_char *cap_ptr = bufPtr + 2;

            for (int c=0; c < open_msg_data->opt_param.param_len; ) {
                //cap = (cap_param *)cap_ptr;
                open_capabilities open_cap;
                memcpy(&open_cap, cap_ptr, 2);
//                SELF_DEBUG("%s: Capability code=%d len=%d", peer_addr.c_str(), cap->code, cap->len);

                /*
                 * Handle the capability
                 */
                switch (open_cap.cap_code) {
                    case BGP_CAP_4OCTET_ASN :
                        if (open_cap.cap_len == 4) {
                            //uint32_t asn;
                            memcpy(&open_cap.cap_values.asn, cap_ptr + 2, 4);
                            SWAP_BYTES(&open_cap.cap_values.asn);

                            //snprintf(capStr, sizeof(capStr), "4 Octet ASN (%d)", BGP_CAP_4OCTET_ASN);
                            //capabilities.push_back(capStr);
                            open_msg_data->opt_param.param_values.push_back(open_cap);
                        } else {
//                            LOG_NOTICE("%s: 4 octet ASN capability length is invalid %d expected 4", peer_addr.c_str(), cap->len);
                        }
                        break;

                    case BGP_CAP_ROUTE_REFRESH:
                        //                       SELF_DEBUG("%s: supports route-refresh", peer_addr.c_str());
                        //snprintf(capStr, sizeof(capStr), "Route Refresh (%d)", BGP_CAP_ROUTE_REFRESH);
                        //capabilities.push_back(capStr);
                        break;

                    case BGP_CAP_ROUTE_REFRESH_ENHANCED:
                        //                       SELF_DEBUG("%s: supports route-refresh enhanced", peer_addr.c_str());
                        //snprintf(capStr, sizeof(capStr), "Route Refresh Enhanced (%d)", BGP_CAP_ROUTE_REFRESH_ENHANCED);
                        //capabilities.push_back(capStr);
                        break;

                    case BGP_CAP_ROUTE_REFRESH_OLD:
                        //                       SELF_DEBUG("%s: supports OLD route-refresh", peer_addr.c_str());
                        //snprintf(capStr, sizeof(capStr), "Route Refresh Old (%d)", BGP_CAP_ROUTE_REFRESH_OLD);
                        //capabilities.push_back(capStr);
                        break;

                    case BGP_CAP_ADD_PATH: {
                        //cap_add_path_data data;

                        /*
                         * Move past the cap code and len, then iterate over all paths encoded
                         */
                        cap_ptr += 2;
                        if (open_cap.cap_len >= 4) {

                            for (int l = 0; l < open_cap.cap_len; l += 4) {
                                memcpy(&open_cap.cap_values.add_path_data, cap_ptr, 4);
                                cap_ptr += 4;

                                SWAP_BYTES(&open_cap.cap_values.add_path_data.afi);

                                /*snprintf(capStr, sizeof(capStr), "ADD Path (%d) : afi=%d safi=%d send/receive=%d",
                                         BGP_CAP_ADD_PATH, data.afi, data.safi, data.send_recieve);

                                //SELF_DEBUG("%s: supports Add Path afi = %d safi = %d send/receive = %d",peer_addr.c_str(), data.afi, data.safi, data.send_recieve);

                                std::string decodeStr(capStr);
                                decodeStr.append(" : ");

                                decodeStr.append(GET_SAFI_STRING_BY_CODE(data.safi));
                                decodeStr.append(" ");

                                decodeStr.append(GET_AFI_STRING_BY_CODE(data.afi));
                                decodeStr.append(" ");

                                switch (data.send_recieve) {
                                    case BGP_CAP_ADD_PATH_SEND :
                                        decodeStr.append("Send");
                                        break;

                                    case BGP_CAP_ADD_PATH_RECEIVE :
                                        decodeStr.append("Receive");
                                        break;

                                    case BGP_CAP_ADD_PATH_SEND_RECEIVE :
                                        decodeStr.append("Send/Receive");
                                        break;

                                    default:
                                        decodeStr.append("unknown");
                                        break;
                                }*/
                                //TODO: figure out if following is needed
                                libparsebgp_addpath_add(open_msg_data->peer_inf->add_path_capability, open_cap.cap_values.add_path_data.afi,
                                                        open_cap.cap_values.add_path_data.safi, open_cap.cap_values.add_path_data.send_recieve, openMessageIsSent);
                                //open_msg_data->peer_info->add_path_capability.addAddPath(data.afi, data.safi, data.send_recieve,
                                //                                                openMessageIsSent);
                                open_msg_data->opt_param.param_values.push_back(open_cap);
                                //capabilities.push_back(decodeStr);
                            }
                        }

                        break;
                    }

                    case BGP_CAP_GRACEFUL_RESTART:
                        //                     SELF_DEBUG("%s: supports graceful restart", peer_addr.c_str());
                        //snprintf(capStr, sizeof(capStr), "Graceful Restart (%d)", BGP_CAP_GRACEFUL_RESTART);
                        //capabilities.push_back(capStr);
                        break;

                    case BGP_CAP_OUTBOUND_FILTER:
                        //                    SELF_DEBUG("%s: supports outbound filter", peer_addr.c_str());
                        //snprintf(capStr, sizeof(capStr), "Outbound Filter (%d)", BGP_CAP_OUTBOUND_FILTER);
                        //capabilities.push_back(capStr);
                        break;

                    case BGP_CAP_MULTI_SESSION:
                        //                    SELF_DEBUG("%s: supports multi-session", peer_addr.c_str());
                        //snprintf(capStr, sizeof(capStr), "Multi-session (%d)", BGP_CAP_MULTI_SESSION);
                        //capabilities.push_back(capStr);
                        break;

                    case BGP_CAP_MPBGP:
                    {
                        //cap_mpbgp_data data;
                        if (open_cap.cap_len == sizeof(open_cap.cap_values.mpbgp_data)) {
                            memcpy(&data, (cap_ptr + 2), sizeof(data));
                            SWAP_BYTES(&open_cap.cap_values.mpbgp_data.afi);

                            //                        SELF_DEBUG("%s: supports MPBGP afi = %d safi=%d",peer_addr.c_str(), data.afi, data.safi);

                            /*snprintf(capStr, sizeof(capStr), "MPBGP (%d) : afi=%d safi=%d",
                                     BGP_CAP_MPBGP, data.afi, data.safi);

                            ///Building capability string

                            std::string decodedStr(capStr);
                            decodedStr.append(" : ");
                            decodedStr.append(GET_SAFI_STRING_BY_CODE(data.safi));
                            decodedStr.append(" ");
                            decodedStr.append(GET_AFI_STRING_BY_CODE(data.afi));*/
                            open_msg_data->opt_param.param_values.push_back(open_cap);
                            //capabilities.push_back(decodedStr);

                        }
                        else {
                            //                     LOG_NOTICE("%s: MPBGP capability but length %d is invalid expected %d.",peer_addr.c_str(), cap->len, sizeof(data));
                            return 0;
                        }

                        break;
                    }

                    default :
                        //snprintf(capStr, sizeof(capStr), "%d", cap->code);
                        //capabilities.push_back(capStr);

                        //                   SELF_DEBUG("%s: Ignoring capability %d, not implemented", peer_addr.c_str(), cap->code);
                        break;
                }

                // Move the pointer to the next capability
                c += 2 + open_cap.cap_len;
                cap_ptr += 2 + open_cap.cap_len;
            }
        }

        // Move index to next param
        i += 2 + open_msg_data->opt_param.param_len;
        bufPtr += 2 + open_msg_data->opt_param.param_len;
        read_size += 2 + open_msg_data->opt_param.param_len;
    }

    return read_size;
}
/**
 * Parses an open message
 *
 * \details
 *      Reads the open message from buffer.  The parsed data will be
 *      returned via the out params.
 *
 * \param [in]   data               Pointer to raw bgp payload data, starting at the notification message
 * \param [in]   size               Size of the data available to read; prevent overrun when reading
 * \param [in]   openMessageIsSent  If open message is sent. False if received
 * \param [out]  asn                Reference to the ASN that was discovered
 * \param [out]  holdTime           Reference to the hold time
 * \param [out]  bgp_id             Reference to string for bgp ID in printed form
 * \param [out]  capabilities       Reference to the capabilities list<string> (decoded values)
 *
 * \return ZERO is error, otherwise a positive value indicating the number of bytes read for the open message
 */
size_t libparsebgp_open_msg_parse_open_msg(libparsebgp_open_msg_data *open_msg_data,u_char *data, size_t size, bool openMessageIsSent) {
    char        bgp_id_char[16];
    size_t      read_size       = 0;
    u_char      *bufPtr         = data;
//    open_bgp_hdr open_hdr       = {0};
    //capabilities.clear();

    /*
     * Make sure available size is large enough for an open message
     */
    if (size < 10) {
    //    LOG_WARN("%s: Cloud not read open message due to buffer having less bytes than open message size", peer_addr.c_str());
        return 0;
    }

    memcpy(&open_msg_data, bufPtr,10); //reading the first few parameters
    read_size = 10;
    bufPtr += read_size;                                       // Move pointer past the open header

    // Change to host order
    SWAP_BYTES(&open_msg_data->hold_time);
    SWAP_BYTES(&open_msg_data->asn);
    SWAP_BYTES(&open_msg_data->ver);
    SWAP_BYTES(&open_msg_data->bgp_id);
    SWAP_BYTES(&open_msg_data->opt_param_len);

//    // Update the output params
//    open_msg_data->hold_time = open_hdr.hold;
//    open_msg_data->asn = open_hdr.asn;
//    open_msg_data->bgp_id = open_hdr.bgp_id;

    //inet_ntop(AF_INET, &open_msg_data->bgp_id, bgp_id_char, sizeof(bgp_id_char));
    //bgp_id.assign(bgp_id_char);

//    SELF_DEBUG("%s: Open message:ver=%d hold=%u asn=%hu bgp_id=%s params_len=%d", peer_addr.c_str(),open_hdr.ver, open_hdr.hold, open_hdr.asn, bgp_id.c_str(), open_hdr.param_len);

    /*
     * Make sure the buffer contains the rest of the open message, but allow a zero length in case the
     *  data is missing on purpose (router implementation)
     */
    if (open_msg_data->opt_param_len == 0) {
 //       LOG_WARN("%s: Capabilities in open message is ZERO/empty, this is abnormal and likely a router implementation issue.", peer_addr.c_str());
        return read_size;
    }

    else if (open_msg_data->opt_param_len > (size - read_size)) {
 //       LOG_WARN("%s: Capabilities in open message are truncated, attempting parse what's there; param_len %d > bgp msg bytes remaining of %d",
 //                peer_addr.c_str(), open_hdr.param_len, (size - read_size));

        // Parse as many capabilities as possible
        libparsebgp_open_msg_parse_capabilities(open_msg_data,bufPtr, (size - read_size), openMessageIsSent);

        read_size += (size - read_size);

    } else {

        if (!libparsebgp_open_msg_parse_capabilities(open_msg_data,bufPtr, open_msg_data->opt_param_len, openMessageIsSent)) {
  //          LOG_WARN("%s: Could not read capabilities correctly in buffer, message is invalid.", peer_addr.c_str());
            return 0;
        }

        read_size += open_msg_data->opt_param_len;
    }


    return read_size;
}
//} /* namespace bgp_msg */
