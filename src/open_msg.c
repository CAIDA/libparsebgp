/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include "../include/open_msg.h"
#include "../include/parse_utils.h"

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
 *
 * \return negative values for error, otherwise a positive value indicating the number of bytes read
 */
static ssize_t libparsebgp_open_msg_parse_capabilities(libparsebgp_open_msg_data *open_msg_data,u_char **data, size_t size, bool openMessageIsSent) {
    int      read_size   = 0;
    uint8_t count_param = 0, count_cap = 0;
    u_char   **bufPtr     = data;
    open_param      *opt_param = (open_param *)malloc(sizeof(open_param));
    open_msg_data->opt_param = (open_param *)malloc(sizeof(open_param));

    for (int i=0; i < size; ) {
        count_cap = 0;
        if(count_param)
            open_msg_data->opt_param = (open_param *)realloc(open_msg_data->opt_param, (count_param+1)*sizeof(open_param));
        memset(opt_param, 0, sizeof(opt_param));

        memcpy(&opt_param->param_type, *bufPtr, 1);  //reading type
        memcpy(&opt_param->param_len, *bufPtr+1, 1);   //reading length

        if (opt_param->param_type != BGP_CAP_PARAM_TYPE) {
            return INVALID_MSG;
            //LOG_NOTICE("%s: Open param type %d is not supported, expected type %d", peer_addr.c_str(),param->type, BGP_CAP_PARAM_TYPE);
        }

        /*
         * Process the capabilities if present
         */
        else if (opt_param->param_len >= 2 && (read_size + 2 + opt_param->param_len) <= size) {
            u_char *cap_ptr = *bufPtr + 2;
            open_capabilities *open_cap = (open_capabilities *)malloc(sizeof(open_capabilities));
            opt_param->param_values = (open_capabilities *)malloc(sizeof(open_capabilities));
            for (int c=0; c < opt_param->param_len; ) {
                if(count_cap)
                    opt_param->param_values = (open_capabilities *)realloc(opt_param->param_values, (count_cap+1)*sizeof(open_capabilities));

                memset(open_cap, 0, sizeof(open_cap));
                memcpy(&open_cap->cap_code, cap_ptr, 1); //reading capability code
                memcpy(&open_cap->cap_len, cap_ptr+1, 1); //reading capability length

                /*
                 * Handle the capability
                 */
                switch (open_cap->cap_code) {
                    case BGP_CAP_4OCTET_ASN :
                        if (open_cap->cap_len == 4) {
                            memcpy(&open_cap->cap_values.asn, cap_ptr + 2, 4);
                            SWAP_BYTES(&open_cap->cap_values.asn, 4);

                            //snprintf(capStr, sizeof(capStr), "4 Octet ASN (%d)", BGP_CAP_4OCTET_ASN);
                            //capabilities.push_back(capStr);
                            opt_param->param_values[count_cap++]=*open_cap;
                        } else {
                            return INVALID_MSG;
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
                        if (open_cap->cap_len >= 4) {

                            for (int l = 0; l < open_cap->cap_len; l += 4) {
                                memcpy(&open_cap->cap_values.add_path_data, cap_ptr, 4);
                                cap_ptr += 4;

                                SWAP_BYTES(&open_cap->cap_values.add_path_data.afi, 4);

                                /*snprintf(capStr, sizeof(capStr), "ADD Path (%d) : afi=%d safi=%d send/receive=%d",
                                         BGP_CAP_ADD_PATH, data.afi, data.safi, data.send_recieve);

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
//                                libparsebgp_addpath_add(open_msg_data->add_path_capability, open_cap.cap_values.add_path_data.afi,
//                                                        open_cap.cap_values.add_path_data.safi, open_cap.cap_values.add_path_data.send_recieve, openMessageIsSent);
                                opt_param->param_values[count_cap++]=*open_cap;
                                //capabilities.push_back(decodeStr);
                            }
                        }

                        break;
                    }

                    case BGP_CAP_GRACEFUL_RESTART:
                        break;

                    case BGP_CAP_OUTBOUND_FILTER:
                        break;

                    case BGP_CAP_MULTI_SESSION:
                        break;

                    case BGP_CAP_MPBGP:
                    {
                        //cap_mpbgp_data data;
                        if (open_cap->cap_len == sizeof(open_cap->cap_values.mpbgp_data)) {
                            memcpy(&open_cap->cap_values.mpbgp_data, (cap_ptr + 2), sizeof(open_cap->cap_values.mpbgp_data));
                            SWAP_BYTES(&open_cap->cap_values.mpbgp_data.afi, sizeof(open_cap->cap_values.mpbgp_data));
                            opt_param->param_values[count_cap++]=*open_cap;
                        }
                        else {
                            //LOG_NOTICE("%s: MPBGP capability but length %d is invalid expected %d.",peer_addr.c_str(), cap->len, sizeof(data));
                            return INVALID_MSG;
                        }
                        break;
                    }

                    default :
                        //snprintf(capStr, sizeof(capStr), "%d", cap->code);
                        //capabilities.push_back(capStr);

                        //                   SELF_DEBUG("%s: Ignoring capability %d, not implemented", peer_addr.c_str(), cap->code);
                        break;
                    }
//                // Move the pointer to the next capability
                    c += 2 + open_cap->cap_len;
                    cap_ptr += 2 + open_cap->cap_len;
            }
            opt_param->count_param_val = count_cap;
        }

        // Move index to next param
        i += 2 + opt_param->param_len;
        *bufPtr += 2 + opt_param->param_len;
        read_size += 2 + opt_param->param_len;
        open_msg_data->opt_param[count_param++] = *opt_param;
    }
    open_msg_data->count_opt_param = count_param;
    free(opt_param);
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
 *
 * \return ZERO is error, otherwise a positive value indicating the number of bytes read for the open message
 */
ssize_t libparsebgp_open_msg_parse_open_msg(libparsebgp_open_msg_data *open_msg_data, u_char *data, size_t size, bool openMessageIsSent) {
    int      read_size       = 0;
    u_char   *bufPtr         = data;
    int      buf_size = size;

    /*
     * Make sure available size is large enough for an open message
     */
    if (size < 10) {
    //    LOG_WARN("%s: Cloud not read open message due to buffer having less bytes than open message size", peer_addr.c_str());
        return INCOMPLETE_MSG;
    }

    if ( extract_from_buffer(&bufPtr, &buf_size, &open_msg_data->ver, 1) != 1)
        return ERR_READING_MSG;
    if ( extract_from_buffer(&bufPtr, &buf_size, &open_msg_data->asn, 2) != 2)
        return ERR_READING_MSG;
    if ( extract_from_buffer(&bufPtr, &buf_size, &open_msg_data->hold_time, 2) != 2)
        return ERR_READING_MSG;
    if ( extract_from_buffer(&bufPtr, &buf_size, &open_msg_data->bgp_id, 4) != 4)
        return ERR_READING_MSG;
    if ( extract_from_buffer(&bufPtr, &buf_size, &open_msg_data->opt_param_len, 1) != 1)
        return ERR_READING_MSG;
//    memcpy(&open_msg_data, bufPtr,10); //reading the first few parameters
      read_size = 10;
//    bufPtr += read_size;                                       // Move pointer past the open header

    // Change to host order
    SWAP_BYTES(&open_msg_data->hold_time, 2);
    SWAP_BYTES(&open_msg_data->asn, 2);

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
        libparsebgp_open_msg_parse_capabilities(open_msg_data,&bufPtr, (size - read_size), openMessageIsSent);

        read_size += (size - read_size);

    } else {

        if (!libparsebgp_open_msg_parse_capabilities(open_msg_data,&bufPtr, open_msg_data->opt_param_len, openMessageIsSent)) {
  //          LOG_WARN("%s: Could not read capabilities correctly in buffer, message is invalid.", peer_addr.c_str());
            return INVALID_MSG;
        }
        read_size += open_msg_data->opt_param_len;
    }
    return read_size;
}

//static void libparsebgp_parse_open_msg_opt_param_destructor(open_param &param) {
//    for (int i = 0; i < param.param_len; ++i) {
//        free(&param.param_values[i]);
//    }
//    free(&param);
//}

void libparsebgp_parse_open_msg_destructor(libparsebgp_open_msg_data *open_msg_data) {
    for (int i = 0; i < open_msg_data->count_opt_param; i++) {
        free(open_msg_data->opt_param[i].param_values);
    }
    free(open_msg_data->opt_param);
}