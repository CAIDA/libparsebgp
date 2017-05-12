/*
 * Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include <arpa/inet.h>
#include "../include/mp_link_state.h"

//namespace bgp_msg {
/**
 * Constructor for class
 *
 * \details Handles bgp Extended Communities
 *
 * \param [in]     logPtr       Pointer to existing Logger for app logging
 * \param [in]     peerAddr     Printed form of peer address used for logging
 * \param [out]    parsed_data  Reference to parsed_update_data; will be updated with all parsed data
 * \param [in]     enable_debug Debug true to enable, false to disable
 */

/**********************************************************************************//*
 * Parse a Local or Remote Descriptor sub-tlv's
 *
 * \details will parse a local/remote descriptor
 *
 * \param [in]   data           Pointer to the start of the node NLRI data
 * \param [in]   data_len       Length of the data
 * \param [out]  info           Node descriptor information returned/updated
 *
 * \returns number of bytes read
 */
int libparsebgp_mp_link_state_parse_descr_local_remote_node(u_char *data, int data_len, node_descriptor &info) {
    int             data_read = 0;

    if (data_len < 4) {
        //      LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor; too short",peer_addr.c_str());
        return data_len;
    }

    memcpy(&info.type, data, 2);
    SWAP_BYTES(&info.type);

    memcpy(&info.len, data+2, 2);
    SWAP_BYTES(&info.len);

    //SELF_DEBUG("%s: bgp-ls: Parsing node descriptor type %d len %d", peer_addr.c_str(), type, len);

    if (info.len > data_len - 4) {
        //      LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return data_len;
    }

    data += 4; data_read += 4;

    switch (info.type) {
        case NODE_DESCR_AS:
        {
            if (info.len != 4) {
                //           LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor AS sub-tlv; too short",peer_addr.c_str());
                data_read += info.len;
                break;
            }

            memcpy(&info.asn, data, 4);
            SWAP_BYTES(&info.asn);
            data_read += 4;

            //       SELF_DEBUG("%s: bgp-ls: Node descriptor AS = %u", peer_addr.c_str(), info.asn);

            break;
        }

        case NODE_DESCR_BGP_LS_ID:
        {
            if (info.len != 4) {
                //     LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor BGP-LS ID sub-tlv; too short",peer_addr.c_str());
                data_read += info.len;
                break;
            }


                memcpy(&info.bgp_ls_id, data, 4);
                SWAP_BYTES(&info.bgp_ls_id);
                data_read += 4;

            //     SELF_DEBUG("%s: bgp-ls: Node descriptor BGP-LS ID = %08X", peer_addr.c_str(), info.bgp_ls_id);
            break;
        }

        case NODE_DESCR_OSPF_AREA_ID:
        {
            if (info.len != 4) {
                //          LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor OSPF Area ID sub-tlv; too short",peer_addr.c_str());
                data_read += info.len <= data_len ? info.len : data_len;
                break;
            }


            char    ipv4_char[16];
            memcpy(info.ospf_area_Id, data, 4);
            inet_ntop(AF_INET, info.ospf_area_Id, ipv4_char, sizeof(ipv4_char));
            data_read += 4;

            //          SELF_DEBUG("%s: bgp-ls: Node descriptor OSPF Area ID = %s", peer_addr.c_str(), ipv4_char);
            break;
        }

        case NODE_DESCR_IGP_ROUTER_ID:
        {
            if (info.len > data_len or info.len > 8) {
                //               LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor IGP Router ID sub-tlv; len (%d) is invalid",peer_addr.c_str(), len);
                data_read += info.len;
                break;
            }

            bzero(info.igp_router_id, sizeof(info.igp_router_id));
            memcpy(info.igp_router_id, data, info.len);
            data_read += info.len;

            //          SELF_DEBUG("%s: bgp-ls: Node descriptor IGP Router ID %d = %d.%d.%d.%d (%02x%02x.%02x%02x.%02x%02x.%02x %02x)", peer_addr.c_str(), data_read,
//                            info.igp_router_id[0], info.igp_router_id[1], info.igp_router_id[2], info.igp_router_id[3],
//                        info.igp_router_id[0], info.igp_router_id[1], info.igp_router_id[2], info.igp_router_id[3],
//                        info.igp_router_id[4], info.igp_router_id[5], info.igp_router_id[6], info.igp_router_id[7]);
            break;
        }

        case NODE_DESCR_BGP_ROUTER_ID:
        {
            if (info.len != 4) {
                //           LOG_NOTICE("%s: bgp-ls: failed to parse node descriptor BGP Router ID sub-tlv; too short",peer_addr.c_str());
                data_read += info.len <= data_len ? info.len : data_len;
                break;
            }


            char    ipv4_char[16];
            memcpy(&info.bgp_router_id, data, 4);
            inet_ntop(AF_INET, &info.bgp_router_id, ipv4_char, sizeof(ipv4_char));
            data_read += 4;

            //       SELF_DEBUG("%s: bgp-ls: Node descriptor BGP Router-ID = %s", peer_addr.c_str(), ipv4_char);
            break;
        }

        default:
            //       LOG_NOTICE("%s: bgp-ls: node descriptor sub-tlv %d not yet implemented, skipping.",peer_addr.c_str(), type);
            data_read += info.len;
            break;
    }

    return data_read;
}
/**********************************************************************************//*
 * Decode Protocol ID
 *
 * \details will decode and return string representation of protocol (matches DB enum)
 *
 * \param [in]   proto_id       NLRI protocol type id
 *
 * \return string representation for the protocol that matches the DB enum string value
 *          empty will be returned if invalid/unknown.
 */
static std::string libparsebgp_mp_link_state_decode_nlri_protocol_id(uint8_t proto_id) {
    std::string value = "";

    switch (proto_id) {
        case NLRI_PROTO_DIRECT:
            value = "Direct";
            break;

        case NLRI_PROTO_STATIC:
            value = "Static";
            break;

        case NLRI_PROTO_ISIS_L1:
            value = "IS-IS_L1";
            break;

        case NLRI_PROTO_ISIS_L2:
            value = "IS-IS_L2";
            break;

        case NLRI_PROTO_OSPFV2:
            value = "OSPFv2";
            break;

        case NLRI_PROTO_OSPFV3:
            value = "OSPFv3";
            break;

        case NLRI_PROTO_EPE:
            value = "EPE";
            break;

        default:
            break;
    }
    return value;
}

/**********************************************************************************//*
 * Parse NODE NLRI
 *
 * \details will parse the node NLRI type. Data starts at local node descriptor.
 *
 * \param [in]   data           Pointer to the start of the node NLRI data
 * \param [in]   data_len       Length of the data
 * \param [in]   id             NLRI/type identifier
 * \param [in]   proto_id       NLRI protocol type id
 */
static void libparsebgp_parse_nlri_node(mp_reach_ls *mp_reach_ls, u_char *data, int data_len) {

    if (data_len < 4) {
        //LOG_WARN("%s: bgp-ls: Unable to parse node NLRI since it's too short (invalid)", peer_addr.c_str());
        return;
    }

    /*
     * Parse the local node descriptor sub-tlv
     */
    node_descriptor info;
    bzero(&info, sizeof(info));

    memcpy(&mp_reach_ls->nlri_ls.node_nlri.type, data, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.node_nlri.type);
    memcpy(&mp_reach_ls->nlri_ls.node_nlri.len, data + 2, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.node_nlri.len);
    data_len -= 4;
    data += 4;

    if (mp_reach_ls->nlri_ls.node_nlri.len > data_len) {
        //LOG_WARN("%s: bgp-ls: failed to parse node descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return;
    }

    if (mp_reach_ls->nlri_ls.node_nlri.type != NODE_DESCR_LOCAL_DESCR) {
        //LOG_WARN("%s: bgp-ls: failed to parse node descriptor; Type (%d) is not local descriptor",peer_addr.c_str(), type);
        return;
    }

    // Parse the local descriptor sub-tlv's
    int data_read;
    while (mp_reach_ls->nlri_ls.node_nlri.len > 0) {
        data_read = libparsebgp_mp_link_state_parse_descr_local_remote_node(data, mp_reach_ls->nlri_ls.node_nlri.len, info);
        mp_reach_ls->nlri_ls.node_nlri.len -= data_read;

        // Update the nlri data pointer and remaining length after processing the local descriptor sub-tlv
        data += data_read;
        data_len -= data_read;
        mp_reach_ls->nlri_ls.node_nlri.local_nodes.push_back(info);
    }// Save the parsed data
}

/**********************************************************************************//*
 * Parse Link Descriptor sub-tlvs
 *
 * \details will parse a link descriptor (series of sub-tlv's)
 *
 * \param [in]   data           Pointer to the start of the node NLRI data
 * \param [in]   data_len       Length of the data
 * \param [out]  info           link descriptor information returned/updated
 *
 * \returns number of bytes read
 */
int libparsebgp_parse_descr_link(u_char *data, int data_len, link_descriptor &info) {
    uint16_t        type;
    uint16_t        len;
    int             data_read = 0;

    if (data_len < 4) {
        //LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor; too short",peer_addr.c_str());
        return data_len;
    }

    memcpy(&type, data, 2);
    SWAP_BYTES(&type);

    memcpy(&len, data+2, 2);
    SWAP_BYTES(&len);

    if (len > data_len - 4) {
        //LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return data_len;
    }

    data += 4; data_read += 4;

    switch (type) {
        case LINK_DESCR_ID:
        {
            if (len != 8) {
                //LOG_NOTICE("%s: bgp-ls: failed to parse link ID descriptor sub-tlv; too short",peer_addr.c_str());
                data_read += len;
                break;
            }

            memcpy(&info.local_id, data, 4); SWAP_BYTES(&info.local_id);
            memcpy(&info.remote_id, data+4, 4); SWAP_BYTES(&info.remote_id);
            data_read += 8;

            //SELF_DEBUG("%s: bgp-ls: Link descriptor ID local = %08x remote = %08x", peer_addr.c_str(), info.local_id, info.remote_id);

            break;
        }

        case LINK_DESCR_MT_ID:
        {
            if (len < 2) {
                //LOG_NOTICE("%s: bgp-ls: failed to parse link MT-ID descriptor sub-tlv; too short",peer_addr.c_str());
                data_read += len;
                break;
            }

            if (len > 4) {
                //SELF_DEBUG("%s: bgp-ls: failed to parse link MT-ID descriptor sub-tlv; too long %d",peer_addr.c_str(), len);
                info.mt_id = 0;
                data_read += len;
                break;
            }

            memcpy(&info.mt_id, data, len); SWAP_BYTES(&info.mt_id);
            info.mt_id >>= 16;          // MT ID is 16 bits
            data_read += len;

            //SELF_DEBUG("%s: bgp-ls: Link descriptor MT-ID = %08x ", peer_addr.c_str(), info.mt_id);

            break;
        }


        case LINK_DESCR_IPV4_INTF_ADDR:
        {
            info.is_ipv4 = true;
            if (len != 4) {
                //           LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor interface IPv4 sub-tlv; too short",peer_addr.c_str());
                data_read += len <= data_len ? len : data_len;
                break;
            }

            char ip_char[46];
            memcpy(info.intf_addr, data, 4);
            inet_ntop(AF_INET, info.intf_addr, ip_char, sizeof(ip_char));
            data_read += 4;

            //      SELF_DEBUG("%s: bgp-ls: Link descriptor Interface Address = %s", peer_addr.c_str(), ip_char);
            break;
        }

        case LINK_DESCR_IPV6_INTF_ADDR:
        {
            info.is_ipv4 = false;
            if (len != 16) {
                //              LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor interface IPv6 sub-tlv; too short",peer_addr.c_str());
                data_read += len <= data_len ? len : data_len;
                break;
            }

            char ip_char[46];
            memcpy(info.intf_addr, data, 16);
            inet_ntop(AF_INET6, info.intf_addr, ip_char, sizeof(ip_char));
            data_read += 16;

            //           SELF_DEBUG("%s: bgp-ls: Link descriptor interface address = %s", peer_addr.c_str(), ip_char);
            break;
        }

        case LINK_DESCR_IPV4_NEI_ADDR:
        {
            info.is_ipv4 = true;

            if (len != 4) {
                //              LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor neighbor IPv4 sub-tlv; too short",peer_addr.c_str());
                data_read += len <= data_len ? len : data_len;
                break;
            }

            char ip_char[46];
            memcpy(info.nei_addr, data, 4);
            inet_ntop(AF_INET, info.nei_addr, ip_char, sizeof(ip_char));
            data_read += 4;

            //         SELF_DEBUG("%s: bgp-ls: Link descriptor neighbor address = %s", peer_addr.c_str(), ip_char);
            break;
        }

        case LINK_DESCR_IPV6_NEI_ADDR:
        {
            info.is_ipv4 = false;
            if (len != 16) {
                //LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor neighbor IPv6 sub-tlv; too short",peer_addr.c_str());
                data_read += len <= data_len ? len : data_len;
                break;
            }

            char ip_char[46];
            memcpy(info.nei_addr, data, 16);
            inet_ntop(AF_INET6, info.nei_addr, ip_char, sizeof(ip_char));
            data_read += 16;

            //SELF_DEBUG("%s: bgp-ls: Link descriptor neighbor address = %s", peer_addr.c_str(), ip_char);
            break;
        }


        default:
            //        LOG_NOTICE("%s: bgp-ls: link descriptor sub-tlv %d not yet implemented, skipping",peer_addr.c_str(), type);
            data_read += len;
            break;
    }

    return data_read;
}

/**********************************************************************************//*
 * Parse LINK NLRI
 *
 * \details will parse the LINK NLRI type.  Data starts at local node descriptor.
 *
 * \param [in]   data           Pointer to the start of the node NLRI data
 * \param [in]   data_len       Length of the data
 * \param [in]   id             NLRI/type identifier
 * \param [in]   proto_id       NLRI protocol type id
 */
static void libparsebgp_parse_nlri_link(mp_reach_ls *mp_reach_ls, u_char *data, int data_len) {

    if (data_len < 4) {
        //         LOG_WARN("%s: bgp-ls: Unable to parse link NLRI since it's too short (invalid)", peer_addr.c_str());
        return;
    }

    //parsing local node descriptor
    node_descriptor info;

    memcpy(&mp_reach_ls->nlri_ls.link_nlri.type, data, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.link_nlri.type);
    memcpy(&mp_reach_ls->nlri_ls.link_nlri.len, data + 2, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.link_nlri.len);
    data_len -= 4;
    data += 4;

    if (mp_reach_ls->nlri_ls.link_nlri.len > data_len) {
        //           LOG_WARN("%s: bgp-ls: failed to parse node descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return;
    }

    // Parse the local descriptor sub-tlv's
    int data_read;
    while (mp_reach_ls->nlri_ls.link_nlri.len > 0) {
        bzero(&info, sizeof(info));
        data_read = libparsebgp_mp_link_state_parse_descr_local_remote_node(data, mp_reach_ls->nlri_ls.link_nlri.len, info);
        mp_reach_ls->nlri_ls.link_nlri.len -= data_read;

        mp_reach_ls->nlri_ls.link_nlri.local_nodes.push_back(info);
        // Update the nlri data pointer and remaining length after processing the local descriptor sub-tlv
        data += data_read;
        data_len -= data_read;
    }

    //parsing remote node descriptor
    bzero(&info, sizeof(info));

    memcpy(&mp_reach_ls->nlri_ls.link_nlri.type, data, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.link_nlri.type);
    memcpy(&mp_reach_ls->nlri_ls.link_nlri.len, data + 2, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.link_nlri.len);
    data_len -= 4;
    data += 4;

    if (mp_reach_ls->nlri_ls.link_nlri.len > data_len) {
        //           LOG_WARN("%s: bgp-ls: failed to parse node descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return;
    }

    // Parse the local descriptor sub-tlv's
    while (mp_reach_ls->nlri_ls.link_nlri.len > 0) {
        bzero(&info, sizeof(info));
        data_read = libparsebgp_mp_link_state_parse_descr_local_remote_node(data, mp_reach_ls->nlri_ls.link_nlri.len, info);
        mp_reach_ls->nlri_ls.link_nlri.len -= data_read;
        mp_reach_ls->nlri_ls.link_nlri.remote_nodes.push_back(info);
        // Update the nlri data pointer and remaining length after processing the local descriptor sub-tlv
        data += data_read;
        data_len -= data_read;
    }



    /*
     * Remaining data is the link descriptor sub-tlv's
     */
    link_descriptor link_info;
    while (data_len > 0) {
        bzero(&info, sizeof(info));
        data_read = libparsebgp_parse_descr_link(data, data_len, link_info);
        mp_reach_ls->nlri_ls.link_nlri.link_desc.push_back(link_info);
        // Update the nlri data pointer and remaining length after processing the local descriptor sub-tlv
        data += data_read;
        data_len -= data_read;
    }
}

/**********************************************************************************//*
 * Parse Prefix Descriptor sub-tlvs
 *
 * \details will parse a prefix descriptor (series of sub-tlv's)
 *
 * \param [in]   data           Pointer to the start of the node NLRI data
 * \param [in]   data_len       Length of the data
 * \param [out]  info           prefix descriptor information returned/updated
 * \param [in]   isIPv4         Bool value to indicate IPv4(true) or IPv6(false)
 * \returns number of bytes read
 */
int libparsebgp_parse_descr_prefix(u_char *data, int data_len, prefix_descriptor &info, bool is_ipv4) {
    uint16_t type;
    uint16_t len;
    int data_read = 0;

    if (data_len < 4) {
        //         LOG_NOTICE("%s: bgp-ls: failed to parse link descriptor; too short",peer_addr.c_str());
        return data_len;
    }

        memcpy(&type, data, 2);
        SWAP_BYTES(&type);

        memcpy(&len, data + 2, 2);
        SWAP_BYTES(&len);

    if (len > data_len - 4) {
        //    LOG_NOTICE("%s: bgp-ls: failed to parse prefix descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return data_len;
    }

    data += 4; data_read += 4;

    switch (type) {
        case PREFIX_DESCR_IP_REACH_INFO: {
            uint64_t    value_64bit;
            uint32_t    value_32bit;

            if (len < 1) {
                //        LOG_INFO("%s: bgp-ls: Not parsing prefix ip_reach_info sub-tlv; too short at len=%d",peer_addr.c_str(), len);
                data_read += len;
                break;
            }

            info.prefix_len = *data;
            data_read++; data++;

            char ip_char[46];
            bzero(info.prefix, sizeof(info.prefix));

            // If length is greater than 1 then parse the prefix (default/zero prefix will not have prefix bytes)
            if (len > 1) {
                memcpy(info.prefix, data, len - 1);
                data_read += len - 1;
            }

            if (is_ipv4) {
                inet_ntop(AF_INET, info.prefix, ip_char, sizeof(ip_char));

                    // Get the broadcast/ending IP address
                    if (info.prefix_len < 32) {
                        memcpy(&value_32bit, info.prefix, 4);
                        SWAP_BYTES(&value_32bit);

                        value_32bit |= 0xFFFFFFFF >> info.prefix_len;
                        SWAP_BYTES(&value_32bit);
                        memcpy(info.prefix_bcast, &value_32bit, 4);

                } else
                    memcpy(info.prefix_bcast, info.prefix, sizeof(info.prefix_bcast));


            } else {
                inet_ntop(AF_INET6, info.prefix, ip_char, sizeof(ip_char));

                // Get the broadcast/ending IP address
                if (info.prefix_len < 128) {
                    if (info.prefix_len >= 64) {
                        // High order bytes are left alone
                        memcpy(info.prefix_bcast, info.prefix, 8);

                            // Low order bytes are updated
                            memcpy(&value_64bit, &info.prefix[8], 8);
                            SWAP_BYTES(&value_64bit);

                            value_64bit |= 0xFFFFFFFFFFFFFFFF >> (info.prefix_len - 64);
                            SWAP_BYTES(&value_64bit);
                            memcpy(&info.prefix_bcast[8], &value_64bit, 8);

                        } else {
                            // Low order types are all ones
                            value_64bit = 0xFFFFFFFFFFFFFFFF;
                            memcpy(&info.prefix_bcast[8], &value_64bit, 8);

                        // High order bypes are updated
                        memcpy(&value_64bit, info.prefix, 8);
                        SWAP_BYTES(&value_64bit);

                            value_64bit |= 0xFFFFFFFFFFFFFFFF >> info.prefix_len;
                            SWAP_BYTES(&value_64bit);
                            memcpy(info.prefix_bcast, &value_64bit, 8);
                        }
                    } else
                        memcpy(info.prefix_bcast, info.prefix, sizeof(info.prefix_bcast));
                }

            //       SELF_DEBUG("%s: bgp-ls: prefix ip_reach_info: prefix = %s/%d", peer_addr.c_str(),ip_char, info.prefix_len);
            break;
        }
        case PREFIX_DESCR_MT_ID:
            if (len < 2) {
                //          LOG_NOTICE("%s: bgp-ls: failed to parse prefix MT-ID descriptor sub-tlv; too short",peer_addr.c_str());
                data_read += len;
                break;
            }

            if (len > 4) {
                //            SELF_DEBUG("%s: bgp-ls: failed to parse link MT-ID descriptor sub-tlv; too long %d",peer_addr.c_str(), len);
                info.mt_id = 0;
                data_read += len;
                break;
            }

                memcpy(&info.mt_id, data, len); SWAP_BYTES(&info.mt_id);
                info.mt_id >>= 16;          // MT ID is 16 bits

            data_read += len;

            //        SELF_DEBUG("%s: bgp-ls: Link descriptor MT-ID = %08x ", peer_addr.c_str(), info.mt_id);

            break;

        case PREFIX_DESCR_OSPF_ROUTE_TYPE: {
            data_read++;
            switch (*data) {
                case OSPF_RT_EXTERNAL_1:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type), "Ext-1");
                    break;

                case OSPF_RT_EXTERNAL_2:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type),"Ext-2");
                    break;

                case OSPF_RT_INTER_AREA:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type),"Inter");
                    break;

                case OSPF_RT_INTRA_AREA:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type),"Intra");
                    break;

                case OSPF_RT_NSSA_1:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type),"NSSA-1");
                    break;

                case OSPF_RT_NSSA_2:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type),"NSSA-2");
                    break;

                default:
                    snprintf(info.ospf_route_type, sizeof(info.ospf_route_type),"Intra");
            }
            //        SELF_DEBUG("%s: bgp-ls: prefix ospf route type is %s", peer_addr.c_str(), info.ospf_route_type);
            break;
        }

        default:
            //       LOG_NOTICE("%s: bgp-ls: Prefix descriptor sub-tlv %d not yet implemented, skipping.",peer_addr.c_str(), type);
            data_read += len;
            break;
    }


    return data_read;
}

/**********************************************************************************//*
 * Parse PREFIX NLRI
 *
 * \details will parse the PREFIX NLRI type.  Data starts at local node descriptor.
 *
 * \param [in]   data           Pointer to the start of the node NLRI data
 * \param [in]   data_len       Length of the data
 * \param [in]   id             NLRI/type identifier
 * \param [in]   proto_id       NLRI protocol type id
 * \param [in]   isIPv4         Bool value to indicate IPv4(true) or IPv6(false)
 */
static void libparsebgp_parse_nlri_prefix(mp_reach_ls *mp_reach_ls, u_char *data, int data_len, bool isIPv4) {

    if (data_len < 4) {
        //       LOG_WARN("%s: bgp-ls: Unable to parse prefix NLRI since it's too short (invalid)", peer_addr.c_str());
        return;
    }
    /*
     * Parse the local node descriptor sub-tlv
     */
    node_descriptor local_node;


    memcpy(&mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.type, data, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.type);
    memcpy(&mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.len, data + 2, 2);
    SWAP_BYTES(&mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.len);
    data_len -= 4;
    data += 4;

    if (mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.len > data_len) {
        //        LOG_WARN("%s: bgp-ls: failed to parse node descriptor; type length is larger than available data %d>=%d",peer_addr.c_str(), len, data_len);
        return;
    }

    if (mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.type != NODE_DESCR_LOCAL_DESCR) {
        //        LOG_WARN("%s: bgp-ls: failed to parse node descriptor; Type (%d) is not local descriptor",peer_addr.c_str(), type);
        return;
    }

    // Parse the local descriptor sub-tlv's
    int data_read;
    while (mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.len > 0) {
        bzero(&local_node, sizeof(local_node));
        data_read = libparsebgp_mp_link_state_parse_descr_local_remote_node(data, mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.len, local_node);
        mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.len -= data_read;

        mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.local_nodes.push_back(local_node);
        // Update the nlri data pointer and remaining length after processing the local descriptor sub-tlv
        data += data_read;
        data_len -= data_read;
    }

    /*
     * Remaining data is the link descriptor sub-tlv's
     */
    prefix_descriptor info;
    while (data_len > 0) {
        bzero(&info, sizeof(info));
        data_read = libparsebgp_parse_descr_prefix(data, data_len, info, isIPv4);

        mp_reach_ls->nlri_ls.prefix_nlri_ipv4_ipv6.prefix_desc.push_back(info);
        // Update the nlri data pointer and remaining length after processing the local descriptor sub-tlv
        data += data_read;
        data_len -= data_read;
    }
}
/**********************************************************************************//*
 * Parses Link State NLRI data
 *
 * \details Will parse the link state NLRI's from MP_REACH or MP_UNREACH.
 *
 * \param [in]   data           Pointer to the NLRI data
 * \param [in]   len            Length of the NLRI data
 */
static void libparsebgp_parse_link_state_nlri_data(update_path_attrs *path_attrs, u_char *data, uint16_t len) {
    uint16_t        nlri_len_read = 0;
    // Process the NLRI data
    while (nlri_len_read < len) {
        mp_reach_ls mp_nlri_ls;
        /*
         * Parse the NLRI TLV
         */
        memcpy(&mp_nlri_ls.nlri_type, data, 2);
        data += 2;
        SWAP_BYTES(&mp_nlri_ls.nlri_type);

        memcpy(&mp_nlri_ls.nlri_len, data, 2);
        data += 2;
        SWAP_BYTES(&mp_nlri_ls.nlri_len);

        nlri_len_read += 4;

        if (mp_nlri_ls.nlri_len > len) {
//                LOG_NOTICE("%s: bgp-ls: failed to parse link state NLRI; length is larger than available data",peer_addr.c_str());
            return;
        }

        /*
         * Parse out the protocol and ID (present in each NLRI ypte
         */

        mp_nlri_ls.proto_id = *data;
        memcpy(&mp_nlri_ls.id, data + 1, sizeof(mp_nlri_ls.id));
        SWAP_BYTES(&mp_nlri_ls.id);

        // Update read NLRI attribute, current TLV length and data pointer
        nlri_len_read += 9; mp_nlri_ls.nlri_len -= 9; data += 9;

        /*
         * Decode based on bgp-ls NLRI type
         */
        switch (mp_nlri_ls.nlri_type) {
            case NLRI_TYPE_NODE:
                libparsebgp_parse_nlri_node(&mp_nlri_ls, data, mp_nlri_ls.nlri_len);
                break;

            case NLRI_TYPE_LINK:
                libparsebgp_parse_nlri_link(&mp_nlri_ls, data,mp_nlri_ls.nlri_len);
                break;

            case NLRI_TYPE_IPV4_PREFIX:
                libparsebgp_parse_nlri_prefix(&mp_nlri_ls, data, mp_nlri_ls.nlri_len, true);
                break;

            case NLRI_TYPE_IPV6_PREFIX:
                libparsebgp_parse_nlri_prefix(&mp_nlri_ls, data, mp_nlri_ls.nlri_len, false);
                break;

            default :
                return;
        }
        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls.push_back(mp_nlri_ls);
        // Move to next link state type
        data += mp_nlri_ls.nlri_len;
        nlri_len_read += mp_nlri_ls.nlri_len;
    }
}
/**
 * MP Reach Link State NLRI parse
 *
 * \details Will handle parsing the link state NLRI
 *
 * \param [in]   nlri           Reference to parsed NLRI struct
 */
void libparsebgp_mp_link_state_parse_reach_link_state(update_path_attrs *path_attrs, int nlri_len, unsigned char *next_hop, unsigned char *nlri_data) {

    memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, next_hop, path_attrs->attr_value.mp_reach_nlri_data.nh_len);

    /*
     * Decode based on SAFI
     */
    switch (path_attrs->attr_value.mp_reach_nlri_data.safi) {
        case BGP_SAFI_BGPLS: // Unicast BGP-LS
            libparsebgp_parse_link_state_nlri_data(path_attrs, nlri_data, nlri_len);
            break;

    default :
        //LOG_INFO("%s: MP_UNREACH AFI=bgp-ls SAFI=%d is not implemented yet, skipping for now",
        //        peer_addr.c_str(), nlri.afi, nlri.safi);
        return;
    }
}


/**
 * MP UnReach Link State NLRI parse
 *
 * \details Will handle parsing the unreach link state NLRI
 *
 * \param [in]   nlri           Reference to parsed NLRI struct
 */
void libparsebgp_mp_link_state_parse_unreach_link_state(update_path_attrs *path_attrs, unsigned char *nlri_data, int len) {
    //data->ls_data = &data->parsed_data->ls_withdrawn;

        /*
         * Decode based on SAFI
         */
        switch (path_attrs->attr_value.mp_unreach_nlri_data.safi) {
            case BGP_SAFI_BGPLS: // Unicast BGP-LS
                //SELF_DEBUG("UNREACH: bgp-ls: len=%d", nlri.nlri_len);
                libparsebgp_parse_link_state_nlri_data(path_attrs, nlri_data, len);
                break;

        default :
            //LOG_INFO("%s: MP_UNREACH AFI=bgp-ls SAFI=%d is not implemented yet, skipping for now",
//                    peer_addr.c_str(), nlri.afi, nlri.safi);
            return;
    }
}
/**********************************************************************************//*
 * Hash node descriptor info
 *
 * \details will produce a hash for the node descriptor.  Info hash_bin will be updated.
 *
 * \param [in/out]  info           Node descriptor information returned/updated
 * \param [out]  hash_bin       Node descriptor information returned/updated
 */
/*
void MPLinkState::genNodeHashId(node_descriptor &info) {
    MD5 hash;

    hash.update(info.igp_router_id, sizeof(info.igp_router_id));
    hash.update((unsigned char *)&info.bgp_ls_id, sizeof(info.bgp_ls_id));
    hash.update((unsigned char *)&info.asn, sizeof(info.asn));
    hash.update(info.ospf_area_Id, sizeof(info.ospf_area_Id));
    hash.finalize();

    // Save the hash
    unsigned char *hash_bin = hash.raw_digest();
    memcpy(info.hash_bin, hash_bin, 16);
    delete[] hash_bin;
}*/

//} /* namespace bgp_msg */
