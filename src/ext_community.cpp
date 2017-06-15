/*
 * Copyright (c) 2014-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * Copyright (c) 2014 Sungard Availability Services and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 * 
 */

#include <arpa/inet.h>
#include "../include/update_msg.h"
#include "../include/ext_community.h"

/**
 * Decode common Type/Subtypes
 *
 * \details
 *      Decodes the common 2-octet, 4-octet, and IPv4 specific common subtypes.
 *      Converts to human readable form.
 *
 * \param [in]   ec_hdr            Reference to the extended community header
 * \param [in]   is_global_4bytes  True if the global admin field is 4 bytes, false if 2
 * \param [in]   is_global_ipv4    True if the global admin field is an IPv4 address, false if not
 *
 * \return  Decoded string value
 */
static void decode_type_common(const extcomm_hdr *ec_hdr, u_char *value, bool is_global_4bytes = false, bool is_global_ipv4 = false) {
//    std::stringstream   val_ss;
    uint16_t            val_16b;
    uint32_t            val_32b;
    char                ipv4_char[16] = {0};

    /*
     * Decode values based on bit size
     */
    if (is_global_4bytes) {
        // Four-byte global field
        memcpy(&val_32b, value, 4);
        memcpy(&val_16b, value + 4, 2);

        SWAP_BYTES(&val_16b, 2);

        if (is_global_ipv4) {
            inet_ntop(AF_INET, &val_32b, ipv4_char, sizeof(ipv4_char));
        } else
            SWAP_BYTES(&val_32b, 4);

    } else {
        // Two-byte global field
        memcpy(&val_16b, value, 2);
        memcpy(&val_32b, value + 2, 4);

        // Chagne to host order
        SWAP_BYTES(&val_16b, 2);
        SWAP_BYTES(&val_32b, 4);
    }

    /*
     * Decode by subtype
     */
    switch (ec_hdr->low_type) {

        case EXT_COMMON_BGP_DATA_COL :
            if (is_global_4bytes)
                sprintf(ec_hdr->val, "colc=%d:%d", val_32b, val_16b);
//                val_ss << "colc=" << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "colc=%d:%d", val_16b, val_32b);
//                val_ss << "colc=" << val_16b << ":" << val_32b;

            break;

        case EXT_COMMON_ROUTE_ORIGIN :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "soo=%s:%d", ipv4_char, val_16b);
//                val_ss << "soo=" << ipv4_char << ":" << val_16b;

            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "soo=%d:%d", val_32b, val_16b);
//                val_ss << "soo=" << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "soo=%d:%d", val_16b, val_32b);
//                val_ss << "soo=" << val_16b << ":" << val_32b;
            break;

        case EXT_COMMON_ROUTE_TARGET :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "rt=%s:%d", ipv4_char, val_16b);
//                val_ss << "rt=" << ipv4_char << ":" << val_16b;

            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "rt=%d:%d", val_32b, val_16b);
//                val_ss << "rt=" << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "rt=%d:%d", val_16b, val_32b);
//                val_ss << "rt=" << val_16b << ":" << val_32b;
            break;

        case EXT_COMMON_SOURCE_AS :
            if (is_global_4bytes)
                sprintf(ec_hdr->val, "sas=%d:%d", val_32b, val_16b);
//                val_ss << "sas=" << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "sas=%d:%d", val_16b, val_32b);
//                val_ss << "sas=" << val_16b << ":" << val_32b;

            break;

        case EXT_COMMON_CISCO_VPN_ID :
            if (is_global_ipv4)
                //TODO: check
                sprintf(ec_hdr->val, "vpn-id=%s:%d", ipv4_char, val_16b);
//                val_ss << "vpn-id=" << ipv4_char << ":0x" << std::hex << val_16b;

            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "vpn-id=%d:%d", val_32b, val_16b);
//                val_ss << "vpn-id=" << val_32b << ":0x" << std::hex << val_16b;

            else
                sprintf(ec_hdr->val, "vpn-id=%d:%d", val_16b, val_32b);
//                val_ss << "vpn-id=" << val_16b << ":0x" << std::hex << val_32b;

            break;

        case EXT_COMMON_L2VPN_ID :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "vpn-id=%s:%d", ipv4_char, val_16b);
//                val_ss << "vpn-id=" << ipv4_char << ":0x" << std::hex << val_16b;

            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "vpn-id=%d:%d", val_32b, val_16b);
//                val_ss << "vpn-id=" << val_32b << ":0x" << std::hex << val_16b;

            else
                sprintf(ec_hdr->val, "vpn-id=%d:%d", val_16b, val_32b);
//                val_ss << "vpn-id=" << val_16b << ":0x" << std::hex << val_32b;

            break;

        case EXT_COMMON_LINK_BANDWIDTH : // is same as EXT_COMMON_GENERIC
            if (is_global_4bytes)
                sprintf(ec_hdr->val, "link-bw=%d:%d", val_32b, val_16b);
//                val_ss << "link-bw=" << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "link-bw=%d:%d", val_16b, val_32b);
//                val_ss << "link-bw=" << val_16b << ":" << val_32b;

            break;

        case EXT_COMMON_OSPF_DOM_ID :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "ospf-did=%s:%d", ipv4_char, val_16b);
//                val_ss << "ospf-did=" << ipv4_char << ":" << val_16b;
            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "ospf-did=%d:%d", val_32b, val_16b);
//                val_ss << "ospf-did=" << val_32b << ":" << val_16b;
            else
                sprintf(ec_hdr->val, "ospf-did=%d:%d", val_16b, val_32b);
//                val_ss << "ospf-did=" << val_16b << ":" << val_32b;
            break;

        case EXT_COMMON_VRF_IMPORT :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "import=%s:%d", ipv4_char, val_16b);
//                val_ss << "import=" << ipv4_char << ":" << val_16b;

            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "import=%d:%d", val_32b, val_16b);
//                val_ss << "import=" << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "import=%d:%d", val_16b, val_32b);
//                val_ss << "import=" << val_16b << ":" << val_32b;

            break;

        case EXT_COMMON_IA_P2MP_SEG_NH :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "p2mp-nh=%s:%d", ipv4_char, val_16b);
//                val_ss << "p2mp-nh=" << ipv4_char << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "p2mp-nh=%d:%d", val_16b, val_32b);
//                val_ss << "p2mp-nh=" << val_16b << ":" << val_32b;

            break;

        case EXT_COMMON_OSPF_ROUTER_ID :
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "ospf-rid=%s:%d", ipv4_char, val_16b);
//                val_ss << "ospf-rid=" << ipv4_char << ":" << val_16b;
            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "ospf-rid=%d:%d", val_32b, val_16b);
//                val_ss << "ospf-rid=" << val_32b << ":" << val_16b;
            else
                sprintf(ec_hdr->val, "ospf-rid=%d:%d", val_16b, val_32b);
//                val_ss << "ospf-rid=" << val_16b << ":" << val_32b;
            break;

        default :
            //LOG_INFO("%s: Extended community common type %d subtype = %d is not yet supported", peer_addr.c_str(),
            //        ec_hdr.high_type, ec_hdr.low_type);
            break;
    }
}

/**
 * Decode EVPN subtypes
 *
 * \details
 *      Converts to human readable form.
 *
 * \param [in]   ec_hdr          Reference to the extended community header
 *
 * \return  Decoded string value
 */
static void decode_type_evpn(const extcomm_hdr *ec_hdr, u_char *value) {
    uint32_t            val_32b;

    switch(ec_hdr->low_type) {
        case EXT_EVPN_MAC_MOBILITY: {
            u_char flags = value[0];

            memcpy(&val_32b, value + 2, 4);
            SWAP_BYTES(&val_32b, 4);

            sprintf(ec_hdr->val, "mac_mob_flags=%c mac_mob_seq_num=%d", flags, val_32b);
            break;
        }
        case EXT_EVPN_MPLS_LABEL: {
            u_char flags = value[0];

            memcpy(&val_32b, value + 3, 3);
            SWAP_BYTES(&val_32b, 4);
            val_32b = val_32b >> 8;

            sprintf(ec_hdr->val, "esi_label_flags=%c esi_label=%d", flags, val_32b);
            break;
        }
        case EXT_EVPN_ES_IMPORT: {
            sprintf(ec_hdr->val, "es_import=%s", value);
            break;
        }
        case EXT_EVPN_ROUTER_MAC: {

            sprintf(ec_hdr->val, "router_mac=%s", value);
            break;
        }
        default: {
            break;
        }
    }
}

/**
 * Decode Opaque subtypes
 *
 * \details
 *      Converts to human readable form.
 *
 * \param [in]   ec_hdr          Reference to the extended community header
 *
 * \return  Decoded string value
 */
static void decode_type_opaque(const extcomm_hdr *ec_hdr, u_char *value) {
//    std::stringstream   val_ss;
    uint16_t            val_16b;
    uint32_t            val_32b;

    switch(ec_hdr->low_type) {
        case EXT_OPAQUE_COST_COMMUNITY: {
            u_char poi = value[0];  // Point of Insertion
            u_char cid = value[1];  // Community-ID
            memcpy(&val_32b, value + 2, 4);
            SWAP_BYTES(&val_32b, 4);

            switch (poi) {
                case 128 : // Absolute_value
                    sprintf(ec_hdr->val, "cost=abs:%d:%d", (int)cid, val_32b);
                    break;
                case 129 : // IGP Cost
                    sprintf(ec_hdr->val, "cost=igp:%d:%d", (int)cid, val_32b);
                    break;
                case 130: // External_Internal
                    sprintf(ec_hdr->val, "cost=ext:%d:%d", (int)cid, val_32b);
                    break;
                case 131: // BGP_ID
                    sprintf(ec_hdr->val, "cost=bgp_id:%d:%d", (int)cid, val_32b);
                    break;
                default:
                    sprintf(ec_hdr->val, "cost=unkn:%d:%d", (int)cid, val_32b);
                    break;
            }
            break;
        }

        case EXT_OPAQUE_CP_ORF:
            sprintf(ec_hdr->val, "cp-orf=%d:%d", val_16b, val_32b);
            break;

        case EXT_OPAQUE_OSPF_ROUTE_TYPE: {
            memcpy(&val_32b, value, 4);
            SWAP_BYTES(&val_32b, 4);

            // Get the route type
            switch (value[4]) {
                case 1: // intra-area routes
                case 2: // intra-area routes
                    sprintf(ec_hdr->val, "ospf-rt=area-%d:O:%d", val_32b, (int)value[5]);
                    break;
                case 3: // Inter-area routes
                    sprintf(ec_hdr->val, "ospf-rt=area-%d:IA:%d", val_32b, (int)value[5]);
                    break;
                case 5: // External routes
                    sprintf(ec_hdr->val, "ospf-rt=area-%d:E:%d", val_32b, (int)value[5]);
                   break;
                case 7: // NSSA routes
                    sprintf(ec_hdr->val, "ospf-rt=area-%d:N:%d", val_32b, (int)value[5]);
                   break;
                default:
                    sprintf(ec_hdr->val, "ospf-rt=area-%d:unkn:%d", val_32b, (int)value[5]);
                   break;
            }

            // Add the options
//            val_ss << (int)value[5];

            break;
        }

        case EXT_OPAQUE_COLOR :
            memcpy(&val_32b, value + 2, 4);
            SWAP_BYTES(&val_32b, 4);

            sprintf(ec_hdr->val, "color=%d", val_32b);
//            val_ss << "color=" << val_32b;
            break;

        case EXT_OPAQUE_ENCAP :
            sprintf(ec_hdr->val, "encap=%d", (int)value[5]);
//            val_ss << "encap=" << (int)value[5];
            break;

        case EXT_OPAQUE_DEFAULT_GW : // draft-ietf-l2vpn-evpn (value is zero/reserved)
            sprintf(ec_hdr->val, "default-gw");
//            val_ss << "default-gw";
            break;
    }

//    return val_ss.str();
}

/**
 * Decode Generic subtypes
 *
 * \details
 *      Converts to human readable form.
 *
 * \param [in]   ec_hdr          Reference to the extended community header
 * \param [in]   is_global_4bytes  True if the global admin field is 4 bytes, false if 2
 * \param [in]   is_global_ipv4    True if the global admin field is an IPv4 address, false if not
 *
 * \return  Decoded string value
 */
static void decode_type_generic(const extcomm_hdr *ec_hdr, u_char *value, bool is_global_4bytes = false, bool is_global_ipv4 = false) {
//    std::stringstream   val_ss;
    uint16_t            val_16b;
    uint32_t            val_32b;
    char                ipv4_char[16] = {0};

    /*
     * Decode values based on bit size
     */
    if (is_global_4bytes) {
        // Four-byte global field
        memcpy(&val_32b, value, 4);
        memcpy(&val_16b, value + 4, 2);

        SWAP_BYTES(&val_16b, 2);

        if (is_global_ipv4) {
            inet_ntop(AF_INET, &val_32b, ipv4_char, sizeof(ipv4_char));
        } else
            SWAP_BYTES(&val_32b, 4);

    } else {
        // Two-byte global field
        memcpy(&val_16b, value, 2);
        memcpy(&val_32b, value + 2, 4);

        // Chagne to host order
        SWAP_BYTES(&val_16b, 2);
        SWAP_BYTES(&val_32b, 4);
    }

    switch (ec_hdr->low_type) {
        case EXT_GENERIC_OSPF_ROUTE_TYPE :  // deprecated
        case EXT_GENERIC_OSPF_ROUTER_ID :   // deprecated
        case EXT_GENERIC_OSPF_DOM_ID :      // deprecated
            //LOG_INFO("%s: Ignoring deprecated extended community %d/%d", peer_addr.c_str(),
            //        ec_hdr.high_type, ec_hdr.low_type);
            break;

        case EXT_GENERIC_LAYER2_INFO : {    // rfc4761
            u_char encap_type    = value[0];
            u_char ctrl_flags   = value[1];
            memcpy(&val_16b, value + 2, 2);          // Layer 2 MTU
            SWAP_BYTES(&val_16b, 2);

//            val_ss << "l2info=";

            switch (encap_type) {
                case 19 : // VPLS
                    sprintf(ec_hdr->val, "12info=vpls:%c:mtu:%d", ctrl_flags, val_16b);
//                    val_ss << "vpls:";
                    break;

                default:
                    sprintf(ec_hdr->val, "12info=%d:%c:mtu:%d", (int)encap_type, ctrl_flags, val_16b);
//                    val_ss << (int) encap_type << ":";
                    break;
            }

//            val_ss << ctrl_flags << ":mtu:" << val_16b;
            break;
        }

        case EXT_GENERIC_FLOWSPEC_TRAFFIC_RATE : {
            // 4 byte float
            // TODO: would prefer to use std::defaultfloat, but this is not available in centos6.5 gcc
//            val_ss << "flow-rate=" << val_16b << ":" << (float) val_32b;
            sprintf(ec_hdr->val, "flow-rate=%d:%f", val_16b, (float)val_32b);

            break;
        }

        case EXT_GENERIC_FLOWSPEC_TRAFFIC_ACTION : {
//            val_ss << "flow-act=";

            // TODO: need to validate if byte 0 or 5, using 5 here
            if (value[5] & 0x02)             // Terminal action
                sprintf(ec_hdr->val, "flow-act=S");
//                val_ss << "S";

            if (value[5] & 0x01)             // Sample and logging enabled
                sprintf(ec_hdr->val, "flow-act=T");
//                val_ss << "T";

            break;
        }

        case EXT_GENERIC_FLOWSPEC_REDIRECT : {
//            val_ss << "flow-redir=";

            // Route target
            if (is_global_ipv4)
                sprintf(ec_hdr->val, "flow-redir=%s:%d", ipv4_char, val_16b);
//                val_ss << ipv4_char << ":" << val_16b;

            else if (is_global_4bytes)
                sprintf(ec_hdr->val, "flow-redir=%d:%d", val_32b, val_16b);
//                val_ss << val_32b << ":" << val_16b;

            else
                sprintf(ec_hdr->val, "flow-redir=%d:%d", val_16b, val_32b);
//                val_ss << val_16b << ":" << val_32b;
            break;
        }

        case EXT_GENERIC_FLOWSPEC_TRAFFIC_REMARK :
            sprintf(ec_hdr->val, "flow-remark=%d", (int)value[5]);
//            val_ss << "flow-remark=" << (int)value[5];
    }

//    return val_ss.str();
}

/**
 * Parse the extended communities path attribute (8 byte as per RFC4360)
 *
 * \details
 *     Will parse the EXTENDED COMMUNITIES data passed. Parsed data will be stored
 *     in parsed_data.
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 *
 */
void libparsebgp_ext_communities_parse_ext_communities(update_path_attrs *path_attrs, u_char *data) {

//    std::string decode_str = "";
    extcomm_hdr *ec_hdr = (extcomm_hdr *)malloc(sizeof(extcomm_hdr));
    ec_hdr->val = (char *)malloc(20*sizeof(char));
    u_char *value;

    if ( (path_attrs->attr_len % 8) ) {
        //LOG_NOTICE("%s: Parsing extended community len=%d is invalid, expecting divisible by 8", peer_addr.c_str(), attr_len);
        return;
    }

    path_attrs->attr_value.ext_comm = (extcomm_hdr *)malloc(path_attrs->attr_len/8*sizeof(extcomm_hdr));
    uint16_t count = 0;
    /*
     * Loop through consecutive entries
     */
    for (int i = 0; i < path_attrs->attr_len; i += 8) {
//        decode_str = "";
        // Setup extended community header
        ec_hdr->high_type = data[0];
        ec_hdr->low_type  = data[1];
        value     = data + 2;

        /*
         * Docode the community by type
         */
        switch (ec_hdr->high_type << 2 >> 2) {
            case EXT_TYPE_IPV4 :
//                decode_str.append(decode_type_common(ec_hdr, value, true, true));
                decode_type_common(ec_hdr, value, true, true);
                break;

            case EXT_TYPE_2OCTET_AS :
                decode_type_common(ec_hdr, value);
//                decode_str.append(decode_type_common(ec_hdr, value));
                break;

            case EXT_TYPE_4OCTET_AS :
                decode_type_common(ec_hdr, value, true);
//                decode_str.append(decode_type_common(ec_hdr, value, true));
                break;

            case EXT_TYPE_GENERIC :
                decode_type_generic(ec_hdr, value);
                break;

            case EXT_TYPE_GENERIC_4OCTET_AS :
                decode_type_generic(ec_hdr, value, true);
                break;

            case EXT_TYPE_GENERIC_IPV4 :
                decode_type_generic(ec_hdr, value, true, true);
                break;

            case EXT_TYPE_OPAQUE :
                decode_type_opaque(ec_hdr, value);
                break;

            case EXT_TYPE_EVPN :
                decode_type_evpn(ec_hdr, value);
                break;

            case EXT_TYPE_QOS_MARK  : break;// TODO: Implement
            case EXT_TYPE_FLOW_SPEC : break;// TODO: Implement
            case EXT_TYPE_COS_CAP   : break;// TODO: Implement
            default: break;
                //LOG_INFO("%s: Extended community type %d,%d is not yet supported", peer_addr.c_str(),ec_hdr.high_type, ec_hdr.low_type);
        }
        // Move data pointer to next entry
        data += 8;
//            if ((i + 8) < attr_len)
//                decode_str.append(" ");
//        ec_hdr->val = decode_str;
        path_attrs->attr_value.ext_comm[count++]=*ec_hdr;
    }
    path_attrs->attr_value.count_ext_comm = count;
    free(ec_hdr->val);
    free(ec_hdr);
//        parsed_data.attrs[ATTR_TYPE_EXT_COMMUNITY] = decode_str;
}

/**
 * Decode IPv6 Specific Type/Subtypes
 *
 * \details
 *      Decodes the IPv6 specific and 2-octet, 4-octet.  This is pretty much the as common for IPv4,
 *      but with some differences. Converts to human readable form.
 *
 * \param [in]   ec_hdr          Reference to the extended community header
 *
 * \return  Decoded string value
 */
static void decodeType_ipv6_specific(const extcomm_hdr *ec_hdr, u_char *value) {
//    std::stringstream   val_ss;
    uint16_t            val_16b;
    u_char              ipv6_raw[16] = {0};
    char                ipv6_char[40] = {0};

    memcpy(ipv6_raw, value, 16);
    if (inet_ntop(AF_INET6, ipv6_raw, ipv6_char, sizeof(ipv6_char)) != NULL)
        return;

    memcpy(&val_16b, value + 16, 2);
    SWAP_BYTES(&val_16b, 2);

    switch (ec_hdr->low_type) {

        case EXT_IPV6_ROUTE_ORIGIN :
            sprintf(ec_hdr->val, "soo=%s:%d", ipv6_char, val_16b);
//            val_ss << "soo=" << ipv6_char << ":" << val_16b;
            break;

        case EXT_IPV6_ROUTE_TARGET :
            sprintf(ec_hdr->val, "rt=%s:%d", ipv6_char, val_16b);
//            val_ss << "rt=" << ipv6_char << ":" << val_16b;
            break;

        case EXT_IPV6_CISCO_VPN_ID :
            //TODO: hex, check
            sprintf(ec_hdr->val, "vpn-id=%s:%d", ipv6_char, val_16b);
//            val_ss << "vpn-id=" << ipv6_char << ":0x" << std::hex << val_16b;

            break;

        case EXT_IPV6_VRF_IMPORT :
            sprintf(ec_hdr->val, "import=%s:%d", ipv6_char, val_16b);
//            val_ss << "import=" << ipv6_char << ":" << val_16b;

            break;

        case EXT_IPV6_IA_P2MP_SEG_NH :
            sprintf(ec_hdr->val, "p2mp-nh=%s:%d", ipv6_char, val_16b);
//            val_ss << "p2mp-nh=" << ipv6_char << ":" << val_16b;

            break;

        default :
            //LOG_INFO("%s: Extended community ipv6 specific type %d subtype = %d is not yet supported", peer_addr.c_str(),
            //        ec_hdr.high_type, ec_hdr.low_type);
            break;
    }

//    return val_ss.str();
}

/**
 * Parse the extended communities path attribute (20 byte as per RFC5701)
 *
 * \details
 *     Will parse the EXTENDED COMMUNITIES data passed. Parsed data will be stored
 *     in parsed_data.
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 *
 */
void libparsebgp_ext_communities_parse_v6_ext_communities(update_path_attrs *path_attrs, u_char *data) {
//    std::string decode_str = "";
    extcomm_hdr *ec_hdr = (extcomm_hdr *)malloc(sizeof(extcomm_hdr));;
    u_char       *value;

    //LOG_INFO("%s: Parsing IPv6 extended community len=%d", peer_addr.c_str(), attr_len);

    if ( (path_attrs->attr_len % 20) ) {
        //LOG_NOTICE("%s: Parsing IPv6 extended community len=%d is invalid, expecting divisible by 20", peer_addr.c_str(), attr_len);
        return;
    }

    path_attrs->attr_value.ext_comm = (extcomm_hdr *)malloc(path_attrs->attr_len/20*sizeof(extcomm_hdr));
    memset(path_attrs->attr_value.ext_comm ,0 , sizeof(path_attrs->attr_value.ext_comm));

    uint16_t count = 0;

    /*
     * Loop through consecutive entries
     */
    for (int i = 0; i < path_attrs->attr_len; i += 20) {
        memset(ec_hdr, 0, sizeof(ec_hdr));
        // Setup extended community header
        ec_hdr->high_type = data[0];
        ec_hdr->low_type = data[1];
        value = data + 2;

        /*
         * Docode the community by type
         */
        switch (ec_hdr->high_type << 2 >> 2) {
            case 0 :  // Currently IPv6 specific uses this type field
                decodeType_ipv6_specific(ec_hdr, value);
                break;

            default :
                //LOG_NOTICE("%s: Unexpected type for IPv6 %d,%d", peer_addr.c_str(),
                //        ec_hdr.high_type, ec_hdr.low_type);
                break;
        }
//        ec_hdr->val=decode_str;
        path_attrs->attr_value.ext_comm[count++] = *ec_hdr;
    }
    path_attrs->attr_value.count_ext_comm = count;
    free(ec_hdr->val);
    free(ec_hdr);
    free(value);
}
