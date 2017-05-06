/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include "../include/update_msg.h"

#include <arpa/inet.h>

#include "../include/ext_community.h"
#include "../include/mp_reach_attr.h"
#include "../include/mp_un_reach_attr.h"
#include "../include/mp_link_state_attr.h"

//namespace bgp_msg {

//
//    void libparsebgp_update_msg_init(libparsebgp_update_msg_data *update_msg, std::string peer_addr,
//                                               std::string router_addr, peer_info *peer_info){
//        update_msg->peer_inf = peer_info;
//        update_msg->peer_addr = peer_addr;
//        update_msg->router_addr = router_addr;
//    }


/**
 * Parses NLRI info (IPv4) from the BGP message
 *
 * \details
 *      Will get the NLRI and Withdrawn prefix entries from the data buffer.  As per RFC,
 *      this is only for v4.  V6/mpls is via mpbgp attributes (RFC4760)
 *
 * \param [in]   data       Pointer to the start of the prefixes to be parsed
 * \param [in]   len        Length of the data in bytes to be read
 * \param [out]  prefixes   Reference to a list<prefix_tuple> to be updated with entries
 */
static void libparsebgp_update_msg_parse_nlri_data_v4(u_char *data, uint16_t len, std::list<update_prefix_tuple> &prefixes) {
        u_char       ipv4_raw[4];
        char         ipv4_char[16];
        u_char       addr_bytes;

        //prefix_tuple tuple;
        update_prefix_tuple prefix_tuple;

        if (len <= 0 or data == NULL)
            return;

        // TODO: Can extend this to support multicast, but right now we set it to unicast v4
        // Set the type for all to be unicast V4
        //tuple.type = PREFIX_UNICAST_V4;
        //tuple.is_ipv4 = true;

        // Loop through all prefixes
        for (size_t read_size=0; read_size < len; read_size++) {

            //bzero(ipv4_raw, sizeof(ipv4_raw));
            //bzero(tuple.prefix_bin, sizeof(tuple.prefix_bin));

            // Parse add-paths if enabled
            //if (update_msg->peer_info->add_path_capability.isAddPathEnabled(bgp::BGP_AFI_IPV4, bgp::BGP_SAFI_UNICAST)
            //TODO: check with Alistair if this is important
//            if (libparsebgp_addpath_is_enabled(update_msg->peer_inf->add_path_capability, BGP_AFI_IPV4, BGP_SAFI_UNICAST)
//                and (len - read_size) >= 4) {
//                //memcpy(&tuple.path_id, data, 4);
//                //SWAP_BYTES(&tuple.path_id);
//                //data += 4; read_size += 4;
//            } //else
                //tuple.path_id = 0;

            // set the address in bits length
            //tuple.len = *data++;
            prefix_tuple.len = *data++;

            // Figure out how many bytes the bits requires
            addr_bytes = prefix_tuple.len / 8;
            if (prefix_tuple.len % 8)
                ++addr_bytes;

            //SELF_DEBUG("%s: rtr=%s: Reading NLRI data prefix bits=%d bytes=%d", peer_addr.c_str(),
            //           router_addr.c_str(), tuple.len, addr_bytes);

            if (addr_bytes <= 4) {
                memcpy(ipv4_raw, data, addr_bytes);
                read_size += addr_bytes;
                data += addr_bytes;

                // Convert the IP to string printed format
                inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
                prefix_tuple.prefix.assign(ipv4_char);
                //SELF_DEBUG("%s: rtr=%s: Adding prefix %s len %d", peer_addr.c_str(),
                //           router_addr.c_str(), ipv4_char, tuple.len);

                // set the raw/binary address
                //memcpy(tuple.prefix_bin, ipv4_raw, sizeof(ipv4_raw));

                // Add tuple to prefix list
                prefixes.push_back(prefix_tuple);

            } else if (addr_bytes > 4) {
                //LOG_NOTICE("%s: rtr=%s: NRLI v4 address is larger than 4 bytes bytes=%d len=%d",
                //           peer_addr.c_str(), router_addr.c_str(), addr_bytes, tuple.len);
            }
        }
    }


/**
 * Parses the update message
 *
 * \details
 *      Reads the update message from socket and parses it.  The parsed output will
 *      be added to the DB.
 *
 * \param [in]   data           Pointer to raw bgp payload data, starting at the notification message
 * \param [in]   size           Size of the data available to read; prevent overrun when reading
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 *
 * \return ZERO is error, otherwise a positive value indicating the number of bytes read from update message
 */
int libparsebgp_update_msg_parse_update_msg(libparsebgp_update_msg_data *update_msg, u_char *data, size_t size, bool &has_end_of_rib_marker) {
    int      read_size       = 0;
    u_char      *bufPtr         = data;

    // Clear the parsed_data
//    update_msg->parsed_data.advertised.clear();
//    update_msg->parsed_data.attrs.clear();
//    update_msg->parsed_data.withdrawn.clear();

    /* ---------------------------------------------------------
     * Parse and setup the update header struct
     */
    //update_bgp_hdr uHdr;

    //SELF_DEBUG("%s: rtr=%s: Parsing update message of size %d", peer_addr.c_str(), router_addr.c_str(), size);

    if (size < 2) {
        //LOG_WARN("%s: rtr=%s: Update message is too short to parse header", peer_addr.c_str(), router_addr.c_str());
        return 0;
    }

    // Get the withdrawn length
    memcpy(&update_msg->wdrawn_route_len, bufPtr, sizeof(update_msg->wdrawn_route_len));
    SWAP_BYTES(&update_msg->wdrawn_route_len);
    bufPtr += sizeof(update_msg->wdrawn_route_len); read_size += sizeof(update_msg->wdrawn_route_len);

    // Set the withdrawn data pointer
    if ((size - read_size) < update_msg->wdrawn_route_len) {
        //LOG_WARN("%s: rtr=%s: Update message is too short to parse withdrawn data", peer_addr.c_str(), router_addr.c_str());
        return 0;
    }

    u_char *withdrawn_ptr, *attr_ptr, *nlri_ptr;
    withdrawn_ptr = bufPtr;
    bufPtr += update_msg->wdrawn_route_len; read_size += update_msg->wdrawn_route_len;

    //SELF_DEBUG("%s: rtr=%s: Withdrawn len = %hu", peer_addr.c_str(), router_addr.c_str(), update_msg->wdrawn_route_len );

    // Get the attributes length
    memcpy(&update_msg->total_path_attr_len, bufPtr, sizeof(update_msg->total_path_attr_len));
    SWAP_BYTES(&update_msg->total_path_attr_len);
    bufPtr += sizeof(update_msg->total_path_attr_len); read_size += sizeof(update_msg->total_path_attr_len);
    //SELF_DEBUG("%s: rtr=%s: Attribute len = %hu", peer_addr.c_str(), router_addr.c_str(), update_msg->total_path_attr_len);

    // Set the attributes data pointer
    if ((size - read_size) < update_msg->total_path_attr_len) {
        //LOG_WARN("%s: rtr=%s: Update message is too short to parse attr data", peer_addr.c_str(), router_addr.c_str());
        return 0;
    }
    attr_ptr = bufPtr;
    bufPtr += update_msg->total_path_attr_len; read_size += update_msg->total_path_attr_len;

    // Set the NLRI data pointer
    nlri_ptr = bufPtr;

    /*
     * Check if End-Of-RIB
     */
    if (not update_msg->wdrawn_route_len and (size - read_size) <= 0 and not update_msg->total_path_attr_len) {
        has_end_of_rib_marker = true;
        //LOG_INFO("%s: rtr=%s: End-Of-RIB marker", peer_addr.c_str(), router_addr.c_str());

    } else {

        /* ---------------------------------------------------------
         * Parse the withdrawn prefixes
         */
        //SELF_DEBUG("%s: rtr=%s: Getting the IPv4 withdrawn data", peer_addr.c_str(), router_addr.c_str());
        if (update_msg->wdrawn_route_len > 0)
            libparsebgp_update_msg_parse_nlri_data_v4(withdrawn_ptr, update_msg->wdrawn_route_len, update_msg->wdrawn_routes);

        /* ---------------------------------------------------------
         * Parse the attributes
         *      Handles MP_REACH/MP_UNREACH parsing as well
         */
        if (update_msg->total_path_attr_len > 0) {
            libparsebgp_update_msg_parse_attributes(update_msg, attr_ptr, update_msg->total_path_attr_len, has_end_of_rib_marker);
        }

        /* ---------------------------------------------------------
         * Parse the NLRI data
         */
        //SELF_DEBUG("%s: rtr=%s: Getting the IPv4 NLRI data, size = %d", peer_addr.c_str(), router_addr.c_str(), (size - read_size));
        if ((size - read_size) > 0) {
            libparsebgp_update_msg_parse_nlri_data_v4(nlri_ptr, (size - read_size), update_msg->nlri);
            read_size = size;
        }
    }

    return read_size;
}

    /**
 * Parse attribute AS_PATH data
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  attrs          Reference to the parsed attr map - will be updated
 */
static void libparsebgp_update_msg_parse_attr_as_path(update_path_attrs *path_attrs, u_char *data) {
//    std::string decoded_path;
    int         path_len    = path_attrs->attr_len;
    uint16_t    as_path_cnt = 0;
    as_path_segment as_segment;


    if (path_len < 4) // Nothing to parse if length doesn't include at least one asn
        return;

    /*
     * Per draft-ietf-grow-bmp, UPDATES must be sent as 4-octet, but this requires the
     *    UPDATE to be modified. In draft 14 a new peer header flag indicates size, but
     *    not all implementations support this draft yet.
     *
     *    IOS XE/XR does not modify the UPDATE and therefore a peers
     *    that is using 2-octet ASN's will not be parsed correctly.  Global instance var
     *    four_octet_asn is used to check if the OPEN cap sent/recv 4-octet or not. A compliant
     *    BMP implementation will still use 4-octet even if the peer is 2-octet, so a check is
     *    needed to see if the as path is encoded using 4 or 2 octet. This check is only done
     *    once.
     *
     *    This is temporary and can be removed after all implementations are complete with bmp draft 14 or greater.
     */
        //TODO: talk to Alistair
//    if (not update_msg->peer_inf->checked_asn_octet_length and not update_msg->four_octet_asn)
//    {
//        /*
//         * Loop through each path segment
//         */
//        u_char *d_ptr = data;
//        while (path_len > 0) {
//            d_ptr++; // seg_type
//            as_segment.seg_len = *d_ptr++;
//
//            path_len -= 2 + (as_segment.seg_len * 4);
//
//            if (path_len >= 0)
//                d_ptr += as_segment.seg_len * 4;
//        }
//
//        if (path_len != 0) {
//            //LOG_INFO("%s: rtr=%s: Using 2-octet ASN path parsing", peer_addr.c_str(), router_addr.c_str());
//            update_msg->peer_inf->using_2_octet_asn = true;
//        }
//
//        update_msg->peer_inf->checked_asn_octet_length = true;         // No more checking needed
//        path_len = attr_len;                                // Put the path length back to starting value
//    }

    // Define the octet size by known/detected size
//    char asn_octet_size = (update_msg->peer_inf->using_2_octet_asn and not update_msg->four_octet_asn) ? 2 : 4;
      uint8_t asn_octet_size=2;
    /*
     * Loop through each path segment
     */
    while (path_len > 0) {

        as_segment.seg_type = *data++;
        as_segment.seg_len  = *data++;                  // Count of AS's, not bytes
        path_len -= 2;

//        if (as_segment.seg_type == 1) {                 // If AS-SET open with a brace
//            decoded_path.append(" {");
//        }

        //SELF_DEBUG("%s: rtr=%s: as_path seg_len = %d seg_type = %d, path_len = %d total_len = %d as_octet_size = %d",
        //           peer_addr.c_str(), router_addr.c_str(),
        //           seg_len, seg_type, path_len, attr_len, asn_octet_size);
//TODO: check for this section
//        if ((as_segment.seg_len * asn_octet_size) > path_len){
//
//            //LOG_NOTICE("%s: rtr=%s: Could not parse the AS PATH due to update message buffer being too short when using ASN octet size %d",
//            //           peer_addr.c_str(), router_addr.c_str(), asn_octet_size);
//            //LOG_NOTICE("%s: rtr=%s: switching encoding size to 2-octet due to parsing failure",
//            //           peer_addr.c_str(), router_addr.c_str());
//
//            update_msg->peer_inf->using_2_octet_asn = true;
//        }

        // The rest of the data is the as path sequence, in blocks of 2 or 4 bytes
        for (; as_segment.seg_len > 0; as_segment.seg_len--) {
            uint32_t seg_asn;
            seg_asn = 0;
            memcpy(&seg_asn, data, asn_octet_size);  data += asn_octet_size;
            path_len -= asn_octet_size;                               // Adjust the path length for what was read

            SWAP_BYTES(&seg_asn, asn_octet_size);
//            decoded_path.append(" ");
//            std::ostringstream numString;
//            numString << as_segment.seg_asn;
//            decoded_path.append(numString.str());

            // Increase the as path count
            ++as_path_cnt;
            as_segment.seg_asn.push_back(seg_asn);
        }

//        if (as_segment.seg_type == 1) {            // If AS-SET close with a brace
//            decoded_path.append(" }");
//        }
        path_attrs->attr_value.as_path.push_back(as_segment);
    }

    //SELF_DEBUG("%s: rtr=%s: Parsed AS_PATH count %hu : %s", peer_addr.c_str(), router_addr.c_str(), as_path_cnt, decoded_path.c_str());

    /*
     * Update the attributes map
     */
//    attrs[ATTR_TYPE_AS_PATH] = decoded_path;
//
//    std::ostringstream numString;
//    numString << as_path_cnt;
//    attrs[ATTR_TYPE_INTERNAL_AS_COUNT] = numString.str();

    /*
     * Get the last ASN and update the attributes map
     */
//    int spos = -1;
//    int epos = decoded_path.size() - 1;
//    for (int i=epos; i >= 0; i--) {
//        if (spos < 0 and decoded_path[i] >= '0' and decoded_path[i] <= '9') {
//            epos = i; spos = i;
//
//        } else if (decoded_path[i] >= '0' and decoded_path[i] <= '9')
//            spos = i;
//        else if (spos >= 0)
//            break;
//    }
//
//    if (spos >= 0)   // positive only if found
//        attrs[ATTR_TYPE_INTERNAL_AS_ORIGIN] = decoded_path.substr(spos, (epos - spos) + 1);
}

    /**
 * Parse attribute AGGEGATOR data
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  attrs          Reference to the parsed attr map - will be updated
 */
static void libparsebgp_update_msg_parse_attr_aggegator(update_path_attrs *path_attrs, u_char *data) {
    std::string decodeStr;
    uint32_t    value32bit = 0;
    uint16_t    value16bit = 0;
    u_char      ipv4_raw[4];
    char        ipv4_char[16];

    // If using RFC6793, the len will be 8 instead of 6
    if (path_attrs->attr_len == 8) { // RFC6793 ASN of 4 octets
        memcpy(&value32bit, data, 4); data += 4;
        SWAP_BYTES(&value32bit);
        std::ostringstream numString;
        numString << value32bit;
        decodeStr.assign(numString.str());

    } else if (path_attrs->attr_len == 6) {
        memcpy(&value16bit, data, 2); data += 2;
        SWAP_BYTES(&value16bit);
        std::ostringstream numString;
        numString << value16bit;
        decodeStr.assign(numString.str());

    } else {
        //LOG_ERR("%s: rtr=%s: path attribute is not the correct size of 6 or 8 octets.", peer_addr.c_str(), router_addr.c_str());
        //throw "path attribute is not the correct size of 6 or 8 octets";
        return;
    }

    decodeStr.append(" ");
    memcpy(ipv4_raw, data, 4);
    inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
    decodeStr.append(ipv4_char);

    //attrs[ATTR_TYPE_AGGEGATOR] = decodeStr;
         path_attrs->attr_value.aggregator = decodeStr;
}
/**
 * Parse attribute data based on attribute type
 *
 * \details
 *      Parses the attribute data based on the passed attribute type.
 *      Parsed_data will be updated based on the attribute data parsed.
 *
 * \param [in]   attr_type      Attribute type
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
static void libparsebgp_update_msg_parse_attr_data(update_path_attrs *path_attrs, u_char *data, bool &has_end_of_rib_marker) {
        std::string decodeStr       = "";
        u_char      ipv4_raw[4];
        char        ipv4_char[16];
        uint32_t    value32bit;
        uint16_t    value16bit;

        /*
         * Parse based on attribute type
         */
        switch (path_attrs->attr_type.attr_type_code) {

            case ATTR_TYPE_ORIGIN : // Origin
                switch (data[0]) {
                    case 0 : decodeStr.assign("igp"); break;
                    case 1 : decodeStr.assign("egp"); break;
                    case 2 : decodeStr.assign("incomplete"); break;
                }

//                parsed_data.attrs[ATTR_TYPE_ORIGIN] = decodeStr;
                path_attrs->attr_value.origin = data[0];
                break;

            case ATTR_TYPE_AS_PATH : // AS_PATH
                libparsebgp_update_msg_parse_attr_as_path(path_attrs, data);
                break;

            case ATTR_TYPE_NEXT_HOP : // Next hop v4
                memcpy(path_attrs->attr_value.ipv4_raw, data, 4);
//                inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
                break;

            case ATTR_TYPE_MED : // MED value
            {
                memcpy(&path_attrs->attr_value.value32bit, data, 4);
                SWAP_BYTES(&path_attrs->attr_value.value32bit);
//                std::ostringstream numString;
//                numString << value32bit;
//                parsed_data.attrs[ATTR_TYPE_MED] = numString.str();

                break;
            }
            case ATTR_TYPE_LOCAL_PREF : // local pref value
            {
                memcpy(&path_attrs->attr_value.value32bit, data, 4);
                SWAP_BYTES(&path_attrs->attr_value.value32bit);
//                std::ostringstream numString;
//                numString << value32bit;
//                parsed_data.attrs[ATTR_TYPE_LOCAL_PREF] = numString.str();
                break;
            }
            case ATTR_TYPE_ATOMIC_AGGREGATE : // Atomic aggregate
//                parsed_data.attrs[ATTR_TYPE_ATOMIC_AGGREGATE] = std::string("1");
//                path_attrs->attr_value.origin = 1;
                break;

            case ATTR_TYPE_AGGEGATOR : // Aggregator
                libparsebgp_update_msg_parse_attr_aggegator(path_attrs, data);
                break;

            case ATTR_TYPE_ORIGINATOR_ID : // Originator ID
                memcpy(path_attrs->attr_value.ipv4_raw, data, 4);
//                inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
//                parsed_data.attrs[ATTR_TYPE_ORIGINATOR_ID] = std::string(ipv4_char);
                break;

            case ATTR_TYPE_CLUSTER_LIST : // Cluster List (RFC 4456)
                // According to RFC 4456, the value is a sequence of cluster id's
                for (int i=0; i < path_attrs->attr_len; i += 4) {
                    memcpy(ipv4_raw, data, 4);
                    data += 4;
//                    inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
//                    decodeStr.append(ipv4_char);
//                    decodeStr.append(" ");
//                    path_attrs->attr_value.cluster_list.push_back(ipv4_raw);
                }

//                parsed_data.attrs[ATTR_TYPE_CLUSTER_LIST] = decodeStr;
                break;

            case ATTR_TYPE_COMMUNITIES : // Community list
            {
                for (int i = 0; i < path_attrs->attr_len; i += 4) {
//                    std::ostringstream numString;

                    // Add space between entries
//                    if (i)
//                        decodeStr.append(" ");

                    // Add entry
                    memcpy(&value16bit, data, 2);
                    data += 2;
                    SWAP_BYTES(&value16bit);
//                    numString << value16bit;
//                    numString << ":";
                    path_attrs->attr_value.attr_type_comm.push_back(value16bit);

                    memcpy(&value16bit, data, 2);
                    data += 2;
                    SWAP_BYTES(&value16bit);
//                    numString << value16bit;
//                    decodeStr.append(numString.str());
                    path_attrs->attr_value.attr_type_comm.push_back(value16bit);
                }

//                parsed_data.attrs[ATTR_TYPE_COMMUNITIES] = decodeStr;

                break;
            }
            case ATTR_TYPE_EXT_COMMUNITY : // extended community list (RFC 4360)
            {
//                ExtCommunity ec(update_msg->peer_addr);
//                ec.parseExtCommunities(attr_len, data, parsed_data);
                libparsebgp_ext_communities_parse_ext_communities(path_attrs, data);
                break;
            }

            case ATTR_TYPE_IPV6_EXT_COMMUNITY : // IPv6 specific extended community list (RFC 5701)
            {
//                ExtCommunity ec6(update_msg->peer_addr);
//                ec6.parsev6ExtCommunities(attr_len, data, parsed_data);
                libparsebgp_ext_communities_parse_v6_ext_communities(path_attrs, data);
                break;
            }

            case ATTR_TYPE_MP_REACH_NLRI :  // RFC4760
            {
//                libparsebgp_mp_reach_attr_parsed_data *parse_data;
//                libparsebgp_mp_reach_attr_init(parse_data, update_msg->peer_addr, update_msg->peer_inf);
                libparsebgp_mp_reach_attr_parse_reach_nlri_attr(path_attrs, path_attrs->attr_len, data);
                break;
            }

            case ATTR_TYPE_MP_UNREACH_NLRI : // RFC4760
            {
//                libparsebgp_mp_un_reach_attr_parse_data *mp_un_reach_attr_data;
//                libparsebgp_mp_un_reach_attr_init(mp_un_reach_attr_data, update_msg->peer_addr, update_msg->peer_inf);
                libparsebgp_mp_un_reach_attr_parse_un_reach_nlri_attr(path_attrs, path_attrs->attr_len, data, has_end_of_rib_marker);
                break;
            }

            case ATTR_TYPE_AS_PATHLIMIT : // deprecated
            {
                break;
            }

            case ATTR_TYPE_BGP_LS:
            {
//                libparsebgp_attr_link_state_parsed_data *parse_data;
//                libparsebgp_mp_link_state_attr_init(parse_data, update_msg->peer_addr, &parsed_data);
                libparsebgp_mp_link_state_attr_parse_attr_link_state(path_attrs, path_attrs->attr_len, data);
                break;
            }

            case ATTR_TYPE_AS4_PATH:
            {
                //SELF_DEBUG("%s: rtr=%s: attribute type AS4_PATH is not yet implemented, skipping for now.",
                //         peer_addr.c_str(), router_addr.c_str());
                break;
            }

            case ATTR_TYPE_AS4_AGGREGATOR:
            {
                //SELF_DEBUG("%s: rtr=%s: attribute type AS4_AGGREGATOR is not yet implemented, skipping for now.",
                //           peer_addr.c_str(), router_addr.c_str());
                break;
            }

            default:
                //LOG_INFO("%s: rtr=%s: attribute type %d is not yet implemented or intentionally ignored, skipping for now.",
                //        peer_addr.c_str(), router_addr.c_str(), attr_type);
                break;

        } // END OF SWITCH ATTR TYPE
    }


/**
 * Parses the BGP attributes in the update
 *
 * \details
 *     Parses all attributes.  Decoded values are updated in 'parsed_data'
 *
 * \param [in]   data       Pointer to the start of the prefixes to be parsed
 * \param [in]   len        Length of the data in bytes to be read
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void libparsebgp_update_msg_parse_attributes(libparsebgp_update_msg_data *update_msg, u_char *data, uint16_t len, bool &has_end_of_rib_marker) {
    /*
     * Per RFC4271 Section 4.3, flat indicates if the length is 1 or 2 octets
     */
    //u_char   attr_flags;
    //u_char   attr_type;
    //uint16_t attr_len;

    if (len == 0)
        return;

    else if (len < 3) {
        //LOG_WARN("%s: rtr=%s: Cannot parse the attributes due to the data being too short, error in update message. len=%d",
        //        peer_addr.c_str(), router_addr.c_str(), len);
        return;
    }

    /*
     * Iterate through all attributes and parse them
     */
    update_path_attrs path_attrs;

    for (int read_size=0;  read_size < len; read_size += 2) {
        path_attrs.attr_type.attr_flags = *data++;
        path_attrs.attr_type.attr_type_code = *data++;

        // Check if the length field is 1 or two bytes
        if (ATTR_FLAG_EXTENDED(path_attrs.attr_type.attr_flags)) {
            //SELF_DEBUG("%s: rtr=%s: extended length path attribute bit set for an entry", peer_addr.c_str(), router_addr.c_str());

            memcpy(&path_attrs.attr_len, data, 2);
            data += 2;
            read_size += 2;
            SWAP_BYTES(&path_attrs.attr_len);

        } else
            path_attrs.attr_len = *data++;
        read_size++;

        //SELF_DEBUG("%s: rtr=%s: attribute type = %d len_sz = %d",
        //       peer_addr.c_str(), router_addr.c_str(), attr_type, attr_len);

        // Get the attribute data, if we have any; making sure to not overrun buffer
        if (path_attrs.attr_len > 0 and (read_size + path_attrs.attr_len) <= len) {
            // Data pointer is currently at the data position of the attribute

            /*
             * Parse data based on attribute type
             */
            libparsebgp_update_msg_parse_attr_data(&path_attrs, data, has_end_of_rib_marker);
            data += path_attrs.attr_len;
            read_size += path_attrs.attr_len;

            //SELF_DEBUG("%s: rtr=%s: parsed attr type=%d, size=%hu", peer_addr.c_str(), router_addr.c_str(),
            //            attr_type, attr_len);

        } else if (path_attrs.attr_len) {
            //LOG_NOTICE("%s: rtr=%s: Attribute data len of %hu is larger than available data in update message of %hu",
            //        peer_addr.c_str(), router_addr.c_str(), attr_len, (len - read_size));
            return;
        }
        update_msg->path_attributes.push_back(path_attrs);
//        delete path_attrs;
    }

}
//} /* namespace bgp_msg */
