/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include <arpa/inet.h>
#include "../include/update_msg.h"
#include "../include/ext_community.h"
#include "../include/mp_reach_attr.h"
#include "../include/mp_un_reach_attr.h"
#include "../include/mp_link_state_attr.h"
#include "../include/mp_link_state.h"
#include "../include/parse_utils.h"

/**
 * Parses NLRI info (IPv4) from the BGP message
 *
 * @details
 *      Will get the NLRI and Withdrawn prefix entries from the data buffer.  As per RFC,
 *      this is only for v4.  V6/mpls is via mpbgp attributes (RFC4760)
 *
 * @param [in]   data       Pointer to the start of the prefixes to be parsed
 * @param [in]   len        Length of the data in bytes to be read
 * @param [out]  prefixes   Reference to a list<prefix_tuple> to be updated with entries
 */
static ssize_t libparsebgp_update_msg_parse_nlri_data_v4(u_char *data, uint16_t len, update_prefix_tuple **prefixes, uint16_t *count_prefix) {
    int          addr_bytes = 0;
    uint16_t          count = 0;
    //prefix_tuple tuple;
    update_prefix_tuple *prefix_tuple = (update_prefix_tuple *)malloc(sizeof(update_prefix_tuple));
    prefixes = (update_prefix_tuple **)malloc(sizeof(update_prefix_tuple*));

    if (len <= 0 || data == NULL)
        return 0;

    // TODO: Can extend this to support multicast, but right now we set it to unicast v4
    // Set the type for all to be unicast V4
    //tuple.type = PREFIX_UNICAST_V4;
    //tuple.is_ipv4 = true;

    // Loop through all prefixes
    for (size_t read_size=0; read_size < len; read_size++) {
        if(count)
            prefixes = (update_prefix_tuple **)realloc(prefixes, (count+1)*sizeof(update_prefix_tuple*));

        memset(prefix_tuple, 0, sizeof(prefix_tuple));

        // Parse add-paths if enabled
//        if (libparsebgp_addpath_is_enabled(add_path_map, BGP_AFI_IPV4, BGP_SAFI_UNICAST)
//            and (len - read_size) >= 4) {
//            memcpy(&prefix_tuple->path_id, data, 4);
//            SWAP_BYTES(&prefix_tuple->path_id.afi);
//            data += 4; read_size += 4;
//        } else {
//            prefix_tuple->path_id.afi = 0;
//            prefix_tuple->path_id.safi = 0;
//            prefix_tuple->path_id.send_recieve = 0;
//        }
        prefix_tuple->path_id.afi = 0;
        prefix_tuple->path_id.safi = 0;
        prefix_tuple->path_id.send_recieve = 0;

        // set the address in bits length
        //tuple.len = *data++;
//        if (extract_from_buffer(data, &len, &prefix_tuple->len, 1) != 1)
//            return ERR_READING_MSG;
        prefix_tuple->len = *data++;

        // Figure out how many bytes the bits requires
        addr_bytes = prefix_tuple->len / 8;
        if (prefix_tuple->len % 8)
            ++addr_bytes;

        //SELF_DEBUG("%s: rtr=%s: Reading NLRI data prefix bits=%d bytes=%d", peer_addr.c_str(),
        //           router_addr.c_str(), tuple.len, addr_bytes);

        if (addr_bytes <= 4) {
            memcpy(&prefix_tuple->prefix, data, addr_bytes);
            read_size += addr_bytes;
            data += addr_bytes;

            // Add tuple to prefix list
            prefixes[count++]=prefix_tuple;

        } else if (addr_bytes > 4) {
            //LOG_NOTICE("%s: rtr=%s: NRLI v4 address is larger than 4 bytes bytes=%d len=%d",
            //           peer_addr.c_str(), router_addr.c_str(), addr_bytes, tuple.len);
        }
    }
    *count_prefix = count;
    free(prefix_tuple);
    return len;
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
ssize_t libparsebgp_update_msg_parse_update_msg(libparsebgp_update_msg_data *update_msg, u_char *data, ssize_t size, bool *has_end_of_rib_marker) {
    ssize_t     read_size       = 0, bytes_read = 0, bytes_check = 0;
    u_char      *buf_ptr        = data;
//    libparsebgp_addpath_map add_path_map;
    if (size < 2) {
        //LOG_WARN("%s: rtr=%s: Update message is too short to parse header", peer_addr.c_str(), router_addr.c_str());
        return INCOMPLETE_MSG;
    }

    // Get the withdrawn length
    memcpy(&update_msg->wdrawn_route_len, buf_ptr, sizeof(update_msg->wdrawn_route_len));
    SWAP_BYTES(&update_msg->wdrawn_route_len, sizeof(update_msg->wdrawn_route_len));
    buf_ptr += sizeof(update_msg->wdrawn_route_len);
    read_size += sizeof(update_msg->wdrawn_route_len);
    bytes_check += sizeof(update_msg->wdrawn_route_len);

    // Set the withdrawn data pointer
    if ((size - bytes_check) < update_msg->wdrawn_route_len) {
        //LOG_WARN("%s: rtr=%s: Update message is too short to parse withdrawn data", peer_addr.c_str(), router_addr.c_str());
        return INCOMPLETE_MSG;
    }

    u_char *withdrawn_ptr, *attr_ptr, *nlri_ptr;
    withdrawn_ptr = buf_ptr;
    buf_ptr += update_msg->wdrawn_route_len; bytes_check += update_msg->wdrawn_route_len;

    // Get the attributes length
    memcpy(&update_msg->total_path_attr_len, buf_ptr, sizeof(update_msg->total_path_attr_len));
    SWAP_BYTES(&update_msg->total_path_attr_len, sizeof(update_msg->total_path_attr_len));
    buf_ptr += sizeof(update_msg->total_path_attr_len); read_size += sizeof(update_msg->total_path_attr_len); bytes_check += sizeof(update_msg->total_path_attr_len);

    // Set the attributes data pointer
    if ((size - bytes_check) < update_msg->total_path_attr_len) {
        //LOG_WARN("%s: rtr=%s: Update message is too short to parse attr data", peer_addr.c_str(), router_addr.c_str());
        return INCOMPLETE_MSG;
    }
    attr_ptr = buf_ptr;
    buf_ptr += update_msg->total_path_attr_len; bytes_check += update_msg->total_path_attr_len;

    // Set the NLRI data pointer
    nlri_ptr = buf_ptr;

    update_msg->count_nlri = 0;
    update_msg->count_path_attr = 0;
    update_msg->count_wdrawn_route = 0;
    /*
     * Check if End-Of-RIB
     */
    if (!update_msg->wdrawn_route_len && (size - bytes_check) <= 0 && !update_msg->total_path_attr_len) {
        *has_end_of_rib_marker = true;
        //LOG_INFO("%s: rtr=%s: End-Of-RIB marker", peer_addr.c_str(), router_addr.c_str());

    } else {

        /* ---------------------------------------------------------
         * Parse the withdrawn prefixes
         */
        if (update_msg->wdrawn_route_len > 0) {
            bytes_read = libparsebgp_update_msg_parse_nlri_data_v4(withdrawn_ptr, update_msg->wdrawn_route_len,
                                                                   update_msg->wdrawn_routes, &update_msg->count_wdrawn_route);
            if(bytes_read<0) return bytes_read;
            read_size += bytes_read;
        }
        /* ---------------------------------------------------------
         * Parse the attributes
         *      Handles MP_REACH/MP_UNREACH parsing as well
         */
        if (update_msg->total_path_attr_len > 0) {
            bytes_read = libparsebgp_update_msg_parse_attributes(update_msg->path_attributes, attr_ptr, update_msg->total_path_attr_len, has_end_of_rib_marker, &update_msg->count_path_attr);

            if(bytes_read<0) return bytes_read;
            read_size += bytes_read;
        }

        /* ---------------------------------------------------------
         * Parse the NLRI data
         */
        if ((size - bytes_check) > 0) {
            bytes_read = libparsebgp_update_msg_parse_nlri_data_v4(nlri_ptr, (size - read_size), update_msg->nlri, &update_msg->count_nlri);

            if(bytes_read<0) return bytes_read;
            read_size += bytes_read;
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
    int         path_len    = path_attrs->attr_len;
    uint16_t    as_path_cnt = 0;
    as_path_segment *as_segment = (as_path_segment *)malloc(sizeof(as_path_segment));

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
    int count_as_segment = 0;
    path_attrs->attr_value.as_path = (as_path_segment *)malloc(sizeof(as_path_segment));
    while (path_len > 0) {

        if(count_as_segment)
            path_attrs->attr_value.as_path = (as_path_segment *)realloc(path_attrs->attr_value.as_path,(count_as_segment+1)*sizeof(as_path_segment));
        memset(as_segment, 0, sizeof(as_segment));

        as_segment->seg_type = *data++;
        as_segment->seg_len  = *data++;                  // Count of AS's, not bytes
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
        int seg_len = as_segment->seg_len;
        uint16_t count_seg_asn=0;
        as_segment->seg_asn = (uint32_t *)malloc(as_segment->seg_len*sizeof(uint32_t));
        for (; seg_len > 0; seg_len--) {
            uint32_t seg_asn = 0;
            seg_asn = 0;
            memcpy(&seg_asn, data, asn_octet_size);  data += asn_octet_size;
            path_len -= asn_octet_size;                               // Adjust the path length for what was read

            SWAP_BYTES(&seg_asn, asn_octet_size);
            // Increase the as path count
            ++as_path_cnt;
            as_segment->seg_asn[count_seg_asn++]=seg_asn;
        }
        as_segment->count_seg_asn = count_seg_asn;
        path_attrs->attr_value.as_path[count_as_segment++]=*as_segment;
    }
    path_attrs->attr_value.count_as_path = count_as_segment;
    free(as_segment);

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
static void libparsebgp_update_msg_parse_attr_aggegator(update_path_attrs *path_attrs, u_char **data) {

    // If using RFC6793, the len will be 8 instead of 6
    if (path_attrs->attr_len == 8) { // RFC6793 ASN of 4 octets
        memcpy(&path_attrs->attr_value.aggregator, *data, 4);
        *data += 4;

    } else if (path_attrs->attr_len == 6) {
        memcpy(&path_attrs->attr_value.aggregator, *data, 2);
        *data += 2;

    } else {
        //LOG_ERR("%s: rtr=%s: path attribute is not the correct size of 6 or 8 octets.", peer_addr.c_str(), router_addr.c_str());
        //throw "path attribute is not the correct size of 6 or 8 octets";
        return;
    }
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
ssize_t libparsebgp_update_msg_parse_attr_data(update_path_attrs *path_attrs, u_char *data, bool *has_end_of_rib_marker) {
    uint16_t    value16bit;

    /*
     * Parse based on attribute type
     */
    switch (path_attrs->attr_type.attr_type_code) {

        case ATTR_TYPE_ORIGIN : // Origin
            path_attrs->attr_value.origin = data[0];
            break;

        case ATTR_TYPE_AS_PATH : // AS_PATH
            libparsebgp_update_msg_parse_attr_as_path(path_attrs, data);
            break;

        case ATTR_TYPE_NEXT_HOP : // Next hop v4
            memcpy(path_attrs->attr_value.next_hop, data, 4);
            break;

        case ATTR_TYPE_MED : // MED value
        {
            memcpy(&path_attrs->attr_value.med, data, 4);
            SWAP_BYTES(&path_attrs->attr_value.med, 4);
            break;
        }
        case ATTR_TYPE_LOCAL_PREF : // local pref value
        {
            memcpy(&path_attrs->attr_value.local_pref, data, 4);
            SWAP_BYTES(&path_attrs->attr_value.local_pref, 4);
            break;
        }
        case ATTR_TYPE_ATOMIC_AGGREGATE : // Atomic aggregate
//                parsed_data.attrs[ATTR_TYPE_ATOMIC_AGGREGATE] = std::string("1");
//                path_attrs->attr_value.origin = 1;
            break;

        case ATTR_TYPE_AGGEGATOR : // Aggregator
            libparsebgp_update_msg_parse_attr_aggegator(path_attrs, &data);
            break;

        case ATTR_TYPE_ORIGINATOR_ID : // Originator ID
            memcpy(path_attrs->attr_value.originator_id, data, 4);
            break;

        case ATTR_TYPE_CLUSTER_LIST : // Cluster List (RFC 4456)
        {    // According to RFC 4456, the value is a sequence of cluster id's
            path_attrs->attr_value.cluster_list = (u_char **) malloc(path_attrs->attr_len / 4 * sizeof(u_char *));
            int count = 0;
            for (int i = 0; i < path_attrs->attr_len; i += 4) {
                path_attrs->attr_value.cluster_list[count] = (u_char *) malloc(4 * sizeof(u_char));
                memcpy(path_attrs->attr_value.cluster_list[count], data, 4);
                count++;
                data += 4;
            }
            break;
        }
        case ATTR_TYPE_COMMUNITIES : // Community list
        {
            path_attrs->attr_value.attr_type_comm = (uint16_t *)malloc(path_attrs->attr_len/2*sizeof(uint16_t));
            int count=0;
            for (int i = 0; i < path_attrs->attr_len; i += 4) {
                // Add entry
                memcpy(&value16bit, data, 2);
                data += 2;
                SWAP_BYTES(&value16bit, 2);
                path_attrs->attr_value.attr_type_comm[count++]=value16bit;

                memcpy(&value16bit, data, 2);
                data += 2;
                SWAP_BYTES(&value16bit, 2);
                path_attrs->attr_value.attr_type_comm[count++]=value16bit;
            }
            break;
        }
        case ATTR_TYPE_EXT_COMMUNITY : // extended community list (RFC 4360)
        {
            libparsebgp_ext_communities_parse_ext_communities(path_attrs, &data);
            break;
        }

        case ATTR_TYPE_IPV6_EXT_COMMUNITY : // IPv6 specific extended community list (RFC 5701)
        {
            libparsebgp_ext_communities_parse_v6_ext_communities(path_attrs, &data);
            break;
        }

        case ATTR_TYPE_MP_REACH_NLRI :  // RFC4760
        {
            libparsebgp_mp_reach_attr_parse_reach_nlri_attr(path_attrs, path_attrs->attr_len, &data);
            break;
        }

        case ATTR_TYPE_MP_UNREACH_NLRI : // RFC4760
        {
            libparsebgp_mp_un_reach_attr_parse_un_reach_nlri_attr(path_attrs, path_attrs->attr_len, &data, has_end_of_rib_marker);
            break;
        }

        case ATTR_TYPE_AS_PATHLIMIT : // deprecated
            return NOT_YET_IMPLEMENTED;

        case ATTR_TYPE_BGP_LS:
        {
            libparsebgp_mp_link_state_attr_parse_attr_link_state(path_attrs, path_attrs->attr_len, &data);
            break;
        }

        case ATTR_TYPE_AS4_PATH:
            return NOT_YET_IMPLEMENTED;

        case ATTR_TYPE_AS4_AGGREGATOR:
            return NOT_YET_IMPLEMENTED;

        default:
            break;

    } // END OF SWITCH ATTR TYPE
    return path_attrs->attr_len;
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
ssize_t libparsebgp_update_msg_parse_attributes(update_path_attrs **update_msg, u_char *data, uint16_t len, bool *has_end_of_rib_marker, uint16_t *count_path_attrs) {

    ssize_t bytes_read = 0, read_size = 0;
    if (len <= 3)
        return CORRUPT_MSG;

    int count = 0;
    update_msg = (update_path_attrs **)malloc(sizeof(update_path_attrs*));
    update_path_attrs *path_attrs =(update_path_attrs *)malloc(sizeof(update_path_attrs));
    /*
     * Iterate through all attributes and parse them
     */

    for (int read=0;  read < len; read += 2) {
        if(count)
            update_msg = (update_path_attrs **)realloc(update_msg,(count+1)*sizeof(update_path_attrs *));
        memset(path_attrs, 0, sizeof(path_attrs));

        //TODO: Check this while debugging:
//        if (extract_from_buffer(data, &len, &path_attrs->attr_type, 2) != 2)
//            return ERR_READING_MSG;
        path_attrs->attr_type.attr_flags = *data++;
        path_attrs->attr_type.attr_type_code = *data++;
        read_size += 2;

        // Check if the length field is 1 or two bytes
        if (ATTR_FLAG_EXTENDED(path_attrs->attr_type.attr_flags)) {
            memcpy(&path_attrs->attr_len, data, 2);
            data += 2;
            read += 2;
            read_size += 2;
            SWAP_BYTES(&path_attrs->attr_len, 2);

        } else {
//            if (extract_from_buffer(data, &len, &path_attrs->attr_len, 1) != 1)
//                return ERR_READING_MSG;
            path_attrs->attr_len = *data++;
            read++;
            read_size++;
        }

        // Get the attribute data, if we have any; making sure to not overrun buffer
        if (path_attrs->attr_len > 0 || (read + path_attrs->attr_len) <= len) {
            // Data pointer is currently at the data position of the attribute

            /*
             * Parse data based on attribute type
             */
            bytes_read = libparsebgp_update_msg_parse_attr_data(path_attrs, data, has_end_of_rib_marker);
            if(bytes_read<0) return bytes_read;
            data += path_attrs->attr_len;
            read += path_attrs->attr_len;
            read_size += path_attrs->attr_len;

        } else if (path_attrs->attr_len) {
            return INCOMPLETE_MSG;
        }
        update_msg[count] = (update_path_attrs *)malloc(sizeof(update_path_attrs));
        memcpy(update_msg[count++],path_attrs, sizeof(update_path_attrs));
    }
    *count_path_attrs = count;
    free(path_attrs);
    return read_size;
}

void libparsebgp_parse_update_path_attrs_destructor(update_path_attrs *path_attrs) {
    switch (path_attrs->attr_type.attr_type_code) {
        case ATTR_TYPE_AS_PATH: {
            for (int i = 0; i < path_attrs->attr_value.count_as_path; ++i) {
                free(path_attrs->attr_value.as_path[i].seg_asn);
                path_attrs->attr_value.as_path[i].seg_asn = NULL;
            }
            free(path_attrs->attr_value.as_path);
            path_attrs->attr_value.as_path = NULL;
            break;
        }
        case ATTR_TYPE_CLUSTER_LIST: {
            for (int i = 0; i < path_attrs->attr_value.count_cluster_list; ++i) {
                free(path_attrs->attr_value.cluster_list[i]);
                path_attrs->attr_value.cluster_list[i] = NULL;
            }
            free(path_attrs->attr_value.cluster_list);
            path_attrs->attr_value.cluster_list = NULL;
            break;
        }
        case ATTR_TYPE_COMMUNITIES: {
            free(path_attrs->attr_value.attr_type_comm);
            path_attrs->attr_value.attr_type_comm = NULL;
            break;
        }
        case ATTR_TYPE_EXT_COMMUNITY: {
            free(path_attrs->attr_value.ext_comm);
            path_attrs->attr_value.ext_comm = NULL;
            break;
        }
        case ATTR_TYPE_MP_UNREACH_NLRI: {
            free(path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.evpn_withdrawn);
            path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.evpn_withdrawn = NULL;

            free(path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.wdrawn_routes);
            path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.wdrawn_routes = NULL;

            free(path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.wdrawn_routes_label);
            path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.wdrawn_routes_label = NULL;
//            free(&path_attrs->attr_value.mp_unreach_nlri_data);
            break;
        }
        case ATTR_TYPE_MP_REACH_NLRI: {
            free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.evpn);
            path_attrs->attr_value.mp_reach_nlri_data.nlri_info.evpn = NULL;

            free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.nlri_info);
            path_attrs->attr_value.mp_reach_nlri_data.nlri_info.nlri_info = NULL;

            for (int count = 0; count < path_attrs->attr_value.mp_reach_nlri_data.nlri_info.count_mp_rch_ls; ++count) {
                switch (path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_type) {
                    case NLRI_TYPE_NODE: {
                        free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.node_nlri.local_nodes);
                        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.node_nlri.local_nodes = NULL;
                        break;
                    }

                    case NLRI_TYPE_LINK: {
                        free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.link_nlri.local_nodes);
                        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.link_nlri.local_nodes = NULL;

                        free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.link_nlri.link_desc);
                        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.link_nlri.link_desc = NULL;

                        free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.link_nlri.remote_nodes);
                        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.link_nlri.remote_nodes = NULL;

                        break;
                    }

                    case NLRI_TYPE_IPV4_PREFIX:
                    case NLRI_TYPE_IPV6_PREFIX: {
                        free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.prefix_nlri_ipv4_ipv6.local_nodes);
                        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.prefix_nlri_ipv4_ipv6.local_nodes = NULL;

                        free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.prefix_nlri_ipv4_ipv6.prefix_desc);
                        path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls[count].nlri_ls.prefix_nlri_ipv4_ipv6.prefix_desc = NULL;
                        break;
                    }
                }
            }
            free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.mp_rch_ls);

            free(path_attrs->attr_value.mp_reach_nlri_data.nlri_info.nlri_label_info);
            path_attrs->attr_value.mp_reach_nlri_data.nlri_info.nlri_label_info = NULL;

//            free(&path_attrs->attr_value.mp_reach_nlri_data);
            break;
        }
        case ATTR_TYPE_BGP_LS: {
            free(path_attrs->attr_value.bgp_ls);
            break;
        }
    }
}

void libparsebgp_parse_update_msg_destructor(libparsebgp_update_msg_data *update_msg, int total_size) {

    if (update_msg->count_wdrawn_route > 0) {
        for (int i = 0; i < update_msg->count_wdrawn_route; ++i) {
            free(update_msg->wdrawn_routes[i]);
            update_msg->wdrawn_routes[i] = NULL;
        }
        free(update_msg->wdrawn_routes);
        update_msg->wdrawn_routes = NULL;
    }

    if (update_msg->count_path_attr > 0) {
        for (int i = 0; i < update_msg->count_path_attr; ++i) {
            libparsebgp_parse_update_path_attrs_destructor(&update_msg->path_attributes[i]);
        }
        free(update_msg->path_attributes);
        update_msg->path_attributes = NULL;
    }

    if (update_msg->count_nlri > 0) {
        for (int i = 0; i < update_msg->count_nlri; ++i) {
            free(update_msg->nlri[i]);
            update_msg->nlri[i] = NULL;
        }
        free(update_msg->nlri);
        update_msg->nlri = NULL;
    }

}