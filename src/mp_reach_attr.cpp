/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/mp_reach_attr.h"
#include "../include/mp_link_state.h"
#include "../include/evpn.h"

//namespace bgp_msg {

/**
 * Constructor for class
 *
 * \details Handles BGP MP Reach NLRI
 *
 * \param [in]     logPtr                   Pointer to existing Logger for app logging
 * \param [in]     pperAddr                 Printed form of peer address used for logging
 * \param [in]     peer_info                Persistent Peer info pointer
 * \param [in]     enable_debug             Debug true to enable, false to disable
 */

    void libparsebgp_mp_reach_attr_init(libparsebgp_mp_reach_attr_parsed_data *parse_data, std::string peerAddr,
                                        peer_info *peer_info)
    {
        parse_data->peer_inf=peer_info;
        parse_data->peer_addr = peerAddr;
    }


    /**
 * Parses mp_reach_nlri and mp_unreach_nlri (IPv4/IPv6)
 *
 * \details
 *      Will parse the NLRI encoding as defined in RFC3107 Section 3 (Carrying Label Mapping information).
 *
 * \param [in]   is_ipv4                 True false to indicate if IPv4 or IPv6
 * \param [in]   data                   Pointer to the start of the label + prefixes to be parsed
 * \param [in]   len                    Length of the data in bytes to be read
 * \param [in]   peer_info              Persistent Peer info pointer
 * \param [out]  prefixes               Reference to a list<label, prefix_tuple> to be updated with entries
 */
    template <typename PREFIX_TUPLE>
    void libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(bool is_ipv4, u_char *data, uint16_t len, std::list<PREFIX_TUPLE> &prefixes) {
        u_char            ip_raw[16];
        char              ip_char[40];
        int               addr_bytes;
        PREFIX_TUPLE      tuple;
        string            label;
        if (len <= 0 or data == NULL)
            return;

        //tuple.type = is_ipv4 ? PREFIX_LABEL_UNICAST_V4 : PREFIX_LABEL_UNICAST_V6;
        //tuple.is_ipv4 = is_ipv4;

        //bool add_path_enabled = peer_info->add_path_capability.isAddPathEnabled(is_ipv4 ? bgp::BGP_AFI_IPV4 : bgp::BGP_AFI_IPV6,
        //                                                                        bgp::BGP_SAFI_NLRI_LABEL);
        //bool add_path_enabled = libparsebgp_addpath_is_enabled(peer_info->add_path_capability, is_ipv4 ? BGP_AFI_IPV4 : BGP_AFI_IPV6,
        //                                                       BGP_SAFI_NLRI_LABEL);

        bool isVPN = typeid(vpn_tuple) == typeid(tuple);
        uint16_t label_bytes;

        // Loop through all prefixes
        for (size_t read_size=0; read_size < len; read_size++) {

            // Only check for add-paths if not mpls/vpn
            /*if (not isVPN and add_path_enabled and (len - read_size) >= 4) {
                memcpy(&tuple.path_id, data, 4);
                SWAP_BYTES(&tuple.path_id);
                data += 4;
                read_size += 4;

            } else
                tuple.path_id = 0;*/

            bzero(ip_raw, sizeof(ip_raw));

            // set the address in bits length
            tuple.len = *data++;

            // Figure out how many bytes the bits requires
            addr_bytes = tuple.len / 8;
            if (tuple.len % 8)
                ++addr_bytes;

            if (isVPN) {
                label_bytes = decode_label(data, addr_bytes, label);

                tuple.len -= (8 * label_bytes);      // Update prefix len to not include the label(s)
                data += label_bytes;               // move data pointer past labels
                addr_bytes -= label_bytes;
                read_size += label_bytes;
            }

            // Parse RD if VPN
            if (isVPN and addr_bytes >= 8) {
                vpn_tuple *vtuple = (vpn_tuple *)&tuple;
                libparsebgp_evpn_parse_route_distinguisher(data, &vtuple->rd_type, &vtuple->rd_assigned_number,
                                              &vtuple->rd_administrator_subfield);
                data += 8;
                addr_bytes -= 8;
                read_size += 8;
                tuple.len -= 64;
            }

            // Parse the prefix if it isn't a default route
            if (addr_bytes > 0) {
                memcpy(ip_raw, data, addr_bytes);
                data += addr_bytes;
                read_size += addr_bytes;

                // Convert the IP to string printed format
                inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char, sizeof(ip_char));

                tuple.prefix.assign(ip_char);

                // set the raw/binary address
                //memcpy(tuple.prefix_bin, ip_raw, sizeof(ip_raw));

            } else {
                tuple.prefix.assign(is_ipv4 ? "0.0.0.0" : "::");
            }

            prefixes.push_back(tuple);
        }
    }

    /**
* MP Reach NLRI parse for BGP_AFI_IPv4 & BGP_AFI_IPV6
*
* \details Will handle parsing the SAFI's for address family ipv6 and IPv4
*
* \param [in]   is_ipv4         True false to indicate if IPv4 or IPv6
* \param [in]   nlri           Reference to parsed NLRI struct
* \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
*/
    static void libparsebgp_mp_reach_attr_parse_afi_ipv4_ipv6(bool is_ipv4, update_path_attrs *path_attrs, unsigned char *next_hop, unsigned char *nlri_data) {
        u_char      ip_raw[16];
        char        ip_char[40];

        bzero(ip_raw, sizeof(ip_raw));

        /*
         * Decode based on SAFI
         */
        switch (path_attrs->attr_value.mp_reach_nlri_data.safi) {
            case BGP_SAFI_UNICAST: // Unicast IP address prefix

                // Next-hop is an IP address - Change/set the next-hop attribute in parsed data to use this next-hop
                if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
                    memcpy(ip_raw, next_hop, 16);
                else
                    memcpy(ip_raw, next_hop, path_attrs->attr_value.mp_reach_nlri_data.nh_len);

                inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char, sizeof(ip_char));

                path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

                // Data is an IP address - parse the address and save it
                libparsebgp_mp_reach_attr_parse_nlri_data_ipv4_ipv6(is_ipv4, nlri_data, path_attrs->attr_value.mp_reach_nlri_data.nlri_len, path_attrs->advertised);
                break;

            case BGP_SAFI_NLRI_LABEL:
                // Next-hop is an IP address - Change/set the next-hop attribute in parsed data to use this next-hop
                if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
                    memcpy(ip_raw, next_hop, 16);
                else
                    memcpy(ip_raw, next_hop, path_attrs->attr_value.mp_reach_nlri_data.nh_len);

                inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char, sizeof(ip_char));

                path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

                // Data is an Label, IP address tuple parse and save it
                libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(is_ipv4, nlri_data, path_attrs->attr_value.mp_reach_nlri_data.nlri_len, path_attrs->advertised);
                break;

            case BGP_SAFI_MPLS: {

                if (is_ipv4) {
                    //Next hop encoded in 12 bytes, last 4 bytes = IPv4
                    next_hop += 8;
                    path_attrs->attr_value.mp_reach_nlri_data.nh_len -= 8;
                }

                // Next-hop is an IP address - Change/set the next-hop attribute in parsed data to use this next-hop
                if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
                    memcpy(ip_raw, next_hop, 16);
                else
                    memcpy(ip_raw, next_hop, path_attrs->attr_value.mp_reach_nlri_data.nh_len);

                inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char, sizeof(ip_char));

                path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

                libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(is_ipv4, nlri_data, path_attrs->attr_value.mp_reach_nlri_data.nlri_len, path_attrs->vpn);

                break;
            }

            default :
                //LOG_INFO("%s: MP_REACH AFI=ipv4/ipv6 (%d) SAFI=%d is not implemented yet, skipping for now",
                //         peer_addr.c_str(), is_ipv4, nlri.safi);
                return;
        }
    }

/**
 * MP Reach NLRI parse based on AFI
 *
 * \details Will parse the next-hop and nlri data based on AFI.  A call to
 *          the specific SAFI method will be performed to further parse the message.
 *
 * \param [in]   nlri           Reference to parsed NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
    static void libparsebgp_parse_afi(update_path_attrs *path_attrs, unsigned char *nlri_data, unsigned char *next_hop) {

        switch (path_attrs->attr_value.mp_reach_nlri_data.afi) {
            case BGP_AFI_IPV6 :  // IPv6
                libparsebgp_mp_reach_attr_parse_afi_ipv4_ipv6(false, path_attrs, next_hop, nlri_data);
                break;

            case BGP_AFI_IPV4 : // IPv4
                libparsebgp_mp_reach_attr_parse_afi_ipv4_ipv6(true, path_attrs, next_hop, nlri_data);
                break;

            case BGP_AFI_BGPLS : // BGP-LS (draft-ietf-idr-ls-distribution-10)
            {
                //libparsebgp_mp_link_state_parsed_data *data;
                //libparsebgp_mp_link_state_init(data, parse_data->peer_addr, &parsed_data);
                libparsebgp_mp_link_state_parse_reach_link_state(path_attrs, next_hop, nlri_data);
                break;
            }

            case BGP_AFI_L2VPN :
            {
                u_char      ip_raw[16];
                char        ip_char[40];

                bzero(ip_raw, sizeof(ip_raw));

                // Next-hop is an IP address - Change/set the next-hop attribute in parsed data to use this next-hop
                if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
                    memcpy(ip_raw, next_hop, 16);
                else
                    memcpy(ip_raw, next_hop, path_attrs->attr_value.mp_reach_nlri_data.nh_len);

                inet_ntop(path_attrs->attr_value.mp_reach_nlri_data.nh_len == 4 ? AF_INET : AF_INET6, ip_raw, ip_char, sizeof(ip_char));

                path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

                // parse by safi
                switch (path_attrs->attr_value.mp_reach_nlri_data.safi) {
                    case BGP_SAFI_EVPN : // https://tools.ietf.org/html/rfc7432
                    {
                        //libparsebgp_evpn_data *evpn_data;
                        //libparsebgp_evpn_init(evpn_data,parse_data->peer_addr, false, &parsed_data);
                        libparsebgp_evpn_parse_nlri_data(path_attrs, nlri_data, path_attrs->attr_value.mp_reach_nlri_data.nlri_len, false);
                        break;
                    }

                    default : break;
                        //LOG_INFO("%s: EVPN::parse SAFI=%d is not implemented yet, skipping",
                        //         peer_addr.c_str(), nlri.safi);
                }

                break;
            }

            default : // Unknown
                //LOG_INFO("%s: MP_REACH AFI=%d is not implemented yet, skipping", peer_addr.c_str(), nlri.afi);
                return;
        }
    }


    /**
 * Parse the MP_REACH NLRI attribute data
 *
 * \details
 *      Will parse the MP_REACH_NLRI data passed.  Parsed data will be stored
 *      in parsed_data.
 *
 *      \see RFC4760 for format details.
 *
 * \param [in]   attr_len               Length of the attribute data
 * \param [in]   data                   Pointer to the attribute data
 * \param [out]  parsed_data            Reference to parsed_update_data; will be updated with all parsed data
 */
void libparsebgp_mp_reach_attr_parse_reach_nlri_attr(update_path_attrs *path_attrs, int attr_len, u_char *data) {
    //mp_reach_nlri nlri;
    /*
     * Set the MP NLRI struct
     */
    // Read address family
    unsigned char  *nlri_data, *next_hop;
    memcpy(&path_attrs->attr_value.mp_reach_nlri_data.afi, data, 2); data += 2; attr_len -= 2;
    SWAP_BYTES(&path_attrs->attr_value.mp_reach_nlri_data.afi);                     // change to host order

    path_attrs->attr_value.mp_reach_nlri_data.safi = *data++; attr_len--;                 // Set the SAFI - 1 octet
    path_attrs->attr_value.mp_reach_nlri_data.nh_len = *data++; attr_len--;              // Set the next-hop length - 1 octet
    next_hop = data;  data += path_attrs->attr_value.mp_reach_nlri_data.nh_len; attr_len -= path_attrs->attr_value.mp_reach_nlri_data.nh_len;    // Set pointer position for nh data
    path_attrs->attr_value.mp_reach_nlri_data.reserved = *data++; attr_len--;             // Set the reserve octet
    nlri_data = data;                          // Set pointer position for nlri data
    path_attrs->attr_value.mp_reach_nlri_data.nlri_len = attr_len;                       // Remaining attribute length is for NLRI data

    /*
     * Make sure the parsing doesn't exceed buffer
     */
    if (attr_len < 0) {
        //LOG_NOTICE("%s: MP_REACH NLRI data length is larger than attribute data length, skipping parse", peer_addr.c_str());
        return;
    }

    //SELF_DEBUG("%s: afi=%d safi=%d nh_len=%d reserved=%d", peer_addr.c_str(),
    //            nlri.afi, nlri.safi, nlri.nh_len, nlri.reserved);

    /*
     * Next-hop and NLRI data depends on the AFI & SAFI
     *  Parse data based on AFI + SAFI
     */
        libparsebgp_parse_afi(path_attrs, nlri_data, next_hop);
}




/**
 * Parses mp_reach_nlri and mp_unreach_nlri (IPv4/IPv6)
 *
 * \details
 *      Will parse the NLRI encoding as defined in RFC4760 Section 5 (NLRI Encoding).
 *
 * \param [in]   is_ipv4                 True false to indicate if IPv4 or IPv6
 * \param [in]   data                   Pointer to the start of the prefixes to be parsed
 * \param [in]   len                    Length of the data in bytes to be read
 * \param [in]   peer_info              Persistent Peer info pointer
 * \param [out]  prefixes               Reference to a list<prefix_tuple> to be updated with entries
 */
void libparsebgp_mp_reach_attr_parse_nlri_data_ipv4_ipv6(bool is_ipv4, u_char *data, uint16_t len, std::list<update_prefix_tuple> &prefixes) {
    u_char            ip_raw[16];
    char              ip_char[40];
    u_char            addr_bytes;
    update_prefix_tuple tuple;

    if (len <= 0 or data == NULL)
        return;

    // TODO: Can extend this to support multicast, but right now we set it to unicast v4/v6
    //tuple.type = is_ipv4 ? PREFIX_UNICAST_V4 : PREFIX_UNICAST_V6;
    //tuple.is_ipv4 = is_ipv4;

    //bool add_path_enabled = libparsebgp_addpath_is_enabled(peer_info->add_path_capability, is_ipv4 ? BGP_AFI_IPV4 : BGP_AFI_IPV6,
    //                                                                        BGP_SAFI_NLRI_LABEL);

    // Loop through all prefixes
    for (size_t read_size=0; read_size < len; read_size++) {
        //tuple.path_id = 0;

        bzero(ip_raw, sizeof(ip_raw));

        // Parse add-paths if enabled
        /*if (add_path_enabled and (len - read_size) >= 4) {
            memcpy(&tuple.path_id, data, 4);
            SWAP_BYTES(&tuple.path_id);
            data += 4; read_size += 4;
        } else
            tuple.path_id = 0;*/

        // set the address in bits length
        tuple.len = *data++;

        // Figure out how many bytes the bits requires
        addr_bytes = tuple.len / 8;
        if (tuple.len % 8)
           ++addr_bytes;

        memcpy(ip_raw, data, addr_bytes);
        data += addr_bytes;
        read_size += addr_bytes;

        // Convert the IP to string printed format
        inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char, sizeof(ip_char));

        tuple.prefix.assign(ip_char);

        // set the raw/binary address
        //memcpy(tuple.prefix_bin, ip_raw, sizeof(ip_raw));

        // Add tuple to prefix list
        prefixes.push_back(tuple);
    }
}



/**
 * Decode label from NLRI data
 *
 * \details
 *      Decodes the labels from the NLRI data into labels string
 *
 * \param [in]   data                   Pointer to the start of the label + prefixes to be parsed
 * \param [in]   len                    Length of the data in bytes to be read
 * \param [out]  labels                 Reference to string that will be updated with labels delimited by comma
 *
 * \returns number of bytes read to decode the label(s) and updates string labels
 *
 */
inline uint16_t decode_label(u_char *data, uint16_t len, std::string &labels) {
    int read_size = 0;
    typedef union {
        struct {
            uint8_t   ttl     : 8;          // TTL - not present since only 3 octets are used
            uint8_t   bos     : 1;          // Bottom of stack
            uint8_t   exp     : 3;          // EXP - not really used
            uint32_t  value   : 20;         // Label value
        } decode;
        uint32_t  data;                 // Raw label - 3 octets only per RFC3107
    } mpls_label;

    mpls_label label;

    labels.clear();

    u_char *data_ptr = data;

    // the label is 3 octets long
    while (read_size <= len)
    {
        bzero(&label, sizeof(label));

        memcpy(&label.data, data_ptr, 3);
        SWAP_BYTES(&label.data);     // change to host order

        data_ptr += 3;
        read_size += 3;

        ostringstream convert;
        convert << label.decode.value;
        labels.append(convert.str());

        printf("label data = %x\n", label.data);
        if (label.decode.bos == 1 or label.data == 0x80000000 /* withdrawn label as 32bits instead of 24 */
                or label.data == 0 /* l3vpn seems to use zero instead of rfc3107 suggested value */) {
            break;               // Reached EoS

        } else {
            labels.append(",");
        }
    }

    return read_size;
}

//} /* namespace bgp_msg */
