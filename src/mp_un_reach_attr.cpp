/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/mp_un_reach_attr.h"
#include "../include/mp_link_state.h"
#include "../include/evpn.h"

/**
 * MP Reach NLRI parse for BGP_AFI_IPV4 & BGP_AFI_IPV6
 *
 * \details Will handle the SAFI and parsing of AFI IPv4 & IPv6
 *
 * \param [in]   is_ipv4         True false to indicate if IPv4 or IPv6
 * \param [in]   nlri           Reference to parsed Unreach NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
static void libparsebgp_mp_un_reach_attr_parse_afi_ipv4_ipv6(bool is_ipv4, mp_unreach_nlri &nlri, u_char *data, int len) {

    /*
     * Decode based on SAFI
     */
    switch (nlri.safi) {
        case BGP_SAFI_UNICAST: // Unicast IP address prefix
            libparsebgp_mp_reach_attr_parse_nlri_data_ipv4_ipv6(is_ipv4, data, len, nlri.withdrawn_routes_nlri.wdrawn_routes, &nlri.withdrawn_routes_nlri.count_wdrawn_routes);
            break;

        case BGP_SAFI_NLRI_LABEL: // Labeled unicast
            libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(is_ipv4, data, len, nlri.withdrawn_routes_nlri.wdrawn_routes_label, &nlri.withdrawn_routes_nlri.count_wdrawn_routes_label);
            break;

        case BGP_SAFI_MPLS: // MPLS (vpnv4/vpnv6)
            libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(is_ipv4, data, len, nlri.withdrawn_routes_nlri.wdrawn_routes_label, &nlri.withdrawn_routes_nlri.count_wdrawn_routes_label);
            break;

        default :
            //LOG_INFO("%s: MP_UNREACH AFI=ipv4/ipv6 (%d) SAFI=%d is not implemented yet, skipping for now",
            //         peer_addr.c_str(), is_ipv4, nlri.safi);
            return;
    }
}

/**
 * MP UnReach NLRI parse based on AFI
 *
 * \details Will parse the nlri data based on AFI.  A call to the specific SAFI method will
 *          be performed to further parse the message.
 *
 * \param [in]   nlri           Reference to parsed Unreach NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
static void libparsebgp_mp_un_reach_attr_parse_afi(update_path_attrs *path_attrs, u_char *data, int len) {

    switch (path_attrs->attr_value.mp_unreach_nlri_data.afi) {
        case BGP_AFI_IPV6 :  // IPv6
            libparsebgp_mp_un_reach_attr_parse_afi_ipv4_ipv6(false, path_attrs->attr_value.mp_unreach_nlri_data, data, len);
            break;

        case BGP_AFI_IPV4 : // IPv4
            libparsebgp_mp_un_reach_attr_parse_afi_ipv4_ipv6(true, path_attrs->attr_value.mp_unreach_nlri_data, data, len);
            break;

        case BGP_AFI_BGPLS : // BGP-LS (draft-ietf-idr-ls-distribution-10)
        {
//            libparsebgp_mp_link_state_init(link_state_parse_data, parse_data->peer_addr, &parsed_data);
            libparsebgp_mp_link_state_parse_unreach_link_state(path_attrs, data, len);
            break;
        }

        case BGP_AFI_L2VPN :
        {
            // parse by safi
            switch (path_attrs->attr_value.mp_unreach_nlri_data.safi) {
                case BGP_SAFI_EVPN : // https://tools.ietf.org/html/rfc7432
                {
//                    libparsebgp_evpn_data *evpn_data;
//                    libparsebgp_evpn_init(evpn_data,parse_data->peer_addr, true, &parsed_data);
                    libparsebgp_evpn_parse_nlri_data(path_attrs, data, len, true);
                    break;
                }

                default : break;
                    //LOG_INFO("%s: EVPN::parse SAFI=%d is not implemented yet, skipping",peer_addr.c_str(), nlri.safi);
            }

            break;
        }

        default : // Unknown
            //LOG_INFO("%s: MP_UNREACH AFI=%d is not implemented yet, skipping", peer_addr.c_str(), nlri.afi);
            return;
    }
}

/**
 * Parse the MP_UNREACH NLRI attribute data
 *
 * \details
 *      Will parse the MP_REACH_NLRI data passed.  Parsed data will be stored
 *      in parsed_data.
 *
 *      \see RFC4760 for format details.
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void libparsebgp_mp_un_reach_attr_parse_un_reach_nlri_attr(update_path_attrs *path_attrs, int attr_len, u_char *data, bool &has_end_of_rib_marker) {
    //mp_unreach_nlri nlri;
    /*
     * Set the MP Unreach NLRI struct
     */
    // Read address family
    memcpy(&path_attrs->attr_value.mp_unreach_nlri_data.afi, data, 2); data += 2; attr_len -= 2;
    SWAP_BYTES(&path_attrs->attr_value.mp_unreach_nlri_data.afi, 2);                     // change to host order

    path_attrs->attr_value.mp_unreach_nlri_data.safi = *data++; attr_len--;                // Set the SAFI - 1 octet
//    mp_unreach_data->nlri_data = data;                          // Set pointer position for nlri data
//    mp_unreach_data->nlri_len = attr_len;                       // Remaining attribute length is for NLRI data

    /*
     * Make sure the parsing doesn't exceed buffer
     */
    if (attr_len < 0) {
        //LOG_NOTICE("%s: MP_UNREACH NLRI data length is larger than attribute data length, skipping parse", peer_addr.c_str());
        return;
    }

    //SELF_DEBUG("%s: afi=%d safi=%d", peer_addr.c_str(), mp_unreach_data->afi, mp_unreach_data->safi);

    if (attr_len == 0) {
        has_end_of_rib_marker = true;
        //LOG_INFO("%s: End-Of-RIB marker (mp_unreach len=0)", peer_addr.c_str());

    } else {
        /*
         * NLRI data depends on the AFI & SAFI
         *  Parse data based on AFI + SAFI
         */
        libparsebgp_mp_un_reach_attr_parse_afi(path_attrs, data, attr_len);
    }
}

//} /* namespace bgp_msg */
