/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#ifndef MPUNREACHATTR_H_
#define MPUNREACHATTR_H_

#include "bgp_common.h"
#include <list>
#include <string>

#include "mp_reach_attr.h"
#include "parse_common.h"

//namespace bgp_msg {

/**
 * \class   MPUnReachAttr
 *
 * \brief   BGP attribute MP_UNREACH parser
 * \details This class parses MP_UNREACH attributes.
 *          It can be extended to create attributes messages.
 */

/**
 * struct defines the MP_UNREACH_NLRI (RFC4760 Section 4)
 */
struct mp_unreach_nlri {
    uint16_t       afi;                 ///< Address Family Identifier
    unsigned char  safi;                ///< Subsequent Address Family Identifier
    unsigned char  *nlri_data;          ///< NLRI data - Pointer to data (normally does not require freeing)
    uint16_t       nlri_len;            ///< Not in RFC header; length of the NLRI data
};

struct libparsebgp_mp_un_reach_attr_parse_data {
    std::string peer_addr;          ///< Printed form of the peer address for logging
    peer_info *peer_inf;         ///< Persistent Peer info pointer
};
/**
 * Constructor for class
 *
 * \details Handles bgp MP_UNREACH attributes
 *
 * \param [in]     logPtr                   Pointer to existing Logger for app logging
 * \param [in]     pperAddr                 Printed form of peer address used for logging
 * \param [in]     peer_info                Persistent Peer info pointer
 * \param [in]     enable_debug             Debug true to enable, false to disable
 */
void libparsebgp_mp_un_reach_attr_init(libparsebgp_mp_un_reach_attr_parse_data *parse_data, std::string peerAddr,
                                       peer_info *peer_info);


/**
 * Parse the MP_UNREACH NLRI attribute data
 *
 * \details
 *      Will parse the MP_UNBREACH_NLRI data passed.  Parsed data will be stored
 *      in parsed_data.
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 *
 */
void libparsebgp_mp_un_reach_attr_parse_un_reach_nlri_attr(libparsebgp_mp_un_reach_attr_parse_data *parse_data, int attr_len, u_char *data, parsed_update_data &parsed_data, bool &hasEndOfRIBMarker);

/**
 * MP UnReach NLRI parse based on AFI
 *
 * \details Will parse the next-hop and nlri data based on AFI.  A call to
 *          the specific SAFI method will be performed to further parse the message.
 *
 * \param [in]   nlri           Reference to parsed UnReach NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void libparsebgp_mp_un_reach_attr_parse_afi(libparsebgp_mp_un_reach_attr_parse_data *parse_data,mp_unreach_nlri &nlri, parsed_update_data &parsed_data);

/**
 * MP Reach NLRI parse for BGP_AFI_IPV4 & BGP_AFI_IPV6
 *
 * \details Will handle the SAFI and parsing of AFI IPv4 & IPv6
 *
 * \param [in]   isIPv4         True false to indicate if IPv4 or IPv6
 * \param [in]   nlri           Reference to parsed UnReach NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void libparsebgp_mp_un_reach_attr_parse_afi_ipv4_ipv6(libparsebgp_mp_un_reach_attr_parse_data *parse_data, bool isIPv4, mp_unreach_nlri &nlri, parsed_update_data &parsed_data);

//} /* namespace bgp_msg */

#endif /* MPUNREACHATTR_H_ */
