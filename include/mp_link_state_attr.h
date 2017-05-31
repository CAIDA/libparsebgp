/*
 * Copyright (c) 2015-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef _OPENBMP_LINKSTATEATTR_H_
#define _OPENBMP_LINKSTATEATTR_H_

#include <cstdint>
#include <cinttypes>
#include <sys/types.h>
#include "update_msg.h"

/**
 * Node Attribute types
 */
enum attr_node_types {
    ATTR_NODE_MT_ID                     = 263,    ///< Multi-Topology Identifier (len=variable)
    ATTR_NODE_FLAG                      = 1024,   ///< Node Flag Bits see enum NODE_FLAG_TYPES (len=1)
    ATTR_NODE_OPAQUE,                             ///< Opaque Node Properties (len=variable)
    ATTR_NODE_NAME,                               ///< Node Name (len=variable)
    ATTR_NODE_ISIS_AREA_ID,                       ///< IS-IS Area Identifier (len=variable)
    ATTR_NODE_IPV4_ROUTER_ID_LOCAL,               ///< Local NODE IPv4 Router ID (len=4) (rfc5305/4.3)
    ATTR_NODE_IPV6_ROUTER_ID_LOCAL,               ///< Local NODE IPv6 Router ID (len=16) (rfc6119/4.1)
    ATTR_NODE_SR_CAPABILITIES           = 1034,   ///< SR Capabilities
    ATTR_NODE_SR_ALGORITHM,                       ///< SR Algorithm
    ATTR_NODE_SR_LOCAL_BLOCK,                     ///< SR Local block
    ATTR_NODE_SR_SRMS_PREF                        ///< SR mapping server preference
};

enum sub_tlv_types {
    SUB_TLV_SID_LABEL = 1161    ///<SID/Label Sub-TLV
};

/**
 * Link Attribute types
 */
enum attr_link_types {
    ATTR_LINK_IPV4_ROUTER_ID_LOCAL      = 1028,         ///< IPv4 Router-ID of local node 134/- (rfc5305/4.3)
    ATTR_LINK_IPV6_ROUTER_ID_LOCAL,                     ///< IPv6 Router-ID of local node 140/- (rfc6119/4.1)
    ATTR_LINK_IPV4_ROUTER_ID_REMOTE,                    ///< IPv4 Router-ID of remote node 134/- (rfc5305/4.3)
    ATTR_LINK_IPV6_ROUTER_ID_REMOTE,                    ///< IPv6 Router-ID of remote node 140- (rfc6119/4.1)
    ATTR_LINK_ADMIN_GROUP               = 1088,         ///< Administrative group (color) 22/3 (rfc5305/3.1)
    ATTR_LINK_MAX_LINK_BW,                              ///< Maximum link bandwidth 22/9 (rfc5305/3.3)
    ATTR_LINK_MAX_RESV_BW,                              ///< Maximum reservable link bandwidth 22/10 (rfc5305/3.5)
    ATTR_LINK_UNRESV_BW,                                ///< Unreserved bandwidth 22/11 (RFC5305/3.6)
    ATTR_LINK_TE_DEF_METRIC,                            ///< TE default metric 22/18
    ATTR_LINK_PROTECTION_TYPE,                          ///< Link protection type 22/20 (rfc5307/1.2)
    ATTR_LINK_MPLS_PROTO_MASK,                          ///< MPLS protocol mask
    ATTR_LINK_IGP_METRIC,                               ///< IGP link metric
    ATTR_LINK_SRLG,                                     ///< Shared risk link group
    ATTR_LINK_OPAQUE,                                   ///< Opaque link attribute
    ATTR_LINK_NAME,                                     ///< Link name
    ATTR_LINK_ADJACENCY_SID,                            ///< Peer Adjacency SID (https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.2.1)

    ATTR_LINK_PEER_EPE_NODE_SID        = 1101,          ///< Peer Node SID (draft-ietf-idr-bgpls-segment-routing-epe)
    ATTR_LINK_PEER_EPE_ADJ_SID,                         ///< Peer Adjacency SID (draft-ietf-idr-bgpls-segment-routing-epe)
    ATTR_LINK_PEER_EPE_SET_SID                          ///< Peer Set SID (draft-ietf-idr-bgpls-segment-routing-epe)
};

/**
 * MPLS Protocol Mask BIT flags/codes
 */
enum MPLS_PROTO_MASK_CODES {
    MPLS_PROTO_MASK_LDP                 = 0x80,         ///< Label distribuion protocol (rfc5036)
    MPLS_PROTO_RSVP_TE                  = 0x40          ///< Extension to RSVP for LSP tunnels (rfc3209)
};

/**
 * Prefix Attribute types
 */
enum ATTR_PREFIX_TYPES {
    ATTR_PREFIX_IGP_FLAGS               = 1152,         ///< IGP Flags (len=1)
    ATTR_PREFIX_ROUTE_TAG,                              ///< Route Tag (len=4*n)
    ATTR_PREFIX_EXTEND_TAG,                             ///< Extended Tag (len=8*n)
    ATTR_PREFIX_PREFIX_METRIC,                          ///< Prefix Metric (len=4)
    ATTR_PREFIX_OSPF_FWD_ADDR,                          ///< OSPF Forwarding Address
    ATTR_PREFIX_OPAQUE_PREFIX,                          ///< Opaque prefix attribute (len=variable)
    ATTR_PREFIX_SID                                     ///< Prefix-SID TLV (len=variable)
};

/**
 * Parse Link State attribute
 *
 * @details Will handle parsing the link state attributes
 *
 * @param [in]   path_attrs     Reference to the struct update_path_attrs
 * @param [in]   attr_len       Length of the attribute data
 * @param [in]   data           Pointer to the attribute data
 */
void libparsebgp_mp_link_state_attr_parse_attr_link_state(update_path_attrs *path_attrs, int attr_len, u_char *data);


#define IEEE_INFINITY            0x7F800000
#define MINUS_INFINITY          (int32_t)0x80000000L
#define PLUS_INFINITY           0x7FFFFFFF
#define IEEE_NUMBER_WIDTH       32        /* bits in number */
#define IEEE_EXP_WIDTH          8         /* bits in exponent */
#define IEEE_MANTISSA_WIDTH     (IEEE_NUMBER_WIDTH - 1 - IEEE_EXP_WIDTH)
#define IEEE_SIGN_MASK          0x80000000
#define IEEE_EXPONENT_MASK      0x7F800000
#define IEEE_MANTISSA_MASK      0x007FFFFF

#define IEEE_IMPLIED_BIT        (1 << IEEE_MANTISSA_WIDTH)
#define IEEE_INFINITE           ((1 << IEEE_EXP_WIDTH) - 1)
#define IEEE_BIAS               ((1 << (IEEE_EXP_WIDTH - 1)) - 1)

/**
 * Parse Link State attribute TLV
 *
 * @details Will handle parsing the link state attribute
 *
 * @param [in]   path_attrs     Reference to struct update_path_attrs
 * @param [in]   attr_len       Length of the attribute data
 * @param [in]   data           Pointer to the attribute data
 *
 * @returns length of the TLV attribute parsed
 */
int libparsebgp_mp_link_state_attr_parse_attr_link_state_tlv(update_path_attrs *path_attrs, int attr_len, u_char *data, int count);

#endif //_OPENBMP_LINKSTATEATTR_H_
