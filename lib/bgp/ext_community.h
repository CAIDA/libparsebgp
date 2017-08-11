/*
 * Copyright (c) 2014-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * Copyright (c) 2014 Sungard Availability Services and others.  All rights
 * reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#ifndef __EXTCOMMUNITY_H__
#define __EXTCOMMUNITY_H__

#include "update_msg.h"

/**
 * Defines the BGP Extended communities Types
 *      http://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml
 */
enum ext_comm_types {

  // Either Transitive or non-Transitive high order byte Types
  EXT_TYPE_2OCTET_AS = 0, ///< Transitive Two-Octet AS-Specific (RFC7153)
  EXT_TYPE_IPV4,          ///< Transitive IPv4-Address-Specific (RFC7153)
  EXT_TYPE_4OCTET_AS,     ///< Transitive Four-Octet AS-Specific (RFC7153)

  EXT_TYPE_OPAQUE,   ///< Transitive Opaque (RFC7153)
  EXT_TYPE_QOS_MARK, ///< QoS Marking (Thomas_Martin_Knoll)
  EXT_TYPE_COS_CAP,  ///< CoS Capability (Thomas_Martin_Knoll)
  EXT_TYPE_EVPN,     ///< EVPN (RFC7153)

  EXT_TYPE_FLOW_SPEC = 8, ///< Flow spec redirect/mirror to IP next-hop
                          ///< (draft-simpson-idr-flowspec-redirect)

  EXT_TYPE_GENERIC = 0x80, ///< Generic Transitive Experimental Use (RFC7153)
  EXT_TYPE_GENERIC_IPV4 = 0x81, ///< Generic/Experimental Use IPv4
                                ///< (draft-ietf-idr-flowspec-redirect-rt-bis)
  EXT_TYPE_GENERIC_4OCTET_AS    ///< Generic/Experimental Use 4Octet AS
                                ///< (draft-ietf-idr-flowspec-redirect-rt-bis)
};

/**
 * Defines the BGP Extended community subtype for EXT_TYPE_TRANS_EVPN
 */
enum ext_comm_subtype_evpn {
  EXT_EVPN_MAC_MOBILITY = 0, ///< MAC Mobility (RFC-ietf-l2vpn-evpn-11)
  EXT_EVPN_MPLS_LABEL,       ///< ESI MPLS Label (RFC-ietf-l2vpn-evpn-11)
  EXT_EVPN_ES_IMPORT,        ///< ES Import (RFC-ietf-l2vpn-evpn-11)
  EXT_EVPN_ROUTER_MAC        ///< EVPN Router’s MAC
                      ///< (draft-sajassi-l2vpn-evpn-inter-subnet-forwarding)
};

/**
 * Defines the BGP Extended community subtype for EXT_TYPE_IPV4,
 * EXT_TYPE_4OCTET_AS, and EXT_TYPE_2OCTET_AS. The subtypes are in common with
 * these.
 */
enum ext_comm_subtype_ipv4 {
  EXT_COMMON_ROUTE_TARGET = 2, ///< Route Target (RFC4360/RFC5668)
  EXT_COMMON_ROUTE_ORIGIN,     ///< Route Origin (RFC5668/RFC5668)
  EXT_COMMON_GENERIC,          ///< 4-Octet Generic
                      ///< (draft-ietf-idr-as4octet-extcommon-generic-subtype)
  EXT_COMMON_LINK_BANDWIDTH =
    4, ///< 2-Octet Link Bandwidth (draft-ietf-idr-link-bandwidth)

  EXT_COMMON_OSPF_DOM_ID = 5,    ///< OSPF Domain Identifier (RFC4577)
  EXT_COMMON_OSPF_ROUTER_ID = 7, ///< OSPF Router ID (RFC4577)

  EXT_COMMON_BGP_DATA_COL = 8, ///< BGP Data Collection (RFC4384)

  EXT_COMMON_SOURCE_AS = 9, ///< Source AS (RFC6514)

  EXT_COMMON_L2VPN_ID = 0x0a,   ///< L2VPN Identifier (RFC6074)
  EXT_COMMON_VRF_IMPORT = 0x0b, ///< VRF Route Import (RFC6514)

  EXT_COMMON_CISCO_VPN_ID = 0x10, ///< Cisco VPN-Distinguisher (Eric Rosen)

  EXT_COMMON_IA_P2MP_SEG_NH = 0x12 ///< Inter-area P2MP Segmented Next-Hop
                                   ///< (draft-ietf-mpls-seamless-mcast)
};

/**
 * Defines the BGP Extended community subtype for EXT_TYPE_IPV6 (same type as
 * 2OCTET but attribute type is IPv6 ext comm)
 */
enum ext_comm_subtype_ipv6 {
  EXT_IPV6_ROUTE_TARGET = 2, ///< Route Target (RFC5701)
  EXT_IPV6_ROUTE_ORIGIN,     ///< Route Origin (RFC5701)

  EXT_IPV6_OSPF_ROUTE_ATTRS =
    4, ///< OSPFv3 Route Attributes (deprecated) (RFC6565)

  EXT_IPV6_VRF_IMPORT = 0x0b, ///< VRF Route Import (RFC6514 & RFC6515)

  EXT_IPV6_CISCO_VPN_ID = 0x10, ///< Cisco VPN-Distinguisher (Eric Rosen)

  EXT_IPV6_UUID_ROUTE_TARGET =
    0x11, ///< UUID-based Route Target (Dhananjaya Rao)

  EXT_IPV6_IA_P2MP_SEG_NH = 0x12 ///< Inter-area P2MP Segmented Next-Hop
                                 ///< (draft-ietf-mpls-seamless-mcast)
};

/**
 * Defines the BGP Extended community subtype for EXT_TYPE_OPAQUE
 */
enum ext_comm_subtype_trans_opaque {
  EXT_OPAQUE_ORIGIN_VALIDATION =
    0, ///< BGP Origin Validation State
       ///< (draft-ietf-sidr-origin-validation-signaling)
  EXT_OPAQUE_COST_COMMUNITY =
    1, ///< Cost Community (draft-ietf-idr-custom-decision)

  EXT_OPAQUE_CP_ORF = 3, ///< CP-ORF (draft-ietf-l3vpn-orf-covering-prefixes)

  EXT_OPAQUE_OSPF_ROUTE_TYPE = 6, ///< OSPF Route Type (RFC4577)

  EXT_OPAQUE_COLOR = 0x0b, ///< Color (RFC5512)
  EXT_OPAQUE_ENCAP,        ///< Encapsulation (RFC5512)
  EXT_OPAQUE_DEFAULT_GW    ///< Default Gateway (Yakov Rekhter)
};

/**
 * Defines the BGP Extended community subtype for EXT_TYPE_GENERIC
 *      Experimental Use
 */
enum ext_comm_subtype_generic {
  EXT_GENERIC_OSPF_ROUTE_TYPE = 0, ///< OSPF Route Type (deprecated) (RFC4577)
  EXT_GENERIC_OSPF_ROUTER_ID,      ///< OSPF Router ID (deprecated) (RFC4577)

  EXT_GENERIC_OSPF_DOM_ID = 5, ///< OSPF Domain ID (deprecated) (RFC4577)

  EXT_GENERIC_FLOWSPEC_TRAFFIC_RATE = 6, ///< Flow spec traffic-rate (RFC5575)
  EXT_GENERIC_FLOWSPEC_TRAFFIC_ACTION,   ///< Flow spec traffic-action (RFC5575)
  EXT_GENERIC_FLOWSPEC_REDIRECT,       ///< Flow spec traffic redirect (RFC5575)
  EXT_GENERIC_FLOWSPEC_TRAFFIC_REMARK, ///< Flow spec traffic remarking
                                       ///< (RFC5575)

  EXT_GENERIC_LAYER2_INFO ///< Layer 2 info (RFC4761)
};

/**
 * Parse the extended communities path attribute (8 byte as per RFC4360)
 *
 * @details
 *     Will parse the EXTENDED COMMUNITIES data passed. Parsed data will be
 * stored in parsed_data.
 *
 * @param [in]   data           Pointer to the attribute data
 * @param [in]   path_attrs     Reference to update_path_attrs struct; will be
 * updated with all parsed data
 *
 */
void libparsebgp_ext_communities_parse_ext_communities(
  update_path_attrs *path_attrs, uint8_t **data);

/**
 * Parse the extended communities path attribute (20 byte as per RFC5701)
 *
 * @details
 *     Will parse the EXTENDED COMMUNITIES data passed. Parsed data will be
 * stored in parsed_data.
 *
 * @param [in]   data           Pointer to the attribute data
 * @param [in]   path_attrs     Reference to update_path_attrs struct; will be
 * updated with all parsed data
 *
 */
void libparsebgp_ext_communities_parse_v6_ext_communities(
  update_path_attrs *path_attrs, uint8_t **data);

#endif /* __EXTCOMMUNITY_H__ */
