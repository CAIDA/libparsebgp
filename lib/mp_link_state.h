/*
 * Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef _OPENBMP_MPLINKSTATE_H_
#define _OPENBMP_MPLINKSTATE_H_

#include "mp_un_reach_attr.h"
#include <stdint.h>
#include <sys/types.h>

/**
 * Defines the BGP link state NLRI types
 *      https://tools.ietf.org/html/draft-ietf-idr-ls-distribution-10#section-3.2
 */
enum nlri_types {
  NLRI_TYPE_NODE = 1,    ///< Node
  NLRI_TYPE_LINK,        ///< Link
  NLRI_TYPE_IPV4_PREFIX, ///< IPv4 Prefix
  NLRI_TYPE_IPV6_PREFIX  ///< IPv6 Prefix
};

/**
 * Defines the NLRI protocol-id values
 */
enum nlri_protocol_ids {
  NLRI_PROTO_ISIS_L1 = 1, ///< IS-IS Level 1
  NLRI_PROTO_ISIS_L2,     ///< IS-IS Level 2
  NLRI_PROTO_OSPFV2,      ///< OSPFv2
  NLRI_PROTO_DIRECT,      ///< Direct
  NLRI_PROTO_STATIC,      ///< Static configuration
  NLRI_PROTO_OSPFV3,      ///< OSPFv3
  NLRI_PROTO_EPE = 7      ///< EPE per draft-ietf-idr-bgpls-segment-routing-epe
};

/**
 * Node descriptor Sub-TLV's
 *      Used by both remote and local node descriptors
 */
enum node_descr_sub_types {
  NODE_DESCR_LOCAL_DESCR = 256, ///< Local node descriptor
  NODE_DESCR_REMOTE_DESCR,      ///< Remote node descriptor

  NODE_DESCR_AS = 512,      ///< Autonomous System (len=4)
  NODE_DESCR_BGP_LS_ID,     ///< BGP-LS Identifier (len=4)
  NODE_DESCR_OSPF_AREA_ID,  ///< OSPF Area-ID (len=4)
  NODE_DESCR_IGP_ROUTER_ID, ///< IGP Router-ID (len=variable)
  NODE_DESCR_BGP_ROUTER_ID  ///< BGP Router ID
                            ///< (draft-ietf-idr-bgpls-segment-routing-epe)
};

/**
 * Link Descriptor Sub-TLV's
 */
enum link_descr_sub_types {
  LINK_DESCR_ID = 258, ///< Link Local/Remote Identifiers 22/4 (rfc5307/1.1)
  LINK_DESCR_IPV4_INTF_ADDR, ///< IPv4 interface address 22/6 (rfc5305/3.2)
  LINK_DESCR_IPV4_NEI_ADDR,  ///< IPv4 neighbor address 22/8 (rfc5305/3.3)
  LINK_DESCR_IPV6_INTF_ADDR, ///< IPv6 interface address 22/12 (rfc6119/4.2)
  LINK_DESCR_IPV6_NEI_ADDR,  ///< IPv6 neighbor address 22/13 (rfc6119/4.3)
  LINK_DESCR_MT_ID           ///< Multi-Topology Identifier
};

/**
 * Prefix Descriptor Sub-TLV's
 */
enum prefix_descr_sub_types {
  PREFIX_DESCR_MT_ID = 263,     ///< Multi-Topology Identifier (len=variable)
  PREFIX_DESCR_OSPF_ROUTE_TYPE, ///< OSPF Route Type (len=1)
  PREFIX_DESCR_IP_REACH_INFO    ///< IP Reachability Information (len=variable)
};

/**
 * OSPF Route Types
 */
enum ospf_route_types {
  OSPF_RT_INTRA_AREA = 1, ///< Intra-Area
  OSPF_RT_INTER_AREA,     ///< Inter-Area
  OSPF_RT_EXTERNAL_1,     ///< External type 1
  OSPF_RT_EXTERNAL_2,     ///< External type 2
  OSPF_RT_NSSA_1,         ///< NSSA type 1
  OSPF_RT_NSSA_2          ///< NSSA type 2
};

/**
 * MP Reach Link State NLRI parse
 *
 * @details Will handle parsing the link state NLRI
 *
 * @param [in]  path_attrs          Reference to update_path_attrs struct
 * @param [in]  nlri_len            Length of nlri_data
 * @param [in]  next_hop            Buffer containing next_hop data, to be
 * parsed
 * @param [in]  nlri_data           Buffer containing nlri_data to be parsed
 */
ssize_t libparsebgp_mp_link_state_parse_reach_link_state(
  update_path_attrs *path_attrs, int nlri_len, unsigned char **next_hop,
  unsigned char **nlri_data);

/**
 * MP UnReach Link State NLRI parse
 *
 * @details Will handle parsing the unreach link state NLRI
 * @param path_attrs     Reference to update_path_attrs struct
 * @param nlri_data      Buffer containing nlri_data to be parsed
 * @param len            Length of nlri_data
 */
void libparsebgp_mp_link_state_parse_unreach_link_state(
  update_path_attrs *path_attrs, unsigned char **nlri_data, int len);

/**********************************************************************************/ /*
                                                                                      * Parse Prefix Descriptor sub-tlvs
                                                                                      *
                                                                                      * \details will parse a prefix descriptor (series of sub-tlv's)
                                                                                      *
                                                                                      * \param [in]   data           Pointer to the start of the node NLRI data
                                                                                      * \param [in]   data_len       Length of the data
                                                                                      * \param [out]  info           prefix descriptor information returned/updated
                                                                                      * \param [in]   isIPv4         Bool value to indicate IPv4(true) or IPv6(false)
                                                                                      *
                                                                                      * \returns number of bytes read
                                                                                      */
int libparsebgp_mp_link_state_parse_descr_prefix(u_char **data, int data_len,
                                                 prefix_descriptor *info,
                                                 bool is_ipv4);

#endif //_OPENBMP_MPLINKSTATE_H_
