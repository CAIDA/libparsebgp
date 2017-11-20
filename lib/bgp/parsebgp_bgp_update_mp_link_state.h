#ifndef __PARSEBGP_BGP_UPDATE_MP_LINK_STATE_H
#define __PARSEBGP_BGP_UPDATE_MP_LINK_STATE_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include "parsebgp_bgp_update_mp_reach.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * Defines the BGP link state NLRI types
 *      https://tools.ietf.org/html/draft-ietf-idr-ls-distribution-10#section-3.2
 */
typedef enum {

  /** NLRI TYPE: NODE NLRI */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_NODE = 1,

  /** NLRI TYPE: LINK NLRI */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_LINK = 2,

  /** NLRI TYPE: IPV4 PREFIX NLRI */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_IPV4_PREFIX = 3,

  /** NLRI TYPE: IPV^ PREFIX NLRI */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_IPV6_PREFIX = 4

} parsebgp_bgp_update_mp_link_state_nlri_types_t;


typedef enum {

  /** Routing Universe: Default Layer 3 Routing topology */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_DEF_LAYER_3_ROUTING_TOPOLOGY = 0,

} parsebgp_bgp_update_mp_link_state_identifier_t;

/**
 * Node descriptor Sub-TLV's
 *      Used by both remote and local node descriptors
 */
typedef enum {
  //TODO: check this field
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_LOCAL_DESCR =
      256,  ///< Local node descriptor
  //TODO: check this field
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_REMOTE_DESCR =
      257, ///< Remote node descriptor

  /** Node Descriptor: Autonomous System (len = 4) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_AS = 512,

  /** Node Descriptor: BGP LS Identifier (len = 4) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_BGP_LS_ID = 513,

  /** Node Descriptor: OSPF Area ID (len = 4) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_OSPF_AREA_ID = 514,

  /** Node Descriptor: IGP Router ID (len = variable) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_IGP_ROUTER_ID = 515,

  //TODO: check this field
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_BGP_ROUTER_ID = 516 ///< BGP Router ID
  ///< (draft-ietf-idr-bgpls-segment-routing-epe)
} parsebgp_bgp_update_mp_link_state_node_descr_sub_types_t;

/**
 * Link Descriptor Sub-TLV's
 */
typedef enum {

  /** Link Descriptor: Link Local/Remote Identifiers 22/4 (rfc5307/1.1) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_ID = 258,

  /** Link Descriptor: IPv4 interface address 22/6 (rfc5305/3.2) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV4_INTF_ADDR = 259,

  /** Link Descriptor: IPv4 neighbor address 22/8 (rfc5305/3.3) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV4_NEI_ADDR = 260,

  /** Link Descriptor: IPv4 interface address 22/6 (rfc5305/3.2) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV6_INTF_ADDR = 261,

  /** Link Descriptor: IPv6 neighbor address 22/13 (rfc6119/4.3) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV6_NEI_ADDR = 262,

  /** Link Descriptor: Multi-Topology Identifier */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_MT_ID = 263

} parsebgp_bgp_update_mp_link_state_link_descr_sub_types_t;

/**
 * Prefix Descriptor Sub-TLV's
 */
typedef enum {

  /** Prefix Descriptor: Multi-Topology Identifier (len = variable) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_PREFIX_DESCR_MT_ID = 263,

  /** Prefix Descriptor: OSPF Route Type (len=1) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_PREFIX_DESCR_OSPF_ROUTE_TYPE = 264,

  /** Prefix Descriptor: IP Reachability Information (len=variable) */
      PARSEBGP_BGP_UPDATE_MP_LINK_STATE_PREFIX_DESCR_IP_REACH_INFO = 265

} parsebgp_bgp_update_mp_link_state_prefix_descr_sub_types_t;


/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_link_state_decode(parsebgp_opts_t *opts,
                                               parsebgp_bgp_update_mp_reach_t *msg,
                                               uint8_t *buf,
                                               size_t *lenp,
                                               size_t remain);

/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_unreach_link_state_decode(parsebgp_opts_t *opts,
                                               parsebgp_bgp_update_mp_unreach_t *msg,
                                               uint8_t *buf,
                                               size_t *lenp,
                                               size_t remain);

#endif __PARSEBGP_BGP_UPDATE_MP_LINK_STATE_H