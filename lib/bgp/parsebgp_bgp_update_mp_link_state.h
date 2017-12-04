/*
 * Copyright (C) 2017 The Regents of the University of California.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PARSEBGP_BGP_UPDATE_MP_LINK_STATE_H
#define __PARSEBGP_BGP_UPDATE_MP_LINK_STATE_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_bgp_update_mp_reach.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
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

void parsebgp_bgp_update_mp_reach_link_state_dump(parsebgp_bgp_update_mp_reach_t *msg,
                                                  int depth);

void parsebgp_bgp_update_mp_reach_link_state_destroy(
    parsebgp_bgp_update_mp_reach_t *msg);

void parsebgp_bgp_update_mp_reach_link_state_clear(
    parsebgp_bgp_update_mp_reach_t *msg);

/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_unreach_link_state_decode(parsebgp_opts_t *opts,
                                               parsebgp_bgp_update_mp_unreach_t *msg,
                                               uint8_t *buf,
                                               size_t *lenp,
                                               size_t remain);

void parsebgp_bgp_update_mp_unreach_link_state_dump(parsebgp_bgp_update_mp_unreach_t *msg,
                                                  int depth);

void parsebgp_bgp_update_mp_unreach_link_state_destroy(
    parsebgp_bgp_update_mp_unreach_t *msg);

void parsebgp_bgp_update_mp_unreach_link_state_clear(
    parsebgp_bgp_update_mp_unreach_t *msg);

#endif /* __PARSEBGP_BGP_UPDATE_MP_LINK_STATE_H */