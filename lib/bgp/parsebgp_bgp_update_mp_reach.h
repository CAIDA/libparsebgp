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

#ifndef __PARSEBGP_BGP_UPDATE_MP_REACH_H
#define __PARSEBGP_BGP_UPDATE_MP_REACH_H

#include "parsebgp_bgp_common.h"
//#include "parsebgp_bgp_update_mp_link_state.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * Node (local and remote) common fields
 */
typedef struct parsebgp_bgp_update_mp_link_state_node_descriptor {

  /** Type of the node descriptor */
  uint16_t type;

  /** Length of the node descriptor */
  uint16_t len;

  union {
    /** Node Descriptor: Autonomous System (len = 4) */
    uint32_t asn;

    /** Node Descriptor: BGP LS Identifier (len = 4) */
    uint32_t bgp_ls_id;

    /** Node Descriptor: OSPF Area ID (len = 4) */
    uint32_t ospf_area_Id;

    /** Node Descriptor: IGP Router ID (len = variable) */
    uint8_t igp_router_id[8];

  } node_value;
} parsebgp_bgp_update_mp_link_state_node_descriptor_t;

/**
 * Link Descriptor common fields
 */
typedef struct parsebgp_bgp_update_mp_link_state_link_descriptor {

  /** Type of the link descriptor */
  uint16_t type;

  /** Length of the link descriptor */
  uint16_t len;

  struct {
    /** Link Local ID */
    uint32_t link_local_id;

    /** Link Remote ID */
    uint32_t link_remote_id;    ///< Link Remote ID
  } link_ids;

  /** ipv4 Interface binary address */
  uint8_t link_ipv4_intf_addr[4];

  /** ipv4 Neighbor binary address */
  uint8_t link_ipv4_neigh_addr[4];

  /** ipv6 Interface binary address */
  uint8_t link_ipv6_intf_addr[16];

  /** ipv6 Neighbor binary address */
  uint8_t link_ipv6_neigh_addr[16];

  /** Multi-Topology ID (len=variable) */
  struct {

    /** Array of mt_ids */
    uint16_t *ids;

    /** Allocated length of ids */
    int _ids_alloc_cnt;

    /** Populated ids count */
    int ids_cnt;

  } link_mt_id;

} parsebgp_bgp_update_mp_link_state_link_descriptor_t;

/**
 * Prefix descriptor common fields
 */
typedef struct parsebgp_bgp_update_mp_link_state_prefix_descriptor {

  /** Type of the prefix descriptor */
  uint16_t type;

  /** Length of the prefix descriptor */
  uint16_t len;

  /** Multi-Topology ID (len=variable) */
  struct {

    /** Array of mt_ids */
    uint16_t *ids;

    /** Allocated length of ids */
    int _ids_alloc_cnt;

    /** Populated ids count */
    int ids_cnt;

  } prefix_mt_id;

  /** OSPF Route type */
  uint8_t prefix_ospf_route_type;

  struct {
    uint8_t prefix_len;

    /** Array of ip_prefix */
    uint8_t *ip_prefix;

    /** Allocated length of ip_prefix */
    int _ip_prefix_cnt;

    /** Populated ip_prefix count */
    int ip_prefix_cnt;

  }prefix_ip_reach_info;

} parsebgp_bgp_update_mp_link_state_prefix_descriptor_t;

typedef struct parsebgp_bgp_update_mp_link_state {

  /** AFI : 16388, SAFI : 71 */

  /** Type of NLRI: node, link, ipv4 prefix, ipv6 prefix */
  uint16_t nlri_type;

  /** Length of the rest of the NLRI excluding type and itslef */
  uint16_t nlri_len;

  /** Contains NLRI information source protocol */
  uint8_t protocol_id;

  /** Identifier has info of Routing Universe */
  uint64_t identifier;

  struct nlri_ls {

    struct node_nlri {

      /** type of the node descriptor */
      uint16_t type;

      /** Length of node descriptor (len = variable) */
      uint16_t len;

      struct {
        /** Array of node descriptors */
        parsebgp_bgp_update_mp_link_state_node_descriptor_t *nodes;

        /** Allocated length of nodes */
        int _nodes_alloc_cnt;

        /** Populated length of nodes */
        int nodes_cnt;
      } local_node_desc;

    } node_nlri;

    struct link_nlri {

      struct {
        /** type of the local node descriptor */
        uint16_t type;

        /** Length of local node descriptor (len = variable) */
        uint16_t len;

        /** Array of node descriptors */
        parsebgp_bgp_update_mp_link_state_node_descriptor_t *nodes;

        /** Allocated length of nodes */
        int _nodes_alloc_cnt;

        /** Populated length of nodes */
        int nodes_cnt;
      } local_node_desc;

      struct {
        /** type of the remote node descriptor */
        uint16_t type;

        /** Length of remote node descriptor (len = variable) */
        uint16_t len;

        /** Array of node descriptors */
        parsebgp_bgp_update_mp_link_state_node_descriptor_t *nodes;

        /** Allocated length of nodes */
        int _nodes_alloc_cnt;

        /** Populated length of nodes */
        int nodes_cnt;
      } remote_node_desc;

      struct {
        /** type of the link descriptor */
        uint16_t type;

        /** Length of link descriptor (len = variable) */
        uint16_t len;

        /** Array of node descriptors */
        parsebgp_bgp_update_mp_link_state_link_descriptor_t *links;

        /** Allocated length of nodes */
        int _links_alloc_cnt;

        /** Populated length of nodes */
        int links_cnt;
      } link_desc;

    } link_nlri;

    struct prefix_nlri_ipv4_ipv6 {

      struct {
        /** type of the prefix descriptor */
        uint16_t type;

        /** Length of prefix descriptor (len = variable) */
        uint16_t len;

        /** Array of node descriptors */
        parsebgp_bgp_update_mp_link_state_node_descriptor_t *nodes;

        /** Allocated length of nodes */
        int _nodes_alloc_cnt;

        /** Populated length of nodes */
        int nodes_cnt;
      } local_node_desc;

      struct {

        /** type of the prefix descriptor */
        uint16_t type;

        /** Length of prefix descriptor (len = variable) */
        uint16_t len;

        /** Array of node descriptors */
        parsebgp_bgp_update_mp_link_state_prefix_descriptor_t *pref;

        /** Allocated length of nodes */
        int _pref_alloc_cnt;

        /** Populated length of nodes */
        int pref_cnt;
      } prefix_desc;

    } prefix_nlri;

  } nlri_ls;

} parsebgp_bgp_update_mp_link_state_t;

/**
 * MP_REACH_NLRI
 */
typedef struct parsebgp_bgp_update_mp_reach {

  /** AFI */
  uint16_t afi;

  /** SAFI */
  uint8_t safi;

  /** Next-Hop Length (bytes) */
  uint8_t next_hop_len;

  /** Next-Hop Address */
  uint8_t next_hop[16];

  /** Next-Hop Link-Local Address (only used for IPv6 and when next_hop_len is
      32) */
  uint8_t next_hop_ll[16];

  /** Reserved (always zero) */
  uint8_t reserved;

  /** NLRI information */
  parsebgp_bgp_prefix_t *nlris;

  /** Number of allocated NLRIs (INTERNAL) */
  int _nlris_alloc_cnt;

  /** (Inferred) number of NLRIs */
  int nlris_cnt;

  struct mp_ls {

    /** MP LS NLRI information */
    parsebgp_bgp_update_mp_link_state_t *mp_ls;

    /** Number of allocated NLRIs (INTERNAL) */
    int _mp_ls_alloc_cnt;

    /** (Inferred) number of NLRIs */
    int mp_ls_cnt;

  }mp_ls;


} parsebgp_bgp_update_mp_reach_t;

/**
 * MP_UNREACH_NLRI
 */
typedef struct parsebgp_bgp_update_mp_unreach {

  /** AFI */
  uint16_t afi;

  /** SAFI */
  uint8_t safi;

  /** NLRI information */
  parsebgp_bgp_prefix_t *withdrawn_nlris;

  /** Number of allocated NLRIs (INTERNAL) */
  int _withdrawn_nlris_alloc_cnt;

  /** (Inferred) number of Withdrawn NLRIs */
  int withdrawn_nlris_cnt;

  struct mp_ls {

    /** MP LS NLRI information */
    parsebgp_bgp_update_mp_link_state_t *mp_ls;

    /** Number of allocated NLRIs (INTERNAL) */
    int _mp_ls_alloc_cnt;

    /** (Inferred) number of NLRIs */
    int mp_ls_cnt;

  }mp_ls;

} parsebgp_bgp_update_mp_unreach_t;

/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_mp_reach_t *msg,
                                    uint8_t *buf, size_t *lenp, size_t remain);

/** Destroy an MP_REACH message */
void parsebgp_bgp_update_mp_reach_destroy(parsebgp_bgp_update_mp_reach_t *msg);

/** Clear an MP_REACH message */
void parsebgp_bgp_update_mp_reach_clear(parsebgp_bgp_update_mp_reach_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_REACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_reach_dump(parsebgp_bgp_update_mp_reach_t *msg,
                                       int depth);

/** Decode an MP_UNREACH message */
parsebgp_error_t parsebgp_bgp_update_mp_unreach_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_mp_unreach_t *msg, uint8_t *buf,
  size_t *lenp, size_t remain);

/** Destroy an MP_UNREACH message */
void parsebgp_bgp_update_mp_unreach_destroy(
  parsebgp_bgp_update_mp_unreach_t *msg);

/** Clear an MP_UNREACH message */
void parsebgp_bgp_update_mp_unreach_clear(
  parsebgp_bgp_update_mp_unreach_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_UNREACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_unreach_dump(parsebgp_bgp_update_mp_unreach_t *msg,
                                         int depth);

#endif /* __PARSEBGP_BGP_UPDATE_MP_REACH_H */
