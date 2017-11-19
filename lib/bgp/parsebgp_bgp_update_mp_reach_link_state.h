#ifndef __PARSEBGP_BGP_UPDATE_MP_MP_REACH_LINK_STATE_H
#define __PARSEBGP_BGP_UPDATE_MP_MP_REACH_LINK_STATE_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include "../parsebgp_opts.h"
#include "parsebgp_bgp_update_mp_reach.h"
#include "../parsebgp_error.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * Defines the BGP link state NLRI types
 *      https://tools.ietf.org/html/draft-ietf-idr-ls-distribution-10#section-3.2
 */
typedef enum {

  /** NLRI TYPE: NODE NLRI */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_TYPE_NODE = 1,

  /** NLRI TYPE: LINK NLRI */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_TYPE_LINK = 2,

  /** NLRI TYPE: IPV4 PREFIX NLRI */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_TYPE_IPV4_PREFIX = 3,

  /** NLRI TYPE: IPV^ PREFIX NLRI */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_TYPE_IPV6_PREFIX = 4

} parsebgp_bgp_update_mp_reach_link_state_nlri_types_t;

/**
 * TODO: check if this is required
 * Defines the NLRI protocol-id values
 */
typedef enum {

  /** NLRI information source protocol: IS-IS Level 1 */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_PROTO_ISIS_L1 = 1,

  /** NLRI information source protocol: IS-IS Level 2 */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_PROTO_ISIS_L2 = 2,

  /** NLRI information source protocol: OSPFv2 */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_PROTO_OSPFV2 = 3,

  /** NLRI information source protocol: DIRECT */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_PROTO_DIRECT = 4,

  /** NLRI information source protocol: Static configuration */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_PROTO_STATIC = 5,

  /** NLRI information source protocol: OSPFv3 */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NLRI_PROTO_OSPFV3 = 6,

} parsebgp_bgp_update_mp_reach_link_state_protocol_ids_t;

typedef enum {

  /** Routing Universe: Default Layer 3 Routing topology */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_DEF_LAYER_3_ROUTING_TOPOLOGY = 0,

} parsebgp_bgp_update_mp_reach_link_state_identifier_t;

/**
 * Node descriptor Sub-TLV's
 *      Used by both remote and local node descriptors
 */
typedef enum {
  //TODO: check this field
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_LOCAL_DESCR =
      256,  ///< Local node descriptor
  //TODO: check this field
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_REMOTE_DESCR =
      257, ///< Remote node descriptor

  /** Node Descriptor: Autonomous System (len = 4) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_AS = 512,

  /** Node Descriptor: BGP LS Identifier (len = 4) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_BGP_LS_ID = 513,

  /** Node Descriptor: OSPF Area ID (len = 4) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_OSPF_AREA_ID = 514,

  /** Node Descriptor: IGP Router ID (len = variable) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_IGP_ROUTER_ID = 515,

  //TODO: check this field
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_NODE_DESCR_BGP_ROUTER_ID = 516 ///< BGP Router ID
  ///< (draft-ietf-idr-bgpls-segment-routing-epe)
} parsebgp_bgp_update_mp_reach_link_state_node_descr_sub_types_t;

/**
 * Link Descriptor Sub-TLV's
 */
typedef enum {

  /** Link Descriptor: Link Local/Remote Identifiers 22/4 (rfc5307/1.1) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_LINK_DESCR_ID = 258,

  /** Link Descriptor: IPv4 interface address 22/6 (rfc5305/3.2) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_LINK_DESCR_IPV4_INTF_ADDR = 259,

  /** Link Descriptor: IPv4 neighbor address 22/8 (rfc5305/3.3) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_LINK_DESCR_IPV4_NEI_ADDR = 260,

  /** Link Descriptor: IPv4 interface address 22/6 (rfc5305/3.2) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_LINK_DESCR_IPV6_INTF_ADDR = 261,

  /** Link Descriptor: IPv6 neighbor address 22/13 (rfc6119/4.3) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_LINK_DESCR_IPV6_NEI_ADDR = 262,

  /** Link Descriptor: Multi-Topology Identifier */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_LINK_DESCR_MT_ID = 263

} parsebgp_bgp_update_mp_reach_link_state_link_descr_sub_types_t;

/**
 * Prefix Descriptor Sub-TLV's
 */
typedef enum prefix_descr_sub_types {

  /** Prefix Descriptor: Multi-Topology Identifier (len = variable) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_PREFIX_DESCR_MT_ID = 263,

  /** Prefix Descriptor: OSPF Route Type (len=1) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_PREFIX_DESCR_OSPF_ROUTE_TYPE = 264,

  /** Prefix Descriptor: IP Reachability Information (len=variable) */
      PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_PREFIX_DESCR_IP_REACH_INFO = 265

} parsebgp_bgp_update_mp_reach_link_state_prefix_descr_sub_types_t;

/**
 * OSPF Route Types
 */
//TODO: Not sure if this is required
typedef enum ospf_route_types {
  OSPF_RT_INTRA_AREA = 1, ///< Intra-Area
  OSPF_RT_INTER_AREA,     ///< Inter-Area
  OSPF_RT_EXTERNAL_1,     ///< External type 1
  OSPF_RT_EXTERNAL_2,     ///< External type 2
  OSPF_RT_NSSA_1,         ///< NSSA type 1
  OSPF_RT_NSSA_2          ///< NSSA type 2
};

/**
 * Node (local and remote) common fields
 */
typedef struct parsebgp_bgp_update_mp_reach_link_state_node_descriptor {

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
} parsebgp_bgp_update_mp_reach_link_state_node_descriptor_t;

/**
 * Link Descriptor common fields
 */
typedef struct parsebgp_bgp_update_mp_reach_link_state_link_descriptor {

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

} parsebgp_bgp_update_mp_reach_link_state_link_descriptor_t;

/**
 * Prefix descriptor common fields
 */
typedef struct parsebgp_bgp_update_mp_reach_link_state_prefix_descriptor {

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

} parsebgp_bgp_update_mp_reach_link_state_prefix_descriptor_t;

typedef struct parsebgp_bgp_update_mp_reach_link_state {

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
        parsebgp_bgp_update_mp_reach_link_state_node_descriptor_t *nodes;

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
        parsebgp_bgp_update_mp_reach_link_state_node_descriptor_t *nodes;

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
        parsebgp_bgp_update_mp_reach_link_state_node_descriptor_t *nodes;

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
        parsebgp_bgp_update_mp_reach_link_state_link_descriptor_t *links;

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
        parsebgp_bgp_update_mp_reach_link_state_node_descriptor_t *nodes;

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
        parsebgp_bgp_update_mp_reach_link_state_prefix_descriptor_t *pref;

        /** Allocated length of nodes */
        int _pref_alloc_cnt;

        /** Populated length of nodes */
        int pref_cnt;
      } prefix_desc;

    } prefix_nlri;

  } nlri_ls;

} parsebgp_bgp_update_mp_reach_link_state_t;

/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_link_state_decode(parsebgp_opts_t *opts,
                                               parsebgp_bgp_update_mp_reach_t *msg,
                                               uint8_t *buf,
                                               size_t *lenp,
                                               size_t remain);

#endif __PARSEBGP_BGP_UPDATE_MP_REACH_LINK_STATE_H