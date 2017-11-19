#ifndef __PARSEBGP_BGP_UPDATE_LINK_STATE_H
#define __PARSEBGP_BGP_UPDATE_LINK_STATE_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <stdint.h>
#include <sys/types.h>


/**
 * Node Attribute types
 */
typedef enum {

/** Node Attr: Multi-Topology ID (len=variable) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_MT_ID = 263,

  /** Node Attr: Flag bits (len=1) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_FLAG = 1024,

  /** Node Attr: Opaque Node (len=variable) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_OPAQUE = 1025,

  /** Node Attr: Node Name (len=variable) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_NAME = 1026,

  /** Node Attr: IS-IS Area Identifier (len=variable) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_ISIS_AREA_ID = 1027,

  /** Node Attr: Local NODE IPv4 Router ID (len=4) [RFC5305] */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_IPV4_ROUTER_ID_LOCAL = 1028,

  /** Node Attr: Local NODE IPv6 Router ID (len=16) [RFC6119] */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_IPV6_ROUTER_ID_LOCAL = 1029,

      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_CAPABILITIES = 1034,
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_ALGORITHM = 1035,

      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_LOCAL_BLOCK = 1036,
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_SRMS_PREF = 1037,

} parsebgp_bgp_update_bgp_ls_attr_node_type_t;

/**
 * Link Attribute types
 */
typedef enum {

  /** Link Attr: IPv4 Router ID of Remote Node 134/- (rfc5305/4.3) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE = 1030,

  /** Link Attr: IPv6 Router ID of Remote Node 140/- (rfc6119/4.1) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE = 1031,

  /** Link Attr: Administrative group (color) 22/3 (rfc5305/3.1) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP = 1088,

  /** Link Attr: Maximum link bandwidth 22/9 (rfc5305/3.3) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW = 1089,

  /** Link Attr: Maximum reservable link bandwidth 22/10 (rfc5305/3.5) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW = 1090,

  /** Link Attr: Unreserved bandwidth 22/11 (RFC5305/3.6) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW = 1091,

  /** Link Attr: TE default metric 22/18 */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC = 1092,

  /** Link Attr: Link protection type 22/20 (rfc5307/1.2) */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE = 1093,

  /** Link Attr: MPLS protocol mask */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK = 1094,

  /** Link Attr: IGP link metric */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC = 1095,

  /** Link Attr: Shared risk link group */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG = 1096,

  /** Link Attr: Opaque link attribute */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE = 1097,

  /** Link Attr: Link name */
      PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME = 1098

} parsebgp_bgp_update_bgp_ls_attr_link_type_t;

/**
 * Prefix Attribute types
 */
typedef enum ATTR_PREFIX_TYPES {

  /** Prefix Attr: IGP Flags (len=1) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_IGP_FLAGS = 1152,

  /** Prefix Attr: Route Tag (len=4*n) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_ROUTE_TAG = 1153,

  /** Prefix Attr: Extended Tag (len=8*n) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_EXTEND_ROUTE_TAG = 1154,

  /** Prefix Attr: Prefix Metric (len=4) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_PREFIX_METRIC = 1155,

  /** Prefix Attr: OSPF Forwarding Address */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_OSPF_FWD_ADDR = 1156,

  /** Prefix Attr: Opaque prefix attribute (len=variable) */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_OPAQUE_PREFIX = 1157,

  /** Prefix Attr: Prefix SID attribute */
      PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_SID = 1158

} parsebgp_bgp_update_bgp_ls_attr_prefix_type_t;

/**
 * Node attributes
 */
typedef struct parsebgp_bgp_update_bgp_ls_attr_node_attr {

  /** Node Attr: Multi-Topology ID (len=variable) */
  struct {

    /** Array of mt_ids */
    uint16_t *ids;

    /** Allocated length of ids */
    int _ids_alloc_cnt;

    /** Populated ids count */
    int ids_cnt;

  } node_mt_id;

  /** Node Attr: Flag bits (len=1) */
  uint8_t node_flag_bits;

  /** Node Attr: Opaque Node (len=variable) */
  struct {

    /** Array of opaque values */
    uint8_t *opaque;

    /** Allocated length of opaque */
    int _opaque_alloc_cnt;

    /** Populated opaque count */
    int opaque_cnt;

  } node_opaque;

  /** Node Attr: Node Name (len=variable) */
  char node_name[256];

  /** Node Attr: IS-IS Area Identifier (len=variable) */
  struct {

    /** Array of area_ids */
    uint8_t *ids;

    /** Allocated length of ids */
    int _ids_alloc_cnt;

    /** Populated ids count */
    int ids_cnt;

  } node_isis_area_id;

  /** Node Attr: Local NODE IPv4 Router ID (len=4) [RFC5305] */
  uint8_t node_ipv4_router_id_local[4];

  /** Node Attr: Local NODE IPv6 Router ID (len=16) [RFC6119] */
  uint8_t node_ipv6_router_id_local[16];

  /** Node Attr: SR Algorithm (len=variable) */
  struct {

    /** Array of algo ids */
    uint8_t *algo;

    /** Allocated length of ids */
    int _algo_alloc_cnt;

    /** Populated ids count */
    int algo_cnt;

  } node_sr_algo;

  uint8_t node_sr_srms_pref;

} parsebgp_bgp_update_bgp_ls_attr_node_attr_t;

/**
 * Link attributes
 */
typedef struct parsebgp_bgp_update_bgp_ls_attr_link_attr {

  /** These two fields ipv4_router_id_local and ipv6_router_id_local are populated in node attributes*/

  /** Link Attr: IPv4 Router ID of Remote Node 134/- (rfc5305/4.3) */
  uint8_t link_ipv4_router_id_remote[4];

  /** Link Attr: IPv6 Router ID of Remote Node 140/- (rfc6119/4.1) */
  uint8_t link_ipv6_router_id_remote[16];

  /** Link Attr: Administrative group (color) 22/3 (rfc5305/3.1) */
  uint32_t link_admin_group;

  /** Link Attr: Maximum link bandwidth 22/9 (rfc5305/3.3) */
  uint8_t link_max_link_bw[4];

  /** Link Attr: Maximum reservable link bandwidth 22/10 (rfc5305/3.5) */
  uint8_t link_max_resv_bw[4];

  /** Link Attr: Unreserved bandwidth 22/11 (RFC5305/3.6) */
  uint8_t link_unresv_bw[32];

  /** Link Attr: TE default metric 22/18 */
  uint32_t link_te_def_metric;

  /** Link Attr: Link protection type 22/20 (rfc5307/1.2) */
  uint16_t link_protective_type;

  /** Link Attr: MPLS protocol mask */
  uint8_t link_mpls_protocal_mask;

  /** Link Attr: IGP link metric */
  uint32_t link_igp_metric;

  /** Link Attr: Shared risk link group */
  struct {

    /** Array of opaque values */
    uint32_t *srlg;

    /** Allocated length of opaque */
    int _srlg_alloc_cnt;

    /** Populated opaque count */
    int srlg_cnt;

  } link_srlg;

  /** Link Attr: Opaque link attribute */
  struct {

    /** Array of opaque values */
    uint8_t *opaque;

    /** Allocated length of opaque */
    int _opaque_alloc_cnt;

    /** Populated opaque count */
    int opaque_cnt;

  } link_opaque;

  /** Link Attr: Link name */
  char link_name[256];

} parsebgp_bgp_update_bgp_ls_attr_link_attr_t;

/**
 * Prefix attributes
 */
typedef struct parsebgp_bgp_update_bgp_ls_attr_prefix_attr {

  /** Prefix Attr: IGP Flags (len=1) */
  uint8_t prefix_igp_flags;

  /** Prefix Attr: Route Tag (len=4*n) */
  struct {

    /** Array of route tags */
    uint32_t *tags;

    /** Allocated length of tags */
    int _tags_alloc_cnt;

    /** Populated tags count */
    int tags_cnt;

  } prefix_route_tag;

  /** Prefix Attr: Extended Tag (len=8*n) */
  struct {

    /** Array of route extended tags */
    uint64_t *ex_tags;

    /** Allocated length of extended tags */
    int _ex_tags_alloc_cnt;

    /** Populated extended tags count */
    int ex_tags_cnt;

  } prefix_extended_route_tag;

  /** Prefix Attr: Prefix Metric (len=4) */
  uint32_t prefix_metric;

  /** Prefix Attr: OSPF Forwarding Address */
  uint8_t prefix_ospf_forwarding_address[4];

  /** Prefix Attr: Opaque prefix attribute (len=variable) */
  struct {

    /** Array of opaque values */
    uint8_t *opaque;

    /** Allocated length of opaque */
    int _opaque_alloc_cnt;

    /** Populated opaque count */
    int opaque_cnt;

  } prefix_opaque;

  /** Prefix Attr: Sid prefix attribute (len=variable) */
  struct {

    /** Array of data for prefic sid */
    uint8_t *sid;

    /** Allocated length of sid */
    int _sid_alloc_cnt;

    /** Populated sid value */
    int sid_count;

  } prefix_sid;

} parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t;

/**
 * BGP LINK STATE
 */
typedef struct parsebgp_bgp_update_bgp_ls_attr {

  /** Type of link state attribute*/
  uint16_t type;

  /** Length of link state attribute*/
  uint16_t len;

  /** Union of node, link and prefix values*/
  struct {

    /** Node attribute value*/
    parsebgp_bgp_update_bgp_ls_attr_node_attr_t node;

    /** Link attribute value*/
    parsebgp_bgp_update_bgp_ls_attr_link_attr_t link;

    /** Prefix attribute value*/
    parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t prefix;

  } attr;

} parsebgp_bgp_update_bgp_ls_attr_t;

/**
 * BGP LINK STATE
 */
typedef struct parsebgp_bgp_update_bgp_ls {

  /** Array of (bgp_ls_attrs_cnt) BGP LINK STATE */
  parsebgp_bgp_update_bgp_ls_attr_t *attrs;

  /** Allocated length of the attrs_used array (INTERNAL) */
  int _attrs_alloc_cnt;

  /** Number of populated Link State Attributes in the attrs field */
  int attrs_cnt;

} parsebgp_bgp_update_bgp_ls_t;

/** Decode a BGP LS message */
parsebgp_error_t
parsebgp_bgp_update_bgp_ls_decode(parsebgp_opts_t *opts,
                                  parsebgp_bgp_update_bgp_ls_t *msg,
                                  uint8_t *buf, size_t *lenp, size_t remain);

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
void parsebgp_bgp_update_bgp_ls_dump(
    parsebgp_bgp_update_bgp_ls_t *msg, int depth);

/** Destroy a BGP Link State message */
void parsebgp_bgp_update_bgp_ls_destroy(
    parsebgp_bgp_update_bgp_ls_t *msg);

/** Clear a BGP Link State message */
void parsebgp_bgp_update_bgp_ls_clear(
    parsebgp_bgp_update_bgp_ls_t *msg);

#endif /* __PARSEBGP_BGP_UPDATE_LINK_STATE_H */
