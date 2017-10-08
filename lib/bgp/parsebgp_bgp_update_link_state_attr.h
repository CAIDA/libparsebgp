#ifndef __PARSEBGP_BGP_UPDATE_LINK_STATE_H
#define __PARSEBGP_BGP_UPDATE_LINK_STATE_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include "../parsebgp_error.h"
#include "../parsebgp_opts.h"
#include <stdint.h>
#include <sys/types.h>

/**
 * Node Attribute types
 */
enum attr_node_types {
  ATTR_NODE_MT_ID = 263,  ///< Multi-Topology Identifier (len=variable)
  ATTR_NODE_FLAG = 1024,  ///< Node Flag Bits see enum NODE_FLAG_TYPES (len=1)
  ATTR_NODE_OPAQUE,       ///< Opaque Node Properties (len=variable)
  ATTR_NODE_NAME,         ///< Node Name (len=variable)
  ATTR_NODE_ISIS_AREA_ID, ///< IS-IS Area Identifier (len=variable)
  ATTR_NODE_IPV4_ROUTER_ID_LOCAL,   ///< Local NODE IPv4 Router ID (len=4)
                                    ///< (rfc5305/4.3)
  ATTR_NODE_IPV6_ROUTER_ID_LOCAL,   ///< Local NODE IPv6 Router ID (len=16)
                                    ///< (rfc6119/4.1)
  ATTR_NODE_SR_CAPABILITIES = 1034, ///< SR Capabilities
  ATTR_NODE_SR_ALGORITHM,           ///< SR Algorithm
  ATTR_NODE_SR_LOCAL_BLOCK,         ///< SR Local block
  ATTR_NODE_SR_SRMS_PREF            ///< SR mapping server preference
};

enum sub_tlv_types {
  SUB_TLV_SID_LABEL = 1161 ///< SID/Label Sub-TLV
};

/**
 * Link Attribute types
 */
enum attr_link_types {
  ATTR_LINK_IPV4_ROUTER_ID_LOCAL =
    1028, ///< IPv4 Router-ID of local node 134/- (rfc5305/4.3)
  ATTR_LINK_IPV6_ROUTER_ID_LOCAL,  ///< IPv6 Router-ID of local node 140/-
                                   ///< (rfc6119/4.1)
  ATTR_LINK_IPV4_ROUTER_ID_REMOTE, ///< IPv4 Router-ID of remote node 134/-
                                   ///< (rfc5305/4.3)
  ATTR_LINK_IPV6_ROUTER_ID_REMOTE, ///< IPv6 Router-ID of remote node 140-
                                   ///< (rfc6119/4.1)
  ATTR_LINK_ADMIN_GROUP =
    1088,                  ///< Administrative group (color) 22/3 (rfc5305/3.1)
  ATTR_LINK_MAX_LINK_BW,   ///< Maximum link bandwidth 22/9 (rfc5305/3.3)
  ATTR_LINK_MAX_RESV_BW,   ///< Maximum reservable link bandwidth 22/10
                           ///< (rfc5305/3.5)
  ATTR_LINK_UNRESV_BW,     ///< Unreserved bandwidth 22/11 (RFC5305/3.6)
  ATTR_LINK_TE_DEF_METRIC, ///< TE default metric 22/18
  ATTR_LINK_PROTECTION_TYPE, ///< Link protection type 22/20 (rfc5307/1.2)
  ATTR_LINK_MPLS_PROTO_MASK, ///< MPLS protocol mask
  ATTR_LINK_IGP_METRIC,      ///< IGP link metric
  ATTR_LINK_SRLG,            ///< Shared risk link group
  ATTR_LINK_OPAQUE,          ///< Opaque link attribute
  ATTR_LINK_NAME,            ///< Link name
  ATTR_LINK_ADJACENCY_SID,   ///< Peer Adjacency SID
                           ///< (https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.2.1)

  ATTR_LINK_PEER_EPE_NODE_SID =
    1101, ///< Peer Node SID (draft-ietf-idr-bgpls-segment-routing-epe)
  ATTR_LINK_PEER_EPE_ADJ_SID, ///< Peer Adjacency SID
                              ///< (draft-ietf-idr-bgpls-segment-routing-epe)
  ATTR_LINK_PEER_EPE_SET_SID  ///< Peer Set SID
                              ///< (draft-ietf-idr-bgpls-segment-routing-epe)
};

/**
 * MPLS Protocol Mask BIT flags/codes
 */
enum MPLS_PROTO_MASK_CODES {
  MPLS_PROTO_MASK_LDP = 0x80, ///< Label distribuion protocol (rfc5036)
  MPLS_PROTO_RSVP_TE = 0x40   ///< Extension to RSVP for LSP tunnels (rfc3209)
};

/**
 * Prefix Attribute types
 */
enum ATTR_PREFIX_TYPES {
  ATTR_PREFIX_IGP_FLAGS = 1152, ///< IGP Flags (len=1)
  ATTR_PREFIX_ROUTE_TAG,        ///< Route Tag (len=4*n)
  ATTR_PREFIX_EXTEND_TAG,       ///< Extended Tag (len=8*n)
  ATTR_PREFIX_PREFIX_METRIC,    ///< Prefix Metric (len=4)
  ATTR_PREFIX_OSPF_FWD_ADDR,    ///< OSPF Forwarding Address
  ATTR_PREFIX_OPAQUE_PREFIX,    ///< Opaque prefix attribute (len=variable)
  ATTR_PREFIX_SID               ///< Prefix-SID TLV (len=variable)
};

#define IEEE_INFINITY 0x7F800000
#define MINUS_INFINITY (int32_t)0x80000000L
#define PLUS_INFINITY 0x7FFFFFFF
#define IEEE_NUMBER_WIDTH 32 /* bits in number */
#define IEEE_EXP_WIDTH 8     /* bits in exponent */
#define IEEE_MANTISSA_WIDTH (IEEE_NUMBER_WIDTH - 1 - IEEE_EXP_WIDTH)
#define IEEE_SIGN_MASK 0x80000000
#define IEEE_EXPONENT_MASK 0x7F800000
#define IEEE_MANTISSA_MASK 0x007FFFFF

#define IEEE_IMPLIED_BIT (1 << IEEE_MANTISSA_WIDTH)
#define IEEE_INFINITE ((1 << IEEE_EXP_WIDTH) - 1)
#define IEEE_BIAS ((1 << (IEEE_EXP_WIDTH - 1)) - 1)

/**
 * Node (local and remote) common fields
 */
typedef struct node_descriptor {
    uint16_t type;
    uint16_t len;
    uint32_t asn;             ///< BGP ASN
    uint32_t bgp_ls_id;       ///< BGP-LS Identifier
    uint8_t igp_router_id[8]; ///< IGP router ID
    uint8_t ospf_area_Id[4];  ///< OSPF area ID
    uint32_t
            bgp_router_id; ///< BGP router ID (draft-ietf-idr-bgpls-segment-routing-epe)
    uint8_t hash_bin[16]; ///< binary hash for node descriptor
} node_descriptor;

/**
 * Link Descriptor common fields
 */
typedef struct link_descriptor {
    uint16_t type;
    uint16_t len;
    uint32_t local_id;     ///< Link Local ID
    uint32_t remote_id;    ///< Link Remote ID
    uint8_t intf_addr[16]; ///< Interface binary address
    uint8_t nei_addr[16];  ///< Neighbor binary address
    uint32_t mt_id;        ///< Multi-Topology ID
    int is_ipv4;           ///< True if IPv4, false if IPv6
} link_descriptor;

/**
 * Prefix descriptor common fields
 */
typedef struct prefix_descriptor {
    uint16_t type;
    uint16_t len;
    char ospf_route_type[32]; ///< OSPF Route type in string form for DB enum
    uint32_t mt_id;           ///< Multi-Topology ID
    uint8_t prefix[16];       ///< Prefix binary address
    uint8_t prefix_bcast[16]; ///< Prefix broadcast/ending binary address
    uint8_t prefix_len;       ///< Length of prefix in bits
} prefix_descriptor;

typedef struct mp_reach_ls {
    uint16_t nlri_type;
    uint16_t nlri_len;
    uint8_t proto_id;
    uint64_t id;
    union nlri_ls {
        struct node_nlri {
            uint16_t type;
            uint16_t len;
            uint16_t count_local_nodes;
            node_descriptor *local_nodes;
        } node_nlri;

        struct link_nlri {
            uint16_t type;
            uint16_t len;
            uint16_t count_local_nodes;
            node_descriptor *local_nodes;
            uint16_t count_remote_nodes;
            node_descriptor *remote_nodes;
            uint16_t count_link_desc;
            link_descriptor *link_desc;
        } link_nlri;

        struct prefix_nlri_ipv4_ipv6 {
            uint16_t type;
            uint16_t len;
            uint16_t count_local_nodes;
            node_descriptor *local_nodes;
            uint16_t count_prefix_desc;
            prefix_descriptor *prefix_desc;
        } prefix_nlri_ipv4_ipv6;
    } nlri_ls;
} mp_reach_ls;

typedef struct link_peer_epe_node_sid {
    uint8_t L_flag;
    uint8_t V_flag;
    uint32_t sid_3;
    uint32_t sid_4;
    uint8_t ip_raw[16];
} link_peer_epe_node_sid;

/**
 * BGP LINK STATE
 */
typedef struct parsebgp_bgp_update_bgp_ls_attr {
    uint16_t type;
    uint16_t len;
    union node_attr {
        uint8_t node_flag_bits;
        uint8_t node_ipv4_router_id_local[4];
        uint8_t node_ipv6_router_id_local[16];
        //TODO: check the max length of IS-IS AREA ID
        uint8_t node_isis_area_id[256];
        uint8_t node_name[256];
        uint8_t mt_id[256];
    } node;

    union link_attr {
        uint8_t  link_ipv4_router_id_local[4];
        uint8_t  link_ipv6_router_id_local[16];
        uint8_t  link_ipv4_router_id_remote[4];
        uint8_t  link_ipv6_router_id_remote[16];
        uint32_t link_admin_group;
        uint32_t link_max_link_bw;
        uint32_t link_max_resv_bw;
        uint32_t link_unresv_bw[8];
        uint32_t link_te_def_metric;
        uint8_t  link_protective_type[2];
        uint8_t  link_mpls_protocal_mask;
        uint32_t link_igp_metric;
        uint8_t  link_name[256];
        link_peer_epe_node_sid link_peer_epe_sid;
    } link;

    union prefix_attr {
        uint8_t  prefix_igp_flags;
        uint32_t prefix_route_tag;
        uint64_t prefix_extended_route_tag;
        uint32_t prefix_metric;
        uint8_t  prefix_ospf_forwarding_address[16];
        uint8_t  prefix_opaque_prefix_attributr[255];
    } prefix;
} parsebgp_bgp_update_bgp_ls_attr_t;

/**
 * BGP LINK STATE
 */
typedef struct parsebgp_bgp_update_bgp_ls {

    /** Array of (bgp_ls_attrs_cnt) BGP LINK STATE */
    parsebgp_bgp_update_bgp_ls_attr_t *bgp_ls;

    /** Allocated length of the attrs_used array (INTERNAL) */
    int _bgp_ls_used_alloc_cnt;

    /** Number of populated Link State Attributes in the attrs field */
    int bgp_ls_attrs_cnt;

} parsebgp_bgp_update_bgp_ls_t;


/** Decode a BGP LS message */
parsebgp_error_t
parsebgp_bgp_update_bgp_ls_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_bgp_ls_t *msg,
                                    uint8_t *buf, size_t *lenp, size_t remain);

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
parsebgp_error_t
parsebgp_bgp_update_bgp_ls_tlv_decode(parsebgp_opts_t *opts,
                                          parsebgp_bgp_update_bgp_ls_attr_t *msg,
                                          uint8_t *buf, size_t *lenp);

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

/** Destroy an EXTENDED COMMUNITIES message */
void parsebgp_bgp_update_bgp_ls_destroy(
        parsebgp_bgp_update_bgp_ls_t *msg);

/** Clear an EXTENDED COMMUNITIES message */
void parsebgp_bgp_update_bgp_ls_clear(
        parsebgp_bgp_update_bgp_ls_t *msg);

#endif /* __PARSEBGP_BGP_UPDATE_LINK_STATE_H */
