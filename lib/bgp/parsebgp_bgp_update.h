#ifndef __PARSEBGP_BGP_UPDATE_H
#define __PARSEBGP_BGP_UPDATE_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_bgp_update_ext_communities.h"
#include "parsebgp_bgp_update_mp_reach.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * BGP ORIGIN Path Attribute values
 */
typedef enum {

  /** IGP - Network Layer Reachability Information is interior to the
      originating AS */
  PARSEBGP_BGP_UPDATE_ORIGIN_IGP = 0,

  /** EGP - Network Layer Reachability Information learned via the EGP protocol
      [RFC904] */
  PARSEBGP_BGP_UPDATE_ORIGIN_EGP = 1,

  /** INCOMPLETE - Network Layer Reachability Information learned by some other
      means */
  PARSEBGP_BGP_UPDATE_ORIGIN_INCOMPLETE = 2,

} parsebgp_bgp_update_origin_type_t;

/**
 * AS Path Segment Types
 */
typedef enum {

  /** AS_SET: Unordered set of ASes a route in the UPDATE message has
      traversed */
  PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SET = 1,

  /** AS_SEQ: Ordered set of ASes a route in the UPDATE message has traversed */
  PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SEQ = 2,

  /** AS Path Segment Confederation Set */
  PARSEBGP_BGP_UPDATE_AS_PATH_SEG_CONFED_SET = 3,

  /** AS Path Segment Confederation Sequence */
  PARSEBGP_BGP_UPDATE_AS_PATH_SEG_CONFED_SEQ = 4,

} parsebgp_bgp_update_as_path_seg_type_t;

/**
 * AS Path Segment (supports both 2 and 4-byte ASNs)
 */
typedef struct parsebgp_bgp_update_as_path_seg {

  /** Segment Type (parsebgp_bgp_update_as_path_seg_type_t) */
  uint8_t type;

  /** Number of ASNs in the segment */
  uint8_t asns_cnt;

  /** Array of (asn_cnt) ASNs */
  uint32_t *asns;

} parsebgp_bgp_update_as_path_seg_t;

/**
 * AS Path (supports both 2 and 4-byte ASNs)
 */
typedef struct parsebgp_bgp_update_as_path {

  /** Array of AS Path Segments */
  parsebgp_bgp_update_as_path_seg_t *segs;

  /** Number of Segments in the AS Path */
  int segs_cnt;

} parsebgp_bgp_update_as_path_t;

/**
 * AGGREGATOR (supports both 2- and 4-byte ASNs)
 */
typedef struct parsebgp_bgp_update_aggregator {

  /** ASN */
  uint32_t asn;

  /** IP Address (TODO: Does this need to support IPv6?) */
  uint8_t addr[4];

} parsebgp_bgp_update_aggregator_t;

/**
 * COMMUNITIES
 */
typedef struct parsebgp_bgp_update_communities {

  /** Set of communities */
  uint32_t *communities;

  /** (Inferred) Number of communities in the array */
  int communities_cnt;

} parsebgp_bgp_update_communities_t;

/**
 * CLUSTER_LIST
 */
typedef struct parsebgp_bgp_update_cluster_list {

  /** Array of CLUSTER_IDs */
  uint32_t *cluster_ids;

  /** (Inferred) Number of CLUSTER_IDs in the array */
  int cluster_ids_cnt;

} parsebgp_bgp_update_cluster_list_t;

/**
 * AS_PATHLIMIT
 */
typedef struct parsebgp_bgp_update_as_pathlimit {

  /** Upper bound on the number of ASes in the AS_PATH attribute */
  uint8_t max_asns;

  /** AS Number */
  uint32_t asn;

} parsebgp_bgp_update_as_pathlimit_t;

/**
 * LARGE COMMUNITY
 */
typedef struct parsebgp_bgp_update_large_community {

  /** Global Administrator (ASN) */
  uint32_t global_admin;

  /** Local Data Part 1 */
  uint32_t local_1;

  /** Local Data Part 2 */
  uint32_t local_2;

} parsebgp_bgp_update_large_community_t;

/**
 * LARGE COMMUNITIES
 */
typedef struct parsebgp_bgp_update_large_communities {

  /** Array of (communities_cnt) LARGE COMMUNITIES */
  parsebgp_bgp_update_large_community_t *communities;

  /** (Inferred) number of communities */
  int communities_cnt;

} parsebgp_bgp_update_large_communities_t;

typedef enum {

  /** ORIGIN (Type Code 1) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN = 1, // DONE, TESTED

  /** AS_PATH (Type Code 2) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH = 2, // DONE, TESTED

  /** NEXT_HOP (Type Code 3) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP = 3, // DONE, TESTED

  /** MULTI_EXIT_DISC (Type Code 4) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_MED = 4, // DONE, TESTED

  /** LOCAL_PREF (Type Code 5) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF = 5, // DONE

  /** ATOMIC_AGGREGATE (Type Code 6) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE = 6, // DONE, TESTED

  /** AGGREGATOR (Type Code 7) */
  PARSEBGP_BGP_PATH_ATTR_TYPE_AGGEGATOR = 7, // DONE, TESTED

  /** COMMUNITY (Type Code 8) [RFC1997] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES = 8, // DONE, TESTED

  /** ORIGINATOR_ID (Type Code 9) [RFC4456] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID = 9, // DONE

  /** CLUSTER_LIST (Type Code 10) [RFC4456] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST = 10, // DONE

  // ...

  /** MP_REACH_NLRI (Type Code 14) [RFC4760] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI = 14, // DONE-PARTLY, TESTED

  /** MP_UNREACH_NLRI (Type Code 15) [RFC4760] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI = 15, // DONE, TESTED

  /** EXTENDED COMMUNITIES (Type Code 16) [RFC4360] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES = 16, // DONE-PARTLY, TESTED

  /** AS4_PATH (Type Code 17) [RFC6793] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH = 17, // DONE, TESTED

  /** AS4_AGGREGATOR (Type Code 18) [RFC6793] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_AGGREGATOR = 18, // DONE, TESTED

  // ...

  /** AS_PATHLIMIT (deprecated) (Type Code 21) [draft-ietf-idr-as-pathlimit-03]
   */
  PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATHLIMIT = 21, // DONE, TESTED

  // ...

  /** IPv6 Address Specific Extended Community (Type Code 25) [RFC5701] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES = 25, // DONE, TESTED

  // ...

  /** BGP-LS Attribute (Type Code 29) [RFC7752] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS = 29,

  // ...

  /** LARGE_COMMUNITY (Type Code 32) [RFC8092] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES = 32, // DONE, TESTED

  // ...

  /** ATTR_SET (PARSEBGP_NOT_IMPLEMENTED) (Type Code 128) [RFC6368] */
  PARSEBGP_BGP_PATH_ATTR_TYPE_ATTR_SET = 128,

} parsebgp_bgp_update_path_attr_type_t;

typedef enum {

  /** Optional (i.e., not well-known) */
  PARSEBGP_BGP_PATH_ATTR_FLAG_OPTIONAL = 0x80,

  /** Transitive */
  PARSEBGP_BGP_PATH_ATTR_FLAG_TRANSITIVE = 0x40,

  /** Partial */
  PARSEBGP_BGP_PATH_ATTR_FLAG_PARTIAL = 0x20,

  /** Extended */
  PARSEBGP_BGP_PATH_ATTR_FLAG_EXTENDED = 0x10,

} parsebgp_bgp_update_path_attr_flag_t;

/**
 * BGP UPDATE Path Attribute
 */
typedef struct parsebgp_bgp_update_path_attr {

  /** Attribute Flags */
  uint8_t flags;

  /** Attribute Type (parsebgp_bgp_update_path_attr_type_t) */
  uint8_t type;

  /** Attribute Length (in bytes) */
  uint16_t len;

  /** Union of all support Path Attribute data */
  union {

    /** ORIGIN (parsebgp_bgp_update_origin_type_t) */
    uint8_t origin;

    /** AS_PATH or AS4_PATH
     *
     * An AS4_PATH should be merged with the AS_PATH attribute using the method
     * outlined in RFC6793 section 4.2.3.
     */
    parsebgp_bgp_update_as_path_t as_path;

    /** NEXT_HOP */
    uint8_t next_hop[4];

    /** MULIT_EXIT_DISC (MED) */
    uint32_t med;

    /** LOCAL_PREF */
    uint32_t local_pref;

    /** AGGREGATOR */
    parsebgp_bgp_update_aggregator_t aggregator;

    /** COMMUNITIES */
    parsebgp_bgp_update_communities_t communities;

    /** ORIGINATOR_ID */
    uint32_t originator_id;

    /** CLUSTER_LIST */
    parsebgp_bgp_update_cluster_list_t cluster_list;

    /** MP_REACH */
    parsebgp_bgp_update_mp_reach_t mp_reach;

    /** MP_UNREACH */
    parsebgp_bgp_update_mp_unreach_t mp_unreach;

    /** EXT_COMMUNITIES and IPV6_EXT_COMMUNITIES */
    parsebgp_bgp_update_ext_communities_t ext_communities;

    /** AS_PATHLIMIT */
    parsebgp_bgp_update_as_pathlimit_t as_pathlimit;

    /** LARGE COMMUNITIES */
    parsebgp_bgp_update_large_communities_t large_communities;

  } data;

} parsebgp_bgp_update_path_attr_t;

/**
 * BGP Path Attributes
 */
typedef struct parsebgp_bgp_update_path_attrs {

  /** Length of the (raw) Path Attributes data (in bytes) */
  uint16_t len;

  /** Array of (attrs_cnt) Path Attributes */
  parsebgp_bgp_update_path_attr_t *attrs;

  /** Number of Path Attributes in the attrs field */
  int attrs_cnt;

} parsebgp_bgp_update_path_attrs_t;

/**
 * BGP UPDATE NLRIs
 */
typedef struct parsebgp_bgp_update_nlris {

  /** Length of the (raw) NLRI data (in bytes) */
  uint16_t len;

  /** Array of (prefixes_cnt) prefixes */
  parsebgp_bgp_prefix_t *prefixes;

  /** (Inferred) number of prefixes in the prefixes field */
  int prefixes_cnt;

} parsebgp_bgp_update_nlris_t;

/**
 * BGP UPDATE Message
 */
typedef struct parsebgp_bgp_update {

  /** Withdrawn NLRIs */
  parsebgp_bgp_update_nlris_t withdrawn_nlris;

  /** Path Attributes */
  parsebgp_bgp_update_path_attrs_t path_attrs;

  /** Announced NLRIs (Note that the len field is inferred) */
  parsebgp_bgp_update_nlris_t announced_nlris;

} parsebgp_bgp_update_t;

/** Decode an UPDATE message */
parsebgp_error_t parsebgp_bgp_update_decode(parsebgp_opts_t *opts,
                                            parsebgp_bgp_update_t *msg,
                                            uint8_t *buf, size_t *lenp,
                                            size_t remain);

/** Destroy an UPDATE message */
void parsebgp_bgp_update_destroy(parsebgp_bgp_update_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed UPDATE message to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_dump(parsebgp_bgp_update_t *msg, int depth);

/** Decode PATH ATTRIBUTES */
parsebgp_error_t parsebgp_bgp_update_path_attrs_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_path_attrs_t *msg, uint8_t *buf,
  size_t *lenp, size_t remain);

/** Destroy a Path Attributes message */
void parsebgp_bgp_update_path_attrs_destroy(
  parsebgp_bgp_update_path_attrs_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed Path Attrs message to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_path_attrs_dump(parsebgp_bgp_update_path_attrs_t *msg,
                                         int depth);

#endif /* __PARSEBGP_BGP_UPDATE_H */
