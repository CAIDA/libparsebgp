/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef UPDATEMSG_H_
#define UPDATEMSG_H_

#include "bgp_common.h"
#include "add_path_data_container.h"
#include <string>
#include <list>
#include <array>
#include <map>

using namespace std;

/**
 * OBJECT: ls_node
 *
 * BGP-LS Node table schema
 */
struct obj_ls_node {
    uint64_t    id;                         ///< Routing universe identifier
    char        protocol[32];               ///< String representation of the protocol name
    };


/**
 * OBJECT: ls_link
 *
 * BGP-LS Link table schema
 */
struct obj_ls_link {
    uint64_t    id;                         ///< Routing universe identifier
    char        protocol[32];               ///< String representation of the protocol name
    };

/**
 * OBJECT: ls_prefix
 *
 * BGP-LS Prefix table schema
 */
struct obj_ls_prefix {
    uint64_t    id;                     ///< Routing universe identifier
    char        protocol[32];           ///< String representation of the protocol name
};

//############################################################################


enum update_attr_types {
    ATTR_TYPE_ORIGIN=1,
    ATTR_TYPE_AS_PATH,
    ATTR_TYPE_NEXT_HOP,
    ATTR_TYPE_MED,
    ATTR_TYPE_LOCAL_PREF,
    ATTR_TYPE_ATOMIC_AGGREGATE,
    ATTR_TYPE_AGGEGATOR,
    ATTR_TYPE_COMMUNITIES,
    ATTR_TYPE_ORIGINATOR_ID,
    ATTR_TYPE_CLUSTER_LIST,
    ATTR_TYPE_DPA,
    ATTR_TYPE_ADVERTISER,
    ATTR_TYPE_RCID_PATH,
    ATTR_TYPE_MP_REACH_NLRI=14,
    ATTR_TYPE_MP_UNREACH_NLRI,
    ATTR_TYPE_EXT_COMMUNITY=16,
    ATTR_TYPE_AS4_PATH=17,
    ATTR_TYPE_AS4_AGGREGATOR=18,

    ATTR_TYPE_AS_PATHLIMIT=21,              // Deprecated - draft-ietf-idr-as-pathlimit, JunOS will send this

    ATTR_TYPE_IPV6_EXT_COMMUNITY=25,
    ATTR_TYPE_AIGP,                         ///< RFC7311 - Accumulated IGP metric

    ATTR_TYPE_BGP_LS=29,                    // BGP LS attribute draft-ietf-idr-ls-distribution

    ATTR_TYPE_BGP_LINK_STATE_OLD=99,        // BGP link state Older
    ATTR_TYPE_BGP_ATTRIBUTE_SET=128,

    /*
     * Below attribute types are for internal use only... These are derived/added based on other attributes
     */
    ATTR_TYPE_INTERNAL_AS_COUNT=9000,        // AS path count - number of AS's
    ATTR_TYPE_INTERNAL_AS_ORIGIN             // The AS that originated the entry
};

/**
 * parsed path attributes map
 */
typedef std::map<update_attr_types, std::string>    parsed_attrs_map;

// Parsed bgp-ls attributes map
typedef  std::map<uint16_t, std::array<uint8_t, 255>>        parsed_ls_attrs_map;

struct attr_type_tuple {
    uint8_t attr_flags;
    uint8_t attr_type_code;
};

typedef struct as_path_segment {
    uint8_t         seg_type;
    uint8_t         seg_len;
    uint32_t        *seg_asn;
}as_path_segment;

/**
 * struct defines the MP_UNREACH_NLRI (RFC4760 Section 4)
 */
struct mp_unreach_nlri {
    uint16_t       afi;                 ///< Address Family Identifier
    uint8_t        safi;                ///< Subsequent Address Family Identifier
    struct withdrawn_routes_nlri {
        update_prefix_tuple             *wdrawn_routes;   ///< Withdrawn routes
        update_prefix_label_tuple       *wdrawn_routes_label;
    }withdrawn_routes_nlri;
};

/**
* Node (local and remote) common fields
*/
struct node_descriptor {
    uint16_t    type;
    uint16_t    len;
    uint32_t    asn;                           ///< BGP ASN
    uint32_t    bgp_ls_id;                     ///< BGP-LS Identifier
    uint8_t     igp_router_id[8];              ///< IGP router ID
    uint8_t     ospf_area_Id[4];               ///< OSPF area ID
    uint32_t    bgp_router_id;                 ///< BGP router ID (draft-ietf-idr-bgpls-segment-routing-epe)
    uint8_t     hash_bin[16];                  ///< binary hash for node descriptor
};

struct link_descriptor {
    uint16_t    type;
    uint16_t    len;
    uint32_t    local_id;                           ///< Link Local ID
    uint32_t    remote_id;                          ///< Link Remote ID
    uint8_t     intf_addr[16];                      ///< Interface binary address
    uint8_t     nei_addr[16];                       ///< Neighbor binary address
    uint32_t    mt_id;                              ///< Multi-Topology ID
    bool        is_ipv4;                             ///< True if IPv4, false if IPv6
};

/**
 * Node (local and remote) common fields
 */
struct prefix_descriptor {
    uint16_t    type;
    uint16_t    len;
    char        ospf_route_type[32];                ///< OSPF Route type in string form for DB enum
    uint32_t    mt_id;                              ///< Multi-Topology ID
    uint8_t     prefix[16];                         ///< Prefix binary address
    uint8_t     prefix_bcast[16];                   ///< Prefix broadcast/ending binary address
    uint8_t     prefix_len;                         ///< Length of prefix in bits
};

struct mp_reach_ls {
    uint16_t        nlri_type;
    uint16_t        nlri_len;
    uint8_t         proto_id;
    uint64_t        id;
    struct nlri_ls{
        struct node_nlri {
            uint16_t    type;
            uint16_t    len;
            node_descriptor *local_nodes;
        }node_nlri;

        struct link_nlri {
            uint16_t    type;
            uint16_t    len;
            node_descriptor* local_nodes;
            node_descriptor* remote_nodes;
            link_descriptor* link_desc;
        }link_nlri;

        struct prefix_nlri_ipv4_ipv6 {
            uint16_t    type;
            uint16_t    len;
            node_descriptor   *local_nodes;
            prefix_descriptor *prefix_desc;
        }prefix_nlri_ipv4_ipv6;
    }nlri_ls;
};


struct mp_reach_nlri {
    uint16_t afi;                ///< Address Family Identifier
    uint8_t safi;                ///< Subsequent Address Family Identifier
    uint8_t nh_len;              ///< Length of next hop
    unsigned char next_hop[16];  ///< Next hop address - Pointer to data (normally does not require freeing)
    uint8_t reserved;            ///< Reserved
    struct nlri_info {
        update_prefix_tuple              *nlri_info;               ///< Withdrawn routes
        update_prefix_label_tuple        *nlri_label_info;
        mp_reach_ls                      *mp_rch_ls;
    }nlri_info;
};

/**
 * Extended Community header
 *      RFC4360 size is 8 bytes total (6 for value)
 *      RFC5701 size is 20 bytes total (16 for global admin, 2 for local admin)
 */
struct extcomm_hdr {
    uint8_t      high_type;                      ///< Type high byte
    uint8_t      low_type;                       ///< Type low byte - subtype
    string       val;
};

typedef  std::map<uint16_t, std::array<uint8_t, 255>>        parsed_ls_attrs_map;

/**
     * Parsed data structure for BGP-LS
     */
struct parsed_data_ls {

    list<obj_ls_node>   nodes;        ///< List of Link state nodes
    list<obj_ls_link>   links;        ///< List of link state links
    list<obj_ls_prefix> prefixes;     ///< List of link state prefixes
};
typedef struct attr_value{
    uint8_t                 origin;
    as_path_segment         *as_path;
    u_char                  next_hop[4];
    u_char                  originator_id[4];
    uint32_t                med;
    uint32_t                local_pref;
    uint16_t                value16bit;
    string                  aggregator;
    u_char                  **cluster_list;
    uint16_t                *attr_type_comm;
    extcomm_hdr             *ext_comm;
    mp_unreach_nlri         mp_unreach_nlri_data;
    mp_reach_nlri           mp_reach_nlri_data;
}attr_val;

typedef struct bgp_link_state_attrs{
    uint16_t            type;
    uint16_t            len;
    struct node_attr{
        char node_flag_bits;
        char node_ipv4_router_id_local[4];
        char node_ipv6_router_id_local[16];
        char node_isis_area_id[8];
        char node_name[256];
        char mt_id[256];
    }node;
    struct link_attr{
        char link_admin_group [4];
        char link_igp_metric[4];
        char link_ipv4_router_id_remote[4];
        char link_ipv6_router_id_remote[4];
        char link_max_link_bw[4];
        char link_max_resv_bw[4];
        char link_name[256];
        char link_te_def_metric[4];
        char link_unresv_bw[32];
        char link_peer_epe_node_sid[32];
    }link;
    struct prefix_attr {
        char prefix_prefix_metric[4];
        char prefix_route_tag[4];
    }prefix;
}bgp_link_state_attrs;

struct update_path_attrs {
    attr_type_tuple         attr_type;
    uint16_t                attr_len;
    attr_val                attr_value;
    parsed_attrs_map        attrs;
    parsed_data_ls          mp_ls_data;
    //list<vpn_tuple>         vpn_withdrawn;      ///< List of vpn prefixes withdrawn
    evpn_tuple              *evpn;               ///< List of evpn nlris advertised
    parsed_ls_attrs_map     ls_attrs;
    evpn_tuple              *evpn_withdrawn;     ///< List of evpn nlris withdrawn
    parsed_data_ls          ls;                 ///< REACH: Link state parsed data
    //parsed_data_ls          ls_withdrawn;       ///< UNREACH: Parsed Withdrawn data
    //libparsebgp_evpn_data evpn_data;
    //libparsebgp_addpath_map add_path_map;
    bgp_link_state_attrs    *bgp_ls;
};


struct libparsebgp_update_msg_data {
    uint16_t                    wdrawn_route_len;
    update_prefix_tuple         *wdrawn_routes;
    uint16_t                    total_path_attr_len;
    update_path_attrs           *path_attributes;
    update_prefix_tuple         *nlri;
};

 /**
  * Parses the update message
  *
  * \details
  *      Reads the update message from socket and parses it.  The parsed output will
  *      be added to the DB.
  *
  * \param [in]   data           Pointer to raw bgp payload data, starting at the notification message
  * \param [in]   size           Size of the data available to read; prevent overrun when reading
  * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
  *
  * \return ZERO is error, otherwise a positive value indicating the number of bytes read from update message
  */
 ssize_t libparsebgp_update_msg_parse_update_msg(libparsebgp_update_msg_data *update_msg, u_char *data, ssize_t size,
                                                bool &has_end_of_rib_marker);

/**
 * Parses the BGP attributes in the update
 *
 * \details
 *     Parses all attributes.  Decoded values are updated in 'parsed_data'
 *
 * \param [in]   data       Pointer to the start of the prefixes to be parsed
 * \param [in]   len        Length of the data in bytes to be read
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
ssize_t libparsebgp_update_msg_parse_attributes(libparsebgp_addpath_map &add_path_map, update_path_attrs *update_msg, u_char *&data, uint16_t len, bool &has_end_of_rib_marker);

ssize_t libparsebgp_update_msg_parse_attr_data(libparsebgp_addpath_map &add_path_map, update_path_attrs *path_attrs, u_char *data, bool &has_end_of_rib_marker);

#endif /* UPDATEMSG_H_ */
