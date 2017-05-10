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
     * OBJECT: bgp_peers
     *
     * BGP peer table schema
     */
struct obj_bgp_peer {
    u_char      hash_id[16];            ///< hash of router hash_id, peer_rd, peer_addr, and peer_bgp_id
    u_char      router_hash_id[16];     ///< Router hash ID

    char        peer_rd[32];            ///< Peer distinguisher ID (string/printed format)
    char        peer_addr[46];          ///< Peer IP address in printed form
    char        peer_bgp_id[16];        ///< Peer BGP ID in printed form
    uint32_t    peer_as;                ///< Peer ASN
    bool        is_l3vpn;                ///< true if peer is L3VPN, otherwise it is Global
    bool        is_pre_policy;            ///< True if the routes are pre-policy, false if not
    bool        is_adj_in;                ///< True if the routes are Adj-Rib-In, false if not
    bool        is_ipv4;                 ///< true if peer is IPv4 or false if IPv6
    uint32_t    timestamp_secs;         ///< Timestamp in seconds since EPOC
    uint32_t    timestamp_us;           ///< Timestamp microseconds
};


/**
 * OBJECT: ls_node
 *
 * BGP-LS Node table schema
 */
struct obj_ls_node {
    u_char      hash_id[16];                ///< hash id for the entry
    uint64_t    id;                         ///< Routing universe identifier
    bool        is_ipv4;                     ///< True if interface/neighbor is IPv4, false otherwise
    uint32_t    asn;                        ///< BGP ASN
    uint32_t    bgp_ls_id;                  ///< BGP-LS Identifier
    uint8_t     igp_router_id[8];           ///< IGP router ID
    uint8_t     ospf_area_Id[4];            ///< OSPF area ID
    char        protocol[32];               ///< String representation of the protocol name
    uint8_t     router_id[16];              ///< IPv4 or IPv6 router ID
    uint8_t     isis_area_id[9];            ///< IS-IS area ID
    char        flags[32];                  ///< String representation of the flag bits
    char        name[255];                  ///< Name of router
    char        mt_id[255];                 ///< Multi-Topology ID
    char        sr_capabilities_tlv[255];   ///< SR Capabilities TLV
};


/**
 * OBJECT: ls_link
 *
 * BGP-LS Link table schema
 */
struct obj_ls_link {
    u_char      hash_id[16];                ///< hash id for the entry
    uint64_t    id;                         ///< Routing universe identifier
    uint32_t    mt_id;                      ///< Multi-Topology ID

    uint32_t    bgp_ls_id;                  ///< BGP-LS Identifier
    uint8_t     igp_router_id[8];           ///< IGP router ID (local)
    uint8_t     remote_igp_router_id[8];    ///< IGP router ID (remote)
    uint8_t     ospf_area_Id[4];            ///< OSPF area ID
    uint8_t     router_id[16];              ///< IPv4 or IPv6 router ID (local)
    uint8_t     remote_router_id[16];       ///< IPv4 or IPv6 router ID (remote)

    uint32_t    local_node_asn;             ///< Local node asn
    uint32_t    remote_node_asn;            ///< Remote node asn
    uint32_t    local_bgp_router_id;        ///< Local BGP router id (draft-ietf-idr-bgpls-segment-routing-epe)
    uint32_t    remote_bgp_router_id;       ///< Remote BGP router id (draft-ietf-idr-bgpls-segment-routing-epe)

    uint8_t     isis_area_id[9];            ///< IS-IS area ID

    char        protocol[32];               ///< String representation of the protocol name
    uint8_t     intf_addr[16];              ///< Interface binary address
    uint8_t     nei_addr[16];               ///< Neighbor binary address
    uint32_t    local_link_id;              ///< Local Link ID (IS-IS)
    uint32_t    remote_link_id;             ///< Remote Link ID (IS-IS)
    bool        is_ipv4;                     ///< True if interface/neighbor is IPv4, false otherwise
    u_char      local_node_hash_id[16];     ///< Local node hash ID
    u_char      remote_node_hash_id[16];    ///< Remove node hash ID
    uint32_t    admin_group;                ///< Admin group
    uint32_t    max_link_bw;                ///< Maximum link bandwidth
    uint32_t    max_resv_bw;                ///< Maximum reserved bandwidth
    char        unreserved_bw[100];         ///< string for unreserved bandwidth, a set of 8 uint32_t values

    uint32_t    te_def_metric;              ///< Default TE metric
    char        protection_type[60];        ///< String representation for the protection types
    char        mpls_proto_mask[32];        ///< Either LDP or RSVP-TE
    uint32_t    igp_metric;                 ///< IGP metric
    char        srlg[128];                  ///< String representation of the shared risk link group values
    char        name[255];                  ///< Name of router
    char        peer_node_sid[128];         ///< Peer node side (draft-ietf-idr-bgpls-segment-routing-epe)
    char        peer_adj_sid[128];          ///< Peer Adjency Segment Identifier
};

/**
 * OBJECT: ls_prefix
 *
 * BGP-LS Prefix table schema
 */
struct obj_ls_prefix {
    u_char      hash_id[16];            ///< hash for the entry
    uint64_t    id;                     ///< Routing universe identifier
    char        protocol[32];           ///< String representation of the protocol name

    uint32_t    bgp_ls_id;              ///< BGP-LS Identifier
    uint8_t     igp_router_id[8];       ///< IGP router ID
    uint8_t     ospf_area_Id[4];        ///< OSPF area ID
    uint8_t     router_id[16];          ///< IPv4 or IPv6 router ID
    uint8_t     isis_area_id[9];        ///< IS-IS area ID
    uint8_t     intf_addr[16];          ///< Interface binary address
    uint8_t     nei_addr[16];           ///< Neighbor binary address

    u_char      local_node_hash_id[16]; ///< Local node hash ID
    uint32_t    mt_id;                  ///< Multi-Topology ID
    uint32_t    metric;                 ///< Prefix metric
    bool        isIPv4;                 ///< True if interface/neighbor is IPv4, false otherwise
    u_char      prefix_len;             ///< Length of prefix in bits
    char        ospf_route_type[32];    ///< String representation of the OSPF route type
    uint8_t     prefix_bin[16];         ///< Prefix in binary form
    uint8_t     prefix_bcast_bin[16];   ///< Broadcast address/last address in binary form
    char        igp_flags[32];          ///< String representation of the IGP flags
    uint32_t    route_tag;              ///< Route tag
    uint64_t    ext_route_tag;          ///< Extended route tag
    uint8_t     ospf_fwd_addr[16];      ///< IPv4/IPv6 OSPF forwarding address
    char        sid_tlv[128];           ///< Prefix-SID TLV
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
//    std::map<update_attr_types, std::string>            parsed_attrs;
typedef std::pair<update_attr_types, std::string>   parsed_attrs_pair;
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
    list<uint32_t>  seg_asn;
}as_path_segment;

/**
 * struct defines the MP_UNREACH_NLRI (RFC4760 Section 4)
 */
struct mp_unreach_nlri {
    uint16_t       afi;                 ///< Address Family Identifier
    uint8_t        safi;                ///< Subsequent Address Family Identifier
  //  unsigned char  *nlri_data;          ///< NLRI data - Pointer to data (normally does not require freeing)
    uint16_t       nlri_len;            ///< Not in RFC header; length of the NLRI data
    list<update_prefix_tuple> wdrawn_routes_nlri;   ///< Withdrawn routes
};

struct mp_reach_nlri {
    uint16_t       afi;                 ///< Address Family Identifier
    uint8_t        safi;                ///< Subsequent Address Family Identifier
    uint8_t        nh_len;              ///< Length of next hop
    //unsigned char  *next_hop;           ///< Next hop - Pointer to data (normally does not require freeing)
    uint8_t        reserved;            ///< Reserved

    //unsigned char  *nlri_data;          ///< NLRI data - Pointer to data (normally does not require freeing)
    uint16_t       nlri_len;            ///< Not in RFC header; length of the NLRI data
};

/**
 * Extended Community header
 *      RFC4360 size is 8 bytes total (6 for value)
 *      RFC5701 size is 20 bytes total (16 for global admin, 2 for local admin)
 */
struct extcomm_hdr {
    uint8_t      high_type;                      ///< Type high byte
    uint8_t      low_type;                       ///< Type low byte - subtype
    //u_char       *value;                         ///<
    string       val;
};

typedef  std::map<uint16_t, std::array<uint8_t, 255>>        parsed_ls_attrs_map;

/**
     * Parsed data structure for BGP-LS
     */
struct parsed_data_ls {
    std::list<obj_ls_node>   nodes;        ///< List of Link state nodes
    std::list<obj_ls_link>   links;        ///< List of link state links
    std::list<obj_ls_prefix> prefixes;     ///< List of link state prefixes
};
typedef struct attr_value{
    uint8_t                 origin;
    list<as_path_segment>   as_path;
    u_char                  next_hop[4];
    u_char                  originator_id[4];
    uint32_t                med;
    uint32_t                local_pref;
    uint16_t                value16bit;
    string                  aggregator;
    list<u_char*>         cluster_list;
    list<uint16_t>          attr_type_comm;
    list<extcomm_hdr>       ext_comm;
    mp_unreach_nlri         mp_unreach_nlri_data;
    mp_reach_nlri           mp_reach_nlri_data;
}attr_val;

struct update_path_attrs {
    attr_type_tuple         attr_type;
    uint16_t                attr_len;
    attr_val                attr_value;
    parsed_attrs_map        attrs;
    list<vpn_tuple>         vpn;                ///< List of vpn prefixes advertised
    std::list<update_prefix_tuple>  advertised;
    parsed_data_ls          mp_ls_data;
    list<vpn_tuple>         vpn_withdrawn;      ///< List of vpn prefixes withdrawn
    list<evpn_tuple>        evpn;               ///< List of evpn nlris advertised
    list<evpn_tuple>        evpn_withdrawn;     ///< List of evpn nlris withdrawn
    parsed_ls_attrs_map     ls_attrs;
    parsed_data_ls          ls;                 ///< REACH: Link state parsed data
    parsed_data_ls          ls_withdrawn;       ///< UNREACH: Parsed Withdrawn data
    //libparsebgp_evpn_data evpn_data;
    libparsebgp_addpath_map add_path_map;
};


struct libparsebgp_update_msg_data {
    uint16_t                    wdrawn_route_len;
    list <update_prefix_tuple>  wdrawn_routes;
    uint16_t                    total_path_attr_len;
    list <update_path_attrs>    path_attributes;
    list <update_prefix_tuple>  nlri;
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
 int libparsebgp_update_msg_parse_update_msg(libparsebgp_update_msg_data *update_msg, u_char *data, size_t size,
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
void libparsebgp_update_msg_parse_attributes(list<update_path_attrs> &update_msg, u_char *&data, uint16_t len, bool &has_end_of_rib_marker);

void libparsebgp_update_msg_parse_attr_data(update_path_attrs *path_attrs, u_char *data, bool &has_end_of_rib_marker);

#endif /* UPDATEMSG_H_ */
