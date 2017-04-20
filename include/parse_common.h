//
// Created by Induja on 4/13/2017.
//
// For the common types and structs

#ifndef PARSE_LIB_PARSE_COMMON_H_H
#define PARSE_LIB_PARSE_COMMON_H_H

#include <iostream>
#include <list>
#include <vector>
#include <map>
#include "bgp_common.h"
using namespace std;

    /**
     * OBJECT: routers
     *
     * Router table schema
     */
    struct obj_router {
        u_char      hash_id[16];            ///< Router hash ID of name and src_addr
        uint16_t    hash_type;              ///< Router hash type  0:IP, 1:router_name, 2:bgp_id
        u_char      name[255];              ///< BMP router sysName (initiation Type=2)
        u_char      descr[255];             ///< BMP router sysDescr (initiation Type=1)
        u_char      ip_addr[46];            ///< BMP router source IP address in printed form
        char        bgp_id[16];             ///< BMP Router bgp-id
        uint32_t    asn;                    ///< BMP router ASN
        uint16_t    term_reason_code;       ///< BMP termination reason code
        char        term_reason_text[255];  ///< BMP termination reason text decode string

        char        term_data[4096];        ///< Type=0 String termination info data
        char        initiate_data[4096];    ///< Type=0 String initiation info data
        uint32_t    timestamp_secs;         ///< Timestamp in seconds since EPOC
        uint32_t    timestamp_us;           ///< Timestamp microseconds
    };

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
     * OBJECT: peer_down_events
     *
     * Peer Down Events schema
     */
    struct obj_peer_down_event {
        u_char          bmp_reason;         ///< BMP notify reason
        u_char          bgp_err_code;       ///< BGP notify error code
        u_char          bgp_err_subcode;    ///< BGP notify error sub code
        char            error_text[255];    ///< BGP error text string
    };

    /**
     * OBJECT: path_attrs
     *
     * Prefix Path attributes table schema
     */
    struct obj_path_attr {

        /**
         * Path hash
         */
        u_char      hash_id[16];
        char        origin[16];             ///< bgp origin as string name

        /**
         * as_path.
         */
        std::string as_path;

        uint16_t    as_path_count;          ///< Count of AS PATH's in the path (includes all in AS-SET)

        uint32_t    origin_as;              ///< Origin ASN
        bool        nexthop_isIPv4;         ///< True if IPv4, false if IPv6
        char        next_hop[40];           ///< Next-hop IP in printed form
        char        aggregator[40];         ///< Aggregator IP in printed form
        bool        atomic_agg;             ///< 0=false, 1=true for atomic_aggregate

        uint32_t    med;                    ///< bgp MED
        uint32_t    local_pref;             ///< bgp local pref

        /**
         * standard community list.
         */
        std::string community_list;

        /**
         * extended community list.
         */
        std::string  ext_community_list;

        /**
         * cluster list.
         */
        std::string cluster_list;

        char        originator_id[16];      ///< Originator ID in printed form
    };

    /**
     * OBJECT: peer_up_events
     *
     * Peer Up Events schema
     *
     * \note    open_params are the decoded values in string/text format; e.g. "attr=value ..."
     *          Numeric values are converted to printed form.   The buffer itself is
     *          allocated by the caller and freed by the caller.
     */
    struct obj_peer_up_event {
        char        info_data[4096];        ///< Inforamtional data for peer
        char        local_ip[40];           ///< IPv4 or IPv6 printed IP address
        uint16_t    local_port;             ///< Local port number
        uint32_t    local_asn;              ///< Local ASN for peer
        uint16_t    local_hold_time;        ///< BGP hold time
        char        local_bgp_id[16];       ///< Local BGP ID in printed form
        uint32_t    remote_asn;             ///< Remote ASN for peer
        uint16_t    remote_port;            ///< Remote port number
        uint16_t    remote_hold_time;       ///< BGP hold time
        char        remote_bgp_id[16];      ///< Remote Peer BGP ID in printed form

        char        sent_cap[4096];         ///< Received Open param capabilities
        char        recv_cap[4096];         ///< Received Open param capabilities
    };


/**
     * OBJECT: stats_reports
     *
     * Stats Report schema
     */
    struct obj_stats_report {
        uint32_t        prefixes_rej;           ///< type=0 Prefixes rejected
        uint32_t        known_dup_prefixes;     ///< type=1 known duplicate prefixes
        uint32_t        known_dup_withdraws;    ///< type=2 known duplicate withdraws
        uint32_t        invalid_cluster_list;   ///< type=3 Updates invalid by cluster lists
        uint32_t        invalid_as_path_loop;   ///< type=4 Updates invalid by as_path loop
        uint32_t        invalid_originator_id;  ///< type=5 Invalid due to originator_id
        uint32_t        invalid_as_confed_loop; ///< type=6 Invalid due to as_confed loop
        uint64_t        routes_adj_rib_in;      ///< type=7 Number of routes in adj-rib-in
        uint64_t        routes_loc_rib;         ///< type=8 number of routes in loc-rib
    };


    /**
     * OBJECT: rib
     *
     * Prefix rib table schema
     */
    struct obj_rib {
        u_char      hash_id[16];            ///< hash of attr hash prefix, and prefix len
        u_char      path_attr_hash_id[16];  ///< path attrs hash_id
        u_char      peer_hash_id[16];       ///< BGP peer hash ID, need it here for withdraw routes support
        u_char      is_ipv4;                 ///< 0 if IPv6, 1 if IPv4
        char        prefix[46];             ///< IPv4/IPv6 prefix in printed form
        u_char      prefix_len;             ///< Length of prefix in bits
        uint8_t     prefix_bin[16];         ///< Prefix in binary form
        uint8_t     prefix_bcast_bin[16];   ///< Broadcast address/last address in binary form
        uint32_t    path_id;                ///< Add path ID - zero if not used
        char        labels[255];            ///< Labels delimited by comma
    };

    /// Rib extended with Route Distinguisher
    struct obj_route_distinguisher {
        std::string     rd_administrator_subfield;
        std::string     rd_assigned_number;
        uint8_t         rd_type;
    };

    /// Rib extended with vpn specific fields
    struct obj_vpn{
        u_char      hash_id[16];            ///< hash of attr hash prefix, and prefix len
        u_char      path_attr_hash_id[16];  ///< path attrs hash_id
        u_char      peer_hash_id[16];       ///< BGP peer hash ID, need it here for withdraw routes support
        u_char      is_ipv4;                 ///< 0 if IPv6, 1 if IPv4
        char        prefix[46];             ///< IPv4/IPv6 prefix in printed form
        u_char      prefix_len;             ///< Length of prefix in bits
        uint8_t     prefix_bin[16];         ///< Prefix in binary form
        uint8_t     prefix_bcast_bin[16];   ///< Broadcast address/last address in binary form
        uint32_t    path_id;                ///< Add path ID - zero if not used
        char        labels[255];            ///< Labels delimited by comma
        std::string     rd_administrator_subfield;
        std::string     rd_assigned_number;
        uint8_t         rd_type;
    };

    /// Rib extended with evpn specific fields
    struct obj_evpn{
        u_char      hash_id[16];            ///< hash of attr hash prefix, and prefix len
        u_char      path_attr_hash_id[16];  ///< path attrs hash_id
        u_char      peer_hash_id[16];       ///< BGP peer hash ID, need it here for withdraw routes support
        u_char      is_ipv4;                 ///< 0 if IPv6, 1 if IPv4
        char        prefix[46];             ///< IPv4/IPv6 prefix in printed form
        u_char      prefix_len;             ///< Length of prefix in bits
        uint8_t     prefix_bin[16];         ///< Prefix in binary form
        uint8_t     prefix_bcast_bin[16];   ///< Broadcast address/last address in binary form
        uint32_t    path_id;                ///< Add path ID - zero if not used
        char        labels[255];            ///< Labels delimited by comma
        std::string     rd_administrator_subfield;
        std::string     rd_assigned_number;
        uint8_t         rd_type;
        uint8_t     originating_router_ip_len;
        char        originating_router_ip[46];
        char        ethernet_segment_identifier[255];
        char        ethernet_tag_id_hex[16];
        uint8_t     mac_len;
        char        mac[255];
        uint8_t     ip_len;
        char        ip[46];
        int         mpls_label_1;
        int         mpls_label_2;
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
    struct common_bgp_hdr {
        /**
         * 16-octet field is included for compatibility
         * All ones (required).
         */
        unsigned char    marker[16];

        /**
         * Total length of the message, including the header in octets
         *
         * min length is 19, max is 4096
         */
        unsigned short   len;
        /**
         * type code of the message
         *
         * 1 - OPEN
         * 2 - UPDATE
         * 3 - NOTIFICATION
         * 4 - KEEPALIVE
         * 5 - ROUTE-REFRESH
         */
        unsigned char    type;
    } __attribute__ ((__packed__));

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
     * Parsed data structure for BGP-LS
     */
    struct parsed_data_ls {
        std::list<obj_ls_node>   nodes;        ///< List of Link state nodes
        std::list<obj_ls_link>   links;        ///< List of link state links
        std::list<obj_ls_prefix> prefixes;     ///< List of link state prefixes
    };
    /**
     * parsed path attributes map
     */
//    std::map<update_attr_types, std::string>            parsed_attrs;
    typedef std::pair<update_attr_types, std::string>   parsed_attrs_pair;
    typedef std::map<update_attr_types, std::string>    parsed_attrs_map;

    // Parsed bgp-ls attributes map
    typedef  std::map<uint16_t, std::array<uint8_t, 255>>        parsed_ls_attrs_map;

    /**
     * Parsed update data - decoded data from complete update parse
     */
    struct parsed_update_data {
        parsed_attrs_map              attrs;              ///< Parsed attrbutes
        std::list<prefix_tuple>  withdrawn;          ///< List of withdrawn prefixes
        std::list<prefix_tuple>  advertised;         ///< List of advertised prefixes
        parsed_ls_attrs_map           ls_attrs;           ///< BGP-LS specific attributes
        parsed_data_ls                ls;                 ///< REACH: Link state parsed data
        parsed_data_ls                ls_withdrawn;       ///< UNREACH: Parsed Withdrawn data
        std::list<vpn_tuple>     vpn;                ///< List of vpn prefixes advertised
        std::list<vpn_tuple>     vpn_withdrawn;      ///< List of vpn prefixes withdrawn
        std::list<evpn_tuple>    evpn;               ///< List of evpn nlris advertised
        std::list<evpn_tuple>    evpn_withdrawn;     ///< List of evpn nlris withdrawn
    };

    struct parsed_bgp_msg{
        common_bgp_hdr common_hdr;
        parsed_update_data parsed_data;
        std::vector<obj_vpn> obj_vpn_rib_list;
        std::vector<obj_evpn> obj_evpn_rib_list;
        std::vector<obj_rib> adv_obj_rib_list;
        std::vector<obj_rib> wdrawn_obj_rib_list;
        bool has_end_of_rib_marker;
    };

#endif //PARSE_LIB_PARSE_COMMON_H_H