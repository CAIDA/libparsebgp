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

//#include "Logger.h"
#include "../include/bgp_common.h"
#include "../include/AddPathDataContainer.h"
#include "../include/parseBMP.h"

#include <string>
#include <list>
#include <array>
#include <map>


namespace bgp_msg {
/**
 * Defines the attribute types
 *
 *  \see http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
 */
enum UPDATE_ATTR_TYPES {
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
 * \class   UpdateMsg
 *
 * \brief   BGP update message parser
 * \details This class parses a BGP update message.  It can be extended to create messages.
 *          message.
 */
//class UpdateMsg {

//public:


    /**
     * Update header - defined in RFC4271
     */
    struct update_bgp_hdr {
        /**
         * indicates the total len of withdrawn routes field in octets.
         */
        uint16_t withdrawn_len;

        /**
         * Withdrawn routes data pointer
         */
        u_char *withdrawn_ptr;

        /**
         * Total length of the path attributes field in octets
         *
         * A value of 0 indicates NLRI nor path attrs are present
         */
        uint16_t attr_len;

        /**
         * Attribute data pointer
         */
        u_char *attr_ptr;

        /**
         * NLRI data pointer
         */
        u_char *nlri_ptr;
    };

    typedef std::pair<bgp_msg::UPDATE_ATTR_TYPES, std::string> parsed_attrs_pair;
    typedef std::map<bgp_msg::UPDATE_ATTR_TYPES, std::string> parsed_attrs_map;

    // Parsed bgp-ls attributes map
    typedef std::map<uint16_t, std::array<uint8_t, 255>> parsed_ls_attrs_map;

    struct libParseBGP_update_msg_data {
        /**
         * parsed path attributes map
         */
        std::map<bgp_msg::UPDATE_ATTR_TYPES, std::string> parsed_attrs;

        bool debug;                           ///< debug flag to indicate debugging
        //Logger                  *logger;                         ///< Logging class pointer
        std::string peer_addr;                       ///< Printed form of the peer address for logging
        std::string router_addr;                     ///< Router IP address - used for logging
        bool four_octet_asn;                  ///< Indicates true if 4 octets or false if 2
        bmp_message::peer_info *peer_info;                      ///< Persistent Peer info pointer
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
        uint8_t     ospf_area_id[4];            ///< OSPF area ID
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
        uint8_t     ospf_area_id[4];            ///< OSPF area ID
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
        uint8_t     ospf_area_id[4];        ///< OSPF area ID
        uint8_t     router_id[16];          ///< IPv4 or IPv6 router ID
        uint8_t     isis_area_id[9];        ///< IS-IS area ID
        uint8_t     intf_addr[16];          ///< Interface binary address
        uint8_t     nei_addr[16];           ///< Neighbor binary address

        u_char      local_node_hash_id[16]; ///< Local node hash ID
        uint32_t    mt_id;                  ///< Multi-Topology ID
        uint32_t    metric;                 ///< Prefix metric
        bool        is_ipv4;                 ///< True if interface/neighbor is IPv4, false otherwise
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

    /**
     * Parsed data structure for BGP-LS
     */
    struct parsed_data_ls {
        std::list<obj_ls_node>   nodes;        ///< List of Link state nodes
        std::list<obj_ls_link>   links;        ///< List of link state links
        std::list<obj_ls_prefix> prefixes;     ///< List of link state prefixes
    };

    /**
     * Parsed update data - decoded data from complete update parse
     */
    struct parsed_update_data {
        parsed_attrs_map              attrs;              ///< Parsed attrbutes
        std::list<bgp::prefix_tuple>  withdrawn;          ///< List of withdrawn prefixes
        std::list<bgp::prefix_tuple>  advertised;         ///< List of advertised prefixes
        parsed_ls_attrs_map           ls_attrs;           ///< BGP-LS specific attributes
        parsed_data_ls                ls;                 ///< REACH: Link state parsed data
        parsed_data_ls                ls_withdrawn;       ///< UNREACH: Parsed Withdrawn data
        std::list<bgp::vpn_tuple>     vpn;                ///< List of vpn prefixes advertised
        std::list<bgp::vpn_tuple>     vpn_withdrawn;      ///< List of vpn prefixes withdrawn
        std::list<bgp::evpn_tuple>    evpn;               ///< List of evpn nlris advertised
        std::list<bgp::evpn_tuple>    evpn_withdrawn;     ///< List of evpn nlris withdrawn
    };


    /**
     * Constructor for class
     *
     * \details Handles bgp update messages
     *
     * \param [in]     logPtr       Pointer to existing Logger for app logging
     * \param [in]     pperAddr     Printed form of peer address used for logging
     * \param [in]     routerAddr  The router IP address - used for logging
     * \param [in,out] peer_info   Persistent peer information
     * \param [in]     enable_debug Debug true to enable, false to disable
     */
//     UpdateMsg(std::string peer_addr, std::string router_addr, parseBMP::peer_info *peer_info);

//     UpdateMsg(std::string peer_addr, parseBMP::peer_info *peer_info);

//    virtual ~UpdateMsg();

    void libParseBGP_update_msg_init(libParseBGP_update_msg_data *update_msg, std::string peer_addr,
                                               std::string router_addr, bmp_message::peer_info *peer_info);

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
     size_t libParseBGP_update_msg_parse_update_msg(libParseBGP_update_msg_data *update_msg, u_char *data, size_t size,
                                                    parse_common::parsed_update_data &parsed_data, bool &has_end_of_rib_marker);

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
    void libParseBGP_update_msg_parse_attributes(libParseBGP_update_msg_data *update_msg, u_char *data, uint16_t len, parse_common::parsed_update_data &parsed_data,
                         bool &has_end_of_rib_marker);

/*private:
    bool                    debug;                           ///< debug flag to indicate debugging
    //Logger                  *logger;                         ///< Logging class pointer
    std::string             peer_addr;                       ///< Printed form of the peer address for logging
    std::string             router_addr;                     ///< Router IP address - used for logging
    bool                    four_octet_asn;                  ///< Indicates true if 4 octets or false if 2
    parseBMP::peer_info    *peer_info;                      ///< Persistent Peer info pointer
*/

    /**
     * Parses NLRI info (IPv4) from the BGP message
     *
     * \details
     *      Will get the NLRI and Withdrawn prefix entries from the data buffer.  As per RFC,
     *      this is only for v4.  V6/mpls is via mpbgp attributes (RFC4760)
     *
     * \param [in]   data       Pointer to the start of the prefixes to be parsed
     * \param [in]   len        Length of the data in bytes to be read
     * \param [out]  prefixes   Reference to a list<prefix_tuple> to be updated with entries
     */
    //void libParseBGP_update_msg_parse_nlri_data_v4(libParseBGP_update_msg_data *update_msg, u_char *data, uint16_t len,
    //                                               std::list<bgp::prefix_tuple> &prefixes);


    /**
     * Parse attribute data based on attribute type
     *
     * \details
     *      Parses the attribute data based on the passed attribute type.
     *      Parsed_data will be updated based on the attribute data parsed.
     *
     * \param [in]   attr_type      Attribute type
     * \param [in]   attr_len       Length of the attribute data
     * \param [in]   data           Pointer to the attribute data
     * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
     */
    //void libParseBGP_update_msg_parse_attr_data(libParseBGP_update_msg_data *update_msg, u_char attr_type, uint16_t attr_len,
    //                                            u_char *data, parseBMP::parsed_update_data &parsed_data, bool &has_end_of_rib_marker);

    /**
     * Parse attribute AS_PATH data
     *
     * \param [in]   attr_len       Length of the attribute data
     * \param [in]   data           Pointer to the attribute data
     * \param [out]  attrs          Reference to the parsed attr map - will be updated
     */
    //void libParseBGP_update_msg_parse_attr_as_path(libParseBGP_update_msg_data *update_msg, uint16_t attr_len, u_char *data,
    //                                               parseBMP::parsed_attrs_map &attrs);

    /**
     * Parse attribute AGGEGATOR data
     *
     * \param [in]   attr_len       Length of the attribute data
     * \param [in]   data           Pointer to the attribute data
     * \param [out]  attrs          Reference to the parsed attr map - will be updated
     */
    //void libParseBGP_update_msg_parse_attr_aggegator(libParseBGP_update_msg_data *update_msg, uint16_t attr_len, u_char *data,
    //                                                 parseBMP::parsed_attrs_map &attrs);

//};

} /* namespace bgp_msg */

#endif /* UPDATEMSG_H_ */
