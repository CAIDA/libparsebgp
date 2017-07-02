/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef BGPCOMMON_H_
#define BGPCOMMON_H_

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "parse_utils.h"

#define BGP_MAX_MSG_SIZE        65535                   // Max payload size - Larger than RFC4271 of 4096
#define BGP_MSG_HDR_LEN         19                      // BGP message header size
#define BGP_OPEN_MSG_MIN_LEN    29                      // Includes the expected header size
#define BGP_VERSION             4
#define BGP_CAP_PARAM_TYPE      2
#define BGP_AS_TRANS            23456                   // BGP ASN when AS exceeds 16bits

/**
 * defines whether the attribute is optional (if
 *    set to 1) or well-known (if set to 0)
 */
#define ATTR_FLAG_OPT(flags)        ( flags & 0x80 )

/**
 * defines whether an optional attribute is
 *    transitive (if set to 1) or non-transitive (if set to 0)
 */
#define ATTR_FLAG_TRANS(flags)      ( flags & 0x40 )

/**
 * defines whether the information contained in the
 *  (if set to 1) or complete (if set to 0)
 */
#define ATTR_FLAG_PARTIAL(flags)    ( flags & 0x20 )

/**
 * defines whether the Attribute Length is one octet
 *      (if set to 0) or two octets (if set to 1)
 *
 * \details
 *         If the Extended Length bit of the Attribute Flags octet is set
 *         to 0, the third octet of the Path Attribute contains the length
 *         of the attribute data in octets.
 *
 *         If the Extended Length bit of the Attribute Flags octet is set
 *         to 1, the third and fourth octets of the path attribute contain
 *         the length of the attribute data in octets.
 */
 #define ATTR_FLAG_EXTENDED(flags)   ( flags & 0x10 )

/**
 * Defines the BGP address-families (AFI)
 *      http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
 */
enum bgp_afi {
    BGP_AFI_IPV4=1,
    BGP_AFI_IPV6=2,
    BGP_AFI_L2VPN=25,
    BGP_AFI_BGPLS=16388
};

/**
 * Defines the BGP subsequent address-families (SAFI)
 *      http://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
 */
enum bgp_safi {
    BGP_SAFI_UNICAST=1,
    BGP_SAFI_MULTICAST=2,

    BGP_SAFI_NLRI_LABEL=4,          // RFC3107
    BGP_SAFI_MCAST_VPN,             // RFC6514

    BGP_SAFI_VPLS=65,               // RFC4761, RFC6074
    BGP_SAFI_MDT,                   // RFC6037
    BGP_SAFI_4over6,                // RFC5747
    BGP_SAFI_6over4,                // yong cui

    BGP_SAFI_EVPN=70,               // draft-ietf-l2vpn-evpn
    BGP_SAFI_BGPLS=71,              // draft-ietf-idr-ls-distribution

    BGP_SAFI_MPLS=128,              // RFC4364
    BGP_SAFI_MCAST_MPLS_VPN,        // RFC6513, RFC6514

    BGP_SAFI_RT_CONSTRAINS=132      // RFC4684
};

/**
 * ENUM to define the prefix type used for prefix nlri maps in returned data
 */
enum prefix_type {
    PREFIX_UNICAST_V4=1,
    PREFIX_UNICAST_V6,
    PREFIX_LABEL_UNICAST_V4,
    PREFIX_LABEL_UNICAST_V6,
    PREFIX_VPN_V4,
    PREFIX_VPN_v6,
    PREFIX_MULTICAST_V4,
    // Add BGP-LS types
};

/**
* Defines the Add Path capability
*/
typedef struct add_path_capability {
    uint16_t       afi;
    uint8_t        safi;
    uint8_t        send_recieve;
}add_path_capability;


typedef union {
    struct {
        uint8_t   ttl     : 8;          // TTL - not present since only 3 octets are used
        uint8_t   bos     : 1;          // Bottom of stack
        uint8_t   exp     : 3;          // EXP - not really used
        uint32_t  value   : 20;         // Label value
    } decode;
    uint32_t  data;                 // Raw label - 3 octets only per RFC3107
} mpls_label;

/**
 * Defines the prefix tuple in update message
 */
typedef struct update_prefix_tuple {
    add_path_capability path_id;        ///< 4-octet Path identifier
    uint8_t             len;            ///< 1-octet Length of prefix in bits
    u_char              prefix[16];     ///< Address prefix
}update_prefix_tuple;



/**
 * Defines prefix tuple with label
 */
typedef struct update_prefix_label_tuple {
    add_path_capability path_id;        ///< 4-octet path identifier
    uint8_t             len;            ///< 1-octet Length of prefix in bits
    mpls_label          *label;          ///< Labels
    u_char              prefix[16];         ///< Address prefix
}update_prefix_label_tuple;

/**
 * Struct for route distinguisher
 */
typedef struct route_distinguisher {
    uint8_t        rd_type;
    struct rd_type_msg {
        struct rd_type_0 {
            uint16_t rd_administrator_subfield;
            uint32_t rd_assigned_number;
        }rd_type_0;
        struct rd_type_1 {
            uint16_t rd_administrator_subfield;
            uint32_t rd_assigned_number;
        }rd_type_1;
        struct rd_type_2 {
            uint32_t rd_administrator_subfield;
            uint16_t rd_assigned_number;
        }rd_type_2;
    }rd_type_msg;
}route_distinguisher;

/**
* Struct for Ethernet Segment Identifier
*/
typedef struct ethernet_segment_identifier{
    uint8_t         type;
    struct type_0{
        u_char        eth_segment_iden[9];
    }type_0;
    struct type_1{
        u_char        eth_segment_iden[6];
        uint16_t    CE_LACP_port_key;
    }type_1;
    struct type_2{
        u_char        eth_segment_iden[6];
        uint16_t    root_bridge_priority;

    }type_2;
    struct type_3{
        u_char        eth_segment_iden[6];
        uint32_t    local_discriminator_value;

    }type_3;
    struct type_4{
        uint32_t    router_id;
        uint32_t    local_discriminator_value;

    }type_4;
    struct type_5{
        uint32_t    as_number;
        uint32_t local_discriminator_value;
    }type_5;
}ethernet_segment_identifier;

/**
 * Struct for ethernet Auto-discovery route
 */
typedef struct ethernet_ad_route {
    route_distinguisher rd;
    ethernet_segment_identifier eth_seg_iden;
    u_char         ethernet_tag_id_hex[4];
    int                 mpls_label;
}ethernet_ad_route;

/**
 * Struct for MAC/IP Advertisement Route
 */
typedef struct mac_ip_advertisement_route {
    route_distinguisher rd;
    ethernet_segment_identifier eth_seg_iden;
    u_char                ethernet_tag_id_hex[4];
    uint8_t             mac_addr_len;
    u_char              mac_addr[6];
    uint8_t             ip_addr_len;
    u_char                ip_addr[16];
    int                 mpls_label_1;
    int                 mpls_label_2;
}mac_ip_advertisement_route;

/**
 * Struct for Inclusive Multicast Ethernet Tag Route
 */
typedef struct inclusive_multicast_ethernet_tag_route {
    route_distinguisher rd;
    ethernet_segment_identifier eth_seg_iden;
    u_char                ethernet_tag_id_hex[4];
    uint8_t             ip_addr_len;
    u_char                originating_router_ip[16];
}inclusive_multicast_ethernet_tag_route;

/**
 * Struct for Ethernet Segment Route
 */
typedef struct ethernet_segment_route {
    route_distinguisher         rd;
    ethernet_segment_identifier eth_seg_iden;
    uint8_t                     ip_addr_len;
    u_char                        originating_router_ip[16];
}ethernet_segment_route;

/**
* Struct is used for evpn
*/
typedef struct evpn_tuple {
    uint8_t route_type;
    uint8_t length;
    struct route_specific {
        ethernet_ad_route                       eth_ad_route;
        mac_ip_advertisement_route              mac_ip_adv_route;
        inclusive_multicast_ethernet_tag_route  incl_multicast_eth_tag_route;
        ethernet_segment_route                  eth_segment_route;
    }route_type_specific;
}evpn_tuple;

// /**
//  * Function to parse mac
//  * @param data_pointer buffer containing data to read
//  * @return string containing mac
//  */
//inline u_char* parse_mac(u_char *data_pointer) {
//     u_char *pointer = data_pointer;
//     u_char parsed_mac[6];
//     int tmp=0;
//
//    for (int i = 0; i < 6; ++i) {
//        sscanf((char *)pointer + i, "%2x", &tmp);
//        parsed_mac[i] = tmp;
//    }
//
//    return parsed_mac;
//}

/**
 * Function to get string representation of AFI code.
 * @param code AFI http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
 * @return string like "IPv6" or "IPv4"
 */
/*
inline std::string GET_AFI_STRING_BY_CODE(int code) {
    std::string afi_string;

    switch (code) {
        case BGP_AFI_IPV4 :
            afi_string = "IPv4";
            break;

        case BGP_AFI_IPV6 :
            afi_string = "IPv6";
            break;

        case BGP_AFI_BGPLS :
            afi_string = "BGP-LS";
            break;

        default:
            afi_string = "unknown";
            break;
    }
    return afi_string;
}
*/

/**
 * Function to get string representation of SAFI code.
 * @param code SAFI http://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
 * @return string like "Unicast" or "Multicast"
 */
/*inline std::string GET_SAFI_STRING_BY_CODE(int code) {
    std::string safi_string;

    switch (code) {
        case BGP_SAFI_UNICAST : // Unicast IP forwarding
            safi_string = "Unicast";
            break;

        case BGP_SAFI_MULTICAST : // Multicast IP forwarding
            safi_string = "Multicast";
            break;

        case BGP_SAFI_NLRI_LABEL : // NLRI with MPLS Labels
            safi_string = "Labeled Unicast";
            break;

        case BGP_SAFI_MCAST_VPN : // MCAST VPN
            safi_string = "MCAST VPN";
            break;

        case BGP_SAFI_VPLS : // VPLS
            safi_string = "VPLS";
            break;

        case BGP_SAFI_MDT : // BGP MDT
            safi_string = "BGP MDT";
            break;

        case BGP_SAFI_4over6 : // BGP 4over6
            safi_string = "BGP 4over6";
            break;

        case BGP_SAFI_6over4 : // BGP 6over4
            safi_string = "BGP 6over4";
            break;

        case BGP_SAFI_EVPN : // BGP EVPNs
            safi_string = "BGP EVPNs";
            break;

        case BGP_SAFI_BGPLS : // BGP-LS
            safi_string = "BGP-LS";
            break;

        case BGP_SAFI_MPLS : // MPLS-Labeled VPN
            safi_string = "MPLS-Labeled VPN";
            break;

        case BGP_SAFI_MCAST_MPLS_VPN : // Multicast BGP/MPLS VPN
            safi_string = "Multicast BGP/MPLS VPN";
            break;

        case BGP_SAFI_RT_CONSTRAINS : // Route target constrains
            safi_string = "RT constrains";
            break;

    }
    return safi_string;
}*/

#endif /* BGPCOMMON_H */