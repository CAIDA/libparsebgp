#ifndef __PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_H
#define __PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_H

#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

typedef enum{

  /** Type = 1 Ethernet Auto-Discovery (A - D) route */
      PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_ETHERNET_AD = 1,

  /** Type = 2 MAC/IP Advertisement route */
      PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_MAC_IP_ADVERTISMENT = 2,

  /** Type = 3 Inclusive Multicast Ethernet Tag route */
      PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG = 3,

  /** Type = 4 Ethernet Segment route */
      PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_ETHERNET_SEGMENT_ROUTE = 4,

}parsebgp_bgp_update_mp_reach_evpn_route_types_t;

/**
 * Struct for ethernet Auto-discovery route
 */
typedef struct parsebgp_bgp_update_mp_reach_evpn_ethernet_ad_route {

  /** Route Distinguisher */
  uint8_t route_distinguisher[8];

  /** Ethernet Segment Identifier */
  uint8_t ethernet_segment_identifier[10];

  /** Ethernet Tag ID */
  uint32_t ethernet_tag_id;

  /** MPLS Label  */
  uint8_t mpls_label[3];

} parsebgp_bgp_update_mp_reach_evpn_ethernet_ad_route_t;

/**
 * Struct for MAC/IP Advertisement Route
 */
typedef struct parsebgp_bgp_update_mp_reach_evpn_mac_ip_advertisement_route {
  /** Route Distinguisher */
  uint8_t route_distinguisher[8];

  /** Ethernet Segment Identifier */
  uint8_t ethernet_segment_identifier[10];

  /** Ethernet Tag ID */
  uint32_t ethernet_tag_id;

  /** MAC Address Length */
  uint8_t mac_addr_len;

  /** MAC Address */
  uint8_t mac_addr[6];

  /** IP Address Length */
  uint8_t ip_addr_len;

  /** IP Address (0, 4, 16) */
  uint8_t ip_addr[16];

  /** MPLS Label  */
  uint8_t mpls_label1[3];

  /** MPLS Label  */
  uint8_t mpls_label2[3];

} parsebgp_bgp_update_mp_reach_evpn_mac_ip_advertisement_route_t;

/**
 * Struct for Inclusive Multicast Ethernet Tag Route
 */
typedef struct parsebgp_bgp_update_mp_reach_evpn_inclusive_multicast_ethernet_tag_route {
  /** Route Distinguisher */
  uint8_t route_distinguisher[8];

  /** Ethernet Tag ID */
  uint32_t ethernet_tag_id;

  /** IP Address Length */
  uint8_t ip_addr_len;

  /** IP Address (4, 16) */
  uint8_t ip_addr[16];

} parsebgp_bgp_update_mp_reach_evpn_inclusive_multicast_ethernet_tag_route_t;

/**
 * Struct for Ethernet Segment Route
 */
typedef struct parsebgp_bgp_update_mp_reach_evpn_ethernet_segment_route {
  /** Route Distinguisher */
  uint8_t route_distinguisher[8];

  /** Ethernet Segment Identifier */
  uint8_t ethernet_segment_identifier[10];

  /** IP Address Length */
  uint8_t ip_addr_len;

  /** IP Address (4, 16) */
  uint8_t ip_addr[16];

} parsebgp_bgp_update_mp_reach_evpn_ethernet_segment_route_t;

/**
 * Struct is used for evpn
 */
typedef struct parsebgp_bgp_update_mp_reach_evpn {

  /** Route Type definrs the encoding of the rest of message (len = 1)*/
  uint8_t route_type;

  /** Length of the rest of the message (len = 1) */
  uint8_t length;


  union route_specific {
    /** Ethernet Auto-Discovery route type specific EVPN NLRI */
    parsebgp_bgp_update_mp_reach_evpn_ethernet_ad_route_t eth_ad_route;

    /** MAC/IP Advertisement route type specific EVPN NLRI */
    parsebgp_bgp_update_mp_reach_evpn_mac_ip_advertisement_route_t mac_ip_adv_route;

    /** Inclusive Multicast Ethernet Tag route type specific EVPN NLRI */
    parsebgp_bgp_update_mp_reach_evpn_inclusive_multicast_ethernet_tag_route_t incl_multicast_eth_tag_route;

    /** Ethernet Segment route type specific EVPN NLRI */
    parsebgp_bgp_update_mp_reach_evpn_ethernet_segment_route_t eth_segment_route;
  } route_type_specific;

} parsebgp_bgp_update_mp_reach_evpn_t;

/** Decode a BGP LS message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_evpn_decode(parsebgp_opts_t *opts,
                                         parsebgp_bgp_update_mp_reach_evpn_t *msg,
                                  uint8_t *buf, size_t *lenp, size_t remain);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_REACH_EVPN attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_reach_evpn_dump(
    parsebgp_bgp_update_mp_reach_evpn_t *msg, int depth);

/** Destroy a BGP Link State message */
void parsebgp_bgp_update_mp_reach_evpn_destroy(
    parsebgp_bgp_update_mp_reach_evpn_t *msg);

/** Clear a BGP Link State message */
void parsebgp_bgp_update_mp_reach_evpn_clear(
    parsebgp_bgp_update_mp_reach_evpn_t *msg);



#endif //__PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_H
