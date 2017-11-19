#include "parsebgp_bgp_update_mp_reach_evpn.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include "parsebgp_bgp_common.h"
#include <stdlib.h>
#include <string.h>

static parsebgp_error_t
parsebgp_bgp_update_mp_reach_evpn_ethernet(parsebgp_opts_t *opts,
                                           parsebgp_bgp_update_mp_reach_evpn_t *msg,
                                           uint8_t *buf,
                                           size_t *lenp,
                                           size_t remain) {

  size_t len = *lenp, nread = 0;

  if (msg->length
      != sizeof(parsebgp_bgp_update_mp_reach_evpn_ethernet_ad_route_t)) {
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_ad_route.route_distinguisher);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_ad_route.ethernet_segment_identifier);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_ad_route.ethernet_tag_id);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_ad_route.mpls_label);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parsebgp_bgp_update_mp_reach_evpn_mac_ip_adv(parsebgp_opts_t *opts,
                                             parsebgp_bgp_update_mp_reach_evpn_t *msg,
                                             uint8_t *buf,
                                             size_t *lenp,
                                             size_t remain) {

  size_t len = *lenp, nread = 0;

  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.route_distinguisher);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.ethernet_segment_identifier);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.ethernet_tag_id);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.mac_addr_len);

  if (msg->route_type_specific.mac_ip_adv_route.mac_addr_len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  memcpy(msg->route_type_specific.mac_ip_adv_route.mac_addr,
         buf,
         msg->route_type_specific.mac_ip_adv_route.mac_addr_len);
  nread += msg->route_type_specific.mac_ip_adv_route.mac_addr_len;
  buf += msg->route_type_specific.mac_ip_adv_route.mac_addr_len;

  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.ip_addr_len);

  if (msg->route_type_specific.mac_ip_adv_route.ip_addr_len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  memcpy(msg->route_type_specific.mac_ip_adv_route.ip_addr,
         buf,
         msg->route_type_specific.mac_ip_adv_route.ip_addr_len);
  nread += msg->route_type_specific.mac_ip_adv_route.ip_addr_len;
  buf += msg->route_type_specific.mac_ip_adv_route.ip_addr_len;

  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.mpls_label1);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.mac_ip_adv_route.mpls_label2);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parsebgp_bgp_update_mp_reach_evpn_inc_multicast_eth(parsebgp_opts_t *opts,
                                                    parsebgp_bgp_update_mp_reach_evpn_t *msg,
                                                    uint8_t *buf,
                                                    size_t *lenp,
                                                    size_t remain) {

  size_t len = *lenp, nread = 0;

  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.incl_multicast_eth_tag_route.route_distinguisher);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.incl_multicast_eth_tag_route.ethernet_tag_id);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len);

  if (msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  memcpy(msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr,
         buf,
         msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len);
  nread += msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len;
  buf += msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len;

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parsebgp_bgp_update_mp_reach_evpn_ethernet_seg_route(parsebgp_opts_t *opts,
                                                     parsebgp_bgp_update_mp_reach_evpn_t *msg,
                                                     uint8_t *buf,
                                                     size_t *lenp,
                                                     size_t remain) {

  size_t len = *lenp, nread = 0;

  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_segment_route.route_distinguisher);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_segment_route.ethernet_segment_identifier);
  PARSEBGP_DESERIALIZE_VAL(buf,
                           len,
                           nread,
                           msg->route_type_specific.eth_segment_route.ip_addr_len);

  if (msg->route_type_specific.eth_segment_route.ip_addr_len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  memcpy(msg->route_type_specific.eth_segment_route.ip_addr,
         buf,
         msg->route_type_specific.eth_segment_route.ip_addr_len);
  nread += msg->route_type_specific.eth_segment_route.ip_addr_len;
  buf += msg->route_type_specific.eth_segment_route.ip_addr_len;

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t
parsebgp_bgp_update_mp_reach_evpn_decode(parsebgp_opts_t *opts,
                                         parsebgp_bgp_update_mp_reach_evpn_t *msg,
                                         uint8_t *buf,
                                         size_t *lenp,
                                         size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->length);
  if (msg->length > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->route_type);

  switch (msg->route_type) {

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_ETHERNET_AD:
    slen = len - nread;
    if ((err = parsebgp_bgp_update_mp_reach_evpn_ethernet(opts, msg, buf, &slen,
                                                          remain - nread))
        != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_MAC_IP_ADVERTISMENT:
    slen = len - nread;
    if ((err =
             parsebgp_bgp_update_mp_reach_evpn_mac_ip_adv(opts, msg, buf, &slen,
                                                          remain - nread))
        != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
    slen = len - nread;
    if ((err = parsebgp_bgp_update_mp_reach_evpn_inc_multicast_eth(opts,
                                                                   msg,
                                                                   buf,
                                                                   &slen,
                                                                   remain
                                                                       - nread))
        != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_ETHERNET_SEGMENT_ROUTE:

    slen = len - nread;
    if ((err = parsebgp_bgp_update_mp_reach_evpn_ethernet_seg_route(opts,
                                                                    msg,
                                                                    buf,
                                                                    &slen,
                                                                    remain
                                                                        - nread))
        != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;
  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported SAFI (%d)", msg->route_type);

  }

  *lenp = nread;
  return PARSEBGP_OK;

}

void parsebgp_bgp_update_mp_reach_evpn_dump(
    parsebgp_bgp_update_mp_reach_evpn_t *msg, int depth) {

  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_mp_reach_evpn_t, depth);

  PARSEBGP_DUMP_INT(depth, "Route Type", msg->route_type);
  PARSEBGP_DUMP_INT(depth, "Length", msg->length);

  depth++;
  switch (msg->route_type) {

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_ETHERNET_AD:
    PARSEBGP_DUMP_STRUCT_HDR(
        parsebgp_bgp_update_mp_reach_evpn_ethernet_ad_route_t,
        depth);

    PARSEBGP_DUMP_DATA(depth,
                       "Route Distinguisher",
                       msg->route_type_specific.eth_ad_route.route_distinguisher,
                       sizeof(msg->route_type_specific.eth_ad_route.route_distinguisher));
    PARSEBGP_DUMP_DATA(depth,
                       "Ethernet Segment Identifier",
                       msg->route_type_specific.eth_ad_route.ethernet_segment_identifier,
                       sizeof(msg->route_type_specific.eth_ad_route.ethernet_segment_identifier));
    PARSEBGP_DUMP_INT(depth, "Ethernet Tag ID",
                      msg->route_type_specific.eth_ad_route.ethernet_tag_id);
    PARSEBGP_DUMP_DATA(depth,
                       "MPLS Label",
                       msg->route_type_specific.eth_ad_route.mpls_label,
                       sizeof(msg->route_type_specific.eth_ad_route.mpls_label));
    break;

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_MAC_IP_ADVERTISMENT:
    PARSEBGP_DUMP_STRUCT_HDR(
        parsebgp_bgp_update_mp_reach_evpn_mac_ip_advertisement_route_t,
        depth);

    PARSEBGP_DUMP_DATA(depth,
                       "Route Distinguisher",
                       msg->route_type_specific.mac_ip_adv_route.route_distinguisher,
                       sizeof(msg->route_type_specific.mac_ip_adv_route.route_distinguisher));
    PARSEBGP_DUMP_DATA(depth,
                       "Ethernet Segment Identifier",
                       msg->route_type_specific.mac_ip_adv_route.ethernet_segment_identifier,
                       sizeof(msg->route_type_specific.mac_ip_adv_route.ethernet_segment_identifier));
    PARSEBGP_DUMP_INT(depth,
                      "Ethernet Tag ID",
                      msg->route_type_specific.mac_ip_adv_route.ethernet_tag_id);

    PARSEBGP_DUMP_INT(depth, "MAC Address Length",
                      msg->route_type_specific.mac_ip_adv_route.mac_addr_len);

    if (msg->route_type_specific.mac_ip_adv_route.mac_addr_len == 4) {
      PARSEBGP_DUMP_IP(depth,
                       "MAC Address",
                       PARSEBGP_BGP_AFI_IPV4,
                       msg->route_type_specific.mac_ip_adv_route.mac_addr
      );
    } else {
      PARSEBGP_DUMP_IP(depth,
                       "MAC Address",
                       PARSEBGP_BGP_AFI_IPV6,
                       msg->route_type_specific.mac_ip_adv_route.mac_addr
      );
    }

    PARSEBGP_DUMP_INT(depth, "IP Address Length",
                      msg->route_type_specific.mac_ip_adv_route.ip_addr_len);

    if (msg->route_type_specific.mac_ip_adv_route.ip_addr_len == 4) {
      PARSEBGP_DUMP_IP(depth,
                       "IP Address",
                       PARSEBGP_BGP_AFI_IPV4,
                       msg->route_type_specific.mac_ip_adv_route.ip_addr
      );
    } else if(msg->route_type_specific.mac_ip_adv_route.ip_addr_len == 16) {
      PARSEBGP_DUMP_IP(depth,
                       "IP Address",
                       PARSEBGP_BGP_AFI_IPV6,
                       msg->route_type_specific.mac_ip_adv_route.ip_addr
      );
    }

    PARSEBGP_DUMP_DATA(depth,
                       "MPLS Label 1",
                       msg->route_type_specific.mac_ip_adv_route.mpls_label1,
                       sizeof(msg->route_type_specific.mac_ip_adv_route.mpls_label1));
    PARSEBGP_DUMP_DATA(depth,
                       "MPLS Label 2",
                       msg->route_type_specific.mac_ip_adv_route.mpls_label1,
                       sizeof(msg->route_type_specific.mac_ip_adv_route.mpls_label1));


    break;

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
    PARSEBGP_DUMP_STRUCT_HDR(
        parsebgp_bgp_update_mp_reach_evpn_inclusive_multicast_ethernet_tag_route_t,
        depth);

    PARSEBGP_DUMP_DATA(depth,
                       "Route Distinguisher",
                       msg->route_type_specific.incl_multicast_eth_tag_route.route_distinguisher,
                       sizeof(msg->route_type_specific.incl_multicast_eth_tag_route.route_distinguisher));
    PARSEBGP_DUMP_INT(depth,
                       "Ethernet Tag ID",
                       msg->route_type_specific.incl_multicast_eth_tag_route.ethernet_tag_id);

    PARSEBGP_DUMP_INT(depth, "IP Address Length",
                      msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len);

    if (msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len == 4) {
      PARSEBGP_DUMP_IP(depth,
                       "IP Address",
                       PARSEBGP_BGP_AFI_IPV4,
                       msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr
      );
    } else {
      PARSEBGP_DUMP_IP(depth,
                       "IP Address",
                       PARSEBGP_BGP_AFI_IPV6,
                       msg->route_type_specific.incl_multicast_eth_tag_route.ip_addr
      );
    }

    break;

  case PARSEBGP_BGP_UPDATE_MP_REACH_EVPN_ETHERNET_SEGMENT_ROUTE:
    PARSEBGP_DUMP_STRUCT_HDR(
        parsebgp_bgp_update_mp_reach_evpn_ethernet_segment_route_t,
        depth);

    PARSEBGP_DUMP_DATA(depth,
                       "Route Distinguisher",
                       msg->route_type_specific.eth_segment_route.route_distinguisher,
                       sizeof(msg->route_type_specific.eth_segment_route.route_distinguisher));
    PARSEBGP_DUMP_DATA(depth,
                       "Ethernet Segment Identifier",
                       msg->route_type_specific.eth_segment_route.ethernet_segment_identifier,
                       sizeof(msg->route_type_specific.eth_segment_route.ethernet_segment_identifier));

    PARSEBGP_DUMP_INT(depth, "IP Address Length",
                      msg->route_type_specific.eth_segment_route.ip_addr_len);

    if (msg->route_type_specific.eth_segment_route.ip_addr_len == 4) {
      PARSEBGP_DUMP_IP(depth,
                       "IP Address",
                       PARSEBGP_BGP_AFI_IPV4,
                       msg->route_type_specific.eth_segment_route.ip_addr
      );
    } else {
      PARSEBGP_DUMP_IP(depth,
                       "IP Address",
                       PARSEBGP_BGP_AFI_IPV6,
                       msg->route_type_specific.eth_segment_route.ip_addr
      );
    }

    break;
  }

}

void parsebgp_bgp_update_mp_reach_evpn_destroy(
    parsebgp_bgp_update_mp_reach_evpn_t *msg) {
  return;
}

void parsebgp_bgp_update_mp_reach_evpn_clear(
    parsebgp_bgp_update_mp_reach_evpn_t *msg) {
  return;
}

