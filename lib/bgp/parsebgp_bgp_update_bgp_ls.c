#include "parsebgp_bgp_update_bgp_ls.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <stdlib.h>
#include <string.h>

#define PARSE_SIMPLE_ATTR(attr)\
    do {    \
      if (ls_attr->len != sizeof(attr)) {\
        PARSEBGP_RETURN_INVALID_MSG_ERR;\
      }\
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, (attr));\
    } while (0)

static parsebgp_error_t
parsebgp_bgp_update_bgp_ls_tlv_decode(parsebgp_opts_t *opts,
                                      parsebgp_bgp_update_bgp_ls_attr_t *ls_attr,
                                      uint8_t *buf, size_t *lenp) {

  int i;
  size_t nread = 0, len = *lenp;

  if (ls_attr->len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  switch (ls_attr->type) {

    /** NODE ATTRIBUTES */
    // type 263
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_MT_ID:
    if ((ls_attr->len % sizeof(uint16_t)) != 0) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    ls_attr->attr.node.node_mt_id.ids_cnt = ls_attr->len / sizeof(uint16_t);

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_mt_id.ids,
                           sizeof(uint16_t),
                           ls_attr->attr.node.node_mt_id._ids_alloc_cnt,
                           ls_attr->attr.node.node_mt_id.ids_cnt);

    for (i = 0; i < ls_attr->attr.node.node_mt_id.ids_cnt; i++) {

      PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_mt_id.ids[i]);

      ls_attr->attr.node.node_mt_id.ids[i] =
          ntohs(ls_attr->attr.node.node_mt_id.ids[i]);
    }
    break;

    //type 1024
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_FLAG:
    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_flag_bits);
    break;

    //type 1025
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_OPAQUE:
    ls_attr->attr.node.node_opaque.opaque_cnt = ls_attr->len;

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_opaque.opaque,
                           sizeof(uint8_t),
                           ls_attr->attr.node.node_opaque._opaque_alloc_cnt,
                           ls_attr->attr.node.node_opaque.opaque_cnt);

    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_opaque.opaque);
    break;

    // type 1026
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_NAME:
    memcpy(ls_attr->attr.node.node_name, buf, ls_attr->len);
    ls_attr->attr.node.node_name[ls_attr->len] = '\0';
    buf += ls_attr->len;
    nread += ls_attr->len;
    break;

    // type 1027
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_ISIS_AREA_ID:
    ls_attr->attr.node.node_isis_area_id.ids_cnt = ls_attr->len;

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_isis_area_id.ids,
                           sizeof(uint8_t),
                           ls_attr->attr.node.node_isis_area_id._ids_alloc_cnt,
                           ls_attr->attr.node.node_isis_area_id.ids_cnt);

    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_isis_area_id.ids);
    break;

    // type 1028
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_IPV4_ROUTER_ID_LOCAL:
    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_ipv4_router_id_local);
    break;

    // type 1029
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_IPV6_ROUTER_ID_LOCAL:
    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_ipv6_router_id_local);
    break;

  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_CAPABILITIES:
    //TODO: Ask Alistair
    break;

  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_ALGORITHM:
    ls_attr->attr.node.node_sr_algo.algo_cnt = ls_attr->len;

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_sr_algo.algo,
                           sizeof(uint8_t),
                           ls_attr->attr.node.node_sr_algo._algo_alloc_cnt,
                           ls_attr->attr.node.node_sr_algo.algo_cnt);

    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_sr_algo.algo);

    break;

  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_LOCAL_BLOCK:
    break;

  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_SR_SRMS_PREF:
    PARSE_SIMPLE_ATTR(ls_attr->attr.node.node_sr_srms_pref);
    break;

    /** LINK ATTRIBUTES */

    // type = 1030
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_ipv4_router_id_remote);
    break;

    // type = 1031
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_ipv6_router_id_remote);
    break;

    // type = 1088
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_admin_group);
    break;

    // type = 1089
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_max_link_bw);
    break;

    // type 1090
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_max_resv_bw);
    break;

    // type 1091
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_unresv_bw);
    break;

    // type 1092
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC:
    if (ls_attr->len == 0) {
      ls_attr->attr.link.link_te_def_metric = 0;
      break;
    }

    if (ls_attr->len > 4) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    memcpy(&ls_attr->attr.link.link_te_def_metric, buf, ls_attr->len);
    ls_attr->attr.link.link_te_def_metric =
        ntohl(ls_attr->attr.link.link_te_def_metric);
    buf += ls_attr->len;
    nread += ls_attr->len;

    break;

    // type 1093
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_protective_type);
    break;

    // type 1094
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK:
    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_mpls_protocal_mask);
    break;

    // type 1095
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC:
    if (ls_attr->len > 3) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    memcpy(&ls_attr->attr.link.link_igp_metric, buf, ls_attr->len);
    buf += ls_attr->len;
    nread += ls_attr->len;

    ls_attr->attr.link.link_igp_metric =
        ntohl(ls_attr->attr.link.link_igp_metric);
    break;

    // type 1096
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG:
    if ((ls_attr->len % sizeof(uint32_t)) != 0) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    ls_attr->attr.link.link_srlg.srlg_cnt = ls_attr->len / sizeof(uint32_t);
    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.link.link_srlg.srlg,
                           sizeof(uint16_t),
                           ls_attr->attr.link.link_srlg._srlg_alloc_cnt,
                           ls_attr->attr.link.link_srlg.srlg_cnt);

    for (i = 0; i < ls_attr->attr.link.link_srlg.srlg_cnt; i++) {
      PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_srlg.srlg[i]);

      ls_attr->attr.link.link_srlg.srlg[i] =
          ntohs(ls_attr->attr.link.link_srlg.srlg[i]);
    }

    break;

    // type 1097
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE:
    ls_attr->attr.link.link_opaque.opaque_cnt = ls_attr->len;

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.link.link_opaque.opaque,
                           sizeof(uint8_t),
                           ls_attr->attr.link.link_opaque._opaque_alloc_cnt,
                           ls_attr->attr.link.link_opaque.opaque_cnt);

    PARSE_SIMPLE_ATTR(ls_attr->attr.link.link_opaque.opaque);
    break;

    // type 1098
  case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME:
    memcpy(ls_attr->attr.link.link_name, buf, ls_attr->len);
    ls_attr->attr.link.link_name[ls_attr->len] = '\0';

    buf += ls_attr->len;
    nread += ls_attr->len;
    break;

    /** PREFIX ATTRIBUTES */

    // type 1152
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_IGP_FLAGS:
    PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_igp_flags);
    break;

    // type 1153
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_ROUTE_TAG:
    if ((ls_attr->len % sizeof(uint32_t)) != 0) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    ls_attr->attr.prefix.prefix_route_tag.tags_cnt =
        ls_attr->len / sizeof(uint32_t);

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_route_tag.tags,
                           sizeof(uint32_t),
                           ls_attr->attr.prefix.prefix_route_tag._tags_alloc_cnt,
                           ls_attr->attr.prefix.prefix_route_tag.tags_cnt);

    for (i = 0; i < ls_attr->attr.prefix.prefix_route_tag.tags_cnt; i++) {
      PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_route_tag.tags[i]);
      ls_attr->attr.prefix.prefix_route_tag.tags[i] =
          ntohl(ls_attr->attr.prefix.prefix_route_tag.tags[i]);
    }
    break;

    // type 1154
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_EXTEND_ROUTE_TAG:
    if ((ls_attr->len % sizeof(uint64_t)) != 0) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt =
        ls_attr->len / sizeof(uint64_t);

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags,
                           sizeof(uint64_t),
                           ls_attr->attr.prefix.prefix_extended_route_tag._ex_tags_alloc_cnt,
                           ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt);

    for (i = 0; i < ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt;
         i++) {
      PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[i]);

      ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[i] =
          ntohll(ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[i]);
    }
    break;

    // type 1155
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_PREFIX_METRIC:
    PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_metric);
    ls_attr->attr.prefix.prefix_metric =
        ntohl(ls_attr->attr.prefix.prefix_metric);
    break;

    // type 1156
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_OSPF_FWD_ADDR:
    PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_ospf_forwarding_address);
    break;

    // type 1157
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_OPAQUE_PREFIX:
    ls_attr->attr.prefix.prefix_opaque.opaque_cnt =
        ls_attr->len;

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_opaque.opaque,
                           sizeof(uint8_t),
                           ls_attr->attr.prefix.prefix_opaque._opaque_alloc_cnt,
                           ls_attr->attr.prefix.prefix_opaque.opaque_cnt);

    PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_opaque.opaque);
    break;
  case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_SID:
    ls_attr->attr.prefix.prefix_sid.sid_count = ls_attr->len;

    PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_sid.sid,
                           sizeof(uint8_t),
                           ls_attr->attr.prefix.prefix_sid._sid_alloc_cnt,
                           ls_attr->attr.prefix.prefix_sid.sid_count);

    PARSE_SIMPLE_ATTR(ls_attr->attr.prefix.prefix_sid.sid);
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(
        opts, buf, nread, ls_attr->len,
        "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
    nread += ls_attr->len;
    break;
  }
  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t
parsebgp_bgp_update_bgp_ls_decode(parsebgp_opts_t *opts,
                                  parsebgp_bgp_update_bgp_ls_t *ls_msg,
                                  uint8_t *buf, size_t *lenp, size_t remain) {

  parsebgp_error_t err;
  size_t len = *lenp, nread = 0, slen;
  parsebgp_bgp_update_bgp_ls_attr_t *ls_attr;

  ls_msg->attrs_cnt = 0;

  /**
   * Loop through all TLV's for the attribute
   */
  while (nread < remain) {

    PARSEBGP_MAYBE_REALLOC(ls_msg->attrs,
                           sizeof(parsebgp_bgp_update_bgp_ls_attr_t),
                           ls_msg->_attrs_alloc_cnt,
                           ls_msg->attrs_cnt + 1);

    ls_attr = &ls_msg->attrs[ls_msg->attrs_cnt];
    ls_msg->attrs_cnt++;

    // Read the attr type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->type);
    ls_attr->type = ntohs(ls_attr->type);

    // Read the attr length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->len);
    ls_attr->len = ntohs(ls_attr->len);

    slen = len - nread;
    if ((err = parsebgp_bgp_update_bgp_ls_tlv_decode(
        opts, ls_attr, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_bgp_ls_dump(
    parsebgp_bgp_update_bgp_ls_t *ls_msg, int depth) {

  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_t, depth);

  depth++;
  int i, j;
  parsebgp_bgp_update_bgp_ls_attr_t *ls_attr;
  for (i = 0; i < ls_msg->attrs_cnt; i++) {
    ls_attr = &ls_msg->attrs[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", ls_attr->type);
    PARSEBGP_DUMP_INT(depth, "Length", ls_attr->len);

    depth++;
    switch (ls_attr->type) {

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_MT_ID:
      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);

      for (j = 0; j < ls_attr->attr.node.node_mt_id.ids_cnt; j++) {
        PARSEBGP_DUMP_INT(depth, "MT_ID", ls_attr->attr.node.node_mt_id.ids[j]);
      }
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_FLAG:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth, "NODE FLAG", ls_attr->attr.node.node_flag_bits);
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_OPAQUE:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);

      PARSEBGP_DUMP_DATA(depth,
                         "LINK OPAQUE",
                         ls_attr->attr.link.link_opaque.opaque, ls_attr->len);

      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_NAME:
      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);
      PARSEBGP_DUMP_INFO(depth, "NODE NAME : %s", ls_attr->attr.node.node_name);
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_ISIS_AREA_ID:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);
      for (j = 0; j < ls_attr->attr.node.node_isis_area_id.ids_cnt; j++) {
        PARSEBGP_DUMP_INT(depth,
                          "PREFIX ROUTE TAG",
                          ls_attr->attr.node.node_isis_area_id.ids[j]);
      }
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_IPV4_ROUTER_ID_LOCAL: // Includes

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);
      PARSEBGP_DUMP_IP(depth,
                       "IPV4 ROUTER ID LOCAL",
                       PARSEBGP_BGP_AFI_IPV4,
                       ls_attr->attr.node.node_ipv4_router_id_local);
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_NODE_IPV6_ROUTER_ID_LOCAL: // Includes

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t,
                               depth);
      PARSEBGP_DUMP_IP(depth,
                       "IPV6 ROUTER ID LOCAL",
                       PARSEBGP_BGP_AFI_IPV6,
                       ls_attr->attr.node.node_ipv6_router_id_local);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_IP(depth,
                       "IPV4 ROUTER ID REMOTE",
                       PARSEBGP_BGP_AFI_IPV4,
                       ls_attr->attr.link.link_ipv4_router_id_remote);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_IP(depth,
                       "IPV6 ROUTER ID REMOTE",
                       PARSEBGP_BGP_AFI_IPV6,
                       ls_attr->attr.link.link_ipv6_router_id_remote);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "LINK ADMIN GROUP",
                        ls_attr->attr.link.link_admin_group);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_DATA(depth,
                         "LINK MAX LINK BW",
                         ls_attr->attr.link.link_max_link_bw, ls_attr->len);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_DATA(depth,
                         "LINK MAX RESV BW",
                         ls_attr->attr.link.link_max_resv_bw, ls_attr->len);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_DATA(depth,
                         "LINK UNRESV BW",
                         ls_attr->attr.link.link_unresv_bw, ls_attr->len);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "LINK TE DEF METRIC",
                        ls_attr->attr.link.link_te_def_metric);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "LINK TE DEF METRIC",
                        ls_attr->attr.link.link_protective_type);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "LINK PROTOCOL MASK",
                        ls_attr->attr.link.link_mpls_protocal_mask);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "LINK IGP METRIC",
                        ls_attr->attr.link.link_igp_metric);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG:
      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      for (j = 0; j < ls_attr->attr.link.link_srlg.srlg_cnt; j++) {
        PARSEBGP_DUMP_INT(depth,
                          "PREFIX ROUTE TAG",
                          ls_attr->attr.link.link_srlg.srlg[j]);
      }
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_DATA(depth,
                         "LINK OPAQUE",
                         ls_attr->attr.link.link_opaque.opaque, ls_attr->len);
      break;

    case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME: {

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t,
                               depth);
      PARSEBGP_DUMP_INFO(depth, "LINK NAME : %s", ls_attr->attr.link.link_name);
      break;
    }

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_IGP_FLAGS:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "PREFIX IGP FLAGS",
                        ls_attr->attr.prefix.prefix_igp_flags);
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_ROUTE_TAG:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      for (j = 0; j < ls_attr->attr.prefix.prefix_route_tag.tags_cnt; j++) {
        PARSEBGP_DUMP_INT(depth,
                          "PREFIX ROUTE TAG",
                          ls_attr->attr.prefix.prefix_route_tag.tags[j]);
      }
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_EXTEND_ROUTE_TAG:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      for (j = 0;
           j < ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt;
           j++) {
        if (j != 0) {
          printf(" ");
        }
        printf("%" PRIu64,
               ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[j]);
      }
      printf("\n");
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_PREFIX_METRIC:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      PARSEBGP_DUMP_INT(depth,
                        "PREFIX METRIC",
                        ls_attr->attr.prefix.prefix_metric);
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_OSPF_FWD_ADDR:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      PARSEBGP_DUMP_IP(depth,
                       "PREFIX OSPF FWD ADDRESS",
                       PARSEBGP_BGP_AFI_IPV4,
                       ls_attr->attr.prefix.prefix_ospf_forwarding_address);
      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_OPAQUE_PREFIX:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      PARSEBGP_DUMP_DATA(depth,
                         "PREFIX OPAQUE",
                         ls_attr->attr.prefix.prefix_opaque.opaque,
                         ls_attr->len);

      break;

    case PARSEBGP_BGP_UPDATE_BGP_LS_ATTR_PREFIX_SID:

      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t,
                               depth);
      PARSEBGP_DUMP_DATA(depth,
                         "PREFIX SID",
                         ls_attr->attr.prefix.prefix_sid.sid,
                         ls_attr->len);

      break;
    }
    --depth;
  }
}

void parsebgp_bgp_update_bgp_ls_destroy(
    parsebgp_bgp_update_bgp_ls_t *ls_msg) {

  if (ls_msg == NULL || ls_msg->attrs == NULL) {
    return;
  }

  parsebgp_bgp_update_bgp_ls_attr_t *attr;

  int i;
  for (i = 0; i < ls_msg->_attrs_alloc_cnt; i++) {
    attr = &ls_msg->attrs[i];

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_MT_ID */
    free(attr->attr.node.node_mt_id.ids);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_OPAQUE */
    free(attr->attr.node.node_opaque.opaque);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_ISIS_AREA_ID */
    free(attr->attr.node.node_isis_area_id.ids);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_SR_ALGORITHM */
    free(attr->attr.node.node_sr_algo.algo);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG */
    free(attr->attr.link.link_srlg.srlg);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE */
    free(attr->attr.link.link_opaque.opaque);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_ROUTE_TAG */
    free(attr->attr.prefix.prefix_route_tag.tags);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_EXTEND_ROUTE_TAG */
    free(attr->attr.prefix.prefix_extended_route_tag.ex_tags);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OPAQUE_PREFIX */
    free(attr->attr.prefix.prefix_opaque.opaque);

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_SID */
    free(attr->attr.prefix.prefix_sid.sid);

  }

  free(ls_msg->attrs);
  free(ls_msg);
}

void parsebgp_bgp_update_bgp_ls_clear(
    parsebgp_bgp_update_bgp_ls_t *ls_msg) {

  parsebgp_bgp_update_bgp_ls_attr_t *attr;
  int i = 0;
  for (i = 0; i < ls_msg->attrs_cnt; i++) {
    attr = &ls_msg->attrs[i];

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_MT_ID */
    attr->attr.node.node_mt_id.ids_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_OPAQUE */
    attr->attr.node.node_opaque.opaque_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_ISIS_AREA_ID */
    attr->attr.node.node_isis_area_id.ids_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_SR_ALGORITHM */
    attr->attr.node.node_sr_algo.algo_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG */
    attr->attr.link.link_srlg.srlg_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE */
    attr->attr.link.link_opaque.opaque_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_ROUTE_TAG */
    attr->attr.prefix.prefix_route_tag.tags_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_EXTEND_ROUTE_TAG */
    attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OPAQUE_PREFIX */
    attr->attr.prefix.prefix_opaque.opaque_cnt = 0;

    /** PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_SID */
    attr->attr.prefix.prefix_sid.sid_count = 0;
  }

  ls_msg->attrs_cnt = 0;
}