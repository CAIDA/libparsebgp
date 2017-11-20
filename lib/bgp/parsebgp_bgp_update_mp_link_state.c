/*
 * Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include "parsebgp_bgp_update_mp_link_state.h"
#include "parsebgp_bgp_update_mp_reach.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include "parsebgp_utils.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static parsebgp_error_t
parse_link_state_nlri_node_val(parsebgp_opts_t *opts,
                               parsebgp_bgp_update_mp_link_state_node_descriptor_t *node,
                               uint8_t *buf,
                               size_t *lenp) {

  size_t len = *lenp, nread = 0;

  // Read the nlri type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, node->type);
  node->type = ntohs(node->type);

  // Read the nlri length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, node->len);
  node->len = ntohs(node->len);

  switch (node->type) {

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_AS:
    if (node->len != sizeof(node->node_value.asn)){
        PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, node->node_value.asn);
    node->node_value.asn = ntohs(node->node_value.asn);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_BGP_LS_ID:
    if (node->len != sizeof(node->node_value.bgp_ls_id)){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, node->node_value.bgp_ls_id);
    node->node_value.bgp_ls_id = ntohs(node->node_value.bgp_ls_id);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_OSPF_AREA_ID:
    if (node->len != sizeof(node->node_value.ospf_area_Id)){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, node->node_value.ospf_area_Id);
    node->node_value.ospf_area_Id = ntohs(node->node_value.ospf_area_Id);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NODE_DESCR_IGP_ROUTER_ID:
    if (node->len > 8) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    memcpy(node->node_value.igp_router_id, buf, node->len);
    nread += node->len;
    buf += node->len;
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts,
                                  buf,
                                  nread,
                                  len,
                                  "Unsupported NLRI node type (%d)",
                                  node->type);

  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_link_state_nlri_node(parsebgp_opts_t *opts,
                           parsebgp_bgp_update_mp_link_state_t *msg,
                           uint8_t *buf,
                           size_t *lenp, size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Read the node type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.node_nlri.type);
  msg->nlri_ls.node_nlri.type = ntohs(msg->nlri_ls.node_nlri.type);

  // Read the node length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.node_nlri.len);
  msg->nlri_ls.node_nlri.len = ntohs(msg->nlri_ls.node_nlri.len);

  msg->nlri_ls.node_nlri.local_node_desc.nodes_cnt = 0;

  parsebgp_bgp_update_mp_link_state_node_descriptor_t *node;

  while(nread < msg->nlri_ls.node_nlri.len) {
    PARSEBGP_MAYBE_REALLOC(msg->nlri_ls.node_nlri.local_node_desc.nodes,
                           sizeof(parsebgp_bgp_update_mp_link_state_node_descriptor_t),
                           msg->nlri_ls.node_nlri.local_node_desc._nodes_alloc_cnt,
                           msg->nlri_ls.node_nlri.local_node_desc.nodes_cnt
                               + 1);

    node = &msg->nlri_ls.node_nlri.local_node_desc.nodes[msg->nlri_ls.node_nlri.local_node_desc.nodes_cnt];
    msg->nlri_ls.node_nlri.local_node_desc.nodes_cnt += 1;

    slen = len - nread;

    if ((err = parse_link_state_nlri_node_val(
        opts, node, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }

    buf += slen;
    nread += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_link_state_nlri_link_val(parsebgp_opts_t *opts,
                               parsebgp_bgp_update_mp_link_state_link_descriptor_t *link,
                               uint8_t *buf,
                               size_t *lenp) {

  size_t len = *lenp, nread = 0;

  // Read the nlri type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->type);
  link->type = ntohs(link->type);

  // Read the nlri length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->len);
  link->len = ntohs(link->len);

  switch (link->type) {

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_ID:

    if (link->len != 8){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_ids.link_local_id);
    link->link_ids.link_local_id = ntohs(link->link_ids.link_local_id);

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_ids.link_remote_id);
    link->link_ids.link_local_id = ntohs(link->link_ids.link_remote_id);

    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV4_INTF_ADDR:
    if (link->len != 4){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_ipv4_intf_addr);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV4_NEI_ADDR:
    if (link->len != 4){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_ipv4_neigh_addr);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV6_INTF_ADDR:
    if (link->len != 16){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_ipv6_intf_addr);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_IPV6_NEI_ADDR:
    if (link->len != 16){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_ipv6_neigh_addr);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_LINK_DESCR_MT_ID:

    if ((link->len % sizeof(uint16_t)) != 0) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    link->link_mt_id.ids_cnt = link->len / sizeof(uint16_t);

    PARSEBGP_MAYBE_REALLOC(link->link_mt_id.ids,
                           sizeof(uint16_t),
                           link->link_mt_id._ids_alloc_cnt,
                           link->link_mt_id.ids_cnt);

    int i;
    for (i = 0; i < link->link_mt_id.ids_cnt; i++) {

      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, link->link_mt_id.ids);

      link->link_mt_id.ids[i] =
          ntohs(link->link_mt_id.ids[i]);
    }
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts,
                                  buf,
                                  nread,
                                  len,
                                  "Unsupported NLRI node type (%d)",
                                  link->type);

  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_link_state_nlri_link(parsebgp_opts_t *opts,
                           parsebgp_bgp_update_mp_link_state_t *msg,
                           uint8_t *buf,
                           size_t *lenp, size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Read the node type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.link_nlri.local_node_desc.type);
  msg->nlri_ls.link_nlri.local_node_desc.type = ntohs(msg->nlri_ls.link_nlri.local_node_desc.type);

  // Read the node length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.link_nlri.local_node_desc.len);
  msg->nlri_ls.link_nlri.local_node_desc.len = ntohs(msg->nlri_ls.link_nlri.local_node_desc.len);

  msg->nlri_ls.link_nlri.local_node_desc.nodes_cnt = 0;

  parsebgp_bgp_update_mp_link_state_node_descriptor_t *node;

  while(nread < msg->nlri_ls.link_nlri.local_node_desc.len) {
    PARSEBGP_MAYBE_REALLOC(msg->nlri_ls.link_nlri.local_node_desc.nodes,
                           sizeof(parsebgp_bgp_update_mp_link_state_node_descriptor_t),
                           msg->nlri_ls.link_nlri.local_node_desc._nodes_alloc_cnt,
                           msg->nlri_ls.link_nlri.local_node_desc.nodes_cnt
                               + 1);

    node = &msg->nlri_ls.link_nlri.local_node_desc.nodes[msg->nlri_ls.link_nlri.local_node_desc.nodes_cnt];
    msg->nlri_ls.link_nlri.local_node_desc.nodes_cnt += 1;

    slen = len - nread;

    if ((err = parse_link_state_nlri_node_val(
        opts, node, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }

    buf += slen;
    nread += slen;
  }


  // Read the node type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.link_nlri.remote_node_desc.type);
  msg->nlri_ls.link_nlri.remote_node_desc.type = ntohs(msg->nlri_ls.link_nlri.remote_node_desc.type);

  // Read the node length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.link_nlri.remote_node_desc.len);
  msg->nlri_ls.link_nlri.remote_node_desc.len = ntohs(msg->nlri_ls.link_nlri.remote_node_desc.len);

  msg->nlri_ls.link_nlri.remote_node_desc.nodes_cnt = 0;

  while(nread < msg->nlri_ls.link_nlri.remote_node_desc.len) {
    PARSEBGP_MAYBE_REALLOC(msg->nlri_ls.link_nlri.remote_node_desc.nodes,
                           sizeof(parsebgp_bgp_update_mp_link_state_node_descriptor_t),
                           msg->nlri_ls.link_nlri.remote_node_desc._nodes_alloc_cnt,
                           msg->nlri_ls.link_nlri.remote_node_desc.nodes_cnt
                               + 1);

    node = &msg->nlri_ls.link_nlri.remote_node_desc.nodes[msg->nlri_ls.link_nlri.remote_node_desc.nodes_cnt];
    msg->nlri_ls.link_nlri.remote_node_desc.nodes_cnt += 1;

    slen = len - nread;

    if ((err = parse_link_state_nlri_node_val(
        opts, node, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }

    buf += slen;
    nread += slen;
  }


  // Read the node type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.link_nlri.link_desc.type);
  msg->nlri_ls.link_nlri.link_desc.type = ntohs(msg->nlri_ls.link_nlri.link_desc.type);

  // Read the node length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.link_nlri.link_desc.len);
  msg->nlri_ls.link_nlri.link_desc.len = ntohs(msg->nlri_ls.link_nlri.link_desc.len);

  msg->nlri_ls.link_nlri.link_desc.links_cnt = 0;

  parsebgp_bgp_update_mp_link_state_link_descriptor_t *link;

  while(nread < msg->nlri_ls.link_nlri.link_desc.len) {
    PARSEBGP_MAYBE_REALLOC(msg->nlri_ls.link_nlri.link_desc.links,
                           sizeof(parsebgp_bgp_update_mp_link_state_link_descriptor_t),
                           msg->nlri_ls.link_nlri.link_desc._links_alloc_cnt,
                           msg->nlri_ls.link_nlri.link_desc.links_cnt
                               + 1);

    link = &msg->nlri_ls.link_nlri.link_desc.links[msg->nlri_ls.link_nlri.link_desc.links_cnt];
    msg->nlri_ls.link_nlri.link_desc.links_cnt += 1;

    slen = len - nread;

    if ((err = parse_link_state_nlri_link_val(
        opts, link, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }

    buf += slen;
    nread += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;

}

static parsebgp_error_t
parse_link_state_nlri_prefix_val(parsebgp_opts_t *opts,
                                 parsebgp_bgp_update_mp_link_state_prefix_descriptor_t *prefix,
                                 uint8_t *buf,
                                 size_t *lenp) {

  size_t len = *lenp, nread = 0;

  // Read the nlri type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, prefix->type);
  prefix->type = ntohs(prefix->type);

  // Read the nlri length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, prefix->len);
  prefix->len = ntohs(prefix->len);

  switch (prefix->type) {

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_PREFIX_DESCR_MT_ID:

    if ((prefix->len % sizeof(uint16_t)) != 0) {
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    prefix->prefix_mt_id.ids_cnt = prefix->len / sizeof(uint16_t);

    PARSEBGP_MAYBE_REALLOC(prefix->prefix_mt_id.ids,
                           sizeof(uint16_t),
                           prefix->prefix_mt_id._ids_alloc_cnt,
                           prefix->prefix_mt_id.ids_cnt);

    int i;
    for (i = 0; i < prefix->prefix_mt_id.ids_cnt; i++) {

      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, prefix->prefix_mt_id.ids);

      prefix->prefix_mt_id.ids[i] =
          ntohs(prefix->prefix_mt_id.ids[i]);
    }
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_PREFIX_DESCR_OSPF_ROUTE_TYPE:
    if (prefix->len != sizeof(prefix->prefix_ospf_route_type)){
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, prefix->prefix_ospf_route_type);
    break;

  case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_PREFIX_DESCR_IP_REACH_INFO:
    //TODO: Ask Alistair
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts,
                                  buf,
                                  nread,
                                  len,
                                  "Unsupported NLRI node type (%d)",
                                  prefix->type);
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts,
                                  buf,
                                  nread,
                                  len,
                                  "Unsupported NLRI node type (%d)",
                                  prefix->type);

  }

  *lenp = nread;
  return PARSEBGP_OK;
}


static parsebgp_error_t
parse_link_state_nlri_prefix(parsebgp_opts_t *opts,
                             parsebgp_bgp_update_mp_link_state_t *msg,
                             uint8_t *buf,
                             size_t *lenp, size_t remain) {
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Read the node type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.prefix_nlri.local_node_desc.type);
  msg->nlri_ls.prefix_nlri.local_node_desc.type = ntohs(msg->nlri_ls.prefix_nlri.local_node_desc.type);

  // Read the node length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.prefix_nlri.local_node_desc.len);
  msg->nlri_ls.prefix_nlri.local_node_desc.len = ntohs(msg->nlri_ls.prefix_nlri.local_node_desc.len);

  msg->nlri_ls.prefix_nlri.local_node_desc.nodes_cnt = 0;

  parsebgp_bgp_update_mp_link_state_node_descriptor_t *node;

  while(nread < msg->nlri_ls.prefix_nlri.local_node_desc.len) {
    PARSEBGP_MAYBE_REALLOC(msg->nlri_ls.prefix_nlri.local_node_desc.nodes,
                           sizeof(parsebgp_bgp_update_mp_link_state_node_descriptor_t),
                           msg->nlri_ls.prefix_nlri.local_node_desc._nodes_alloc_cnt,
                           msg->nlri_ls.prefix_nlri.local_node_desc.nodes_cnt
                               + 1);

    node = &msg->nlri_ls.prefix_nlri.local_node_desc.nodes[msg->nlri_ls.prefix_nlri.local_node_desc.nodes_cnt];
    msg->nlri_ls.prefix_nlri.local_node_desc.nodes_cnt += 1;

    slen = len - nread;

    if ((err = parse_link_state_nlri_node_val(
        opts, node, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }

    buf += slen;
    nread += slen;
  }

  // Read the node type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.prefix_nlri.prefix_desc.type);
  msg->nlri_ls.prefix_nlri.local_node_desc.type = ntohs(msg->nlri_ls.prefix_nlri.local_node_desc.type);

  // Read the node length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->nlri_ls.prefix_nlri.local_node_desc.len);
  msg->nlri_ls.prefix_nlri.local_node_desc.len = ntohs(msg->nlri_ls.prefix_nlri.local_node_desc.len);

  msg->nlri_ls.prefix_nlri.local_node_desc.nodes_cnt = 0;

  parsebgp_bgp_update_mp_link_state_prefix_descriptor_t *prefix;

  while(nread < msg->nlri_ls.prefix_nlri.prefix_desc.len) {
    PARSEBGP_MAYBE_REALLOC(msg->nlri_ls.prefix_nlri.prefix_desc.pref,
                           sizeof(parsebgp_bgp_update_mp_link_state_node_descriptor_t),
                           msg->nlri_ls.prefix_nlri.prefix_desc._pref_alloc_cnt,
                           msg->nlri_ls.prefix_nlri.prefix_desc.pref_cnt
                               + 1);

    prefix = &msg->nlri_ls.prefix_nlri.prefix_desc.pref[msg->nlri_ls.prefix_nlri.prefix_desc.pref_cnt];
    msg->nlri_ls.prefix_nlri.prefix_desc.pref_cnt += 1;

    slen = len - nread;

    if ((err = parse_link_state_nlri_prefix_val(
        opts, prefix, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }

    buf += slen;
    nread += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;

}

static parsebgp_error_t
parse_reach_link_state_nlri(parsebgp_opts_t *opts,
                      parsebgp_bgp_update_mp_reach_t *msg,
                      uint8_t *buf,
                      size_t *lenp,
                      size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;
  msg->mp_ls.mp_ls_cnt = 0;

  parsebgp_bgp_update_mp_link_state_t *ls_nlri;

  /**
   * Loop through all TLV's for the attribute
   */
  while (nread < remain) {

    PARSEBGP_MAYBE_REALLOC(msg->mp_ls.mp_ls,
                           sizeof(parsebgp_bgp_update_mp_link_state_t),
                           msg->mp_ls._mp_ls_alloc_cnt,
                           msg->mp_ls.mp_ls_cnt + 1);

    ls_nlri = &msg->mp_ls.mp_ls[msg->mp_ls.mp_ls_cnt];
    msg->mp_ls.mp_ls_cnt += 1;

    // Read the nlri type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->nlri_type);
    ls_nlri->nlri_type = ntohs(ls_nlri->nlri_type);

    // Read the nlri length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->nlri_len);
    ls_nlri->nlri_len = ntohs(ls_nlri->nlri_len);

    // Read the protocol id
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->protocol_id);

    // Read the identifier
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->identifier);
    ls_nlri->identifier = ntohs(ls_nlri->identifier);

    slen = len - nread;

    /*
     * Decode based on bgp-ls NLRI type
     */
    switch (ls_nlri->nlri_type) {
    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_NODE:

      if ((err = parse_link_state_nlri_node(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_LINK:
      if ((err = parse_link_state_nlri_link(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_IPV4_PREFIX:
      if ((err = parse_link_state_nlri_prefix(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_IPV6_PREFIX:
      if ((err = parse_link_state_nlri_prefix(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    default:
      PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                    "Unsupported NLRI type (%d)", ls_nlri->nlri_type);

    }

    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_unreach_link_state_nlri(parsebgp_opts_t *opts,
                      parsebgp_bgp_update_mp_unreach_t *msg,
                      uint8_t *buf,
                      size_t *lenp,
                      size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;
  msg->mp_ls.mp_ls_cnt = 0;

  parsebgp_bgp_update_mp_link_state_t *ls_nlri;

  /**
   * Loop through all TLV's for the attribute
   */
  while (nread < remain) {

    PARSEBGP_MAYBE_REALLOC(msg->mp_ls.mp_ls,
                           sizeof(parsebgp_bgp_update_mp_link_state_t),
                           msg->mp_ls._mp_ls_alloc_cnt,
                           msg->mp_ls.mp_ls_cnt + 1);

    ls_nlri = &msg->mp_ls.mp_ls[msg->mp_ls.mp_ls_cnt];
    msg->mp_ls.mp_ls_cnt += 1;

    // Read the nlri type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->nlri_type);
    ls_nlri->nlri_type = ntohs(ls_nlri->nlri_type);

    // Read the nlri length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->nlri_len);
    ls_nlri->nlri_len = ntohs(ls_nlri->nlri_len);

    // Read the protocol id
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->protocol_id);

    // Read the identifier
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_nlri->identifier);
    ls_nlri->identifier = ntohs(ls_nlri->identifier);

    slen = len - nread;

    /*
     * Decode based on bgp-ls NLRI type
     */
    switch (ls_nlri->nlri_type) {
    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_NODE:

      if ((err = parse_link_state_nlri_node(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_LINK:
      if ((err = parse_link_state_nlri_link(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_IPV4_PREFIX:
      if ((err = parse_link_state_nlri_prefix(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    case PARSEBGP_BGP_UPDATE_MP_LINK_STATE_NLRI_TYPE_IPV6_PREFIX:
      if ((err = parse_link_state_nlri_prefix(
          opts, ls_nlri, buf, &slen, remain - nread)) !=
          PARSEBGP_OK) {
        return err;
      }

      break;

    default:
      PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                    "Unsupported NLRI type (%d)", ls_nlri->nlri_type);

    }

    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t
parsebgp_bgp_update_mp_reach_link_state_decode(parsebgp_opts_t *opts,
                                               parsebgp_bgp_update_mp_reach_t *msg,
                                               uint8_t *buf,
                                               size_t *lenp,
                                               size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  if (msg->next_hop_len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  memcpy(msg->next_hop, buf, msg->next_hop_len);
  buf += msg->next_hop_len;
  nread += msg->next_hop_len;

  switch (msg->safi) {

  case PARSEBGP_BGP_SAFI_BGPLS:
    slen = len - nread;
    if ((err = parse_reach_link_state_nlri(opts, msg, buf, &slen,
                                           remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported SAFI (%d)", msg->safi);

  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t
parsebgp_bgp_update_mp_unreach_link_state_decode(parsebgp_opts_t *opts,
                                                 parsebgp_bgp_update_mp_unreach_t *msg,
                                                 uint8_t *buf,
                                                 size_t *lenp,
                                                 size_t remain) {

  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  switch (msg->safi) {

  case PARSEBGP_BGP_SAFI_BGPLS:
    slen = len - nread;
    if ((err = parse_unreach_link_state_nlri(opts, msg, buf, &slen,
                                           remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported SAFI (%d)", msg->safi);

  }

  *lenp = nread;
  return PARSEBGP_OK;

}
