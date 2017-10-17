#include "parsebgp_bgp_update_link_state_attr.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <stdlib.h>
#include <string.h>


static parsebgp_error_t
parsebgp_bgp_update_bgp_ls_tlv_decode(parsebgp_opts_t *opts,
                                      parsebgp_bgp_update_bgp_ls_attr_t *ls_attr,
                                      uint8_t *buf, size_t *lenp){

    int i;
    size_t nread = 0, len = *lenp;

    switch (ls_attr->type) {

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_MT_ID:
            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.node.node_mt_id.ids);
            ls_attr->attr.node.node_mt_id.ids_cnt = 0;

            for (i = 0; i < ls_attr->len; i += 2) {
                PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_mt_id.ids, sizeof(uint16_t),
                                       ls_attr->attr.node.node_mt_id._ids_alloc_cnt,
                                       ls_attr->attr.node.node_mt_id.ids_cnt + 1);

                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.node.node_mt_id.ids[i/2]);
                ls_attr->attr.node.node_mt_id.ids[i/2] = ls_attr->attr.node.node_mt_id.ids[i/2];
            }
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_FLAG:

            if (ls_attr->len != 1){
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.node.node_flag_bits);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_OPAQUE:
            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.node.node_opaque.opaque);
            ls_attr->attr.node.node_opaque.opaque_cnt = ls_attr->len;

            PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_opaque.opaque, sizeof(uint8_t),
                                   ls_attr->attr.node.node_opaque._opaque_alloc_cnt,
                                   ls_attr->attr.node.node_opaque.opaque_cnt);

            if(ls_attr->len > len){
                return PARSEBGP_PARTIAL_MSG;
            }

            memcpy(ls_attr->attr.node.node_opaque.opaque, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_NAME:

            if(ls_attr->len > len){
                return PARSEBGP_PARTIAL_MSG;
            }

            memcpy(ls_attr->attr.node.node_name, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_ISIS_AREA_ID:

            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.node.node_isis_area_id.ids);
            ls_attr->attr.node.node_isis_area_id.ids_cnt = ls_attr->len;

            PARSEBGP_MAYBE_REALLOC(ls_attr->attr.node.node_isis_area_id.ids, sizeof(uint8_t),
                                   ls_attr->attr.node.node_isis_area_id._ids_alloc_cnt,
                                   ls_attr->attr.node.node_isis_area_id.ids_cnt);

            if(ls_attr->len > len){
                return PARSEBGP_PARTIAL_MSG;
            }

            memcpy(ls_attr->attr.node.node_isis_area_id.ids, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV4_ROUTER_ID_LOCAL: // Includes

            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.node.node_ipv4_router_id_local);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV6_ROUTER_ID_LOCAL: // Includes

            if (ls_attr->len != 16) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.node.node_ipv6_router_id_local);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE:

            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_ipv4_router_id_remote);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE:

            if (ls_attr->len != 16) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_ipv6_router_id_remote);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_admin_group);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_max_link_bw);
            ls_attr->attr.link.link_max_link_bw = ntohl(ls_attr->attr.link.link_max_link_bw);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_max_resv_bw);
            ls_attr->attr.link.link_max_resv_bw = ntohl(ls_attr->attr.link.link_max_resv_bw);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW: {
            if (ls_attr->len != 32) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            for (i = 0; i < 32; i += 4) {
                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_unresv_bw[i / 4]);
                ls_attr->attr.link.link_unresv_bw[i / 4] = ntohl(ls_attr->attr.link.link_unresv_bw[i / 4]);
            }

            break;
        }

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC:

            if (ls_attr->len == 0) {
                ls_attr->attr.link.link_te_def_metric = 0;
                break;
            }
            else if (ls_attr->len > 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_te_def_metric);
            ls_attr->attr.link.link_te_def_metric=ntohl(ls_attr->attr.link.link_te_def_metric);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE:
            if (ls_attr->len != 2) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_protective_type);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK:
            if (ls_attr->len != 1) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.link.link_mpls_protocal_mask);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC:

            if (ls_attr->len > 3) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            memcpy(&ls_attr->attr.link.link_igp_metric, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;

            ls_attr->attr.link.link_igp_metric = ntohl(ls_attr->attr.link.link_igp_metric);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;


        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE:
            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.link.link_opaque.opaque);
            ls_attr->attr.link.link_opaque.opaque_cnt = ls_attr->len;

            PARSEBGP_MAYBE_REALLOC(ls_attr->attr.link.link_opaque.opaque, sizeof(uint8_t),
                                   ls_attr->attr.link.link_opaque._opaque_alloc_cnt,
                                   ls_attr->attr.link.link_opaque.opaque_cnt);

            if(ls_attr->len > len){
                return PARSEBGP_PARTIAL_MSG;
            }

            memcpy(ls_attr->attr.link.link_opaque.opaque, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME:
            if (ls_attr->len > len) {
                return PARSEBGP_PARTIAL_MSG;
            }

            memcpy(ls_attr->attr.link.link_name, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_IGP_FLAGS:
            if(ls_attr->len!=1){
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.prefix.prefix_igp_flags);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_ROUTE_TAG:
            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.prefix.prefix_route_tag.tags);
            ls_attr->attr.prefix.prefix_route_tag.tags_cnt = 0;

            for (i = 0; i < ls_attr->len; i += 4) {
                PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_route_tag.tags, sizeof(uint32_t),
                                       ls_attr->attr.prefix.prefix_route_tag._tags_alloc_cnt,
                                       ls_attr->attr.prefix.prefix_route_tag.tags_cnt + 1);

                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.prefix.prefix_route_tag.tags[i/4]);
                ls_attr->attr.prefix.prefix_route_tag.tags[i/4] = ls_attr->attr.prefix.prefix_route_tag.tags[i/4];
            }
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_EXTEND_ROUTE_TAG:
            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags);
            ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt = 0;

            for (i = 0; i < ls_attr->len; i += 8) {
                PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags, sizeof(uint64_t),
                                       ls_attr->attr.prefix.prefix_extended_route_tag._ex_tags_alloc_cnt,
                                       ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt + 1);

                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[i/8]);
                ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[i/8] = ls_attr->attr.prefix.prefix_extended_route_tag.ex_tags[i/8];
            }
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_PREFIX_METRIC:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.prefix.prefix_metric);
            ls_attr->attr.prefix.prefix_metric = ntohl(ls_attr->attr.prefix.prefix_metric);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OSPF_FWD_ADDR:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->attr.prefix.prefix_ospf_forwarding_address);
            break;

        case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OPAQUE_PREFIX:
            PARSEBGP_MAYBE_MALLOC_ZERO(ls_attr->attr.prefix.prefix_opaque_prefix_attribute.opaque);
            ls_attr->attr.prefix.prefix_opaque_prefix_attribute.opaque_cnt = ls_attr->len;

            PARSEBGP_MAYBE_REALLOC(ls_attr->attr.prefix.prefix_opaque_prefix_attribute.opaque, sizeof(uint8_t),
                                   ls_attr->attr.prefix.prefix_opaque_prefix_attribute._opaque_alloc_cnt,
                                   ls_attr->attr.prefix.prefix_opaque_prefix_attribute.opaque_cnt);

            if(ls_attr->len > len){
                return PARSEBGP_PARTIAL_MSG;
            }

            memcpy(ls_attr->attr.prefix.prefix_opaque_prefix_attribute.opaque, buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
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

/** Decode a BGP LS message */
parsebgp_error_t
parsebgp_bgp_update_bgp_ls_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_bgp_ls_t *ls_msg,
                                    uint8_t *buf, size_t *lenp, size_t remain) {

    parsebgp_error_t err;
    size_t len = *lenp, nread = 0, slen;
    parsebgp_bgp_update_bgp_ls_attr_t *ls_attr;

    ls_msg->bgp_ls_attrs_cnt = 0;

    /**
     * Loop through all TLV's for the attribute
     */
    while (nread<remain) {

        PARSEBGP_MAYBE_REALLOC(ls_msg->bgp_ls, sizeof(parsebgp_bgp_update_bgp_ls_attr_t),
                               ls_msg->_bgp_ls_attrs_used_alloc_cnt,
                               ls_msg->bgp_ls_attrs_cnt + 1);

        ls_attr = &ls_msg->bgp_ls[ls_msg->bgp_ls_attrs_cnt];
        ls_msg->bgp_ls_attrs_cnt++;

        // Read the attr type
        PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->type);
        ls_attr->type = ntohs(ls_attr->type);

        // Read the attr length
        PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->len);
        ls_attr->len = ntohs(ls_attr->len);

        slen = len - nread;
        if((err = parsebgp_bgp_update_bgp_ls_tlv_decode(
                opts, ls_attr, buf, &slen))!=
                PARSEBGP_OK) {
            return err;
        }
        nread += ls_attr->len;
        buf += ls_attr->len + 4;
    }

    *lenp = nread;
    return PARSEBGP_OK;
}

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_REACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_bgp_ls_dump(
        parsebgp_bgp_update_bgp_ls_t *msg, int depth){

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_t, depth);

    ++depth;
    int i, j;
    parsebgp_bgp_update_bgp_ls_attr_t *attr;
    for (i = 0; i < msg->bgp_ls_attrs_cnt; i++) {
        attr = &msg->bgp_ls[i];

        PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_t, depth);

        PARSEBGP_DUMP_INT(depth, "Type", attr->type);
        PARSEBGP_DUMP_INT(depth, "Length", attr->len);

        depth++;
        switch (attr->type) {

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_MT_ID:
                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);

                for (j = 0; j < attr->attr.node.node_mt_id.ids_cnt; ++j) {
                    PARSEBGP_DUMP_INT(depth, "MT_ID", attr->attr.node.node_mt_id.ids[j]);
                }
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_FLAG:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "NODE FLAG", attr->attr.node.node_flag_bits);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_OPAQUE:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);

                for (j = 0; j < attr->attr.node.node_mt_id.ids_cnt; ++j) {
                    PARSEBGP_DUMP_INT(depth, "NODE MT_ID", attr->attr.node.node_mt_id.ids[j]);
                }
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_NAME:
                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);
                PARSEBGP_DUMP_INFO(depth, "NODE NAME : %s", attr->attr.node.node_name);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_ISIS_AREA_ID:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);
                for (j = 0; j < attr->attr.node.node_isis_area_id.ids_cnt; ++j) {
                    PARSEBGP_DUMP_INT(depth, "PREFIX ROUTE TAG", attr->attr.node.node_isis_area_id.ids[j]);
                }
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV4_ROUTER_ID_LOCAL: // Includes

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);
                PARSEBGP_DUMP_IP(depth, "IPV4 ROUTER ID LOCAL", 0, attr->attr.node.node_ipv4_router_id_local);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV6_ROUTER_ID_LOCAL: // Includes

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_node_attr_t, depth);
                PARSEBGP_DUMP_IP(depth, "IPV6 ROUTER ID LOCAL", 1, attr->attr.node.node_ipv6_router_id_local);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_IP(depth, "IPV4 ROUTER ID REMOTE", 0, attr->attr.link.link_ipv4_router_id_remote);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_IP(depth, "IPV6 ROUTER ID REMOTE", 1, attr->attr.link.link_ipv6_router_id_remote);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "LINK ADMIN GROUP", attr->attr.link.link_admin_group);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "LINK MAX LINK BW", attr->attr.link.link_max_link_bw);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "LINK MAX RESV BW", attr->attr.link.link_max_resv_bw);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                for (j = 0; j < 8; ++j) {
                    PARSEBGP_DUMP_INT(depth, "LINK UNRESV BW", attr->attr.link.link_unresv_bw[j]);
                }
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "LINK TE DEF METRIC", attr->attr.link.link_te_def_metric);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INFO(depth, "LINK TE DEF METRIC : %s", attr->attr.link.link_protective_type);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "LINK PROTOCOL MASK", attr->attr.link.link_mpls_protocal_mask);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "LINK IGP METRIC", attr->attr.link.link_igp_metric);
                break;


            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INFO(depth, "LINK OPAQUE : %s", attr->attr.link.link_opaque.opaque);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME: {

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_link_attr_t, depth);
                PARSEBGP_DUMP_INFO(depth, "LINK NAME : %s", attr->attr.link.link_name);
                break;
            }

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_IGP_FLAGS:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "PREFIX IGP FLAGS", attr->attr.prefix.prefix_igp_flags);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_ROUTE_TAG:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t, depth);
                for (j = 0; j < attr->attr.prefix.prefix_route_tag.tags_cnt; ++j) {
                    PARSEBGP_DUMP_INT(depth, "PREFIX ROUTE TAG", attr->attr.prefix.prefix_route_tag.tags[j]);
                }
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_EXTEND_ROUTE_TAG:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t, depth);
                for (j = 0; j <attr->attr.prefix.prefix_extended_route_tag.ex_tags_cnt ; j++) {
                    if (j != 0) {
                        printf(" ");
                    }
                    printf("%" PRIu64, attr->attr.prefix.prefix_extended_route_tag.ex_tags[j]);
                }
                printf("\n");
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_PREFIX_METRIC:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t, depth);
                PARSEBGP_DUMP_INT(depth, "PREFIX METRIC", attr->attr.prefix.prefix_metric);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OSPF_FWD_ADDR:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t, depth);
                PARSEBGP_DUMP_IP(depth, "PREFIX OSPF FWD ADDRESS", 0, attr->attr.prefix.prefix_ospf_forwarding_address);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OPAQUE_PREFIX:

                PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_bgp_ls_attr_prefix_attr_t, depth);
                PARSEBGP_DUMP_INFO(depth, "PREFIX OPAQUE : %s", attr->attr.prefix.prefix_opaque_prefix_attribute.opaque);
                break;
        }
        --depth;
    }
}

/** Destroy a BGP Link State message */
void parsebgp_bgp_update_bgp_ls_destroy(
        parsebgp_bgp_update_bgp_ls_t *ls_msg){

    if (ls_msg == NULL) {
        return;
    }

    int i;
    for (i = 0; i < ls_msg->bgp_ls_attrs_cnt; i++) {
        switch(ls_msg->bgp_ls->type){
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_MT_ID:
                if(ls_msg->bgp_ls->attr.node.node_mt_id.ids == NULL) {
                    break;
                }

                free(ls_msg->bgp_ls->attr.node.node_mt_id.ids);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_FLAG:
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_OPAQUE:
                if(ls_msg->bgp_ls->attr.node.node_opaque.opaque == NULL) {
                    break;
                }

                free(ls_msg->bgp_ls->attr.node.node_opaque.opaque);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_NAME:
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_ISIS_AREA_ID:
                if(ls_msg->bgp_ls->attr.node.node_isis_area_id.ids == NULL) {
                    break;
                }

                free(ls_msg->bgp_ls->attr.node.node_isis_area_id.ids);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV4_ROUTER_ID_LOCAL:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV6_ROUTER_ID_LOCAL:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG:
                break;
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE:
                if(ls_msg->bgp_ls->attr.link.link_opaque.opaque == NULL) {
                    break;
                }

                free(ls_msg->bgp_ls->attr.link.link_opaque.opaque);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_IGP_FLAGS:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_ROUTE_TAG:
                if(ls_msg->bgp_ls->attr.prefix.prefix_route_tag.tags == NULL) {
                    break;
                }

                free(ls_msg->bgp_ls->attr.prefix.prefix_route_tag.tags);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_EXTEND_ROUTE_TAG:
                if(ls_msg->bgp_ls->attr.prefix.prefix_extended_route_tag.ex_tags == NULL) {
                    break;
                }

                free(ls_msg->bgp_ls->attr.prefix.prefix_extended_route_tag.ex_tags);
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_PREFIX_METRIC:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OSPF_FWD_ADDR:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OPAQUE_PREFIX:
                break;
        }
    }

    free(ls_msg->bgp_ls);
    free(ls_msg);
}

/** Clear a BGP Link State message */
void parsebgp_bgp_update_bgp_ls_clear(
        parsebgp_bgp_update_bgp_ls_t *ls_msg){
    int i = 0;

    for (i = 0; i < ls_msg->bgp_ls_attrs_cnt; i++) {
        switch(ls_msg->bgp_ls->type){
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_MT_ID:
                ls_msg->bgp_ls->attr.node.node_mt_id.ids_cnt = 0;
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_FLAG:
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_OPAQUE:
                ls_msg->bgp_ls->attr.node.node_opaque.opaque_cnt = 0;
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_NAME:
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_ISIS_AREA_ID:
                ls_msg->bgp_ls->attr.node.node_isis_area_id.ids_cnt = 0;
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV4_ROUTER_ID_LOCAL:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_NODE_IPV6_ROUTER_ID_LOCAL:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV4_ROUTER_ID_REMOTE:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IPV6_ROUTER_ID_REMOTE:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_ADMIN_GROUP:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_LINK_BW:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MAX_RESV_BW:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_UNRESV_BW:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_TE_DEF_METRIC:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_PROTECTION_TYPE:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_MPLS_PROTO_MASK:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_IGP_METRIC:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_SRLG:
                break;
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_OPAQUE:
                ls_msg->bgp_ls->attr.link.link_opaque.opaque_cnt = 0;
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_LINK_NAME:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_IGP_FLAGS:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_ROUTE_TAG:
                ls_msg->bgp_ls->attr.prefix.prefix_route_tag.tags_cnt = 0;
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_EXTEND_ROUTE_TAG:
                ls_msg->bgp_ls->attr.prefix.prefix_extended_route_tag.ex_tags_cnt = 0;
                break;

            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_PREFIX_METRIC:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OSPF_FWD_ADDR:
            case PARSEBGP_BGP_UPDATE_LINK_STATE_ATTR_PREFIX_OPAQUE_PREFIX:
                break;
        }
    }

    ls_msg->bgp_ls_attrs_cnt = 0;
}