#include "parsebgp_bgp_update_link_state_attr.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <stdlib.h>
#include <string.h>

/** Decode a BGP LS message */
parsebgp_error_t
parsebgp_bgp_update_bgp_ls_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_bgp_ls_t *msg,
                                    uint8_t *buf, size_t *lenp, size_t remain)
{

    parsebgp_error_t err;
    size_t len = *lenp, nread = 0, slen;
    parsebgp_bgp_update_bgp_ls_attr_t *ls_attr;

    msg->bgp_ls_attrs_cnt = 0;

    /**
     * Loop through all TLV's for the attribute
     */
    while (nread<remain) {

        PARSEBGP_MAYBE_REALLOC(msg->bgp_ls, sizeof(parsebgp_bgp_update_bgp_ls_attr_t),
                               msg->_bgp_ls_used_alloc_cnt,
                               msg->bgp_ls_attrs_cnt + 1);

        ls_attr = &msg->bgp_ls[msg->bgp_ls_attrs_cnt];
        msg->bgp_ls_attrs_cnt++;

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
        nread += slen;
        buf += slen;
    }

    *lenp = nread;
    return PARSEBGP_OK;
}

static uint32_t ieee_float_to_kbps(int32_t float_val)
{
  int32_t sign, exponent, mantissa;
  int64_t bits_value = 0;

  sign = float_val & IEEE_SIGN_MASK;
  exponent = float_val & IEEE_EXPONENT_MASK;
  mantissa = float_val & IEEE_MANTISSA_MASK;

  if ((float_val & ~IEEE_SIGN_MASK) == 0) {
    /* Number is zero, unnormalized, or not-a-float_val. */
    return 0;
  }

  if (IEEE_INFINITY == exponent) {
    /* Number is positive or negative infinity, or a special value. */
    return (sign ? MINUS_INFINITY : PLUS_INFINITY);
  }

  exponent = (exponent >> IEEE_MANTISSA_WIDTH) - IEEE_BIAS;
  if (exponent < 0) {
    /* Number is between zero and one. */
    return 0;
  }

  mantissa |= IEEE_IMPLIED_BIT;

  bits_value = mantissa;

  if (exponent <= IEEE_MANTISSA_WIDTH) {
    bits_value >>= IEEE_MANTISSA_WIDTH - exponent;
  } else {
    bits_value <<= exponent - IEEE_MANTISSA_WIDTH;
  }

  // Change sign
  if (sign)
    bits_value *= -1;

  bits_value *= 8;    // to bits
  bits_value /= 1000; // to kbits

  return bits_value;
}

/**
* Parse SID/Label value to string
*
* \details Parses the SID to index, label, or IPv6 string value
*
* \param [in]  data            Raw SID data to be parsed
* \param [in]  len             Length of the data (min is 3 and max is 16).
*
* \returns string value of SID
*/
static void parse_sid_value(link_peer_epe_node_sid *sid, u_char *data, int len)
{

  if (len == 3) {
    // 3-octet -  20 rightmost bits are used for encoding the label value.
      memcpy(&sid->sid_3, *data, 3);
      sid->sid_3 = ntohl(sid->sid_3);

  } else if (len >= 16) {
      memcpy(&sid->ip_raw, *data, 16);

  } else if (len == 4) {
    // 4-octet encoded offset in the SID/Label space advertised by this router
    // using the encodings
      memcpy(&sid->sid_4, *data, 4);
      sid->sid_4 = ntohl(sid->sid_4);
  } else {
    //     LOG_WARN("%s: bgp-ls: SID/Label has unexpected length of %d",
    //     peer_addr.c_str(), len);
  }
}


parsebgp_error_t
parsebgp_bgp_update_bgp_ls_tlv_decode(parsebgp_opts_t *opts,
                                          parsebgp_bgp_update_bgp_ls_attr_t *ls_attr,
                                          uint8_t *buf, size_t *lenp){

    uint32_t value_32bit;
    uint32_t float_val;
    size_t nread = 0, len = *lenp;

    if (ls_attr->len < 4) {
        // failed to parse attribute; too short length
        return PARSEBGP_RETURN_INVALID_MSG_ERR;
    }

    switch (ls_attr->type) {
        case ATTR_NODE_FLAG: {
            // ATTR_NODE_FLAG
            if (ls_attr->len != 1) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }
            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->node.node_flag_bits);
        } break;

        case ATTR_NODE_IPV4_ROUTER_ID_LOCAL: // Includes
            // ATTR_NODE_IPV4_ROUTER_ID_LOCAL
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
                break;
            }
            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->node.node_ipv4_router_id_local);
            break;

        case ATTR_NODE_IPV6_ROUTER_ID_LOCAL: // Includes
            // ATTR_NODE_IPV6_ROUTER_ID_LOCAL
            if (ls_attr->len != 16) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }
            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->node.node_ipv6_router_id_local);
            break;

        case ATTR_NODE_ISIS_AREA_ID:
            memcpy(&ls_attr->node.node_isis_area_id, *buf, ls_attr->len);
            break;

        case ATTR_NODE_MT_ID: {
            // TODO: AK tweaked this to remove strcpy of binary data, checkme
            for (int i = 0; i < ls_attr->len; i += 2) {
                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->node.mt_id[i/2]);
            }
            break;
        }

        case ATTR_NODE_NAME:
            memcpy(ls_attr->node.node_name, *buf, ls_attr->len);
            break;

        case ATTR_NODE_OPAQUE:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);

            break;

        case ATTR_NODE_SR_CAPABILITIES: {
            // TODO: Need to change this implementation and add to bgp_ls_attr
            /*val_ss.str(std::string());

            //
        https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.1.1
            // Decode flags
        //            if (strcmp(path_attrs->ls.nodes.front().protocol, "IS-IS") >= 0) {
        //                val_ss << parse_flags_to_string(*data, LS_FLAGS_SR_CAP_ISIS,
        sizeof(LS_FLAGS_SR_CAP_ISIS));
        //
        //            } else if (strcmp(path_attrs->ls.nodes.front().protocol, "OSPF")
        >= 0) {
        //
        //                // TODO: Add flags for OSPF... Currently not defined in
        https://tools.ietf.org/html/draft-ietf-ospf-ospfv3-segment-routing-extensions-07#section-3
        //                val_ss << int(*data);   //this->parse_flags_to_string(*data,
        LS_FLAGS_SR_CAP_OSPF, sizeof(LS_FLAGS_SR_CAP_OSPF));
        //            }

            val_ss << " ";

            // 1 byte reserved (skipping) + 1 byte flags (already parsed)
            data += 2;

            // iterate over each range + sid-tlv
            for (int l=2; l < bgp_ls_attr->len; l += 10) {
                if (l >= 12)
                    val_ss << ", ";

                // 3 bytes for Range
                value_32bit = 0;
                memcpy(&value_32bit, data, 3);
                SWAP_BYTES(&value_32bit);

                data += 3;

                value_32bit = value_32bit >> 8;

                val_ss << value_32bit;

                // 2 byte type
                u_int16_t type;
                memcpy(&type, data, 2);
                SWAP_BYTES(&type);
                data += 2;

                // 2 byte length
                u_int16_t sid_label_size = 0;
                memcpy(&sid_label_size, data, 2);
                SWAP_BYTES(&sid_label_size);
                data += 2;

                // Parsing SID/Label Sub-TLV:
        https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-03#section-2.3.7.2
                if (type == SUB_TLV_SID_LABEL) {

                    if (sid_label_size == 3 || sid_label_size == 4) {
                        memcpy(&value_32bit, data, sid_label_size);
                        SWAP_BYTES(&value_32bit);

                        if (sid_label_size == 3) {
                            value_32bit = value_32bit >> 8;

                        } else {
                            // Add extra byte for sid len of 4 instead of 3
                            l++;
                        }

                        val_ss << " " << value_32bit;

                    } else {
        //                  LOG_NOTICE("%s: bgp-ls: parsed node sr capabilities, sid
        label size is unexpected",peer_addr.c_str()); break;
                    }
                } else {
        //               LOG_NOTICE("%s: bgp-ls: parsed node sr capabilities, SUB TLV
        type %d is unexpected",peer_addr.c_str(), type); break;
                }
            }
        //        SELF_DEBUG("%s: bgp-ls: parsed node sr capabilities (len=%d) %s",
        peer_addr.c_str(), len, val_ss.str().c_str());

            memcpy(path_attrs->ls_attrs[ATTR_NODE_SR_CAPABILITIES].data(),
        val_ss.str().data(), val_ss.str().length());*/
            break;
        }

        case ATTR_LINK_ADMIN_GROUP:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_admin_group);
            break;

        case ATTR_LINK_IGP_METRIC:
            if (ls_attr->len <= 4) {
                value_32bit = 0;

                memcpy(&value_32bit, *buf, ls_attr->len);
                value_32bit = ntohl(value_32bit);

                ls_attr->link.link_igp_metric = value_32bit;
                buf += ls_attr->len;
                nread += ls_attr->len;
            }
            else
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            break;

        case ATTR_LINK_IPV4_ROUTER_ID_LOCAL:
            if (ls_attr->len != 4)
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_ipv4_router_id_local);
            break;

        case ATTR_LINK_IPV6_ROUTER_ID_LOCAL:
            if (ls_attr->len != 16)
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_ipv6_router_id_local);
            break;

        case ATTR_LINK_IPV4_ROUTER_ID_REMOTE:
            if (ls_attr->len != 4)
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_ipv4_router_id_remote);
            break;

        case ATTR_LINK_IPV6_ROUTER_ID_REMOTE:
            if (ls_attr->len != 16)
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_ipv6_router_id_remote);
            break;

        case ATTR_LINK_MAX_LINK_BW:
            if (ls_attr->len != 4)
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            float_val = 0;

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, float_val);
            float_val = ntohl(float_val);
            float_val = ieee_float_to_kbps(float_val);
            ls_attr->link.link_max_link_bw = float_val;
            break;

        case ATTR_LINK_MAX_RESV_BW:
            if (ls_attr->len != 4)
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            float_val = 0;

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, float_val);
            float_val = ntohl(float_val);
            float_val = ieee_float_to_kbps(float_val);
            ls_attr->link.link_max_resv_bw = float_val;
            break;

        case ATTR_LINK_MPLS_PROTO_MASK:
            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_mpls_protocal_mask);
            break;

        case ATTR_LINK_PROTECTION_TYPE:
            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_protective_type);
            break;

        case ATTR_LINK_NAME: {
            memcpy(ls_attr->link.link_name, *buf, ls_attr->len);
            buf += ls_attr->len;
            nread += ls_attr->len;
            break;
        }

        case ATTR_LINK_ADJACENCY_SID: {
            // TODO: Need to change this implementation and add to bgp_ls_attr
            /*val_ss.str(std::string());

            // There can be more than one adj sid, append as list
            if (strlen((char *)path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].data()) >
        0) val_ss << ", ";

        //            // Decode flags
        //            if (strcmp(path_attrs->ls.links.front().protocol, "IS-IS") >= 0) {
        //                val_ss << parse_flags_to_string(*data,
        // LS_FLAGS_PEER_ADJ_SID_ISIS, sizeof(LS_FLAGS_PEER_ADJ_SID_ISIS));
        //
        //            } else if (strcmp(path_attrs->ls.links.front().protocol, "OSPF")
        >= 0) {
        //                val_ss << parse_flags_to_string(*data,
        // LS_FLAGS_PEER_ADJ_SID_OSPF, sizeof(LS_FLAGS_PEER_ADJ_SID_OSPF));
        //            }

            data += 1;

            u_int8_t weight;
            memcpy(&weight, data, 1);

            val_ss << " " << (int)weight;

            // 1 byte for Weight + 2 bytes for Reserved
            data += 3;

            // Parse the sid/value
            val_ss << " ";
            val_ss<< parse_sid_value(data, bgp_ls_attr->len - 4);

            //      SELF_DEBUG("%s: bgp-ls: parsed sr link adjacency segment identifier
        %s", peer_addr.c_str(), val_ss.str().c_str());

            strncat((char *)path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].data(),
                    val_ss.str().c_str(),
                    path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].size() -
                            strlen((char
        *)path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].data()));*/
            break;
        }

        case ATTR_LINK_SRLG:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_LINK_TE_DEF_METRIC:

            // Per rfc7752 Section 3.3.2.3, this is supposed to be 4 bytes, but some
            // implementations have this <=4.

            if (ls_attr->len == 0) {
                ls_attr->link.link_te_def_metric = 0;
                break;
            } else if (ls_attr->len > 4)
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            else {
                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->link.link_te_def_metric);
                ls_attr->link.link_te_def_metric=ntohl(ls_attr->link.link_te_def_metric);
            }

            break;

        case ATTR_LINK_UNRESV_BW: {
            if (ls_attr->len != 32)
                PARSEBGP_RETURN_INVALID_MSG_ERR;

            for (int i = 0; i < 32; i += 4) {
                float_val = 0;
                PARSEBGP_DESERIALIZE_VAL(buf, len, nread, float_val);
                float_val = ntohl(float_val);
                ls_attr->link.link_unresv_bw[i / 4] = ieee_float_to_kbps(float_val);
            }
            break;
        }

        case ATTR_LINK_OPAQUE:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_LINK_PEER_EPE_NODE_SID:
            /*
             * Syntax of value is: [L] <weight> <sid value>
             *
             *      L flag indicates locally significant
             */

            if (*buf & 0x80)
                ls_attr->link.link_peer_epe_sid.V_flag = 1;

            if (*buf & 0x40)
                ls_attr->link.link_peer_epe_sid.L_flag = 1;

            parse_sid_value(&ls_attr->link.link_peer_epe_sid, (buf + 4),
                            ls_attr->len - 4);
            nread += ls_attr->len;
            break;

        case ATTR_LINK_PEER_EPE_SET_SID:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_LINK_PEER_EPE_ADJ_SID:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_PREFIX_EXTEND_TAG:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_PREFIX_IGP_FLAGS:
            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->prefix.prefix_igp_flags);
            break;

        case ATTR_PREFIX_PREFIX_METRIC:
            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->prefix.prefix_metric);
            ls_attr->prefix.prefix_metric = ntohl(ls_attr->prefix.prefix_metric);
            break;

        case ATTR_PREFIX_ROUTE_TAG: {
            // TODO(undefined): Per RFC7752 section 3.3.3, prefix tag can be multiples,
            // but for now we only decode the first one.

            if (ls_attr->len != 4) {
                PARSEBGP_RETURN_INVALID_MSG_ERR;
            }

            PARSEBGP_DESERIALIZE_VAL(buf, len, nread, ls_attr->prefix.prefix_route_tag);
            ls_attr->prefix.prefix_route_tag = ntohl(ls_attr->prefix.prefix_route_tag);
            break;
        }
        case ATTR_PREFIX_OSPF_FWD_ADDR:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_PREFIX_OPAQUE_PREFIX:
            PARSEBGP_SKIP_NOT_IMPLEMENTED(
                    opts, buf, nread, ls_attr->len,
                    "BGP Link State Attribute %d is not yet implemented", ls_attr->type);
            nread += ls_attr->len;
            break;

        case ATTR_PREFIX_SID: {
            // TODO: Need to change this implementation and add to bgp_ls_attr

            // There can be more than one prefix_sid, append as list
            /*
                        if (strlen((char *)path_attrs->ls_attrs[ATTR_PREFIX_SID].data())
            > 0) val_ss << ", ";

                        // Package structure:
                        //
            https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.3.1

            //            // Decode flags
            //            if (strcmp(path_attrs->ls.prefixes.front().protocol, "IS-IS")
            >= 0) {
            //                val_ss << parse_flags_to_string(*data,
            //                                                LS_FLAGS_PREFIX_SID_ISIS,
            sizeof(LS_FLAGS_PREFIX_SID_ISIS));
            //
            //            } else if (strcmp(path_attrs->ls.prefixes.front().protocol,
            "OSPF") >= 0) {
            //                val_ss << parse_flags_to_string(*data,
            //                                                LS_FLAGS_PREFIX_SID_OSPF,
            sizeof(LS_FLAGS_PREFIX_SID_OSPF));
            //            }

                        val_ss << ' ';
                        data += 1;

                        uint8_t alg;
                        alg = *data;
                        data += 1;

                        switch (alg) {
                            case 0: // Shortest Path First (SPF) algorithm based on link
            metric val_ss << "SPF "; break;

                            case 1: // Strict Shortest Path First (SPF) algorithm based
            on link metric val_ss << "strict-SPF "; break;
                        }

                        // 2 bytes reserved
                        data += 2;

                        // Parse the sid/value
                        val_ss << parse_sid_value(data, bgp_ls_attr->len - 4);

                        strncat((char *)path_attrs->ls_attrs[ATTR_PREFIX_SID].data(),
                                val_ss.str().c_str(),
                                path_attrs->ls_attrs[ATTR_PREFIX_SID].size() -
                                        strlen((char
            *)path_attrs->ls_attrs[ATTR_PREFIX_SID].data()));
            */

            //    SELF_DEBUG("%s: bgp-ls: parsed sr prefix segment identifier  flags =
            //    %x len=%d : %s",
            //               peer_addr.c_str(), *(data - 4), len, val_ss.str().c_str());

            break;
        }

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