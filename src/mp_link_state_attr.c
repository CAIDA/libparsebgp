/*
 * Copyright (c) 2015-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parse_utils.h"
#include <arpa/inet.h>
#include "../include/mp_link_state_attr.h"

/* BGP-LS Node flags : https://tools.ietf.org/html/rfc7752#section-3.3.1.1
 *
 * +-----------------+-------------------------+------------+
 * |        Bit       | Description             | Reference  |
 * +-----------------+-------------------------+------------+
 * |       'O'       | Overload Bit            | [ISO10589] |
 * |       'T'       | Attached Bit            | [ISO10589] |
 * |       'E'       | External Bit            | [RFC2328]  |
 * |       'B'       | ABR Bit                 | [RFC2328]  |
 * |       'R'       | Router Bit              | [RFC5340]  |
 * |       'V'       | V6 Bit                  | [RFC5340]  |
 * | Reserved (Rsvd) | Reserved for future use |            |
 * +-----------------+-------------------------+------------+
 */
const char * const LS_FLAGS_NODE_NLRI[] = {
        "O", "T", "E", "B", "R", "V"
};

/* https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.2.1
 *      ISIS: https://tools.ietf.org/html/draft-ietf-isis-segment-routing-extensions-09#section-2.2.1
 *      OSPF: https://tools.ietf.org/html/draft-ietf-ospf-segment-routing-extensions-10#section-7.1
 *            https://tools.ietf.org/html/draft-ietf-ospf-ospfv3-segment-routing-extensions-07#section-7.1
 */
const char * const LS_FLAGS_PEER_ADJ_SID_ISIS[] = {
        "F",            // Address family flag; unset adj is IPv4, set adj is IPv6
        "B",            // Backup flag; set if adj is eligible for protection
        "V",            // Value flag; set = sid carries a value, default is set
        "L",            // Local flag; set = value has local significance
        "S"             // Set flag; set = SID refers to a set of adjacencies
};

// Currently ospfv3 is the same except that G is S, but means the same thing
const char * const LS_FLAGS_PEER_ADJ_SID_OSPF[] = {
        "B",            // Backup flag; set if adj is eligible for protection
        "V",            // Value flag; set = sid carries a value, default is set
        "L",            // Local flag; set = value has local significance
        "G"             // Group flag; set = sid referes to a group of adjacencies
};

/* https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.1.1
 *
 *      ISIS: https://tools.ietf.org/html/draft-ietf-isis-segment-routing-extensions-09#section-3.1
 *      OSPF: https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#ref-I-D.ietf-ospf-ospfv3-segment-routing-extensions
 *
 */
const char * const LS_FLAGS_SR_CAP_ISIS[] = {
        "I",            // MPLS IPv4 flag; set = router is capable of SR MPLS encaps IPv4 all interfaces
        "V",            // MPLS IPv6 flag; set = router is capable of SR MPLS encaps IPv6 all interfaces
        "H"             // SR-IPv6 flag; set = rouer is capable of IPv6 SR header on all interfaces defined in ...
};


/* https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.3.1
 *      ISIS: https://tools.ietf.org/html/draft-ietf-isis-segment-routing-extensions-09#section-2.1.1
 *      OSPF: https://tools.ietf.org/html/draft-ietf-ospf-segment-routing-extensions-10#section-5
 */
const char * const LS_FLAGS_PREFIX_SID_ISIS[] = {
        "R",            // Re-advertisement flag; set = prefix was redistributed or from l1 to l2
        "N",            // Node-SID flag; set = sid refers to the router
        "P",            // no-PHP flag; set = penultimate hop MUST NOT pop before delivering the packet
        "E",            // Explicit-Null flag; set = upstream neighbor must replace SID with Exp-Null label
        "V",            // Value flag; set = SID carries a value instead of an index; default unset
        "L"             // Local flag; set = value/index has local significance; default is unset
};

const char * const LS_FLAGS_PREFIX_SID_OSPF[] = {
        "",             // unused
        "NP",           // no-PHP flag; set = penultimate hop MUST NOT pop before delivering the packet
        "M",            // Mapping server flag; set = SID was advertised by mapping server
        "E",            // Explicit-Null flag; set = upstream neighbor must replace SID with Exp-Null label
        "V",            // Value flag; set = SID carries a value instead of an index; default unset
        "L"             // Local flag; set = value/index has local significance; default is unset
};


/**
 * Parse Link State attribute
 *
 * \details Will handle parsing the link state attributes
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 */
void libparsebgp_mp_link_state_attr_parse_attr_link_state(update_path_attrs *path_attrs, int attr_len, u_char *data) {
    /*
     * Loop through all TLV's for the attribute
     */
    int tlv_len;
    uint16_t count =0;
    path_attrs->attr_value.bgp_ls = (bgp_link_state_attrs *)malloc(sizeof(bgp_link_state_attrs));
    while (attr_len > 0) {
        if(count)
            path_attrs->attr_value.bgp_ls = (bgp_link_state_attrs *)realloc(path_attrs->attr_value.bgp_ls,(count+1)*sizeof(bgp_link_state_attrs));

        tlv_len = libparsebgp_mp_link_state_attr_parse_attr_link_state_tlv(path_attrs, attr_len, data, count);
        attr_len -= tlv_len;

        if (attr_len > 0)
            data += tlv_len;
        count++;
    }
    path_attrs->attr_value.count_bgp_ls = count;
}

static uint32_t ieee_float_to_kbps(int32_t float_val) {
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

    bits_value *= 8;        // to bits
    bits_value /= 1000;     // to kbits

    return bits_value;
}


/*******************************************************************************//**
 * Parse SID/Label value to string
 *
 * \details Parses the SID to index, label, or IPv6 string value
 *
 * \param [in]  data            Raw SID data to be parsed
 * \param [in]  len             Length of the data (min is 3 and max is 16).
 *
 * \returns string value of SID
 */
static void parse_sid_value(link_peer_epe_node_sid *sid, u_char *data, int len) {

    if (len == 3) {
        // 3-octet -  20 rightmost bits are used for encoding the label value.
        memcpy(&sid->sid_3, data, 3);
        SWAP_BYTES(&sid->sid_3, 3);

    } else if (len >= 16) {
        memcpy(&sid->ip_raw, data, 16);

    } else if (len == 4) {
        // 4-octet encoded offset in the SID/Label space advertised by this router using the encodings
        memcpy(&sid->sid_4, data, 4);
        SWAP_BYTES(&sid->sid_4, 4);
    } else {
   //     LOG_WARN("%s: bgp-ls: SID/Label has unexpected length of %d", peer_addr.c_str(), len);
    }
}

/*******************************************************************************//**
 * Parse Link State attribute TLV
 *
 * \details Will handle parsing the link state attribute
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 *
 * \returns length of the TLV attribute parsed (including the tlv header lenght)
 */
int libparsebgp_mp_link_state_attr_parse_attr_link_state_tlv(update_path_attrs *path_attrs, int attr_len, u_char *data, int count) {

    char                ip_char[46];
    uint32_t            value_32bit;
    uint16_t            value_16bit;
    int32_t             float_val;


    if (attr_len < 4) {
//          LOG_NOTICE("%s: bgp-ls: failed to parse attribute; too short",peer_addr.c_str());
        return attr_len;
    }

    bgp_link_state_attrs *bgp_ls_attr = (bgp_link_state_attrs *)malloc(sizeof(bgp_link_state_attrs));
    memcpy(&bgp_ls_attr->type, data, 2);
    SWAP_BYTES(&bgp_ls_attr->type, 2);

    memcpy(&bgp_ls_attr->len, data+2, 2);
    SWAP_BYTES(&bgp_ls_attr->len, 2);

    data += 4;

    switch (bgp_ls_attr->type) {
        case ATTR_NODE_FLAG: {
            //TODO: check
            if (bgp_ls_attr->len != 1) {
//   //             LOG_INFO("%s: bgp-ls: node flag attribute length is too long %d should be 1",peer_addr.c_str(), len);
            }
            memcpy(&bgp_ls_attr->node.node_flag_bits, data, 1);
            data++;
            }
        break;

        case ATTR_NODE_IPV4_ROUTER_ID_LOCAL:  // Includes ATTR_LINK_IPV4_ROUTER_ID_LOCAL
            if (bgp_ls_attr->len != 4)
                break;

            memcpy(&bgp_ls_attr->node.node_ipv4_router_id_local, data, 4);
            break;

        case ATTR_NODE_IPV6_ROUTER_ID_LOCAL:  // Includes ATTR_LINK_IPV6_ROUTER_ID_LOCAL
            if (bgp_ls_attr->len != 16) {
 //               LOG_NOTICE("%s: bgp-ls: failed to parse attribute local router id IPv6 sub-tlv; too short",peer_addr.c_str());
                break;
            }
            memcpy(&bgp_ls_attr->node.node_ipv6_router_id_local, data, 16);
            break;

        case ATTR_NODE_ISIS_AREA_ID:
            if (bgp_ls_attr->len <= 8)
                memcpy(&bgp_ls_attr->node.node_isis_area_id, data, bgp_ls_attr->len);
            break;

        case ATTR_NODE_MT_ID: {
            char *node_mt_id = (char *) malloc(bgp_ls_attr->len / 2);
            for (int i = 0; i < bgp_ls_attr->len; i += 2) {
                memcpy(&node_mt_id[i / 2], data, 2);
                SWAP_BYTES(&node_mt_id[i / 2], 2);
                data += 2;
            }
            strncpy(bgp_ls_attr->node.mt_id, node_mt_id, bgp_ls_attr->len / 2);
            break;
        }

        case ATTR_NODE_NAME:
            strncpy(bgp_ls_attr->node.node_name, (char *)data, bgp_ls_attr->len);
            break;

        case ATTR_NODE_OPAQUE:
            break;

        case ATTR_NODE_SR_CAPABILITIES: {
            //TODO: Need to change this implementation and add to bgp_ls_attr
            /*val_ss.str(std::string());

            // https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.1.1
            // Decode flags
//            if (strcmp(path_attrs->ls.nodes.front().protocol, "IS-IS") >= 0) {
//                val_ss << parse_flags_to_string(*data, LS_FLAGS_SR_CAP_ISIS, sizeof(LS_FLAGS_SR_CAP_ISIS));
//
//            } else if (strcmp(path_attrs->ls.nodes.front().protocol, "OSPF") >= 0) {
//
//                // TODO: Add flags for OSPF... Currently not defined in https://tools.ietf.org/html/draft-ietf-ospf-ospfv3-segment-routing-extensions-07#section-3
//                val_ss << int(*data);   //this->parse_flags_to_string(*data, LS_FLAGS_SR_CAP_OSPF, sizeof(LS_FLAGS_SR_CAP_OSPF));
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

                // Parsing SID/Label Sub-TLV: https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-03#section-2.3.7.2
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
      //                  LOG_NOTICE("%s: bgp-ls: parsed node sr capabilities, sid label size is unexpected",peer_addr.c_str());
                        break;
                    }
                } else {
     //               LOG_NOTICE("%s: bgp-ls: parsed node sr capabilities, SUB TLV type %d is unexpected",peer_addr.c_str(), type);
                    break;
                }
            }
    //        SELF_DEBUG("%s: bgp-ls: parsed node sr capabilities (len=%d) %s", peer_addr.c_str(), len, val_ss.str().c_str());

            memcpy(path_attrs->ls_attrs[ATTR_NODE_SR_CAPABILITIES].data(), val_ss.str().data(), val_ss.str().length());*/
            break;
        }

        case ATTR_LINK_ADMIN_GROUP:
            if (bgp_ls_attr->len != 4) {
       //         LOG_NOTICE("%s: bgp-ls: failed to parse attribute link admin group sub-tlv, size not 4",peer_addr.c_str());
                break;
            } else {
                value_32bit = 0;
                memcpy(&value_32bit, data, bgp_ls_attr->len);
                SWAP_BYTES(&value_32bit, bgp_ls_attr->len);
                memcpy(bgp_ls_attr->link.link_admin_group, &value_32bit, 4);
            }
            break;

        case ATTR_LINK_IGP_METRIC:
            if (bgp_ls_attr->len <= 4) {
                value_32bit = 0;
                memcpy(&value_32bit, data, bgp_ls_attr->len);
                SWAP_BYTES(&value_32bit, bgp_ls_attr->len);
            }

            bgp_ls_attr->link.link_igp_metric = value_32bit;
            break;

        case ATTR_LINK_IPV4_ROUTER_ID_REMOTE:
            if (bgp_ls_attr->len != 4)
                return INVALID_MSG;

            memcpy(bgp_ls_attr->link.link_ipv4_router_id_remote, data, 4);
            break;

        case ATTR_LINK_IPV6_ROUTER_ID_REMOTE:
            if (bgp_ls_attr->len != 16)
                return INVALID_MSG;

            memcpy(bgp_ls_attr->link.link_ipv6_router_id_remote, data, 16);
            break;

        case ATTR_LINK_MAX_LINK_BW:
            if (bgp_ls_attr->len != 4)
                return INVALID_MSG;

            float_val = 0;
            memcpy(&float_val, data, bgp_ls_attr->len);
            SWAP_BYTES(&float_val, bgp_ls_attr->len);
            float_val = ieee_float_to_kbps(float_val);
            bgp_ls_attr->link.link_max_link_bw = float_val;
            break;

        case ATTR_LINK_MAX_RESV_BW:
            if (bgp_ls_attr->len != 4)
                return INVALID_MSG;
            float_val = 0;
            memcpy(&float_val, data, bgp_ls_attr->len);
            SWAP_BYTES(&float_val, bgp_ls_attr->len);
            float_val = ieee_float_to_kbps(float_val);
            bgp_ls_attr->link.link_max_resv_bw = float_val;
            break;

        case ATTR_LINK_MPLS_PROTO_MASK:
            break;

        case ATTR_LINK_PROTECTION_TYPE:
            break;

        case ATTR_LINK_NAME: {
            strncpy(bgp_ls_attr->link.link_name, (char *)data, bgp_ls_attr->len);
            break;
        }

        case ATTR_LINK_ADJACENCY_SID: {
            //TODO: Need to change this implementation and add to bgp_ls_attr
            /*val_ss.str(std::string());

            // There can be more than one adj sid, append as list
            if (strlen((char *)path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].data()) > 0)
                val_ss << ", ";

//            // Decode flags
//            if (strcmp(path_attrs->ls.links.front().protocol, "IS-IS") >= 0) {
//                val_ss << parse_flags_to_string(*data,
//                                                      LS_FLAGS_PEER_ADJ_SID_ISIS, sizeof(LS_FLAGS_PEER_ADJ_SID_ISIS));
//
//            } else if (strcmp(path_attrs->ls.links.front().protocol, "OSPF") >= 0) {
//                val_ss << parse_flags_to_string(*data,
//                                                      LS_FLAGS_PEER_ADJ_SID_OSPF, sizeof(LS_FLAGS_PEER_ADJ_SID_OSPF));
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

            //      SELF_DEBUG("%s: bgp-ls: parsed sr link adjacency segment identifier %s", peer_addr.c_str(), val_ss.str().c_str());

            strncat((char *)path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].data(),
                    val_ss.str().c_str(),
                    path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].size() -
                            strlen((char *)path_attrs->ls_attrs[ATTR_LINK_ADJACENCY_SID].data()));*/
            break;
        }

        case ATTR_LINK_SRLG:
            break;

        case ATTR_LINK_TE_DEF_METRIC:

            // Per rfc7752 Section 3.3.2.3, this is supposed to be 4 bytes, but some implementations have this <=4.

            if (bgp_ls_attr->len == 0) {
                bgp_ls_attr->link.link_te_def_metric = 0;
                break;
            } else if (bgp_ls_attr->len > 4)
                return INVALID_MSG;
            else {
                memcpy(&bgp_ls_attr->link.link_te_def_metric, data, bgp_ls_attr->len);
                SWAP_BYTES(&bgp_ls_attr->link.link_te_def_metric, bgp_ls_attr->len);
            }

            break;

        case ATTR_LINK_UNRESV_BW: {

            //     SELF_DEBUG("%s: bgp-ls: parsing link unreserve bw attribute (len=%d)", peer_addr.c_str(), len);

            if (bgp_ls_attr->len != 32)
                return INVALID_MSG;

            for (int i=0; i < 32; i += 4) {
                float_val = 0;
                memcpy(&float_val, data, 4);
                SWAP_BYTES(&float_val, 4);
                bgp_ls_attr->link.link_unresv_bw[i/4] = ieee_float_to_kbps(float_val);

                data += 4;
            }
            break;
        }

        case ATTR_LINK_OPAQUE:
            //     LOG_INFO("%s: bgp-ls: opaque link attribute (len=%d), not yet implemented", peer_addr.c_str(), len);
            break;

        case ATTR_LINK_PEER_EPE_NODE_SID:
            /*
             * Syntax of value is: [L] <weight> <sid value>
             *
             *      L flag indicates locally significant
             */

            if (*data & 0x80)
                bgp_ls_attr->link.link_peer_epe_sid.V_flag = true;

            if (*data & 0x40)
                bgp_ls_attr->link.link_peer_epe_sid.L_flag = true;

            parse_sid_value(&bgp_ls_attr->link.link_peer_epe_sid, (data+4), bgp_ls_attr->len - 4);
            break;

        case ATTR_LINK_PEER_EPE_SET_SID:
            break;

        case ATTR_LINK_PEER_EPE_ADJ_SID:
            break;

        case ATTR_PREFIX_EXTEND_TAG:
            break;

        case ATTR_PREFIX_IGP_FLAGS:
            break;

        case ATTR_PREFIX_PREFIX_METRIC:
            value_32bit = 0;
            if (bgp_ls_attr->len <= 4) {
                memcpy(&value_32bit, data, bgp_ls_attr->len);
                SWAP_BYTES(&value_32bit, bgp_ls_attr->len);
            }

            bgp_ls_attr->prefix.prefix_prefix_metric = value_32bit;
            break;

        case ATTR_PREFIX_ROUTE_TAG:
        {
            //    SELF_DEBUG("%s: bgp-ls: parsing prefix route tag attribute (len=%d)", peer_addr.c_str(), len);

            // TODO(undefined): Per RFC7752 section 3.3.3, prefix tag can be multiples, but for now we only decode the first one.
            value_32bit = 0;

            if (bgp_ls_attr->len == 4) {
                memcpy(&value_32bit, data, bgp_ls_attr->len);
                SWAP_BYTES(&value_32bit, 4);

                bgp_ls_attr->prefix.prefix_route_tag = value_32bit;
          }
            break;
        }
        case ATTR_PREFIX_OSPF_FWD_ADDR:
            // SELF_DEBUG("%s: bgp-ls: parsing prefix OSPF forwarding address attribute", peer_addr.c_str());
            //    LOG_INFO("%s: bgp-ls: prefix OSPF forwarding address attribute, not yet implemented", peer_addr.c_str());
            break;

        case ATTR_PREFIX_OPAQUE_PREFIX:
            //    LOG_INFO("%s: bgp-ls: opaque prefix attribute (len=%d), not yet implemented", peer_addr.c_str(), len);
            break;

        case ATTR_PREFIX_SID: {
            //TODO: Need to change this implementation and add to bgp_ls_attr

            // There can be more than one prefix_sid, append as list
/*
            if (strlen((char *)path_attrs->ls_attrs[ATTR_PREFIX_SID].data()) > 0)
                val_ss << ", ";

            // Package structure:
            // https://tools.ietf.org/html/draft-gredler-idr-bgp-ls-segment-routing-ext-04#section-2.3.1

//            // Decode flags
//            if (strcmp(path_attrs->ls.prefixes.front().protocol, "IS-IS") >= 0) {
//                val_ss << parse_flags_to_string(*data,
//                                                LS_FLAGS_PREFIX_SID_ISIS, sizeof(LS_FLAGS_PREFIX_SID_ISIS));
//
//            } else if (strcmp(path_attrs->ls.prefixes.front().protocol, "OSPF") >= 0) {
//                val_ss << parse_flags_to_string(*data,
//                                                LS_FLAGS_PREFIX_SID_OSPF, sizeof(LS_FLAGS_PREFIX_SID_OSPF));
//            }

            val_ss << ' ';
            data += 1;

            uint8_t alg;
            alg = *data;
            data += 1;

            switch (alg) {
                case 0: // Shortest Path First (SPF) algorithm based on link metric
                    val_ss << "SPF ";
                    break;

                case 1: // Strict Shortest Path First (SPF) algorithm based on link metric
                    val_ss << "strict-SPF ";
                    break;
            }

            // 2 bytes reserved
            data += 2;

            // Parse the sid/value
            val_ss << parse_sid_value(data, bgp_ls_attr->len - 4);

            strncat((char *)path_attrs->ls_attrs[ATTR_PREFIX_SID].data(),
                    val_ss.str().c_str(),
                    path_attrs->ls_attrs[ATTR_PREFIX_SID].size() -
                            strlen((char *)path_attrs->ls_attrs[ATTR_PREFIX_SID].data()));
*/

            //    SELF_DEBUG("%s: bgp-ls: parsed sr prefix segment identifier  flags = %x len=%d : %s",
            //               peer_addr.c_str(), *(data - 4), len, val_ss.str().c_str());

            break;
        }

        default:
            //        LOG_INFO("%s: bgp-ls: Attribute type=%d len=%d not yet implemented, skipping",
            //           peer_addr.c_str(), type, len);
            break;
    }
    path_attrs->attr_value.bgp_ls[count]= *bgp_ls_attr;
    free(bgp_ls_attr);
    return bgp_ls_attr->len + 4;
}