#include "../include/evpn.h"

/**
 * Parse Ethernet Segment Identifier
 *
 * \details
 *      Will parse the Segment Identifier. Based on https://tools.ietf.org/html/rfc7432#section-5
 *
 * \param [in/out]  data_pointer  Pointer to the beginning of Route Distinguisher
 * \param [out]     rd_type                    Reference to RD type.
 * \param [out]     rd_assigned_number         Reference to Assigned Number subfield
 * \param [out]     rd_administrator_subfield  Reference to Administrator subfield
 */
static void libparsebgp_evpn_parse_ethernet_segment_identifier(update_path_attrs *path_attrs, u_char **data_pointer, ethernet_segment_identifier *parsed_data) {
    parsed_data->type= **data_pointer;

    *data_pointer++;
    switch (parsed_data->type) {
        case 0: {
            memcpy(parsed_data->type_0.eth_segment_iden, *data_pointer,9);
            break;
        }
        case 1: {
            memcpy(parsed_data->type_1.eth_segment_iden, *data_pointer,6);
            *data_pointer += 6;

            memcpy(&parsed_data->type_1.CE_LACP_port_key, *data_pointer, 2);
            SWAP_BYTES(&parsed_data->type_1.CE_LACP_port_key, 2);
            break;
        }
        case 2: {
            memcpy(parsed_data->type_2.eth_segment_iden, *data_pointer,6);
            *data_pointer += 6;

            memcpy(&parsed_data->type_2.root_bridge_priority, *data_pointer, 2);
            SWAP_BYTES(&parsed_data->type_2.root_bridge_priority, 2);
            break;
        }
        case 3: {
            memcpy(parsed_data->type_3.eth_segment_iden, *data_pointer,6);
            *data_pointer += 6;

            memcpy(&parsed_data->type_3.local_discriminator_value, *data_pointer, 3);
            SWAP_BYTES(&parsed_data->type_3.local_discriminator_value, 4);
            parsed_data->type_3.local_discriminator_value = parsed_data->type_3.local_discriminator_value >> 8;
            break;
        }
        case 4: {
            memcpy(&parsed_data->type_4.router_id, *data_pointer, 4);
            SWAP_BYTES(&parsed_data->type_4.router_id, 4);
            *data_pointer += 4;

            memcpy(&parsed_data->type_4.local_discriminator_value, *data_pointer, 4);
            SWAP_BYTES(&parsed_data->type_4.local_discriminator_value, 4);
            break;
        }
        case 5: {
            memcpy(&parsed_data->type_5.as_number, *data_pointer, 4);
            SWAP_BYTES(&parsed_data->type_5.as_number, 4);
            *data_pointer += 4;

            memcpy(&parsed_data->type_5.local_discriminator_value, *data_pointer, 4);
            SWAP_BYTES(&parsed_data->type_4.local_discriminator_value, 4);
            break;
        }
        default:
            break;
    }
}

/**
 * Parse Route Distinguisher
 *
 * \details
 *      Will parse the Route Distinguisher. Based on https://tools.ietf.org/html/rfc4364#section-4.2
 *
 * \param [in/out]  data_pointer  Pointer to the beginning of Route Distinguisher
 * \param [out]     rd_type                    Reference to RD type.
 * \param [out]     rd_assigned_number         Reference to Assigned Number subfield
 * \param [out]     rd_administrator_subfield  Reference to Administrator subfield
 */
static void libparsebgp_evpn_parse_route_distinguisher(u_char **data_pointer, route_distinguisher *rd) {

    memset(&rd, 0, sizeof(rd));
    *data_pointer++;
    rd->rd_type = **data_pointer;
    *data_pointer++;

    switch (rd->rd_type) {
        case 0: {
            memcpy(&rd->rd_type_msg.rd_type_0.rd_administrator_subfield, *data_pointer, 2);
            *data_pointer += 2;

            memcpy(&rd->rd_type_msg.rd_type_0.rd_assigned_number, *data_pointer, 4);
            *data_pointer += 4;

            SWAP_BYTES(&rd->rd_type_msg.rd_type_0.rd_assigned_number, 4);
            SWAP_BYTES(&rd->rd_type_msg.rd_type_0.rd_administrator_subfield, 2);
            break;
        };

        case 1: {
            memcpy(&rd->rd_type_msg.rd_type_1.rd_administrator_subfield, *data_pointer, 4);
            *data_pointer += 4;

            memcpy(&rd->rd_type_msg.rd_type_1.rd_assigned_number, *data_pointer, 2);
            *data_pointer += 2;

            SWAP_BYTES(&rd->rd_type_msg.rd_type_1.rd_assigned_number, 2);
            break;
        };

        case 2: {
            memcpy(&rd->rd_type_msg.rd_type_2.rd_administrator_subfield, *data_pointer, 4);
            *data_pointer += 4;

            memcpy(&rd->rd_type_msg.rd_type_2.rd_assigned_number, *data_pointer, 2);
            *data_pointer +=2;

            SWAP_BYTES(&rd->rd_type_msg.rd_type_2.rd_administrator_subfield, 4);
            SWAP_BYTES(&rd->rd_type_msg.rd_type_2.rd_assigned_number, 2);
            break;
        };
    }
}

// TODO: Refactor this method as it's overloaded - each case statement can be its own method
/**
 * Parse all EVPN nlri's
 *
 *
 * \details
 *      Parsing based on https://tools.ietf.org/html/rfc7432.  Will process all NLRI's in data.
 *
 * \param [in]   data                   Pointer to the start of the prefixes to be parsed
 * \param [in]   data_len               Length of the data in bytes to be read
 *
 */
ssize_t libparsebgp_evpn_parse_nlri_data(update_path_attrs *path_attrs, u_char **data, uint16_t data_len, bool is_unreach) {
    u_char      **data_pointer = data;
    u_char      ip_binary[16];
    int         addr_bytes;
    char        ip_char[40];
    int         data_read = 0;

    evpn_tuple *tuple = (evpn_tuple *)malloc(sizeof(evpn_tuple));
    if (is_unreach)
        path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.evpn_withdrawn = (evpn_tuple *)malloc(sizeof(evpn_tuple));
    else
        path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info.evpn = (evpn_tuple *)malloc(sizeof(evpn_tuple));

    uint16_t count_evpn_withdrawn=0,count_evpn=0;
    while ((data_read + 10 /* min read */) < data_len) {

        memset(tuple, 0, sizeof(tuple));

        // TODO: Keep an eye on this, as we might need to support add-paths for evpn
//        tuple.path_id = 0;
//        tuple.originating_router_ip_len = 0;

        tuple->route_type = **data_pointer;
        *data_pointer++;

        tuple->length = **data_pointer;
        *data_pointer++;
        uint8_t len = tuple->length;

        switch (tuple->route_type) {
            case EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY: {
                libparsebgp_evpn_parse_route_distinguisher(
                        data_pointer,
                        &tuple->route_type_specific.eth_ad_route.rd
                );
                *data_pointer += 8;

                data_read += 10;
                len -= 8; // len doesn't include the route type and len octets

                if ((data_read + 17 /* expected read size */) <= data_len) {

                    // Ethernet Segment Identifier (10 bytes)
                    libparsebgp_evpn_parse_ethernet_segment_identifier(path_attrs, data_pointer, &tuple->route_type_specific.eth_ad_route.eth_seg_iden);
                    *data_pointer += 10;

                    //Ethernet Tag Id (4 bytes), printing in hex.

                    memcpy(tuple->route_type_specific.eth_ad_route.ethernet_tag_id_hex, *data_pointer, 4);
                    *data_pointer += 4;

                    //MPLS Label (3 bytes)
                    memcpy(&tuple->route_type_specific.eth_ad_route.mpls_label, *data_pointer, 3);
                    SWAP_BYTES(&tuple->route_type_specific.eth_ad_route.mpls_label, 3);
                    tuple->route_type_specific.eth_ad_route.mpls_label >>= 8;

                    *data_pointer += 3;
                    data_read += 17;
                    len -= 17;
                }
                break;
            }
            case EVPN_ROUTE_TYPE_MAC_IP_ADVERTISMENT: {
                libparsebgp_evpn_parse_route_distinguisher(
                        data_pointer,
                        &tuple->route_type_specific.mac_ip_adv_route.rd
                );
                *data_pointer += 8;

                data_read += 10;
                len -= 8; // len doesn't include the route type and len octets

                if ((data_read + 25 /* expected read size */) <= data_len) {

                    // Ethernet Segment Identifier (10 bytes)
                    libparsebgp_evpn_parse_ethernet_segment_identifier(path_attrs, data_pointer, &tuple->route_type_specific.mac_ip_adv_route.eth_seg_iden);
                    *data_pointer += 10;

                    // Ethernet Tag ID (4 bytes)

                    u_char ethernet_id[4];
                    bzero(&ethernet_id, 4);
                    memcpy(&ethernet_id, *data_pointer, 4);
                    *data_pointer += 4;

                    memcpy(tuple->route_type_specific.mac_ip_adv_route.ethernet_tag_id_hex, *data_pointer, 4);

                    // MAC Address Length (1 byte)
                    uint8_t mac_address_length = **data_pointer;

                    tuple->route_type_specific.mac_ip_adv_route.mac_addr_len = mac_address_length;
                    *data_pointer++;

                    // MAC Address (6 byte)
                    memcpy(tuple->route_type_specific.mac_ip_adv_route.mac_addr, (*data_pointer), 6);
                    *data_pointer += 6;

                    // IP Address Length (1 byte)
                    tuple->route_type_specific.mac_ip_adv_route.ip_addr_len = **data_pointer;
                    *data_pointer++;

                    data_read += 22;
                    len -= 22;

                    addr_bytes = tuple->route_type_specific.mac_ip_adv_route.ip_addr_len > 0 ? (tuple->route_type_specific.mac_ip_adv_route.ip_addr_len / 8) : 0;

                    if (tuple->route_type_specific.mac_ip_adv_route.ip_addr_len > 0 && (addr_bytes + data_read) <= data_len) {
                        // IP Address (0, 4, or 16 bytes)
                        memset(tuple->route_type_specific.mac_ip_adv_route.ip_addr, 0, 16);
                        memcpy(&tuple->route_type_specific.mac_ip_adv_route.ip_addr, *data_pointer, addr_bytes);

                        *data_pointer += addr_bytes;
                        data_read += addr_bytes;
                        len -= addr_bytes;
                    }

                    if ((data_read + 3) <= data_len) {

                        // MPLS Label1 (3 bytes)
                        memcpy(&tuple->route_type_specific.mac_ip_adv_route.mpls_label_1, *data_pointer, 3);
                        SWAP_BYTES(&tuple->route_type_specific.mac_ip_adv_route.mpls_label_1, 3);
                        tuple->route_type_specific.mac_ip_adv_route.mpls_label_1 >>= 8;

                        *data_pointer += 3;
                        data_read += 3;
                        len -= 3;
                    }

                    // Parse second label if present
                    if (len == 3) {
                        //SELF_DEBUG("%s: parsing second evpn label\n", peer_addr.c_str());

                        memcpy(&tuple->route_type_specific.mac_ip_adv_route.mpls_label_2, *data_pointer, 3);
                        SWAP_BYTES(&tuple->route_type_specific.mac_ip_adv_route.mpls_label_2, 3);
                        tuple->route_type_specific.mac_ip_adv_route.mpls_label_2 >>= 8;

                        *data_pointer += 3;
                        data_read += 3;
                        len -= 3;
                    }
                }
                break;
            }
            case EVPN_ROUTE_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG: {
                libparsebgp_evpn_parse_route_distinguisher(
                        data_pointer,
                        &tuple->route_type_specific.incl_multicast_eth_tag_route.rd
                );
                *data_pointer += 8;

                data_read += 10;
                len -= 8; // len doesn't include the route type and len octets

                if ((data_read + 5 /* expected read size */) <= data_len) {

                    // Ethernet Tag ID (4 bytes)
                    memcpy(&tuple->route_type_specific.incl_multicast_eth_tag_route.ethernet_tag_id_hex, *data_pointer, 4);

                    // IP Address Length (1 byte)
                    tuple->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len = **data_pointer;
                    *data_pointer++;

                    data_read += 5;
                    len -= 5;

                    addr_bytes = tuple->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len > 0 ? (tuple->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len / 8) : 0;

                    if (tuple->route_type_specific.incl_multicast_eth_tag_route.ip_addr_len > 0 && (addr_bytes + data_read) <= data_len) {

                        // Originating Router's IP Address (4 or 16 bytes)
                        memset(tuple->route_type_specific.incl_multicast_eth_tag_route.originating_router_ip, 0, 16);
                        memcpy(&ip_binary, *data_pointer, addr_bytes);

                        *data_pointer += addr_bytes;
                        data_read += addr_bytes;
                        len -= addr_bytes;
                    }
                }

                break;
            }
            case EVPN_ROUTE_TYPE_ETHERNET_SEGMENT_ROUTE: {
                libparsebgp_evpn_parse_route_distinguisher(
                        data_pointer,
                        &tuple->route_type_specific.eth_segment_route.rd
                );
                *data_pointer += 8;

                data_read += 10;
                len -= 8; // len doesn't include the route type and len octets

                if ((data_read + 11 /* expected read size */) <= data_len) {

                    // Ethernet Segment Identifier (10 bytes)
                    libparsebgp_evpn_parse_ethernet_segment_identifier(path_attrs, data_pointer, &tuple->route_type_specific.eth_segment_route.eth_seg_iden);
                    *data_pointer += 10;

                    // IP Address Length (1 bytes)
                    tuple->route_type_specific.eth_segment_route.ip_addr_len = **data_pointer;
                    *data_pointer++;

                    data_read += 11;
                    len -= 11;

                    addr_bytes = tuple->route_type_specific.eth_segment_route.ip_addr_len > 0 ? (tuple->route_type_specific.eth_segment_route.ip_addr_len / 8) : 0;

                    if (tuple->route_type_specific.eth_segment_route.ip_addr_len > 0 && (addr_bytes + data_read) <= data_len) {

                        // Originating Router's IP Address (4 or 16 bytes)
                        memset(tuple->route_type_specific.eth_segment_route.originating_router_ip, 0,16);
                        memcpy(&tuple->route_type_specific.eth_segment_route.originating_router_ip, *data_pointer, (int) tuple->route_type_specific.eth_segment_route.ip_addr_len / 8);
                        data_read += addr_bytes;
                        len -= addr_bytes;
                    }
                }

                break;
            }
            default: {
                //LOG_INFO("%s: EVPN ROUTE TYPE %d is not implemented yet, skipping",
                //         peer_addr.c_str(), route_type);
                break;
            }
        }

        if (is_unreach) {
            if (count_evpn_withdrawn)
                path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.evpn_withdrawn =
                        (evpn_tuple *)realloc(path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.evpn_withdrawn, (count_evpn_withdrawn + 1) * sizeof(evpn_tuple));
            path_attrs->attr_value.mp_unreach_nlri_data.withdrawn_routes_nlri.evpn_withdrawn[count_evpn_withdrawn++] = *tuple;
        }
        else {
            if(count_evpn)
                path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info.evpn =
                        (evpn_tuple *)realloc(path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info.evpn, (count_evpn+1)*sizeof(evpn_tuple));
            path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info.evpn[count_evpn++]=*tuple;
        }
    }
    path_attrs->attr_value.mp_reach_nlri_data.count_evpn = count_evpn;
    path_attrs->attr_value.mp_unreach_nlri_data.count_evpn_withdrawn = count_evpn_withdrawn;
    free(tuple);
}