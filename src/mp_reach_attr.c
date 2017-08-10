/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "mp_reach_attr.h"
#include "evpn.h"
#include "mp_link_state.h"
#include "parse_utils.h"

/**
 * Parses mp_reach_nlri and mp_unreach_nlri (IPv4/IPv6)
 *
 * \details
 *      Will parse the NLRI encoding as defined in RFC3107 Section 3 (Carrying
 * Label Mapping information).
 *
 * \param [in]   is_ipv4                 True false to indicate if IPv4 or IPv6
 * \param [in]   data                   Pointer to the start of the label +
 * prefixes to be parsed \param [in]   len                    Length of the data
 * in bytes to be read \param [in]   peer_info              Persistent Peer info
 * pointer \param [out]  prefixes               Reference to a list<label,
 * prefix_tuple> to be updated with entries
 */
ssize_t libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(
  bool is_ipv4, u_char **data, uint16_t len,
  update_prefix_label_tuple *prefixes, uint16_t *prefix_count)
{
  int addr_bytes, count = 0;
  update_prefix_label_tuple *tuple =
    (update_prefix_label_tuple *)malloc(sizeof(update_prefix_label_tuple));
  prefixes =
    (update_prefix_label_tuple *)malloc(sizeof(update_prefix_label_tuple));

  if (len <= 0 || data == NULL)
    return 0;

  // tuple.type = is_ipv4 ? PREFIX_LABEL_UNICAST_V4 : PREFIX_LABEL_UNICAST_V6;
  // tuple.is_ipv4 = is_ipv4;

  //    bool add_path_enabled = libparsebgp_addpath_is_enabled(add_path_map,
  //    is_ipv4 ? BGP_AFI_IPV4 : BGP_AFI_IPV6, BGP_SAFI_NLRI_LABEL);

  // bool isVPN = typeid(vpn_tuple) == typeid(tuple);
  uint16_t label_bytes;

  // Loop through all prefixes
  for (size_t read_size = 0; read_size < len; read_size++) {
    if (count)
      prefixes = (update_prefix_label_tuple *)realloc(
        prefixes, (count + 1) * sizeof(update_prefix_label_tuple));
    memset(tuple, 0, sizeof(*tuple));

    // Only check for add-paths if not mpls/vpn
    /*        if (add_path_enabled and (len - read_size) >= 4) {
                memcpy(&tuple->path_id, data, 4);
                SWAP_BYTES(&tuple->path_id.afi);
                data += 4;
                read_size += 4;

            } else {
                tuple->path_id.afi = 0;
                tuple->path_id.safi = 0;
                tuple->path_id.send_recieve = 0;
            }*/
    tuple->path_id.afi = 0;
    tuple->path_id.safi = 0;
    tuple->path_id.send_recieve = 0;

    // set the address in bits length
    tuple->len = **data++;

    // Figure out how many bytes the bits requires
    addr_bytes = tuple->len / 8;
    if (tuple->len % 8)
      ++addr_bytes;

    // if (isVPN) {
    label_bytes = decode_label(data, addr_bytes, tuple->label);

    tuple->len -=
      (8 * label_bytes);  // Update prefix len to not include the label(s)
    *data += label_bytes; // move data pointer past labels
    addr_bytes -= label_bytes;
    read_size += label_bytes;
    //}

    // Parse RD if VPN
    /*if (isVPN and addr_bytes >= 8) {
        vpn_tuple *vtuple = (vpn_tuple *)&tuple;
        libparsebgp_evpn_parse_route_distinguisher(data, &vtuple->rd_type,
    &vtuple->rd_assigned_number, &vtuple->rd_administrator_subfield); data += 8;
        addr_bytes -= 8;
        read_size += 8;
        tuple.len -= 64;
    }*/

    // Parse the prefix if it isn't a default route
    if (addr_bytes > 0) {
      memcpy(tuple->prefix, *data, addr_bytes);
      *data += addr_bytes;
      read_size += addr_bytes;
    }
    prefixes[count++] = *tuple;
  }
  *prefix_count = count;
  free(tuple);
  return len;
}

/**
 * MP Reach NLRI parse for BGP_AFI_IPv4 & BGP_AFI_IPV6
 *
 * \details Will handle parsing the SAFI's for address family ipv6 and IPv4
 *
 * \param [in]   is_ipv4         True false to indicate if IPv4 or IPv6
 * \param [in]   nlri           Reference to parsed NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated
 * with all parsed data
 */
static ssize_t libparsebgp_mp_reach_attr_parse_afi_ipv4_ipv6(
  bool is_ipv4, update_path_attrs *path_attrs, int nlri_len,
  unsigned char **next_hop, unsigned char **nlri_data)
{
  ssize_t read_size = 0;
  /*
   * Decode based on SAFI
   */
  switch (path_attrs->attr_value.mp_reach_nlri_data.safi) {
  case BGP_SAFI_UNICAST: // Unicast IP address prefix

    // Next-hop is an IP address - Change/set the next-hop attribute in parsed
    // data to use this next-hop
    if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop, 16);
    else
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop,
             path_attrs->attr_value.mp_reach_nlri_data.nh_len);

    // inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char,
    // sizeof(ip_char));

    // path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

    // Data is an IP address - parse the address and save it
    read_size = libparsebgp_mp_reach_attr_parse_nlri_data_ipv4_ipv6(
      is_ipv4, nlri_data, nlri_len,
      path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info.nlri_info,
      &path_attrs->attr_value.mp_reach_nlri_data.count_nlri_info);
    break;

  case BGP_SAFI_NLRI_LABEL:
    // Next-hop is an IP address - Change/set the next-hop attribute in parsed
    // data to use this next-hop
    if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop, 16);
    else
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop,
             path_attrs->attr_value.mp_reach_nlri_data.nh_len);

    // inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char,
    // sizeof(ip_char));

    // path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

    // Data is an Label, IP address tuple parse and save it
    read_size = libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(
      is_ipv4, nlri_data, nlri_len,
      path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info
        .nlri_label_info,
      &path_attrs->attr_value.mp_reach_nlri_data.count_nlri_label_info);
    break;

  case BGP_SAFI_MPLS: {

    if (is_ipv4) {
      // Next hop encoded in 12 bytes, last 4 bytes = IPv4
      *next_hop += 8;
      path_attrs->attr_value.mp_reach_nlri_data.nh_len -= 8;
    }

    // Next-hop is an IP address - Change/set the next-hop attribute in parsed
    // data to use this next-hop
    if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop, 16);
    else
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop,
             path_attrs->attr_value.mp_reach_nlri_data.nh_len);

    // inet_ntop(is_ipv4 ? AF_INET : AF_INET6, ip_raw, ip_char,
    // sizeof(ip_char));

    // path_attrs->attrs[ATTR_TYPE_NEXT_HOP] = std::string(ip_char);

    read_size = libparsebgp_mp_reach_attr_parse_nlri_data_label_ipv4_ipv6(
      is_ipv4, nlri_data, nlri_len,
      path_attrs->attr_value.mp_reach_nlri_data.mp_reach_nlri_info
        .nlri_label_info,
      &path_attrs->attr_value.mp_reach_nlri_data.count_nlri_label_info);

    break;
  }

  default: {
    // LOG_INFO("%s: MP_REACH AFI=ipv4/ipv6 (%d) SAFI=%d is not implemented yet,
    // skipping for now",
    //         peer_addr.c_str(), is_ipv4, nlri.safi);
    return INVALID_MSG;
  }
  }
  return read_size;
}

/**
 * MP Reach NLRI parse based on AFI
 *
 * \details Will parse the next-hop and nlri data based on AFI.  A call to
 *          the specific SAFI method will be performed to further parse the
 * message.
 *
 * \param [in]   nlri           Reference to parsed NLRI struct
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated
 * with all parsed data
 */
static ssize_t libparsebgp_parse_afi(update_path_attrs *path_attrs,
                                     int nlri_len, unsigned char **nlri_data,
                                     unsigned char **next_hop)
{
  ssize_t read_size = 0;
  switch (path_attrs->attr_value.mp_reach_nlri_data.afi) {
  case BGP_AFI_IPV6: // IPv6
    read_size = libparsebgp_mp_reach_attr_parse_afi_ipv4_ipv6(
      false, path_attrs, nlri_len, next_hop, nlri_data);
    break;

  case BGP_AFI_IPV4: // IPv4
    read_size = libparsebgp_mp_reach_attr_parse_afi_ipv4_ipv6(
      true, path_attrs, nlri_len, next_hop, nlri_data);
    break;

  case BGP_AFI_BGPLS: // BGP-LS (draft-ietf-idr-ls-distribution-10)
  {
    read_size = libparsebgp_mp_link_state_parse_reach_link_state(
      path_attrs, nlri_len, next_hop, nlri_data);
    break;
  }

  case BGP_AFI_L2VPN: {
    // Next-hop is an IP address - Change/set the next-hop attribute in parsed
    // data to use this next-hop
    if (path_attrs->attr_value.mp_reach_nlri_data.nh_len > 16)
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop, 16);
    else
      memcpy(path_attrs->attr_value.mp_reach_nlri_data.next_hop, *next_hop,
             path_attrs->attr_value.mp_reach_nlri_data.nh_len);

    // parse by safi
    switch (path_attrs->attr_value.mp_reach_nlri_data.safi) {
    case BGP_SAFI_EVPN: // https://tools.ietf.org/html/rfc7432
    {
      read_size = libparsebgp_evpn_parse_nlri_data(path_attrs, nlri_data,
                                                   nlri_len, false);
      break;
    }

    default: {
      return NOT_YET_IMPLEMENTED;
      // break;
      // LOG_INFO("%s: EVPN::parse SAFI=%d is not implemented yet, skipping",
      //         peer_addr.c_str(), nlri.safi);
    }
    }

    break;
  }

  default: // Unknown
    // LOG_INFO("%s: MP_REACH AFI=%d is not implemented yet, skipping",
    // peer_addr.c_str(), nlri.afi);
    return NOT_YET_IMPLEMENTED;
  }
  return read_size;
}

/**
 * Parse the MP_REACH NLRI attribute data
 *
 * \details
 *      Will parse the MP_REACH_NLRI data passed.  Parsed data will be stored
 *      in parsed_data.
 *
 *      \see RFC4760 for format details.
 *
 * \param [in]   attr_len               Length of the attribute data
 * \param [in]   data                   Pointer to the attribute data
 * \param [out]  parsed_data            Reference to parsed_update_data; will be
 * updated with all parsed data
 */
ssize_t
libparsebgp_mp_reach_attr_parse_reach_nlri_attr(update_path_attrs *path_attrs,
                                                int attr_len, u_char **data)
{
  ssize_t read_size = 0;
  /*
   * Set the MP NLRI struct
   */
  // Read address family
  unsigned char **nlri_data, **next_hop;
  memcpy(&path_attrs->attr_value.mp_reach_nlri_data.afi, *data, 2);
  *data += 2;
  attr_len -= 2;
  read_size += 2;
  SWAP_BYTES(&path_attrs->attr_value.mp_reach_nlri_data.afi,
             2); // change to host order

  path_attrs->attr_value.mp_reach_nlri_data.safi =
    **data; // Set the SAFI - 1 octet
  *data += 1;
  attr_len--;
  read_size++;

  path_attrs->attr_value.mp_reach_nlri_data.nh_len =
    **data; // Set the next-hop length - 1 octet
  *data += 1;
  attr_len--;
  read_size++;

  next_hop = data;
  *data += path_attrs->attr_value.mp_reach_nlri_data.nh_len;
  attr_len -= path_attrs->attr_value.mp_reach_nlri_data.nh_len;
  read_size += path_attrs->attr_value.mp_reach_nlri_data
                 .nh_len; // Set pointer position for nh data

  path_attrs->attr_value.mp_reach_nlri_data.reserved =
    **data; // Set the reserve octet
  *data += 1;
  attr_len--;
  read_size++;
  nlri_data = data; // Set pointer position for nlri data

  /*
   * Make sure the parsing doesn't exceed buffer
   */
  if (attr_len < 0) {
    // LOG_NOTICE("%s: MP_REACH NLRI data length is larger than attribute data
    // length, skipping parse", peer_addr.c_str());
    return INCOMPLETE_MSG;
  }

  /*
   * Next-hop and NLRI data depends on the AFI & SAFI
   *  Parse data based on AFI + SAFI
   */
  libparsebgp_parse_afi(path_attrs, attr_len, nlri_data, next_hop);
  return read_size;
}

/**
 * Parses mp_reach_nlri and mp_unreach_nlri (IPv4/IPv6)
 *
 * \details
 *      Will parse the NLRI encoding as defined in RFC4760 Section 5 (NLRI
 * Encoding).
 *
 * \param [in]   is_ipv4                 True false to indicate if IPv4 or IPv6
 * \param [in]   data                   Pointer to the start of the prefixes to
 * be parsed \param [in]   len                    Length of the data in bytes to
 * be read \param [in]   peer_info              Persistent Peer info pointer
 * \param [out]  prefixes               Reference to a list<prefix_tuple> to be
 * updated with entries
 */
ssize_t libparsebgp_mp_reach_attr_parse_nlri_data_ipv4_ipv6(
  bool is_ipv4, u_char **data, uint16_t len, update_prefix_tuple *prefixes,
  uint16_t *prefix_count)
{
  u_char ip_raw[16];
  int addr_bytes;

  if (len <= 0 || data == NULL)
    return 0;

  // TODO: Can extend this to support multicast, but right now we set it to
  // unicast v4/v6
  // tuple.type = is_ipv4 ? PREFIX_UNICAST_V4 : PREFIX_UNICAST_V6;
  // tuple.is_ipv4 = is_ipv4;

  //    bool add_path_enabled = libparsebgp_addpath_is_enabled(add_path_map,
  //    is_ipv4 ? BGP_AFI_IPV4 : BGP_AFI_IPV6, BGP_SAFI_NLRI_LABEL);

  int count = 0;
  // Loop through all prefixes
  prefixes = (update_prefix_tuple *)malloc(sizeof(update_prefix_tuple));
  update_prefix_tuple *tuple =
    (update_prefix_tuple *)malloc(sizeof(update_prefix_tuple));

  for (size_t read_size = 0; read_size < len; read_size++) {
    memset(tuple, 0, sizeof(update_prefix_tuple));

    if (count)
      prefixes = (update_prefix_tuple *)realloc(
        prefixes, (count + 1) * sizeof(update_prefix_tuple));

    bzero(ip_raw, sizeof(ip_raw));

    // Parse add-paths if enabled
    /*if (add_path_enabled and (len - read_size) >= 4) {
        memcpy(&tuple->path_id, data, 4);
        SWAP_BYTES(&tuple->path_id.afi);
        data += 4; read_size += 4;
    } else {
        tuple->path_id.afi = 0;
        tuple->path_id.safi = 0;
        tuple->path_id.send_recieve = 0;
    }*/
    tuple->path_id.afi = 0;
    tuple->path_id.safi = 0;
    tuple->path_id.send_recieve = 0;

    // set the address in bits length
    tuple->len = **data++;

    // Figure out how many bytes the bits requires
    addr_bytes = tuple->len / 8;
    if (tuple->len % 8)
      ++addr_bytes;

    memcpy(tuple->prefix, *data, addr_bytes);
    *data += addr_bytes;
    read_size += addr_bytes;

    // Add tuple to prefix list
    prefixes[count++] = *tuple;
  }
  *prefix_count = count;
  free(tuple);
  return len;
}

/**
 * Decode label from NLRI data
 *
 * \details
 *      Decodes the labels from the NLRI data into labels string
 *
 * \param [in]   data                   Pointer to the start of the label +
 * prefixes to be parsed \param [in]   len                    Length of the data
 * in bytes to be read \param [out]  labels                 Reference to string
 * that will be updated with labels delimited by comma
 *
 * \returns number of bytes read to decode the label(s) and updates string
 * labels
 *
 */
inline uint16_t decode_label(u_char **data, uint16_t len, mpls_label *labels)
{
  int read_size = 0, count = 0;
  mpls_label *label = (mpls_label *)malloc(sizeof(mpls_label));
  labels = (mpls_label *)malloc(sizeof(mpls_label));
  u_char **data_ptr = data;

  // the label is 3 octets long
  while (read_size <= len) {
    if (count)
      labels = (mpls_label *)realloc(labels, (count + 1) * sizeof(mpls_label));
    memset(&label, 0, sizeof(label));

    memcpy(&label->data, *data_ptr, 3);
    SWAP_BYTES(&label->data, 3); // change to host order

    *data_ptr += 3;
    read_size += 3;
    labels[count++] = *label;
  }

  return read_size;
}
