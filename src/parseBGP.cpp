/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "parseBGP.h"

#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>
#include <string>
#include <list>
#include <memory>
#include <arpa/inet.h>
#include <bgp/linkstate/MPLinkStateAttr.h>

#include <sstream>
#include <algorithm>

#include "MsgBusInterface.hpp"
#include "NotificationMsg.h"
#include "OpenMsg.h"
#include "UpdateMsg.h"
#include "bgp_common.h"

using namespace std;

/**
 * Constructor for class -
 *
 * \details
 *    This class parses the BGP message and updates DB.  The
 *    'mysql_ptr' must be a pointer reference to an open mysql connection.
 *    'peer_entry' must be a pointer to the peer_entry table structure that
 *    has already been populated.
 *
 * \param [in]     logPtr      Pointer to existing Logger for app logging
 * \param [in]     mbus_ptr     Pointer to exiting dB implementation
 * \param [in,out] peer_entry  Pointer to peer entry
 * \param [in]     routerAddr  The router IP address - used for logging
 * \param [in,out] peer_info   Persistent peer information
 */
parseBGP::parseBGP(Logger *logPtr, MsgBusInterface *mbus_ptr, MsgBusInterface::obj_bgp_peer *peer_entry, string routerAddr,
                   BMPReader::peer_info *peer_info) {
    debug = false;

    logger = logPtr;

    data_bytes_remaining = 0;
    data = NULL;

    bzero(&common_hdr, sizeof(common_hdr));

    // Set our mysql pointer
    this->mbus_ptr = mbus_ptr;

    // Set our peer entry
    p_entry = peer_entry;
    p_info = peer_info;

    router_addr = routerAddr;
}

/**
 * Desctructor
 */
parseBGP::~parseBGP() {
}

/**
 * handle BGP update message and store in DB
 *
 * \details Parses the bgp update message and store it in the DB.
 *
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 *
 * \returns True if error, false if no error.
 */
bool parseBGP::handleUpdate(u_char *data, size_t size) {
    bgp_msg::UpdateMsg::parsed_update_data parsed_data;
    int read_size = 0;

    if (parseBgpHeader(data, size) == BGP_MSG_UPDATE) {
        data += BGP_MSG_HDR_LEN;

        /*
         * Parse the update message - stored results will be in parsed_data
         */
        bgp_msg::UpdateMsg uMsg(logger, p_entry->peer_addr, router_addr, p_info, debug);

        if ((read_size=uMsg.parseUpdateMsg(data, data_bytes_remaining, parsed_data)) != (size - BGP_MSG_HDR_LEN)) {
            LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr,
                        router_addr.c_str(), read_size, (size - read_size));
            return true;
        }

        data_bytes_remaining -= read_size;

        /*
         * Update the DB with the update data
         */
        UpdateDB(parsed_data);
    }

    return false;
}

/**
 * handle BGP notify event - updates the down event with parsed data
 *
 * \details
 *  The notify message does not directly add to Db, so the calling
 *  method/function must handle that.
 *
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 * \param [out]    down_event       Reference to the down event/notification storage buffer
 *
 * \returns True if error, false if no error.
 */
bool parseBGP::handleDownEvent(u_char *data, size_t size, MsgBusInterface::obj_peer_down_event &down_event) {
    bool        rval;

    // Process the BGP message normally
    if (parseBgpHeader(data, size) == BGP_MSG_NOTIFICATION) {
        data += BGP_MSG_HDR_LEN;

        bgp_msg::parsed_notify_msg parsed_msg;
        bgp_msg::NotificationMsg nMsg(logger, debug);
        if ( (rval=nMsg.parseNotify(data, data_bytes_remaining, parsed_msg)))
            LOG_ERR("%s: rtr=%s: Failed to parse the BGP notification message", p_entry->peer_addr, router_addr.c_str());

        else {
            data += 2;                                                 // Move pointer past notification message
            data_bytes_remaining -= 2;

            down_event.bgp_err_code = parsed_msg.error_code;
            down_event.bgp_err_subcode = parsed_msg.error_subcode;
            strncpy(down_event.error_text, parsed_msg.error_text, sizeof(down_event.error_text));
        }
    }
    else {
        LOG_ERR("%s: rtr=%s: BGP message type is not a BGP notification, cannot parse the notification",
                p_entry->peer_addr, router_addr.c_str());
        throw "ERROR: Invalid BGP MSG for BMP down event, expected NOTIFICATION message.";
    }

    return rval;
}

/**
 * Handles the up event by parsing the BGP open messages - Up event will be updated
 *
 * \details
 *  This method will read the expected sent and receive open messages.
 *
 * \param [in]     data             Pointer to the raw BGP message header
 * \param [in]     size             length of the data buffer (used to prevent overrun)
 *
 * \returns True if error, false if no error.
 */
bool parseBGP::handleUpEvent(u_char *data, size_t size, MsgBusInterface::obj_peer_up_event *up_event) {
    bgp_msg::OpenMsg    oMsg(logger, p_entry->peer_addr, this->p_info, debug);
    list <string>       cap_list;
    string              local_bgp_id, remote_bgp_id;
    size_t              read_size;

    p_info->recv_four_octet_asn = false;
    p_info->sent_four_octet_asn = false;
    p_info->using_2_octet_asn = false;


    /*
     * Process the sent open message
     */
    if (parseBgpHeader(data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;

        read_size = oMsg.parseOpenMsg(data, data_bytes_remaining, true, up_event->local_asn, up_event->local_hold_time,
                                      local_bgp_id, cap_list);

        if (!read_size) {
            LOG_ERR("%s: rtr=%s: Failed to read sent open message",  p_entry->peer_addr, router_addr.c_str());
            throw "Failed to read open message";
        }

        data += read_size;                                          // Move the pointer pase the sent open message
        data_bytes_remaining -= read_size;

        strncpy(up_event->local_bgp_id, local_bgp_id.c_str(), sizeof(up_event->local_bgp_id));

        // Convert the list to string
        bzero(up_event->sent_cap, sizeof(up_event->sent_cap));

        string cap_str;
        for (list<string>::iterator it = cap_list.begin(); it != cap_list.end(); it++) {
            if ( it != cap_list.begin())
                cap_str.append(", ");

            // Check for 4 octet ASN support
            if ((*it).find("4 Octet ASN") != std::string::npos)
                p_info->sent_four_octet_asn = true;

            cap_str.append((*it));
        }

        strncpy(up_event->sent_cap, cap_str.c_str(), sizeof(up_event->sent_cap));

    } else {
        LOG_ERR("%s: rtr=%s: BGP message type is not BGP OPEN, cannot parse the open message",  p_entry->peer_addr, router_addr.c_str());
        throw "ERROR: Invalid BGP MSG for BMP Sent OPEN message, expected OPEN message.";
    }

    /*
     * Process the received open message
     */
    cap_list.clear();

    if (parseBgpHeader(data, size) == BGP_MSG_OPEN) {
        data += BGP_MSG_HDR_LEN;

        read_size = oMsg.parseOpenMsg(data, data_bytes_remaining, false, up_event->remote_asn,
                                      up_event->remote_hold_time, remote_bgp_id, cap_list);

        if (!read_size) {
            LOG_ERR("%s: rtr=%s: Failed to read sent open message", p_entry->peer_addr, router_addr.c_str());
            throw "Failed to read open message";
        }

        data += read_size;                                          // Move the pointer pase the sent open message
        data_bytes_remaining -= read_size;

        strncpy(up_event->remote_bgp_id, remote_bgp_id.c_str(), sizeof(up_event->remote_bgp_id));

        // Convert the list to string
        bzero(up_event->recv_cap, sizeof(up_event->recv_cap));

        string cap_str;
        for (list<string>::iterator it = cap_list.begin(); it != cap_list.end(); it++) {
            if ( it != cap_list.begin())
                cap_str.append(", ");

            // Check for 4 octet ASN support - reset to false if
            if ((*it).find("4 Octet ASN") != std::string::npos)
                p_info->recv_four_octet_asn = true;

            cap_str.append((*it));
        }

        strncpy(up_event->recv_cap, cap_str.c_str(), sizeof(up_event->recv_cap));

    } else {
        LOG_ERR("%s: rtr=%s: BGP message type is not BGP OPEN, cannot parse the open message",
                p_entry->peer_addr, router_addr.c_str());
        throw "ERROR: Invalid BGP MSG for BMP Received OPEN message, expected OPEN message.";
    }

    return false;
}

/**
 * Parses the BGP common header
 *
 * \details
 *      This method will parse the bgp common header and will upload the global
 *      c_hdr structure, instance data pointer, and remaining bytes of message.
 *      The return value of this method will be the BGP message type.
 *
 * \param [in]      data            Pointer to the raw BGP message header
 * \param [in]      size            length of the data buffer (used to prevent overrun)
 *
 * \returns BGP message type
 */
u_char parseBGP::parseBgpHeader(u_char *data, size_t size) {
    bzero(&common_hdr, sizeof(common_hdr));

    /*
     * Error out if data size is not large enough for common header
     */
    if (size < BGP_MSG_HDR_LEN) {
        LOG_WARN("%s: rtr=%s: BGP message is being parsed is %d but expected at least %d in size",
                p_entry->peer_addr, router_addr.c_str(), size, BGP_MSG_HDR_LEN);
        return 0;
    }

    memcpy(&common_hdr, data, BGP_MSG_HDR_LEN);

    // Change length to host byte order
    bgp::SWAP_BYTES(&common_hdr.len);

    // Update remaining bytes left of the message
    data_bytes_remaining = common_hdr.len - BGP_MSG_HDR_LEN;

    /*
     * Error out if the remaining size of the BGP message is grater than passed bgp message buffer
     *      It is expected that the passed bgp message buffer holds the complete BGP message to be parsed
     */
    if (common_hdr.len > size) {
        LOG_WARN("%s: rtr=%s: BGP message size of %hu is greater than passed data buffer, cannot parse the BGP message",
                p_entry->peer_addr, router_addr.c_str(), common_hdr.len, size);
    }

    SELF_DEBUG("%s: rtr=%s: BGP hdr len = %u, type = %d", p_entry->peer_addr, router_addr.c_str(), common_hdr.len, common_hdr.type);

    /*
     * Validate the message type as being allowed/accepted
     */
    switch (common_hdr.type) {
        case BGP_MSG_UPDATE         : // Update Message
        case BGP_MSG_NOTIFICATION   : // Notification message
        case BGP_MSG_OPEN           : // OPEN message
            // Message(s) are allowed - calling method will request further parsing of the bgp message type
            break;

        case BGP_MSG_ROUTE_REFRESH: // Route Refresh message
            LOG_NOTICE("%s: rtr=%s: Received route refresh, nothing to do with this message currently.",
                        p_entry->peer_addr, router_addr.c_str());
            break;

        default :
            LOG_WARN("%s: rtr=%s: Unsupported BGP message type = %d", p_entry->peer_addr, router_addr.c_str(), common_hdr.type);
            break;
    }

    return common_hdr.type;
}

/**
 * Update the Database with the parsed updated data
 *
 * \details This method will update the database based on the supplied parsed update data
 *
 * \param  parsed_data          Reference to the parsed update data
 */
void parseBGP::UpdateDB(bgp_msg::UpdateMsg::parsed_update_data &parsed_data) {
    /*
     * Update the path attributes
     */
    UpdateDBAttrs(parsed_data.attrs);

    /*
     * Update the bgp-ls data
     */
    UpdateDbBgpLs(false, parsed_data.ls, parsed_data.ls_attrs);
    UpdateDbBgpLs(true, parsed_data.ls_withdrawn, parsed_data.ls_attrs);

    /*
     * Update the advertised prefixes (both ipv4 and ipv6)
     */
    UpdateDBAdvPrefixes(parsed_data.advertised, parsed_data.attrs);

    UpdateDBL3Vpn(false,parsed_data.vpn, parsed_data.attrs);
    UpdateDBL3Vpn(true,parsed_data.vpn_withdrawn, parsed_data.attrs);

    UpdateDBeVPN(false, parsed_data.evpn, parsed_data.attrs);
    UpdateDBeVPN(true, parsed_data.evpn_withdrawn, parsed_data.attrs);

    /*
     * Update withdraws (both ipv4 and ipv6)
     */
    UpdateDBWdrawnPrefixes(parsed_data.withdrawn);

}

/**
 * Update the Database path attributes
 *
 * \details This method will update the database for the supplied path attributes
 *
 * \param  attrs            Reference to the parsed attributes map
 */
void parseBGP::UpdateDBAttrs(bgp_msg::UpdateMsg::parsed_attrs_map &attrs) {

    /*
     * Setup the record
     */
    base_attr.as_path                  = (string)attrs[bgp_msg::ATTR_TYPE_AS_PATH];
    base_attr.cluster_list             = (string)attrs[bgp_msg::ATTR_TYPE_CLUSTER_LIST];
    base_attr.community_list           = (string)attrs[bgp_msg::ATTR_TYPE_COMMUNITIES];
    base_attr.ext_community_list       = (string)attrs[bgp_msg::ATTR_TYPE_EXT_COMMUNITY];

    base_attr.atomic_agg               = ((string)attrs[bgp_msg::ATTR_TYPE_ATOMIC_AGGREGATE]).compare("1") == 0 ? true : false;

    if (((string)attrs[bgp_msg::ATTR_TYPE_LOCAL_PREF]).length() > 0)
        base_attr.local_pref = std::stoul(((string)attrs[bgp_msg::ATTR_TYPE_LOCAL_PREF]));
    else
        base_attr.local_pref = 0;

    if (((string)attrs[bgp_msg::ATTR_TYPE_MED]).length() > 0)
        base_attr.med = std::stoul(((string)attrs[bgp_msg::ATTR_TYPE_MED]));
    else
        base_attr.med = 0;

    if (((string)attrs[bgp_msg::ATTR_TYPE_INTERNAL_AS_COUNT]).length() > 0)
        base_attr.as_path_count = std::stoi(((string)attrs[bgp_msg::ATTR_TYPE_INTERNAL_AS_COUNT]));
    else
        base_attr.as_path_count = 0;

    if (((string)attrs[bgp_msg::ATTR_TYPE_INTERNAL_AS_ORIGIN]).length() > 0)
        base_attr.origin_as = std::stoul(((string)attrs[bgp_msg::ATTR_TYPE_INTERNAL_AS_ORIGIN]));
    else
        base_attr.origin_as = 0;

    if (((string)attrs[bgp_msg::ATTR_TYPE_ORIGINATOR_ID]).length() > 0)
        strncpy(base_attr.originator_id, ((string)attrs[bgp_msg::ATTR_TYPE_ORIGINATOR_ID]).c_str(), sizeof(base_attr.originator_id));
    else
        bzero(base_attr.originator_id, sizeof(base_attr.originator_id));

    if ( ((string)attrs[bgp_msg::ATTR_TYPE_NEXT_HOP]).find_first_of(':') ==  string::npos)
        base_attr.nexthop_isIPv4 = true;
    else // is IPv6
        base_attr.nexthop_isIPv4 = false;

    if ( ((string)attrs[bgp_msg::ATTR_TYPE_AGGEGATOR]).length() > 0)
        strncpy(base_attr.aggregator, ((string)attrs[bgp_msg::ATTR_TYPE_AGGEGATOR]).c_str(), sizeof(base_attr.aggregator));
    else
        bzero(base_attr.aggregator, sizeof(base_attr.aggregator));

    if ( ((string)attrs[bgp_msg::ATTR_TYPE_ORIGIN]).length() > 0)
            strncpy(base_attr.origin, ((string)attrs[bgp_msg::ATTR_TYPE_ORIGIN]).c_str(), sizeof(base_attr.origin));
    else
        bzero(base_attr.origin, sizeof(base_attr.origin));

    if ( ((string)attrs[bgp_msg::ATTR_TYPE_NEXT_HOP]).length() > 0)
        strncpy(base_attr.next_hop, ((string)attrs[bgp_msg::ATTR_TYPE_NEXT_HOP]).c_str(), sizeof(base_attr.next_hop));

    else {
        // Skip adding path attributes if next hop is missing
        SELF_DEBUG("%s: no next-hop, must be unreach; not sending attributes to message bus", p_entry->peer_addr);
        bzero(base_attr.next_hop, sizeof(base_attr.next_hop));
        bzero(path_hash_id, sizeof(path_hash_id));
        return;
    }

    SELF_DEBUG("%s: adding attributes to message bus", p_entry->peer_addr);

    // Update the DB entry
    mbus_ptr->update_baseAttribute(*p_entry, base_attr, mbus_ptr->BASE_ATTR_ACTION_ADD);

    // Update the class instance variable path_hash_id
    memcpy(path_hash_id, base_attr.hash_id, sizeof(path_hash_id));
}

/**
 * Update the Database advertised l3vpn 
 *
 * \details This method will update the database for the supplied advertised prefixes
 *
 * \param [in] remove          True if the records should be deleted, false if they are to be added/updated
 * \param [in] prefixes        Reference to the list<vpn_tuple> of advertised vpns
 * \param [in] attrs           Reference to the parsed attributes map
 */
void parseBGP::UpdateDBL3Vpn(bool remove, std::list<bgp::vpn_tuple> &prefixes,
                             bgp_msg::UpdateMsg::parsed_attrs_map &attrs) {
    vector<MsgBusInterface::obj_vpn> rib_list;
    MsgBusInterface::obj_vpn         rib_entry;
    uint32_t                         value_32bit;
    uint64_t                         value_64bit;

    /*
     * Loop through all vpn and add/update them in the DB
     */
    for (std::list<bgp::vpn_tuple>::iterator it = prefixes.begin();
                                                it != prefixes.end();
                                                it++) {
        bgp::vpn_tuple &tuple = (*it);

        memcpy(rib_entry.path_attr_hash_id, path_hash_id, sizeof(rib_entry.path_attr_hash_id));
        memcpy(rib_entry.peer_hash_id, p_entry->hash_id, sizeof(rib_entry.peer_hash_id));

        rib_entry.rd_type = tuple.rd_type;
        rib_entry.rd_assigned_number = tuple.rd_assigned_number;
        rib_entry.rd_administrator_subfield = tuple.rd_administrator_subfield;

        strncpy(rib_entry.prefix, tuple.prefix.c_str(), sizeof(rib_entry.prefix));
        
        rib_entry.prefix_len = tuple.len;

        snprintf(rib_entry.labels, sizeof(rib_entry.labels), "%s", tuple.labels.c_str());
        
        rib_entry.isIPv4 = tuple.isIPv4 ? 1 : 0;

        memcpy(rib_entry.prefix_bin, tuple.prefix_bin, sizeof(rib_entry.prefix_bin));

        // Add the ending IP for the prefix based on bits
        if (rib_entry.isIPv4) {
            if (tuple.len < 32) {
                memcpy(&value_32bit, tuple.prefix_bin, 4);
                bgp::SWAP_BYTES(&value_32bit);

                value_32bit |= 0xFFFFFFFF >> tuple.len;
                bgp::SWAP_BYTES(&value_32bit);
                memcpy(rib_entry.prefix_bcast_bin, &value_32bit, 4);

            } else
                memcpy(rib_entry.prefix_bcast_bin, tuple.prefix_bin, sizeof(tuple.prefix_bin));

        } else {
            if (tuple.len < 128) {
                if (tuple.len >= 64) {
                    // High order bytes are left alone
                    memcpy(rib_entry.prefix_bcast_bin, tuple.prefix_bin, 8);

                    // Low order bytes are updated
                    memcpy(&value_64bit, &tuple.prefix_bin[8], 8);
                    bgp::SWAP_BYTES(&value_64bit);

                    value_64bit |= 0xFFFFFFFFFFFFFFFF >> (tuple.len - 64);
                    bgp::SWAP_BYTES(&value_64bit);
                    memcpy(&rib_entry.prefix_bcast_bin[8], &value_64bit, 8);

                } else {
                    // Low order types are all ones
                    value_64bit = 0xFFFFFFFFFFFFFFFF;
                    memcpy(&rib_entry.prefix_bcast_bin[8], &value_64bit, 8);

                    // High order bypes are updated
                    memcpy(&value_64bit, tuple.prefix_bin, 8);
                    bgp::SWAP_BYTES(&value_64bit);

                    value_64bit |= 0xFFFFFFFFFFFFFFFF >> tuple.len;
                    bgp::SWAP_BYTES(&value_64bit);
                    memcpy(rib_entry.prefix_bcast_bin, &value_64bit, 8);
                }
            } else
                memcpy(rib_entry.prefix_bcast_bin, tuple.prefix_bin, sizeof(tuple.prefix_bin));
        }

        rib_entry.path_id = tuple.path_id;
        snprintf(rib_entry.labels, sizeof(rib_entry.labels), "%s", tuple.labels.c_str());

        SELF_DEBUG("%s: %s vpn=%s len=%d", p_entry->peer_addr, remove ? "removing" : "adding",
                   rib_entry.prefix, rib_entry.prefix_len);

        // Add entry to the list
        rib_list.insert(rib_list.end(), rib_entry);
    }

    if (rib_list.size() > 0) {
        mbus_ptr->update_L3Vpn(*p_entry, rib_list, &base_attr,
                             remove ? mbus_ptr->VPN_ACTION_DEL : mbus_ptr->VPN_ACTION_ADD);
    }

    rib_list.clear();
    prefixes.clear();
}

/**
 * Updates for either advertised or withdrawn Evpn NLRI's
 *
 * \param [in] remove          True if the records should be deleted, false if they are to be added/updated
 * \param [in] nlris           Reference to the list<evpn_tuple>
 * \param [in] attrs           Reference to the parsed attributes map
 */
void parseBGP::UpdateDBeVPN(bool remove, std::list<bgp::evpn_tuple> &nlris,
                           bgp_msg::UpdateMsg::parsed_attrs_map &attrs) {

    vector<MsgBusInterface::obj_evpn> rib_list;
    MsgBusInterface::obj_evpn         rib_entry;

    /*
     * Loop through all vpn and add/update them in the DB
     */
    for (std::list<bgp::evpn_tuple>::iterator it = nlris.begin();
         it != nlris.end();
         it++) {
        bgp::evpn_tuple &tuple = (*it);

        memcpy(rib_entry.path_attr_hash_id, path_hash_id, sizeof(rib_entry.path_attr_hash_id));
        memcpy(rib_entry.peer_hash_id, p_entry->hash_id, sizeof(rib_entry.peer_hash_id));

        rib_entry.rd_type = tuple.rd_type;
        rib_entry.rd_assigned_number = tuple.rd_assigned_number;
        rib_entry.rd_administrator_subfield = tuple.rd_administrator_subfield;

        strcpy(rib_entry.ethernet_tag_id_hex, tuple.ethernet_tag_id_hex.c_str());
        rib_entry.mpls_label_1 = tuple.mpls_label_1;
        rib_entry.mac_len = tuple.mac_len;
        strcpy(rib_entry.mac, tuple.mac.c_str());
        rib_entry.ip_len = tuple.ip_len;
        strcpy(rib_entry.ip, tuple.ip.c_str());
        rib_entry.mpls_label_2 = tuple.mpls_label_2;
        rib_entry.originating_router_ip_len = tuple.originating_router_ip_len;
        strcpy(rib_entry.originating_router_ip, tuple.originating_router_ip.c_str());
        strcpy(rib_entry.ethernet_segment_identifier, tuple.ethernet_segment_identifier.c_str());


        rib_entry.path_id = tuple.path_id;

        SELF_DEBUG("%s: %s evpn mac=%s ip=%s", p_entry->peer_addr,
                   remove ? "removing" : "adding", rib_entry.mac, rib_entry.ip);

        // Add entry to the list
        rib_list.insert(rib_list.end(), rib_entry);
    }

    // Update the DB
    if (rib_list.size() > 0)
        mbus_ptr->update_eVPN(*p_entry, rib_list, &base_attr,
                              remove ? mbus_ptr->VPN_ACTION_DEL : mbus_ptr->VPN_ACTION_ADD);

    rib_list.clear();
    nlris.clear();
}


/**
 * Update the Database advertised prefixes
 *
 * \details This method will update the database for the supplied advertised prefixes
 *
 * \param  adv_prefixes         Reference to the list<prefix_tuple> of advertised prefixes
 * \param  attrs            Reference to the parsed attributes map
 */
void parseBGP::UpdateDBAdvPrefixes(std::list<bgp::prefix_tuple> &adv_prefixes,
                                   bgp_msg::UpdateMsg::parsed_attrs_map &attrs) {
    vector<MsgBusInterface::obj_rib> rib_list;
    MsgBusInterface::obj_rib         rib_entry;
    uint32_t                         value_32bit;
    uint64_t                         value_64bit;

    /*
     * Loop through all prefixes and add/update them in the DB
     */
    for (std::list<bgp::prefix_tuple>::iterator it = adv_prefixes.begin();
                                                it != adv_prefixes.end();
                                                it++) {
        bgp::prefix_tuple &tuple = (*it);

        memcpy(rib_entry.path_attr_hash_id, path_hash_id, sizeof(rib_entry.path_attr_hash_id));
        memcpy(rib_entry.peer_hash_id, p_entry->hash_id, sizeof(rib_entry.peer_hash_id));

        strncpy(rib_entry.prefix, tuple.prefix.c_str(), sizeof(rib_entry.prefix));

        rib_entry.prefix_len     = tuple.len;

        rib_entry.isIPv4 = tuple.isIPv4 ? 1 : 0;

        memcpy(rib_entry.prefix_bin, tuple.prefix_bin, sizeof(rib_entry.prefix_bin));

        // Add the ending IP for the prefix based on bits
        if (rib_entry.isIPv4) {
            if (tuple.len < 32) {
                memcpy(&value_32bit, tuple.prefix_bin, 4);
                bgp::SWAP_BYTES(&value_32bit);

                value_32bit |= 0xFFFFFFFF >> tuple.len;
                bgp::SWAP_BYTES(&value_32bit);
                memcpy(rib_entry.prefix_bcast_bin, &value_32bit, 4);

            } else
                memcpy(rib_entry.prefix_bcast_bin, tuple.prefix_bin, sizeof(tuple.prefix_bin));

        } else {
            if (tuple.len < 128) {
                if (tuple.len >= 64) {
                    // High order bytes are left alone
                    memcpy(rib_entry.prefix_bcast_bin, tuple.prefix_bin, 8);

                    // Low order bytes are updated
                    memcpy(&value_64bit, &tuple.prefix_bin[8], 8);
                    bgp::SWAP_BYTES(&value_64bit);

                    value_64bit |= 0xFFFFFFFFFFFFFFFF >> (tuple.len - 64);
                    bgp::SWAP_BYTES(&value_64bit);
                    memcpy(&rib_entry.prefix_bcast_bin[8], &value_64bit, 8);

                } else {
                    // Low order types are all ones
                    value_64bit = 0xFFFFFFFFFFFFFFFF;
                    memcpy(&rib_entry.prefix_bcast_bin[8], &value_64bit, 8);

                    // High order bypes are updated
                    memcpy(&value_64bit, tuple.prefix_bin, 8);
                    bgp::SWAP_BYTES(&value_64bit);

                    value_64bit |= 0xFFFFFFFFFFFFFFFF >> tuple.len;
                    bgp::SWAP_BYTES(&value_64bit);
                    memcpy(rib_entry.prefix_bcast_bin, &value_64bit, 8);
                }
            } else
                memcpy(rib_entry.prefix_bcast_bin, tuple.prefix_bin, sizeof(tuple.prefix_bin));
        }

        rib_entry.path_id = tuple.path_id;
        snprintf(rib_entry.labels, sizeof(rib_entry.labels), "%s", tuple.labels.c_str());

        SELF_DEBUG("%s: Adding prefix=%s len=%d", p_entry->peer_addr, rib_entry.prefix, rib_entry.prefix_len);

        // Add entry to the list
        rib_list.insert(rib_list.end(), rib_entry);
    }

    // Update the DB
    if (rib_list.size() > 0)
        mbus_ptr->update_unicastPrefix(*p_entry, rib_list, &base_attr, mbus_ptr->UNICAST_PREFIX_ACTION_ADD);

    rib_list.clear();
    adv_prefixes.clear();
}

/**
 * Update the Database withdrawn prefixes
 *
 * \details This method will update the database for the supplied advertised prefixes
 *
 * \param  wdrawn_prefixes         Reference to the list<prefix_tuple> of withdrawn prefixes
 */
void parseBGP::UpdateDBWdrawnPrefixes(std::list<bgp::prefix_tuple> &wdrawn_prefixes) {
    vector<MsgBusInterface::obj_rib> rib_list;
    MsgBusInterface::obj_rib         rib_entry;

    /*
     * Loop through all prefixes and add/update them in the DB
     */
    for (std::list<bgp::prefix_tuple>::iterator it = wdrawn_prefixes.begin();
                                                it != wdrawn_prefixes.end();
                                                it++) {

        bgp::prefix_tuple &tuple = (*it);
        memcpy(rib_entry.path_attr_hash_id, path_hash_id, sizeof(rib_entry.path_attr_hash_id));
        memcpy(rib_entry.peer_hash_id, p_entry->hash_id, sizeof(rib_entry.peer_hash_id));
        strncpy(rib_entry.prefix, tuple.prefix.c_str(), sizeof(rib_entry.prefix));

        rib_entry.prefix_len     = tuple.len;

        rib_entry.isIPv4 = tuple.isIPv4 ? 1 : 0;

        memcpy(rib_entry.prefix_bin, tuple.prefix_bin, sizeof(rib_entry.prefix_bin));

        rib_entry.path_id = tuple.path_id;
        snprintf(rib_entry.labels, sizeof(rib_entry.labels), "%s", tuple.labels.c_str());

        SELF_DEBUG("%s: Removing prefix=%s len=%d", p_entry->peer_addr, rib_entry.prefix, rib_entry.prefix_len);

        // Add entry to the list
        rib_list.insert(rib_list.end(), rib_entry);
    }

    // Update the DB
    if (rib_list.size() > 0)
        mbus_ptr->update_unicastPrefix(*p_entry, rib_list, NULL, mbus_ptr->UNICAST_PREFIX_ACTION_DEL);

    rib_list.clear();
    wdrawn_prefixes.clear();
}

/**
 * Update the Database for bgp-ls
 *
 * \details This method will update the database for the BGP-LS information
 *
 * \note    MUST BE called after adding the attributes since the path_hash_id must be set first.
 *
 * \param [in] remove      True if the records should be deleted, false if they are to be added/updated
 * \param [in] ls_data     Reference to the parsed link state nlri information
 * \param [in] ls_attrs    Reference to the parsed link state attribute information
 */
void parseBGP::UpdateDbBgpLs(bool remove, bgp_msg::UpdateMsg::parsed_data_ls ls_data,
                             bgp_msg::UpdateMsg::parsed_ls_attrs_map &ls_attrs) {
    /*
     * Update table entry with attributes based on NLRI
     */
    if (ls_data.nodes.size() > 0) {
        SELF_DEBUG("%s: Updating BGP-LS: Nodes %d", p_entry->peer_addr, ls_data.nodes.size());

        // Merge attributes to each table entry
        for (list<MsgBusInterface::obj_ls_node>::iterator it = ls_data.nodes.begin();
                it != ls_data.nodes.end(); it++) {

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_NAME) != ls_attrs.end())
                memcpy((*it).name, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_NAME].data(), sizeof((*it).name));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV4_ROUTER_ID_LOCAL) != ls_attrs.end())
                memcpy((*it).router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV4_ROUTER_ID_LOCAL].data(), 4);

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV6_ROUTER_ID_LOCAL) != ls_attrs.end()) {
                memcpy((*it).router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV6_ROUTER_ID_LOCAL].data(), 16);
                (*it).isIPv4 = false;
            }

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_MT_ID) != ls_attrs.end()) {
                strncpy((char *)&(*it).mt_id, (char *)ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_MT_ID].data(),
                       strlen((char *)ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_MT_ID].data()) + 1);
            }

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_FLAG) != ls_attrs.end())
                memcpy((*it).flags, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_FLAG].data(), sizeof((*it).flags));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_ISIS_AREA_ID) != ls_attrs.end())
                memcpy((*it).isis_area_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_ISIS_AREA_ID].data(), sizeof((*it).isis_area_id));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_SR_CAPABILITIES) != ls_attrs.end()) {
                memcpy((*it).sr_capabilities_tlv, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_SR_CAPABILITIES].data(), sizeof((*it).sr_capabilities_tlv));
            }
        }

        if (remove)
            mbus_ptr->update_LsNode(*p_entry, base_attr, ls_data.nodes, mbus_ptr->LS_ACTION_DEL);
        else
            mbus_ptr->update_LsNode(*p_entry, base_attr, ls_data.nodes, mbus_ptr->LS_ACTION_ADD);
    }

    if (ls_data.links.size() > 0) {
        SELF_DEBUG("%s: Updating BGP-LS: Links %d ", p_entry->peer_addr, ls_data.links.size());

        // Merge attributes to each table entry
        for (list<MsgBusInterface::obj_ls_link>::iterator it = ls_data.links.begin();
             it != ls_data.links.end(); it++) {

            if (not (*it).isIPv4 and ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV6_ROUTER_ID_LOCAL) != ls_attrs.end())
                memcpy((*it).router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV6_ROUTER_ID_LOCAL].data(), 16);

            else if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV4_ROUTER_ID_LOCAL) != ls_attrs.end()) {
                memcpy((*it).router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV4_ROUTER_ID_LOCAL].data(), 4);
                (*it).isIPv4 = true;
            }

            if (not (*it).isIPv4 and ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_IPV6_ROUTER_ID_REMOTE) != ls_attrs.end())
                memcpy((*it).remote_router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_IPV6_ROUTER_ID_REMOTE].data(), 16);

            else if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_IPV4_ROUTER_ID_REMOTE) != ls_attrs.end()) {
                memcpy((*it).remote_router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_IPV4_ROUTER_ID_REMOTE].data(), 4);
                //(*it).isIPv4 = true; // only set for local rid
            }


            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_ISIS_AREA_ID) != ls_attrs.end())
                memcpy((*it).isis_area_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_ISIS_AREA_ID].data(), sizeof((*it).isis_area_id));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_ADMIN_GROUP) != ls_attrs.end())
                memcpy(&(*it).admin_group, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_ADMIN_GROUP].data(), sizeof((*it).admin_group));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_MAX_LINK_BW) != ls_attrs.end())
                memcpy(&(*it).max_link_bw, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_MAX_LINK_BW].data(),
                       sizeof((*it).max_link_bw));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_MAX_RESV_BW) != ls_attrs.end())
                memcpy(&(*it).max_resv_bw, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_MAX_RESV_BW].data(), sizeof((*it).max_resv_bw));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_UNRESV_BW) != ls_attrs.end())
                memcpy(&(*it).unreserved_bw, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_UNRESV_BW].data(), sizeof((*it).unreserved_bw));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_TE_DEF_METRIC) != ls_attrs.end())
                memcpy(&(*it).te_def_metric, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_TE_DEF_METRIC].data(), sizeof((*it).te_def_metric));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_PROTECTION_TYPE) != ls_attrs.end())
                memcpy((*it).protection_type, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_PROTECTION_TYPE].data(), sizeof((*it).protection_type));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_MPLS_PROTO_MASK) != ls_attrs.end())
                memcpy((*it).mpls_proto_mask, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_MPLS_PROTO_MASK].data(), sizeof((*it).mpls_proto_mask));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_IGP_METRIC) != ls_attrs.end())
                memcpy(&(*it).igp_metric, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_IGP_METRIC].data(), sizeof((*it).igp_metric));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_SRLG) != ls_attrs.end())
                memcpy((*it).srlg, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_SRLG].data(), sizeof((*it).srlg));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_NAME) != ls_attrs.end())
                memcpy((*it).name, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_NAME].data(), sizeof((*it).name));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_PEER_EPE_NODE_SID) != ls_attrs.end())
                memcpy((*it).peer_node_sid, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_PEER_EPE_NODE_SID].data(), sizeof((*it).peer_node_sid));
                
            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_LINK_ADJACENCY_SID) != ls_attrs.end())
                memcpy((*it).peer_adj_sid, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_LINK_ADJACENCY_SID].data(), sizeof((*it).peer_adj_sid));
        }

        if (remove)
            mbus_ptr->update_LsLink(*p_entry, base_attr, ls_data.links, mbus_ptr->LS_ACTION_DEL);
        else
            mbus_ptr->update_LsLink(*p_entry, base_attr, ls_data.links, mbus_ptr->LS_ACTION_ADD);
    }

    if (ls_data.prefixes.size() > 0) {
        SELF_DEBUG("%s: Updating BGP-LS: Prefixes %d ", p_entry->peer_addr, ls_data.prefixes.size());

        // Merge attributes to each table entry
        for (list<MsgBusInterface::obj_ls_prefix>::iterator it = ls_data.prefixes.begin();
             it != ls_data.prefixes.end(); it++) {

            if (not (*it).isIPv4 and ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV6_ROUTER_ID_LOCAL) != ls_attrs.end())
                memcpy((*it).router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV6_ROUTER_ID_LOCAL].data(), 16);

            else if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV4_ROUTER_ID_LOCAL) != ls_attrs.end()) {
                memcpy((*it).router_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_IPV4_ROUTER_ID_LOCAL].data(), 4);
                (*it).isIPv4 = true;
            }

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_NODE_ISIS_AREA_ID) != ls_attrs.end())
                memcpy((*it).isis_area_id, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_NODE_ISIS_AREA_ID].data(), sizeof((*it).isis_area_id));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_PREFIX_IGP_FLAGS) != ls_attrs.end())
                memcpy((*it).igp_flags, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_PREFIX_IGP_FLAGS].data(), sizeof((*it).igp_flags));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_PREFIX_ROUTE_TAG) != ls_attrs.end())
                memcpy(&(*it).route_tag, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_PREFIX_ROUTE_TAG].data(), sizeof((*it).route_tag));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_PREFIX_EXTEND_TAG) != ls_attrs.end())
                memcpy(&(*it).ext_route_tag, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_PREFIX_EXTEND_TAG].data(), sizeof((*it).ext_route_tag));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_PREFIX_PREFIX_METRIC) != ls_attrs.end())
                memcpy(&(*it).metric, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_PREFIX_PREFIX_METRIC].data(), sizeof((*it).metric));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_PREFIX_OSPF_FWD_ADDR) != ls_attrs.end())
                memcpy((*it).ospf_fwd_addr, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_PREFIX_OSPF_FWD_ADDR].data(), sizeof((*it).ospf_fwd_addr));

            if (ls_attrs.find(bgp_msg::MPLinkStateAttr::ATTR_PREFIX_SID) != ls_attrs.end())
                memcpy((*it).sid_tlv, ls_attrs[bgp_msg::MPLinkStateAttr::ATTR_PREFIX_SID].data(), sizeof((*it).sid_tlv));
        }

        if (remove)
            mbus_ptr->update_LsPrefix(*p_entry, base_attr, ls_data.prefixes, mbus_ptr->LS_ACTION_DEL);
        else
            mbus_ptr->update_LsPrefix(*p_entry, base_attr, ls_data.prefixes, mbus_ptr->LS_ACTION_ADD);
    }

    // Data stored, no longer needed, purge it
    ls_attrs.clear();
    ls_data.prefixes.clear();
    ls_data.links.clear();
    ls_data.nodes.clear();
}


void parseBGP::enableDebug() {
    debug = true;
}

void parseBGP::disableDebug() {
    debug = false;
}
