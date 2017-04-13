/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parseMRT.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/bgp_common.h"

// Wrapper for parseMRT
parseMRT parseMRTwrapper(unsigned char *buffer, int bufLen) {
    parseMRT pMRT;
    pMRT.parseMsg(buffer, bufLen);
    return pMRT;
}

/**
 * Constructor for class
 *
 * \note
 *  This class will allocate via 'new' the bgp_peers variables
 *        as needed.  The calling method/class/function should check each var
 *        in the structure for non-NULL pointers.  Non-NULL pointers need to be
 *        freed with 'delete'
 *
 * \param [in]     logPtr      Pointer to existing Logger for app logging
 * \param [in,out] peer_entry  Pointer to the peer entry
 */
parseMRT::parseMRT() {
    mrt_len = 0;
    mrt_data_len = 0;
}

/*
 * Destructor for class
 */
parseMRT::~parseMRT() {
    // clean up
}

bool parseMRT::parseMsg(u_char *&buffer, int& bufLen)
{
    //bool rval = true;
    uint16_t mrt_type = 0;

    try {
        mrt_type = parseCommonHeader(buffer, bufLen);

        switch (mrt_type) {
            case MRT_TYPE::OSPFv2 :     //do nothing
            case MRT_TYPE::OSPFv3 :     //do nothing
            case MRT_TYPE::OSPFv3_ET : { //do nothing
                break;
            }

            case MRT_TYPE::TABLE_DUMP : {
                bufferMRTMessage(buffer, bufLen);
                parseTableDump(mrt_data, mrt_data_len);
                break;
            }

            case MRT_TYPE::TABLE_DUMP_V2 : {
                bufferMRTMessage(buffer, bufLen);
                parseTableDump_V2(mrt_data, mrt_data_len);
                break;
            }

            case MRT_TYPE::BGP4MP :
            case MRT_TYPE::BGP4MP_ET : {
                bufferMRTMessage(buffer, bufLen);
                parseBGP4MP(mrt_data, mrt_data_len);
                break;
            }

            case MRT_TYPE::ISIS :
            case MRT_TYPE::ISIS_ET : {
                break;  //do nothing
            }
            default: {
                throw "MRT type is unexpected as per rfc6396";
            }
        }

    } catch (char const *str) {
        throw str;
    }

    return true;
}

void parseMRT::parseTableDump(u_char *buffer, int& bufLen)
{
    string peer_info_key;
    u_char local_addr[16];
    if (extractFromBuffer(buffer, bufLen, &table_dump.view_number, 2) != 2)
        throw "Error in parsing view number";
    if (extractFromBuffer(buffer, bufLen, &table_dump.sequence, 2) != 2)
        throw "Error in parsing sequence";

    //parsing prefix in local address variable
    if ( extractFromBuffer(buffer, bufLen, &local_addr, 16) != 16)
        throw "Error in parsing prefix in IPv4";

    switch (c_hdr.subType) {
        case AFI_IPv4:{
            snprintf(table_dump.prefix, sizeof(table_dump.prefix), "%d.%d.%d.%d",
                         local_addr[12], local_addr[13], local_addr[14],
                         local_addr[15]);
            break;
        }
        case AFI_IPv6:{
            inet_ntop(AF_INET6, local_addr, table_dump.prefix, sizeof(table_dump.prefix));
            break;
        }
        default: {
            throw "Address family is unexpected as per rfc6396";
        }
    }
    if (extractFromBuffer(buffer, bufLen, &table_dump.prefix_len, 1) != 1)
        throw "Error in parsing prefix length";

    if (extractFromBuffer(buffer, bufLen, &table_dump.status, 1) != 1)
        throw "Error in parsing status";

    if (extractFromBuffer(buffer, bufLen, &table_dump.originated_time, 4) != 4)
        throw "Error in parsing originated time";

    //parsing prefix in local address variable
    if ( extractFromBuffer(buffer, bufLen, &local_addr, 16) != 16)
        throw "Error in parsing prefix in IPv4";

    switch (c_hdr.subType) {
        case AFI_IPv4:{
            snprintf(table_dump.peer_IP, sizeof(table_dump.peer_IP), "%d.%d.%d.%d",
                     local_addr[12], local_addr[13], local_addr[14],
                     local_addr[15]);
            break;
        }
        case AFI_IPv6:{
            inet_ntop(AF_INET6, local_addr, table_dump.peer_IP, sizeof(table_dump.peer_IP));
            break;
        }
        default: {
            throw "Address family is unexpected as per rfc6396";
        }
    }

    if (extractFromBuffer(buffer, bufLen, &table_dump.peerAS, 2) != 2)
        throw "Error in parsing peer AS";

    if (extractFromBuffer(buffer, bufLen, &table_dump.attribute_len, 2) != 2)
        throw "Error in parsing attribute length";

    if (extractFromBuffer(buffer, bufLen, &table_dump.bgp_attribute, table_dump.attribute_len) != table_dump.attribute_len)
        throw "Error in parsing attribute";

    peer_info_key =  bgp4mp_msg.peer_IP;
    bgp_msg::UpdateMsg * uMsg = new bgp_msg::UpdateMsg(table_dump.peer_IP, &peer_info_map[peer_info_key]);
    uMsg->parseAttributes(table_dump.bgp_attribute, table_dump.attribute_len, bgpMsg.parsed_data, bgpMsg.hasEndOfRIBMarker);
            //LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr, router_addr.c_str(), read_size, (size - read_size));
    //parseBgpAttributes(buffer, bufLen); TO DO
    delete uMsg;
}

void parseMRT::parseTableDump_V2(u_char *buffer, int& bufLen) {
    switch (c_hdr.subType) {
        case PEER_INDEX_TABLE:
            parsePeerIndexTable(buffer,bufLen);
            break;

        case RIB_IPV4_UNICAST:
            parseRIB_UNICAST(buffer,bufLen);
            break;
        case RIB_IPV6_UNICAST:
            parseRIB_UNICAST(buffer,bufLen);
            break;

        case RIB_IPV4_MULTICAST: //TO DO: due to lack of multicast data
        case RIB_IPV6_MULTICAST: //TO DO: due to lack of multicast data
        case RIB_GENERIC:
            parseRIB_GENERIC(buffer,bufLen);
            break;
    }
}

void parseMRT::parsePeerIndexTable(unsigned char *buffer, int& bufLen)
{
    uint16_t count = 0;
    uint8_t  AS_num;
    uint8_t  Addr_fam;

    if (extractFromBuffer(buffer, bufLen, &peerIndexTable.collector_BGPID, 4) != 4)
        throw "Error in parsing collector_BGPID";

    if (extractFromBuffer(buffer, bufLen, &peerIndexTable.view_name_length, 2) != 2)
        throw "Error in parsing view_name_length";

    if (peerIndexTable.view_name_length) {
        if (extractFromBuffer(buffer, bufLen, &peerIndexTable.view_name, peerIndexTable.view_name_length) !=
            peerIndexTable.view_name_length)
            throw "Error in parsing view_name";
    }

    if (extractFromBuffer(buffer, bufLen, &peerIndexTable.peer_count, 2) != 2)
        throw "Error in parsing peer count";

    bgp::SWAP_BYTES(&peerIndexTable.peer_count);

    while (count < peerIndexTable.peer_count) {
        peer_entry *p_entry = new peer_entry;
        if (extractFromBuffer(buffer, bufLen, &p_entry->peer_type, 1) != 1)
            throw "Error in parsing collector_BGPID";

        AS_num = p_entry->peer_type & 0x02 ? 4 : 2; //using 32 bits and 16 bits.
        Addr_fam = p_entry->peer_type & 0x01 ? AFI_IPv6:AFI_IPv4;

        if ( extractFromBuffer(buffer, bufLen, &p_entry->peer_BGPID, 4) != 4)
            throw "Error in parsing local address in peer_BGPID";

        switch (Addr_fam) {
            case AFI_IPv4:{
                u_char local_addr[4];
                if ( extractFromBuffer(buffer, bufLen, &local_addr, 4) != 4)
                    throw "Error in parsing local address in IPv4";
//                inet_ntop(AF_INET, local_addr, p_entry->peer_IP, sizeof(local_addr));
                snprintf(p_entry->peer_IP, sizeof(p_entry->peer_IP), "%d.%d.%d.%d",
                         local_addr[0], local_addr[1], local_addr[2],
                         local_addr[3]);
                break;
            }
            case AFI_IPv6:{
                u_char local_addr[6];
                if ( extractFromBuffer(buffer, bufLen, &local_addr, 6) != 6)
                    throw "Error in parsing local address in IPv4";
                inet_ntop(AF_INET6, local_addr, p_entry->peer_IP, sizeof(local_addr));
                break;
            }
            default: {
                throw "Address family is unexpected as per rfc6396";
            }
        }
        if ( extractFromBuffer(buffer, bufLen, &p_entry->peerAS32, AS_num) != AS_num)
            throw "Error in parsing local address in IPv4";

        peerIndexTable.peerEntries.push_back(*p_entry);
        delete p_entry;
        count++;
    }
}

void parseMRT::parseRIB_UNICAST(unsigned char *buffer, int& bufLen)
{
    uint16_t count = 0;
    string peer_info_key;

    if (extractFromBuffer(buffer, bufLen, &ribEntryHeader.sequence_number, 4) != 4)
        throw "Error in parsing sequence number";

    bgp::SWAP_BYTES(&ribEntryHeader.sequence_number);

    if (extractFromBuffer(buffer, bufLen, &ribEntryHeader.prefix_length, 1) != 1)
        throw "Error in parsing view_name_length";

    u_char local_addr[ribEntryHeader.prefix_length/8];

    if (extractFromBuffer(buffer, bufLen, &local_addr, ribEntryHeader.prefix_length/8) != ribEntryHeader.prefix_length/8)
        throw "Error in parsing prefix";

    switch (c_hdr.subType) {
        case RIB_IPV4_UNICAST:
            inet_ntop(AF_INET, local_addr, ribEntryHeader.prefix, sizeof(ribEntryHeader.prefix));
            break;
        case RIB_IPV6_UNICAST:
            inet_ntop(AF_INET6, local_addr, ribEntryHeader.prefix, sizeof(ribEntryHeader.prefix));
            break;
    }
    if (extractFromBuffer(buffer, bufLen, &ribEntryHeader.entry_count, 2) != 2)
        throw "Error in parsing peer count";

    bgp::SWAP_BYTES(&ribEntryHeader.entry_count);

    while (count < ribEntryHeader.entry_count) {
        RIB_entry *r_entry = new RIB_entry;
        if (extractFromBuffer(buffer, bufLen, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        bgp::SWAP_BYTES(&r_entry->peer_index);

        if ( extractFromBuffer(buffer, bufLen, &r_entry->originatedTime, 4) != 4)
            throw "Error in parsing originatedTime";

        bgp::SWAP_BYTES(&r_entry->originatedTime);

        if ( extractFromBuffer(buffer, bufLen, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing attribute_len";

        bgp::SWAP_BYTES(&r_entry->attribute_len);

//        if ( extractFromBuffer(buffer, bufLen, &r_entry->bgp_attribute, r_entry->attribute_len) != r_entry->attribute_len)
//            throw "Error in parsing bgp_attribute";

        peer_info_key =  bgp4mp_msg.peer_IP;
        bgp_msg::UpdateMsg *uMsg= new bgp_msg::UpdateMsg(table_dump.peer_IP, &peer_info_map[peer_info_key]);
        uMsg->parseAttributes(buffer, r_entry->attribute_len, r_entry->parsed_data, r_entry->endOfRIBMarker);
        //LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr, router_addr.c_str(), read_size, (size - read_size));

        ribEntryHeader.RIB_entries.push_back(*r_entry);
        delete uMsg;
        delete r_entry;
        count++;
    }
}

void parseMRT::parseRIB_GENERIC(unsigned char *buffer, int& bufLen)
{
    uint16_t count = 0;
    uint8_t  IPlen;
    u_char* local_addr;
    string peer_info_key;

    if (extractFromBuffer(buffer, bufLen, &ribGenericEntryHeader.sequence_number, 4) != 4)
        throw "Error in parsing sequence number";

    if (extractFromBuffer(buffer, bufLen, &ribGenericEntryHeader.address_family_identifier, 2) != 2)
        throw "Error in parsing address_family_identifier";

    if (extractFromBuffer(buffer, bufLen, &ribGenericEntryHeader.subsequentAFI, 1) != 1)
        throw "Error in subsequent AFI";
    switch (c_hdr.subType) {
        case RIB_IPV4_UNICAST:
            inet_ntop(AF_INET, local_addr, ribEntryHeader.prefix, sizeof(ribEntryHeader.prefix));
            break;
        case RIB_IPV6_UNICAST:
            inet_ntop(AF_INET6, local_addr, ribEntryHeader.prefix, sizeof(ribEntryHeader.prefix));
            break;
    }
    if (extractFromBuffer(buffer, bufLen, &ribEntryHeader.entry_count, 2) != 2)
        throw "Error in parsing peer count";

    while (count < peerIndexTable.peer_count) {
        RIB_entry *r_entry;
        if (extractFromBuffer(buffer, bufLen, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        if ( extractFromBuffer(buffer, bufLen, &r_entry->originatedTime, 4) != 4)
            throw "Error in parsing local address in IPv4";

        if ( extractFromBuffer(buffer, bufLen, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing local address in IPv4";

        if ( extractFromBuffer(buffer, bufLen, &r_entry->parsed_data, r_entry->attribute_len) != r_entry->attribute_len)
            throw "Error in parsing local address in IPv4";

        peer_info_key =  bgp4mp_msg.peer_IP;
        bgp_msg::UpdateMsg * uMsg = new bgp_msg::UpdateMsg(table_dump.peer_IP, &peer_info_map[peer_info_key]);
        uMsg->parseAttributes(table_dump.bgp_attribute, table_dump.attribute_len, bgpMsg.parsed_data, bgpMsg.hasEndOfRIBMarker);
        //LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr, router_addr.c_str(), read_size, (size - read_size));

        ribEntryHeader.RIB_entries.push_back(*r_entry);
        delete uMsg;
        delete r_entry;
        count++;
    }
}

void parseMRT::parseBGP4MP(unsigned char* buffer, int& bufLen) {
    string peer_info_key;
    /*switch (c_hdr.subType) {
        case BGP4MP_STATE_CHANGE: {
            //parseBGP4MPaux(&bgp_state_change, buffer, bufLen, false, true);
            break;
        }
        case BGP4MP_MESSAGE: {
            parseBGP4MPaux(&bgp4mp_msg, buffer, bufLen, false, false);
            peer_info_key =  bgp4mp_msg.peer_IP;
            //peer_info_key += p_entry.peer_rd;
            pBGP = new parseBGP(bgp4mp_msg.peer_IP, bgp4mp_msg.peer_AS_number, (bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            //pBGP->parseBgpHeader(mrt_data, mrt_data_len, pBGP->bgpMsg->common_hdr);
            break;
        }
        case BGP4MP_MESSAGE_AS4: {
//            parseBGP4MPaux(&bgp4mp_msg_as4, buffer, bufLen, true, false);
//            peer_info_key =  bgp4mp_msg_as4.peer_IP;
//            //peer_info_key += p_entry.peer_rd;
//            pBGP = new parseBGP(bgp4mp_msg_as4.peer_IP, bgp4mp_msg_as4.peer_AS_number, (bgp4mp_msg_as4.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            parseBGP4MPaux(&bgp4mp_msg, buffer, bufLen, true, false);
            peer_info_key =  bgp4mp_msg.peer_IP;
            pBGP = new parseBGP(bgp4mp_msg.peer_IP, bgp4mp_msg.peer_AS_number, (bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        case BGP4MP_STATE_CHANGE_AS4: {
            //parseBGP4MPaux(&bgp_state_change_as4, buffer, bufLen, true, true);
            break;
        }
        case BGP4MP_MESSAGE_LOCAL: {
//            parseBGP4MPaux(&bgp4mp_msg_local, buffer, bufLen, false, false);
//            peer_info_key =  bgp4mp_msg_local.peer_IP;
//            //peer_info_key += p_entry.peer_rd;
//            pBGP = new parseBGP(bgp4mp_msg_local.peer_IP, bgp4mp_msg_local.peer_AS_number, (bgp4mp_msg_local.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            parseBGP4MPaux(&bgp4mp_msg, buffer, bufLen, true, false);
            peer_info_key =  bgp4mp_msg.peer_IP;
            pBGP = new parseBGP(bgp4mp_msg.peer_IP, bgp4mp_msg.peer_AS_number, (bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        case BGP4MP_MESSAGE_AS4_LOCAL: {
//            parseBGP4MPaux(&bgp4mp_msg_as4_local, buffer, bufLen, true, false);
//            peer_info_key =  bgp4mp_msg_as4_local.peer_IP;
//            //peer_info_key += p_entry.peer_rd;
//            pBGP = new parseBGP(bgp4mp_msg_as4_local.peer_IP, bgp4mp_msg_as4_local.peer_AS_number, (bgp4mp_msg_as4_local.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            parseBGP4MPaux(&bgp4mp_msg, buffer, bufLen, true, false);
            peer_info_key =  bgp4mp_msg.peer_IP;
            pBGP = new parseBGP(bgp4mp_msg.peer_IP, bgp4mp_msg.peer_AS_number, (bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        default: {
            throw "Subtype for BGP4MP not supported";
        }
    }*/

    switch (c_hdr.subType) {
        case BGP4MP_STATE_CHANGE:
        case BGP4MP_STATE_CHANGE_AS4: {
            int asn_len = (c_hdr.subType == BGP4MP_STATE_CHANGE_AS4) ? 8 : 4;
            int ip_addr_len = 4;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change, asn_len) != asn_len)  // ASNs
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change.interface_index, 2) != 2)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change.address_family, 2) != 2)
                throw;
            if (bgp_state_change.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change.peer_IP, ip_addr_len) != ip_addr_len)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change.local_IP, ip_addr_len) != ip_addr_len)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change.old_state, 2) != 2)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp_state_change.new_state, 2) != 2)
                throw;
            break;
        }
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4:
        case BGP4MP_MESSAGE_LOCAL:
        case BGP4MP_MESSAGE_AS4_LOCAL: {
            int asn_len = (c_hdr.subType == BGP4MP_MESSAGE_AS4 || c_hdr.subType == BGP4MP_MESSAGE_AS4_LOCAL) ? 8 : 4;
            int ip_addr_len = 4;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg, asn_len) != asn_len) //ASNs
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.interface_index, 2) != 2)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.address_family, 2) != 2)
                throw;
            bgp::SWAP_BYTES(&bgp4mp_msg.peer_AS_number);
            bgp::SWAP_BYTES(&bgp4mp_msg.local_AS_number);
            bgp::SWAP_BYTES(&bgp4mp_msg.interface_index);
            bgp::SWAP_BYTES(&bgp4mp_msg.address_family);
            if (bgp4mp_msg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.peer_IP, ip_addr_len) != ip_addr_len)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.local_IP, ip_addr_len) != ip_addr_len)
                throw;
            /*int bgp_msg_len = mrt_data_len;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.BGP_message, mrt_data_len) != bgp_msg_len)
                throw;*/
            if (mrt_data_len != bufLen)
                throw;
            memcpy(&bgp4mp_msg.BGP_message, buffer, mrt_data_len);

            peer_info_key =  bgp4mp_msg.peer_IP;

            parseBMP::obj_bgp_peer p_entry;
            bzero(&p_entry, sizeof(parseBMP::obj_bgp_peer));
            memcpy(&p_entry.peer_addr, bgp4mp_msg.peer_IP, sizeof(p_entry.peer_addr));
            p_entry.isIPv4 = (bgp4mp_msg.address_family == AFI_IPv4);
            p_entry.peer_as = bgp4mp_msg.peer_AS_number;
            p_entry.timestamp_secs = c_hdr.timeStamp;
            p_entry.timestamp_us = c_hdr.microsecond_timestamp;

            pBGP = new parseBGP(&p_entry, "", &peer_info_map[peer_info_key]);
            uint32_t asn = (c_hdr.subType > 5) ? bgp4mp_msg.local_AS_number : bgp4mp_msg.peer_AS_number;
            if (pBGP->parseBGPfromMRT(buffer, mrt_data_len, &bgpMsg, &up_event, &down_event, asn, c_hdr.subType > 5) == parseBGP::BGP_MSG_OPEN) {
                up_event.local_asn = bgp4mp_msg.local_AS_number;
                up_event.remote_asn = bgp4mp_msg.peer_AS_number;
                memcpy(&up_event.local_ip, bgp4mp_msg.local_IP, 40);
            }
            break;
        }
        default: {
            throw "Subtype for BGP4MP not supported";
        }
    }
}

/**
 * Process the incoming MRT message header
 *
 * \returns
 *      returns the MRT message type. A type of >= 0 is normal,
 *      < 0 indicates an error
 *
 * //throws (const  char *) on error.   String will detail error message.
 */

uint16_t parseMRT::parseCommonHeader(u_char *& buffer, int& bufLen) {

//    if (extractFromBuffer(buffer, bufLen, &c_hdr.timeStamp, 4) != 4)
//        throw "Error in parsing MRT common header: timestamp";
//    if (extractFromBuffer(buffer, bufLen, &c_hdr.type, 2) != 2)
//        throw "Error in parsing MRT Common header: type";
//    if (extractFromBuffer(buffer, bufLen, &c_hdr.subType, 2) != 2)
//        throw "Error in parsing MRT common header: subtype";
//    if (extractFromBuffer(buffer, bufLen, &c_hdr.len, 4) != 4)
//        throw "Error in parsing MRT Common header: length";

    if (extractFromBuffer(buffer, bufLen, &c_hdr, 12) != 12)
        throw "Error in parsing MRT common header";

    bgp::SWAP_BYTES(&c_hdr.len);
    bgp::SWAP_BYTES(&c_hdr.type);
    bgp::SWAP_BYTES(&c_hdr.subType);
    bgp::SWAP_BYTES(&c_hdr.timeStamp);

    mrt_len = c_hdr.len;
    if (c_hdr.type == MRT_TYPE::BGP4MP_ET || c_hdr.type == MRT_TYPE::ISIS_ET || c_hdr.type == MRT_TYPE::OSPFv3_ET) {
        if (extractFromBuffer(buffer, bufLen, &c_hdr.microsecond_timestamp, 4) != 4)
            throw "Error in parsing MRT Common header: microsecond timestamp";
        bgp::SWAP_BYTES(&c_hdr.microsecond_timestamp);
        mrt_len -= 4;
    }
    else
        c_hdr.microsecond_timestamp = 0;

    return c_hdr.type;
}

/**
 * get current MRT message type
 */
char parseMRT::getMRTType() {
    return mrt_type;
}

/**
 * get current MRT message length
 *
 * The length returned does not include the common header length
 */
uint32_t parseMRT::getMRTLength() {
    return mrt_len;
}

/**
 * Buffer remaining BMP message
 *
 * \details This method will read the remaining amount of BMP data and store it in the instance variable bmp_data.
 *          Normally this is used to store the BGP message so that it can be parsed.
 *
 * \param [in]  sock       Socket to read the message from
 *
 * \returns true if successfully parsed the bmp peer down header, false otherwise
 *
 * \throws String error
 */
void parseMRT::bufferMRTMessage(u_char *& buffer, int& bufLen) {
    if (mrt_len <= 0)
        return;

    if (mrt_len > sizeof(mrt_data)) {
        throw "MRT message length is too large for buffer, invalid MRT sender";
    }

    if ((mrt_data_len=extractFromBuffer(buffer, bufLen, mrt_data, mrt_len)) != mrt_len) { ;
        throw "Error while reading MRT data from buffer";
    }

    // Indicate no more data is left to read
    mrt_len = 0;
}

int main() {
    /*u_char temp[] = {0x58, 0xb6, 0x12, 0x84, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0xe4, 0x8f,
            0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x00, 0x01, 0x67, 0xf7, 0x03, 0x2d, 0x80, 0xdf, 0x33, 0x66,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x43, 0x02, 0x00, 0x04, 0x18, 0xa8, 0xb5, 0x24, 0x00, 0x24, 0x40, 0x01, 0x01, 0x00, 0x40,
            0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0xe4, 0x8f, 0x00, 0x00, 0x1b, 0x1b, 0x00, 0x04, 0x01, 0xbd,
            0x00, 0x00, 0x6e, 0xb7, 0x00, 0x04, 0x05, 0x73, 0x40, 0x03, 0x04, 0x67, 0xf7, 0x03, 0x2d, 0x18,
            0xbf, 0x05, 0xaa};*/
    u_char temp[] = {0x58, 0x67, 0xb5, 0x31, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x07, 0x2c,
                     0x00, 0x00, 0x31, 0x6e, 0x00, 0x00, 0x00, 0x02, 0x2a, 0x01, 0x02, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x06, 0x7c, 0x02, 0xe8, 0x00, 0x02, 0xff, 0xff,
                     0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04};
    u_char *tmp;
    tmp = temp;
    parseMRT *p = new parseMRT();
    int len = 99;
    try {
        if (p->parseMsg(tmp, len))
            cout << "Hello Ojas and Induja"<<endl;
        else
            cout << "Oh no!"<<endl;
    }
    catch (char const *str) {
        cout << "Crashed!" << str<<endl;
    }
   cout<<"Peer Address "<<int(p->peerIndexTable.peerEntries.begin()->peer_type);
//    cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
//    cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
    return 1;
}