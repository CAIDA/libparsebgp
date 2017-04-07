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
#include "../../src/include/bgp_common.h"

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
/*    bzero(&bgp_state_change, sizeof(bgp_state_change));
    bzero(&bgp_state_change_as4, sizeof(bgp_state_change_as4));
    bzero(&bgp4mp_msg, sizeof(bgp4mp_msg));
    bzero(&bgp4mp_msg_as4, sizeof(bgp4mp_msg_as4));
    bzero(&bgp4mp_msg_local, sizeof(bgp4mp_msg_local));
    bzero(&bgp4mp_msg_as4_local, sizeof(bgp4mp_msg_as4_local));*/
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
                parseBGP4MP(buffer, bufLen);
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

    if (!peerIndexTable.view_name_length) {
        if (extractFromBuffer(buffer, bufLen, &peerIndexTable.view_name, peerIndexTable.view_name_length) !=
            peerIndexTable.view_name_length)
            throw "Error in parsing view_name";
    }

    if (extractFromBuffer(buffer, bufLen, &peerIndexTable.peer_count, 2) != 2)
        throw "Error in parsing peer count";

    bgp::SWAP_BYTES(&peerIndexTable.peer_count);
    u_char local_addr[4];

    while (count < peerIndexTable.peer_count) {
        peer_entry *p_entry = new peer_entry;
        if (extractFromBuffer(buffer, bufLen, &p_entry->peer_type, 1) != 1)
            throw "Error in parsing collector_BGPID";

        AS_num = p_entry->peer_type & 0x16 ? 4 : 2; //using 32 bits and 16 bits.
        Addr_fam = p_entry->peer_type & 0x01 ? AFI_IPv6:AFI_IPv4;

        if ( extractFromBuffer(buffer, bufLen, &local_addr, 4) != 4)
            throw "Error in parsing local address in IPv4";

        switch (Addr_fam) {
            case AFI_IPv4:{
                snprintf(p_entry->peer_IP, sizeof(p_entry->peer_IP), "%d.%d.%d.%d",
                         local_addr[0], local_addr[1], local_addr[2],
                         local_addr[3]);
                break;
            }
            case AFI_IPv6:{
                inet_ntop(AF_INET6, local_addr, p_entry->peer_IP, sizeof(p_entry->peer_IP));
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
    uint8_t  IPlen;
    u_char* local_addr;
    string peer_info_key;
    int read_size;

    if (extractFromBuffer(buffer, bufLen, &ribEntryHeader.sequence_number, 4) != 4)
        throw "Error in parsing sequence number";

    if (extractFromBuffer(buffer, bufLen, &ribEntryHeader.prefix_length, 1) != 1)
        throw "Error in parsing view_name_length";

    if (extractFromBuffer(buffer, bufLen, &local_addr, ribEntryHeader.prefix_length) != ribEntryHeader.prefix_length)
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

    while (count < peerIndexTable.peer_count) {
        RIB_entry *r_entry;
        if (extractFromBuffer(buffer, bufLen, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        if ( extractFromBuffer(buffer, bufLen, &r_entry->originatedTime, 4) != 4)
            throw "Error in parsing local address in IPv4";

        if ( extractFromBuffer(buffer, bufLen, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing local address in IPv4";

        if ( extractFromBuffer(buffer, bufLen, &r_entry->bgp_attribute, r_entry->attribute_len) != r_entry->attribute_len)
            throw "Error in parsing local address in IPv4";

        peer_info_key =  bgp4mp_msg.peer_IP;
        bgp_msg::UpdateMsg *uMsg= new bgp_msg::UpdateMsg(table_dump.peer_IP, &peer_info_map[peer_info_key]);
        uMsg->parseAttributes(table_dump.bgp_attribute, table_dump.attribute_len, bgpMsg.parsed_data, bgpMsg.hasEndOfRIBMarker);
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

        if ( extractFromBuffer(buffer, bufLen, &r_entry->bgp_attribute, r_entry->attribute_len) != r_entry->attribute_len)
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
    //bufferMRTMessage(buffer, bufLen);
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
            if (bgp4mp_msg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.peer_IP, ip_addr_len) != ip_addr_len)
                throw;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.local_IP, ip_addr_len) != ip_addr_len)
                throw;
            int bgp_msg_len = mrt_data_len - asn_len - 2 * ip_addr_len;
            if (extractFromBuffer(buffer, bufLen, &bgp4mp_msg.BGP_message, bgp_msg_len) != bgp_msg_len)
                throw;
            peer_info_key =  bgp4mp_msg.peer_IP;

            pBGP = new parseBGP(bgp4mp_msg.peer_IP, bgp4mp_msg.peer_AS_number, (bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            uint32_t asn = (c_hdr.subType > 5) ? bgp4mp_msg.local_AS_number : bgp4mp_msg.peer_AS_number;
            if (pBGP->parseBGPfromMRT(mrt_data, mrt_data_len, &bgpMsg, &up_event, asn, c_hdr.subType > 5) == parseBGP::BGP_MSG_OPEN) {
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

/*void parseMRT::parseBGP4MPaux(void *bgp4mp, u_char *buffer, int bufLen, bool isAS4, bool isStateChange) {
    int asn_len = isAS4 ? 12 : 8;
    int ip_addr_len = 4;
    if (extractFromBuffer(buffer, bufLen, &bgp4mp, asn_len) != asn_len)
        throw;
    if (bgp4mp.address_family == AFI_IPv6)
        ip_addr_len = 16;
    if (extractFromBuffer(buffer, bufLen, &bgp4mp.peer_IP, ip_addr_len) != ip_addr_len)
        throw;
    if (extractFromBuffer(buffer, bufLen, &bgp4mp.local_IP, ip_addr_len) != ip_addr_len)
        throw;
    if (isStateChange) {
        if (extractFromBuffer(buffer, bufLen, &bgp4mp.old_state, 2) != 2)
            throw;
        if (extractFromBuffer(buffer, bufLen, &bgp4mp.new_state, 2) != 2)
            throw;
    }
    else {
        int bgp_msg_len = mrt_data_len - asn_len - 2 * ip_addr_len;
        if (extractFromBuffer(buffer, bufLen, &bgp4mp.BGP_message, bgp_msg_len) != bgp_msg_len)
            throw;
    }
}*/

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

/*
ssize_t  parseMRT::extractFromBuffer (unsigned char*& buffer, int &bufLen, void *outputbuf, int outputLen) {
    if (outputLen > bufLen)
        return (outputLen - bufLen);
    memcpy(outputbuf, buffer, outputLen);
    buffer = (buffer + outputLen);
    bufLen -= outputLen;
    return outputLen;
}*/

int main() {
    u_char temp[] = {0x58, 0xb6, 0x0f, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x03, 0x96, 0x80, 0xdf, 0x33, 0x66, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x8c, 0xc0, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xd8, 0x12, 0x1f, 0x66, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x45, 0xb8, 0xc1, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x02, 0x05, 0x65, 0x6e, 0x02, 0x05, 0x65, 0x6e, 0x02, 0x00, 0x03, 0x15, 0x22, 0x02, 0x0c, 0x00, 0x01, 0x3f, 0x0c, 0x00, 0x01, 0x3f, 0x00, 0x00, 0x1b, 0x6a, 0x02, 0x44, 0x43, 0x21, 0x63, 0x2d, 0x3d, 0x00, 0x55, 0x00, 0x00, 0x58, 0x7c, 0x02, 0x40, 0x39, 0x1c, 0xf1, 0x40, 0x39, 0x1c, 0xf1, 0x00, 0x00, 0x2d, 0x11, 0x02, 0xd8, 0xda, 0xfc, 0xa4, 0x40, 0x47, 0x89, 0xf1, 0x00, 0x00, 0x1b, 0x1b, 0x02, 0x42, 0xb9, 0x80, 0x01, 0x42, 0xb9, 0x80, 0x01, 0x00, 0x00, 0x06, 0x84, 0x02, 0x43, 0x11, 0x52, 0x72, 0x43, 0x11, 0x52, 0x72, 0x00, 0x00, 0x0d, 0xdd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x44, 0x43, 0x3f, 0xf5, 0x00, 0x00, 0x58, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x50, 0x5b, 0xff, 0x3e, 0x00, 0x00, 0x05, 0x13, 0x02, 0x50, 0x5b, 0xf3, 0x84, 0x50, 0x5b, 0xff, 0x89, 0x00, 0x00, 0x05, 0x13, 0x02, 0x50, 0xf1, 0xb0, 0x1e, 0x50, 0xf1, 0xb0, 0x1f, 0x00, 0x00, 0x51, 0x23, 0x02, 0x55, 0x72, 0x00, 0x68, 0x55, 0x72, 0x00, 0xd9, 0x00, 0x00, 0x21, 0x2c, 0x02, 0xac, 0x10, 0x4d, 0x04, 0x57, 0x79, 0x40, 0x04, 0x00, 0x00, 0xe0, 0x77, 0x02, 0xd5, 0xc8, 0x57, 0x5b, 0x59, 0x95, 0xb2, 0x0a, 0x00, 0x00, 0x0c, 0xb9, 0x02, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xd1, 0x66, 0x01, 0x00, 0x00, 0x9b, 0x4c, 0x02, 0x5b, 0xe4, 0x97, 0x01, 0x5b, 0xe4, 0x97, 0x01, 0x00, 0x00, 0x79, 0x2b, 0x02, 0xd4, 0x49, 0x8b, 0x75, 0x5e, 0x9c, 0xfc, 0x12, 0x00, 0x00, 0x85, 0xb0, 0x02, 0x5f, 0x55, 0x00, 0x02, 0x5f, 0x55, 0x00, 0x02, 0x00, 0x03, 0x0d, 0xc2, 0x02, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x8c, 0x50, 0xfe, 0x00, 0x00, 0x7b, 0x0c, 0x02, 0x60, 0x04, 0x00, 0x37, 0x60, 0x04, 0x00, 0x37, 0x00, 0x00, 0x2d, 0xa6, 0x02, 0x67, 0xf7, 0x03, 0x2d, 0x67, 0xf7, 0x03, 0x2d, 0x00, 0x00, 0xe4, 0x8f, 0x02, 0x69, 0x10, 0x00, 0xf7, 0x69, 0x10, 0x00, 0xf7, 0x00, 0x00, 0x90, 0xec, 0x02, 0x81, 0xfa, 0x00, 0x0c, 0x81, 0xfa, 0x00, 0x0b, 0x00, 0x00, 0x0b, 0x62, 0x02, 0x86, 0xde, 0x55, 0x63, 0x86, 0xde, 0x57, 0x01, 0x00, 0x00, 0x01, 0x1e, 0x02, 0x00, 0x00, 0x00, 0x00, 0x86, 0xde, 0x57, 0x03, 0x00, 0x00, 0x01, 0x1e, 0x02, 0x89, 0x27, 0x03, 0x37, 0x89, 0x27, 0x03, 0x37, 0x00, 0x00, 0x02, 0xbd, 0x02, 0x89, 0xa4, 0x10, 0x54, 0x89, 0xa4, 0x10, 0x54, 0x00, 0x00, 0x08, 0x68, 0x02, 0x8c, 0xc0, 0x08, 0x10, 0x8c, 0xc0, 0x08, 0x10, 0x00, 0x00, 0xd5, 0xc8, 0x02, 0x90, 0xe4, 0xf1, 0x82, 0x90, 0xe4, 0xf1, 0x82, 0x00, 0x00, 0x04, 0xd7, 0x02, 0x93, 0x1c, 0x07, 0x01, 0x93, 0x1c, 0x07, 0x01, 0x00, 0x00, 0x0c, 0x3a, 0x02, 0x93, 0x1c, 0x07, 0x02, 0x93, 0x1c, 0x07, 0x02, 0x00, 0x00, 0x0c, 0x3a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x0b, 0x0b, 0x71, 0x00, 0x00, 0x03, 0x54, 0x02, 0x9a, 0x0b, 0x62, 0xe1, 0x9a, 0x0b, 0x62, 0xe1, 0x00, 0x00, 0x03, 0x54, 0x02, 0xa2, 0xf3, 0xbc, 0x02, 0xa2, 0xf3, 0xbc, 0x02, 0x00, 0x06, 0x00, 0xbe, 0x02, 0xa7, 0x8e, 0x42, 0x14, 0xa7, 0x8e, 0x03, 0x06, 0x00, 0x00, 0x13, 0xc0, 0x02, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xd1, 0xff, 0x17, 0x00, 0x00, 0x0e, 0x9d, 0x02, 0xa8, 0xd1, 0xff, 0x38, 0xa8, 0xd1, 0xff, 0x38, 0x00, 0x00, 0x0e, 0x9d, 0x02, 0x0a, 0x0a, 0x0a, 0xfc, 0xad, 0xcd, 0x39, 0xea, 0x00, 0x00, 0xd0, 0x74, 0x02, 0xb9, 0x2c, 0x74, 0xe3, 0xb9, 0x2c, 0x74, 0x01, 0x00, 0x00, 0xbb, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xcb, 0x74, 0xfd, 0x00, 0x00, 0x57, 0x74, 0x02, 0xc0, 0xf1, 0xa4, 0x04, 0xc0, 0xf1, 0xa4, 0x04, 0x00, 0x00, 0xf4, 0x67, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc1, 0xfb, 0xf5, 0x06, 0x00, 0x00, 0x15, 0x87, 0x02, 0x3e, 0x48, 0x88, 0x95, 0xc2, 0x99, 0x00, 0xfd, 0x00, 0x00, 0x15, 0x25, 0x02, 0xc3, 0x16, 0xd8, 0xbc, 0xc3, 0x16, 0xd8, 0xbc, 0x00, 0x00, 0x1a, 0x6a, 0x02, 0xc2, 0x55, 0x04, 0x04, 0xc3, 0xd0, 0x70, 0xa1, 0x00, 0x00, 0x0c, 0xcd, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xdb, 0x60, 0xef, 0x00, 0x00, 0x19, 0x35, 0x02, 0xc4, 0x07, 0x6a, 0xf5, 0xc4, 0x07, 0x6a, 0xf5, 0x00, 0x00, 0x0b, 0x59, 0x02, 0x86, 0x37, 0xc8, 0x92, 0xc6, 0x81, 0x21, 0x55, 0x00, 0x00, 0x01, 0x25, 0x02, 0xca, 0x49, 0x28, 0x2d, 0xca, 0x49, 0x28, 0x2d, 0x00, 0x00, 0x46, 0xba, 0x02, 0xca, 0x5d, 0x08, 0xf2, 0xca, 0x5d, 0x08, 0xf2, 0x00, 0x00, 0x5f, 0x79, 0x02, 0x3a, 0x8a, 0x60, 0x95, 0xca, 0xe8, 0x00, 0x03, 0x00, 0x00, 0x09, 0xc1, 0x02, 0xcb, 0x3e, 0xfc, 0x53, 0xcb, 0x3e, 0xfc, 0x53, 0x00, 0x00, 0x04, 0xc5, 0x02, 0xcb, 0xb5, 0xf8, 0xa8, 0xcb, 0xb5, 0xf8, 0xa8, 0x00, 0x00, 0x1d, 0xec, 0x02, 0xcb, 0xbd, 0x80, 0xe9, 0xcb, 0xbd, 0x80, 0xe9, 0x00, 0x00, 0x5c, 0x79, 0x02, 0xce, 0x18, 0xd2, 0x50, 0xce, 0x18, 0xd2, 0x50, 0x00, 0x00, 0x0d, 0xe9, 0x02, 0x00, 0x00, 0x00, 0x00, 0xcf, 0x2d, 0xdf, 0xf4, 0x00, 0x00, 0x19, 0x35, 0x02, 0x43, 0x11, 0x50, 0x99, 0xd0, 0x33, 0x86, 0xf6, 0x00, 0x00, 0x0d, 0xdd, 0x02, 0x00, 0x00, 0x00, 0x00, 0xd1, 0x7b, 0x0c, 0x33, 0x00, 0x00, 0x1f, 0x41, 0x02, 0x00, 0x00, 0x00, 0x00, 0xd1, 0xa1, 0xaf, 0x04, 0x00, 0x00, 0x39, 0x10, 0x02, 0xd4, 0x42, 0x60, 0x7e, 0xd4, 0x42, 0x60, 0x7e, 0x00, 0x00, 0x51, 0xb0, 0x02, 0x00, 0x00, 0x00, 0x00, 0xd5, 0x8c, 0x20, 0x94, 0x00, 0x00, 0x32, 0x9c, 0x02, 0xd5, 0x90, 0x80, 0xcb, 0xd5, 0x90, 0x80, 0xcb, 0x00, 0x00, 0x32, 0xe6, 0x02, 0x4a, 0x74, 0xb8, 0x02, 0xd5, 0xf8, 0x4c, 0xca, 0x00, 0x00, 0x05, 0x7b, 0x02, 0xd8, 0x12, 0x1f, 0x66, 0xd8, 0x12, 0x1f, 0x66, 0x00, 0x00, 0x19, 0x8b, 0x02, 0x0a, 0x0a, 0x0a, 0x0b, 0xd8, 0xdd, 0x9d, 0xa2, 0x00, 0x00, 0x9c, 0xff, 0x02, 0x8a, 0xbb, 0x80, 0x9e, 0xd9, 0xc0, 0x59, 0x32, 0x00, 0x00, 0x0c, 0xe7};
    u_char *tmp;
    tmp = temp;
    parseMRT *p = new parseMRT();
    int len = 930;
    try {
        if (p->parseMsg(tmp, len))
            cout << "Hello Ojas and Induja"<<endl;
        else
            cout << "Oh no!"<<endl;
    }
    catch (char const *str) {
        cout << "Crashed!" << str<<endl;
    }
//    cout<<"Peer Address "<<p->p_entry.peer_addr<<" "<<p->p_entry.timestamp_secs<<" "<<p->p_entry.isPrePolicy<<endl;
//    cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
//    cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
    return 1;
}