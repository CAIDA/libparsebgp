/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parseMRT.h"
#include "../../src/include/parseBGP.h"
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

parseMRT::~parseMRT() {
    // clean up
}

parseBGP *pBGP;

bool parseMRT::parseMsg(unsigned char *&buffer, int& bufLen)
{
    bool rval = true;
    char mrt_type = 0;

    try {
        mrt_type = parseCommonHeader(buffer, bufLen);

        switch (mrt_type) {
            case MRT_TYPE::OSPFv2 :     //do nothing
            case MRT_TYPE::OSPFv3 :     //do nothing
            case MRT_TYPE::OSPFv3_ET :  //do nothing

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

            case MRT_TYPE::ISIS : {
                break;
            }

            case MRT_TYPE::ISIS_ET : {
                break;
            }
            default: {
                throw "MRT type is unexpected as per rfc6396";
                break;
            }
        }

    } catch (char const *str) {
        throw str;
    }

    return rval;
}

void parseMRT::parseTableDump(unsigned char *buffer, int& bufLen)
{
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

    //parseBgpAttributes(buffer, bufLen); TO DO

}
void parseMRT::parseTableDump_V2(unsigned char *buffer, int& bufLen) {

    uint16_t count = 0;
    switch (c_hdr.subType) {
        case PEER_INDEX_TABLE:
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

            while(count<peerIndexTable.peer_count)
            {
                peer_entry p_entry;
                if (extractFromBuffer(buffer, bufLen, &p_entry.peer_type, 1) != 1)
                    throw "Error in parsing collector_BGPID";

                if(p_entry.peer_type & 0x01)

                delete p_entry;
            }

            break;
        case RIB_IPV4_UNICAST:
            break;
        case RIB_IPV4_MULTICAST:
            break;
        case RIB_IPV6_UNICAST:
            break;
        case RIB_IPV6_MULTICAST:
            break;
        case RIB_GENERIC:
            break;
    }
}


void parseMRT::parseBGP4MP(unsigned char* buffer, int& bufLen) {
    //bufferMRTMessage(buffer, bufLen);
    string peer_info_key;
    switch (c_hdr.subType) {
        case BGP4MP_STATE_CHANGE: {
            parseBGP4MPaux(bgp_state_change_as4, buffer, bufLen, false, true);
            break;
        }
        case BGP4MP_MESSAGE: {
            parseBGP4MPaux(bgp4mp_msg, buffer, bufLen, false, false);
            peer_info_key =  bgp4mp_msg.peer_IP;
            //peer_info_key += p_entry.peer_rd;
            pBGP = new parseBGP(bgp4mp_msg.peer_IP, bgp4mp_msg.peer_AS_number, (bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            //pBGP->parseBgpHeader(mrt_data, mrt_data_len, pBGP->bgpMsg->common_hdr);
            break;
        }
        case BGP4MP_MESSAGE_AS4: {
            parseBGP4MPaux(bgp4mp_msg_as4, buffer, bufLen, true, false);
            peer_info_key =  bgp4mp_msg_as4.peer_IP;
            //peer_info_key += p_entry.peer_rd;
            pBGP = new parseBGP(bgp4mp_msg_as4.peer_IP, bgp4mp_msg_as4.peer_AS_number, (bgp4mp_msg_as4.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        case BGP4MP_STATE_CHANGE_AS4: {
            parseBGP4MPaux(bgp_state_change_as4, buffer, bufLen, true, true);
            break;
        }
        case BGP4MP_MESSAGE_LOCAL: {
            parseBGP4MPaux(bgp4mp_msg_local, buffer, bufLen, false, false);
            peer_info_key =  bgp4mp_msg_local.peer_IP;
            //peer_info_key += p_entry.peer_rd;
            pBGP = new parseBGP(bgp4mp_msg_local.peer_IP, bgp4mp_msg_local.peer_AS_number, (bgp4mp_msg_local.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        case BGP4MP_MESSAGE_AS4_LOCAL: {
            parseBGP4MPaux(bgp4mp_msg_as4_local, buffer, bufLen, true, false);
            peer_info_key =  bgp4mp_msg_as4_local.peer_IP;
            //peer_info_key += p_entry.peer_rd;
            pBGP = new parseBGP(bgp4mp_msg_as4_local.peer_IP, bgp4mp_msg_as4_local.peer_AS_number, (bgp4mp_msg_as4_local.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        default: {
            throw "Subtype for BGP4MP not supported";
        }
    }
    if (c_hdr.subType != BGP4MP_STATE_CHANGE && c_hdr.subType != BGP4MP_STATE_CHANGE_AS4)
        pBGP->parseBgpHeader(mrt_data, mrt_data_len, pBGP->bgpMsg->common_hdr);
}

void parseMRT::parseBGP4MPaux(void *&bgp4mp, u_char *buffer, int bufLen, bool isAS4, bool isStateChange) {
    int asn_len = isAS4 ? 12 : 8;
    int ip_addr_len = 4;
    if (extractFromBuffer(buffer, bufLen, &bgp4mp, asn_len) != asn_len)
        throw;
    if (bgp4mp_msg_as4.address_family == AFI_IPv6)
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

char parseMRT::parseCommonHeader(unsigned char*& buffer, int& bufLen) {

    /*if (extractFromBuffer(buffer, bufLen, &c_hdr.timeStamp, 4) != 4)
        throw "Error in parsing MRT common header: timestamp";
    if (extractFromBuffer(buffer, bufLen, &c_hdr.type, 2) != 2)
        throw "Error in parsing MRT Common header: type";
    if (extractFromBuffer(buffer, bufLen, &c_hdr.subType, 2) != 2)
        throw "Error in parsing MRT common header: subtype";
    if (extractFromBuffer(buffer, bufLen, &c_hdr.len, 4) != 4)
        throw "Error in parsing MRT Common header: length";*/

    if (extractFromBuffer(buffer, bufLen, &c_hdr, 12) != 12)
        throw "Error in parsing MRT common header";

    mrt_len = c_hdr.len;

    if (c_hdr.type == MRT_TYPE::BGP4MP_ET || c_hdr.type == MRT_TYPE::ISIS_ET || c_hdr.type == MRT_TYPE::OSPFv3_ET) {
        if (extractFromBuffer(buffer, bufLen, &c_hdr.microsecond_timestamp, 4) != 4)
            throw "Error in parsing MRT Common header: microsecond timestamp";
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


ssize_t  parseMRT::extractFromBuffer (unsigned char*& buffer, int &bufLen, void *outputbuf, int outputLen) {
    if (outputLen > bufLen)
        return (outputLen - bufLen);
    memcpy(outputbuf, buffer, outputLen);
    buffer = (buffer + outputLen);
    bufLen -= outputLen;
    return outputLen;
}

int main() {
    u_char temp[] = {0x03, 0x00, 0x00, 0x00, 0x06, 0x04};
    u_char *tmp;
    tmp = temp;
    parseBMP *p = new parseBMP();
    int len = 870;
    try {
        if (p->parseMsg(tmp, len))
            cout << "Hello Ojas and Induja"<<endl;
        else
            cout << "Oh no!"<<endl;
    }
    catch (char const *str) {
        cout << "Crashed!" << str<<endl;
    }
    cout<<"Peer Address "<<p->p_entry.peer_addr<<" "<<p->p_entry.timestamp_secs<<" "<<p->p_entry.isPrePolicy<<endl;
    cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
    cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
    return 1;
}