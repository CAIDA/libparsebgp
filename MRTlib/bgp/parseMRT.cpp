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
            case MRT_TYPE::OSPFv2 : {
                bufferMRTMessage(buffer, bufLen);
                parseOSPFv2(mrt_data, mrt_data_len);
                break;
            }

            case MRT_TYPE::OSPFv3 : {
                break;
            }

            case MRT_TYPE::OSPFv3_ET : {
                break;
            }

            case MRT_TYPE::TABLE_DUMP : {
                break;
            }

            case MRT_TYPE::TABLE_DUMP_V2 : {
                break;
            }

            case MRT_TYPE::BGP4MP : {
                break;
            }

            case MRT_TYPE::BGP4MP_ET : {
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

    if (parseBMP::extractFromBuffer(buffer, bufLen, &c_hdr.timeStamp, 4) != 4)
        throw "Error in parsing MRT common header: timestamp";
    if (parseBMP::extractFromBuffer(buffer, bufLen, &c_hdr.type, 2) != 2)
        throw "Error in parsing MRT Common header: type";
    if (parseBMP::extractFromBuffer(buffer, bufLen, &c_hdr.subType, 2) != 2)
        throw "Error in parsing MRT common header: subtype";
    if (parseBMP::extractFromBuffer(buffer, bufLen, &c_hdr.len, 4) != 4)
        throw "Error in parsing MRT Common header: length";

    if (c_hdr.type == MRT_TYPE::BGP4MP_ET || c_hdr.type == MRT_TYPE::ISIS_ET || c_hdr.type == MRT_TYPE::OSPFv3_ET) {
        if (parseBMP::extractFromBuffer(buffer, bufLen, &c_hdr.microsecond_timestamp, 4) != 4)
            throw "Error in parsing MRT Common header: microsecond timestamp";
    }

    mrt_len = c_hdr.len;

    return c_hdr.type;
}

/**
 * get current BMP message type
 */
char parseBMP::getBMPType() {
    return bmp_type;
}

/**
 * get current BMP message length
 *
 * The length returned does not include the version 3 common header length
 */
uint32_t parseBMP::getBMPLength() {
    return bmp_len;
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
// void parseBMP::bufferBMPMessage(int sock) {
void parseMRT::bufferMRTMessage(u_char *& buffer, int& bufLen) {
    if (mrt_len <= 0)
        return;

    if (mrt_len > sizeof(mrt_data)) {
        //       LOG_WARN("sock=%d: BMP message is invalid, length of %d is larger than max buffer size of %d",sock, bmp_len, sizeof(bmp_data));
        throw "BMP message length is too large for buffer, invalid BMP sender";
    }

//    SELF_DEBUG("sock=%d: Buffering %d from socket", sock, bmp_len);
    /*if ((bmp_data_len=Recv(sock, bmp_data, bmp_len, MSG_WAITALL)) != bmp_len) {
 //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
         throw "Error while reading BMP data into buffer";
    }*/
    if ((mrt_data_len=extractFromBuffer(buffer, bufLen, mrt_data, mrt_len)) != mrt_len) {
        //        LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",sock, bmp_len);
        throw "Error while reading BMP data into buffer";
    }

    // Indicate no more data is left to read
    mrt_len = 0;

}


void parseMRT::parseOSPFv2(unsigned char *buffer, int& bufLen)
{

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