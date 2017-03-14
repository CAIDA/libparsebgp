/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */


#ifndef PARSEMRT_H_
#define PARSEMRT_H_

#include <string>
#include "AddPathDataContainer.h"
#include <list>
#include <vector>

/**
 * \class   parseMRT
 *
 * \brief   Parser for MRT messages
 * \details This class can be used as needed to parse MRT messages. This
 *          class will read directly from the socket to read the BMP message.
 */

using namespace std;

class parseMRT {
public:
    /**
      * MRT Message Types
      */
    enum MRT_TYPE {OSPFv2=11, TABLE_DUMP=12, TABLE_DUMP_V2=13, BGP4MP=16, BGP4MP_ET=17, ISIS=32, ISIS_ET=33, OSPFv3=48, OSPFv3_ET=49};


    /**
      * MRT common header
      */
    struct MRT_common_hdr
    {
        uint32_t        timeStamp;      ///< 4 byte; timestamp value in seconds
        uint16_t        type;           ///< 2 byte; type of information contained in message field
        uint16_t        subType;        ///< 2 byte; further distinguishing message information
        uint32_t        len;            ///< 4 byte; length of the message EXCLUDING common header length
        u_char          *message;       ///< variable length message
    }__attribute__ ((__packed__));


    /**
      * MRT extended header
      */
    struct extended_MRT_header{
        uint32_t        timeStamp;              ///< 4 byte; timestamp value in seconds
        uint16_t        type;                   ///< 2 byte; type of information contained in message field
        uint16_t        subType;                ///< 2 byte; further distinguishing message information
        uint32_t        len;                    ///< 4 byte; length of the message EXCLUDING common header length
        uint32_t        microseond_timestamp;   ///< 4 byte: timestamp in microseconds
        char*           message;                ///< variable length message
    }__attribute__ ((__packed__));

    /**
      * OSPFv2 Message Type
      */
    struct OSPFv2_messsage{
        char        remote_ip[46];
        char        local_ip[46];
        char*       OSPF_message;
    };



private:

};

#endif /* PARSEBMP_H_ */
