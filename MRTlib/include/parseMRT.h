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
#include <list>
#include <vector>
#include "../../src/include/parseBMP.h"


#define MRT_PACKET_BUF_SIZE 4096   ///< Size of the MRT packet buffer (memory)


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
      * Table Dump Types
      */
    enum ADDRESS_FAMILY_TYPES {AFI_IPv4=1,AFI_IPv6};

    /**
      * Table Dump V2 Types
      */
    enum TABLE_DUMP_V2_TYPES {PEER_INDEX_TABLE=1, RIB_IPV4_UNICAST, RIB_IPV4_MULTICAST, RIB_IPV6_UNICAST, RIB_IPV6_MULTICAST, RIB_GENERIC};

    /**
      * BGP4MP Types
      */
    enum BGP4MP_TYPES {BGP4MP_STATE_CHANGE=0, BGP4MP_MESSAGE, BGP4MP_MESSAGE_AS4=4, BGP4MP_STATE_CHANGE_AS4, BGP4MP_MESSAGE_LOCAL, BGP4MP_MESSAGE_AS4_LOCAL};


    enum STATE_VALUES {Idle=1, Connect, Active, OpenSent, OpenConfirm, Esablished};



    /**
      * MRT common header
      */
    struct MRT_common_hdr
    {
        uint32_t        timeStamp;              ///< 4 byte; timestamp value in seconds
        uint16_t        type;                   ///< 2 byte; type of information contained in message field
        uint16_t        subType;                ///< 2 byte; further distinguishing message information
        uint32_t        len;                    ///< 4 byte; length of the message EXCLUDING common header length
        uint32_t        microsecond_timestamp;   ///< 4 byte: timestamp in microseconds
        u_char*         message;                ///< variable length message
    };

    struct table_dump_message{
        uint16_t    view_number;
        uint16_t    sequence;
        char        prefix[46];
        uint8_t     prefix_len;
        uint8_t     status;
        uint32_t    originated_time;
        char        peer_IP[46];
        uint16_t    peerAS;
        uint16_t    attribute_len;
        u_char*     bgp_attribute;
    };

    //4.3.1
    //view name is optional if not present viewname length is set to 0
    struct peer_index_table{
        char                collector_BGPID[4];
        uint16_t            view_name_length;
        char*               view_name[16]; //doubtful about this setting, willl have to confirm
        uint16_t            peer_count;
        list<peer_entry>  peerEntries;
    };

    struct peer_entry{
        uint8_t     peer_type;
        char        peer_BGPID[4];
        char        peer_IP[46];
        bool        isIPv4;
        bool        ASsize; //0 for 16 bits; 1 for 32 bits
        uint16_t    peerAS16;
        uint32_t    peerAS32;
    };

    //4.3.2
    struct RIB_entry_header{
        uint32_t        sequence_number;
        uint8_t         prefix_length;
        u_char*         prefix;
        uint16_t        entry_count;
        list<RIB_entry> RIB_entries;
    };

    //4.3.3
    struct RIB_generic_entry_header{
        uint32_t        sequence_number;
        uint16_t        address_family_identifier;
        uint8_t         subsequentAFI;
        u_char *        NLRI;
        uint16_t        entry_count;
        list<RIB_entry> RIB_entries;
    };

    //4.3.4
    struct RIB_entry{
        uint16_t    peer_index;
        uint32_t    originatedTime;
        uint16_t    attribute_len;
        u_char*     bgp_attribute;
    };

    //4.4.1
    struct BGP4MP_state_change{
        uint16_t    peer_AS_number;
        uint16_t    local_AS_number;
        uint16_t    interface_index;
        uint16_t    address_family;
        char        peer_IP[40];
        char        local_IP[40];
        uint16_t    old_state;
        uint16_t    new_state;
    };

    //4.4.2
    struct BGP4MP_message{
        uint16_t    peer_AS_number;
        uint16_t    local_AS_number;
        uint16_t    interface_index;
        uint16_t    address_family;
        char        peer_IP[40];
        char        local_IP[40];
        u_char*     BGP_message;
    };

    //4.4.3
    struct BGP4MP_message_AS4{
        uint32_t    peer_AS_number;
        uint32_t    local_AS_number;
        uint16_t    interface_index;
        uint16_t    address_family;
        char        peer_IP[40];
        char        local_IP[40];
        u_char*     BGP_message;
    };

    //4.4.4
    struct BGP4MP_state_change_AS4{
        uint32_t    peer_AS_number;
        uint32_t    local_AS_number;
        uint16_t    interface_index;
        uint16_t    address_family;
        char        peer_IP[40];
        char        local_IP[40];
        uint16_t    old_state;
        uint16_t    new_state;
    };

    //4.4.5
    struct BGP4MP_message_local{
        uint16_t    peer_AS_number;
        uint16_t    local_AS_number;
        uint16_t    interface_index;
        uint16_t    address_family;
        char        peer_IP[40];
        char        local_IP[40];
        u_char*     BGP_message;
    };

    //4.4.6
    struct BGP4MP_message_AS4_local{
        uint32_t    peer_AS_number;
        uint32_t    local_AS_number;
        uint16_t    interface_index;
        uint16_t    address_family;
        char        peer_IP[40];
        char        local_IP[40];
        u_char*     BGP_message;
    };

    BGPMsg bgpMsg;

    parseMRT parseMRT();

    parseMRT ~parseMRT();

    bool parseMsg(unsigned char *&buffer, int& bufLen);

    char parseCommonHeader(unsigned char*& buffer, int& bufLen);

    void bufferMRTMessage(u_char *& buffer, int& bufLen);

    void parseTableDump(unsigned char* buffer, int& bufLen);

    void parseBGP4MP(unsigned char* buffer, int& bufLen);

    void parseBGP4MPaux(void *&bgp4mp, char *buffer, int bufLen, bool isAS4, bool isStateChange);

    ssize_t extractFromBuffer(unsigned char*& buffer, int &bufLen, void *outputbuf, int outputLen);

        /**
         * get current MRT message type
        */
    char getMRTType();

    /**
     * get current MRT message length
     *
     * The length returned does not include the common header length
     */
    uint32_t getMRTLength();

    MRT_common_hdr c_hdr;
    table_dump_message table_dump;
    BGP4MP_state_change bgp_state_change;
    BGP4MP_state_change_AS4 bgp_state_change_as4;
    BGP4MP_message bgp4mp_msg;
    BGP4MP_message_AS4 bgp4mp_msg_as4;
    BGP4MP_message_local bgp4mp_msg_local;
    BGP4MP_message_AS4_local bgp4mp_msg_as4_local;

    /**
     * BMP message buffer (normally only contains the BGP message)
     *      BMP data message is read into this buffer so that it can be passed to the BGP parser for handling.
     *      Complete BGP message is read, otherwise error is generated.
     */
    u_char      mrt_data[MRT_PACKET_BUF_SIZE + 1];
    int         mrt_data_len;              ///< Length/size of data in the data buffer



private:
    uint16_t   mrt_type;
    uint32_t   mrt_len;                    ///< Length of the BMP message - does not include the common header size

};

#endif /* PARSEBMP_H_ */





