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
//#include "parse_bmp.h"
#include "parse_bgp.h"
#include "parse_utils.h"
//#include "parse_common.h"

#define MRT_PACKET_BUF_SIZE 4096   ///< Size of the MRT packet buffer (memory)

/**
 * \class   parseMRT
 *
 * \brief   Parser for MRT messages
 * \details This class can be used as needed to parse MRT messages. This
 *          class will read directly from the socket to read the BMP message.
 */

using namespace std;

/**
  * MRT Message Types
  */
enum mrt_type {OSPFv2=11, TABLE_DUMP=12, TABLE_DUMP_V2=13, BGP4MP=16, BGP4MP_ET=17, ISIS=32, ISIS_ET=33, OSPFv3=48, OSPFv3_ET=49};

/**
  * Table Dump Types
  */
enum address_family_types {AFI_IPv4=1,AFI_IPv6};

/**
  * Table Dump V2 Types
  */
enum table_dump_v2_types {PEER_INDEX_TABLE=1, RIB_IPV4_UNICAST, RIB_IPV4_MULTICAST, RIB_IPV6_UNICAST, RIB_IPV6_MULTICAST, RIB_GENERIC};

/**
  * BGP4MP Types
  */
enum bgp4mp_types {BGP4MP_STATE_CHANGE=0, BGP4MP_MESSAGE, BGP4MP_MESSAGE_AS4=4, BGP4MP_STATE_CHANGE_AS4, BGP4MP_MESSAGE_LOCAL, BGP4MP_MESSAGE_AS4_LOCAL};


enum state_values {Idle=1, Connect, Active, OpenSent, OpenConfirm, Esablished};



/**
  * MRT common header
  */
typedef struct libparsebgp_mrt_common_hdr {
    uint32_t        time_stamp;              ///< 4 byte; timestamp value in seconds
    uint16_t        type;                   ///< 2 byte; type of information contained in message field
    uint16_t        sub_type;                ///< 2 byte; further distinguishing message information
    uint32_t        len;                    ///< 4 byte; length of the message EXCLUDING common header length
    uint32_t        microsecond_timestamp;   ///< 4 byte: timestamp in microseconds
//        u_char*         message;                ///< variable length message
}libparsebgp_mrt_common_hdr;

/**
  * Table Dump Message format
  */
typedef struct libparsebgp_table_dump_message{
    uint16_t    view_number;
    uint16_t    sequence;
    char        prefix[46];
    uint8_t     prefix_len;
    uint8_t     status;
    uint32_t    originated_time;
    char        peer_ip[46];
    uint16_t    peer_as;
    uint16_t    attribute_len;
    u_char*     bgp_attribute;
}libparsebgp_table_dump_message;


/**
  * Peer Entry Message format
  */
//4.3.1
//view name is optional if not present viewname length is set to 0

struct peer_entry{
    uint8_t     peer_type;
    char        peer_bgp_id[4];
    char        peer_ip[46];
//        bool        is_ipv4;
//        bool        as_size; //0 for 16 bits; 1 for 32 bits
//       uint16_t    peer_as16;
    uint32_t    peer_as32;
};

/**
  * Peer Index Table Message format
  */
struct libparsebgp_peer_index_table{
    char                collector_bgp_id[4];
    uint16_t            view_name_length;
    char*               view_name[46]; //doubtful about this setting, will have to confirm
    uint16_t            peer_count;
    list<peer_entry>    peer_entries;
};

//4.3.4
/**
  * RIB Entry Message format
  */
struct rib_entry{
    uint16_t                     peer_index;
    uint32_t                     originated_time;
    uint16_t                     attribute_len;
    bool                         end_of_rib_marker;
    //parsed_update_data           parsed_data;
};

//4.3.2
/**
  * RIB Entry Header Message format
  */
struct libparsebgp_rib_entry_header{
    uint32_t        sequence_number;
    uint8_t         prefix_length;
    char            prefix[46];
    uint16_t        entry_count;
    list<rib_entry> rib_entries;
};

//4.3.3
/**
  * RIB generic entry header
  */
struct libparsebgp_rib_generic_entry_header{
    uint32_t        sequence_number;
    uint16_t        address_family_identifier;
    uint8_t         subsequent_afi;
    u_char*         nlri;
    uint16_t        entry_count;
    list<rib_entry> rib_entries;
};

/**
  * BGP4MP State Change Format
  */
struct libparsebgp_bgp4mp_state_change{
    uint16_t    peer_asn;
    uint16_t    local_asn;
    uint16_t    interface_index;
    uint16_t    address_family;
    char        peer_ip[40];
    char        local_ip[40];
    uint16_t    old_state;
    uint16_t    new_state;
};

/**
  * BGP4MP Message Format
  *
struct bgp4mp_message{
    uint16_t    peer_asn;
    uint16_t    local_asn;
    uint16_t    interface_index;
    uint16_t    address_family;
    char        peer_ip[40];
    char        local_ip[40];
    u_char*     BGP_message;
};

/**
  * BGP4MP Message_AS4 Format
  *
struct BGP4MP_message_AS4{
    uint32_t    peer_AS_number;
    uint32_t    local_AS_number;
    uint16_t    interface_index;
    uint16_t    address_family;
    char        peer_IP[40];
    char        local_IP[40];
    u_char*     BGP_message;
};

/**
  * BGP4MP State Change AS4 Format
  *
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

/**
  * BGP4MP Message Local Format
  *
struct BGP4MP_message_local{
    uint16_t    peer_AS_number;
    uint16_t    local_AS_number;
    uint16_t    interface_index;
    uint16_t    address_family;
    char        peer_IP[40];
    char        local_IP[40];
    u_char*     BGP_message;
};

/**
  * BGP4MP Message AS4 Local Format
  *
struct BGP4MP_message_AS4_local{
    uint32_t    peer_AS_number;
    uint32_t    local_AS_number;
    uint16_t    interface_index;
    uint16_t    address_family;
    char        peer_IP[40];
    char        local_IP[40];
    u_char*     BGP_message;
};*/

struct libparsebgp_bgp4mp_msg{
    uint32_t    peer_asn;
    uint32_t    local_asn;
    uint16_t    interface_index;
    uint16_t    address_family;
    char        peer_ip[40];
    char        local_ip[40];
    u_char*     bgp_data;
    libparsebgp_parse_bgp_parsed_data bgp_msg;
};

u_char mrt_data[MRT_PACKET_BUF_SIZE + 1];
int mrt_data_len;              ///< Length/size of data in the data buffer

//    libparsebgp_parse_bgp_parsed_data pbgp;
//    parsed_bgp_msg bgp_msg;

//private:
uint16_t mrt_type;
uint16_t mrt_sub_type;
uint32_t mrt_len;                    ///< Length of the BMP message - does not include the common header size

union libparsebgp_parsed_table_dump_v2 {
    libparsebgp_peer_index_table          peer_index_tbl;
    libparsebgp_rib_entry_header          rib_entry_hdr;
    libparsebgp_rib_generic_entry_header  rib_generic_entry_hdr;
};

struct libparsebgp_parse_mrt_parsed_data {
    libparsebgp_mrt_common_hdr c_hdr;
    union libparsebgp_parsed_mrt_data {
        libparsebgp_table_dump_message table_dump;
        libparsebgp_parsed_table_dump_v2 table_dump_v2;
        union libparsebgp_parsed_bgp4mp_msg {
            libparsebgp_bgp4mp_msg                bgp4mp_msg;
            libparsebgp_bgp4mp_state_change       bgp4mp_state_change_msg;
        }bgp4mp;
    }parsed_data;

//    libparsebgp_table_dump_message table_dump;
//    peer_index_table peer_index_tbl;
//    libparsebgp_rib_entry_header rib_entry_hdr;
//    libparsebgp_rib_generic_entry_header rib_generic_entry_hdr;

//    libparsebgp_bgp4mp_msg bgp4mp_msg;
//    libparsebgp_bgp4mp_state_change bgp4mp_state_change_msg;

//    obj_peer_up_event up_event;
//    obj_peer_down_event down_event;

    std::map<std::string, peer_info> peer_info_map;
};
/*
 * Constructor for class
 */
//parseMRT();
void libparsebgp_parse_mrt_init(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data);

/*
 * Destructor
 */
//~parseMRT();

/**
 * Function to parse MRT message
 *
 * \param [in] buffer       Contains the MRT message
 * \param [in] buf_len       Length of buffer
 */
uint32_t libparsebgp_parse_mrt_parse_msg(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data, unsigned char *buffer, int buf_len);

//extern "C" parseMRT parseMRTwrapper(unsigned char *buffer, int buf_len);
libparsebgp_parse_mrt_parsed_data parse_mrt_wrapper(unsigned char *&buffer, int &buf_len);

#endif /* PARSEBMP_H_ */