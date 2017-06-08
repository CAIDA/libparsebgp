/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

/**
 * @file    parse_mrt.h
 *
 * \brief   Parser for MRT messages
 * \details The functions in this file can be used as needed to parse MRT messages from buffer
 */

#ifndef PARSEMRT_H_
#define PARSEMRT_H_

#include <string>
#include <vector>
#include "parse_bgp.h"
#include "parse_utils.h"

#define MRT_PACKET_BUF_SIZE 4096   ///< Size of the MRT packet buffer (memory)

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

/**
 * FSM states
 */
enum state_values {Idle=1, Connect, Active, OpenSent, OpenConfirm, Esablished};


/**
  * MRT common header
  */
typedef struct libparsebgp_mrt_common_hdr {
    uint32_t        time_stamp;             ///< 4 byte; timestamp value in seconds
    uint16_t        type;                   ///< 2 byte; type of information contained in message field
    uint16_t        sub_type;               ///< 2 byte; further distinguishing message information
    uint32_t        len;                    ///< 4 byte; length of the message EXCLUDING common header length
    uint32_t        microsecond_timestamp;  ///< 4 byte: timestamp in microseconds
}libparsebgp_mrt_common_hdr;

/**
  * Table Dump Message format
  */
typedef struct libparsebgp_table_dump_message{
    uint16_t                view_number;        ///< 2-octet view number
    uint16_t                sequence;           ///< 2-octet sequence
    char                    prefix[16];         ///< 4-octet or 16-octet (depending on type), contains IP address of a particular RIB entry
    uint8_t                 prefix_len;         ///< 1-octet, indicates the length in bits of the prefix mask for the Prefix field
    uint8_t                 status;             ///< 1-octet, The Status octet is unused in the TABLE_DUMP Type and SHOULD be set to 1
    uint32_t                originated_time;    ///< 4-octet, contains time at which this prefix was heard
    char                    peer_ip[16];        ///< 4-octe ot 16-octet (depending on type) peer IP address
    uint16_t                peer_as;            ///< 2-octet peer AS number
    uint16_t                attribute_len;      ///< 2-octet, contains the length of the Attribute field
    update_path_attrs       **bgp_attrs;        ///< contains the BGP attribute information for the RIB entry
}libparsebgp_table_dump_message;


/**
  * Peer Entry Message format
  */
//4.3.1
//view name is optional if not present viewname length is set to 0

struct peer_entry{
    uint8_t     peer_type;                     ///< 1-octet Peer type
    char        peer_bgp_id[4];                ///< 4-octet Peer BGP Id
    char        peer_ip[16];                   ///< Peer IP address
    uint32_t    peer_as;                       ///< Peer AS number
};

/**
  * Peer Index Table Message format
  */
struct libparsebgp_peer_index_table{
    char                collector_bgp_id[4];    ///< 4-octet, Collector BGP ID
    uint16_t            view_name_length;       ///< 2-octet, length of view_name
    char                view_name[1024];        ///< View name, in utf8 format
    uint16_t            peer_count;             ///< 2-octet peer count, number of peer entries
    peer_entry*         peer_entries;           ///< List of peer entries
};

/**
  * RIB Entry Message format
  */
struct rib_entry{
    uint16_t                     peer_index;        ///< 2-octet Peer index
    uint32_t                     originated_time;   ///< 4-octet, originated time for the RIB Entry
    uint16_t                     attribute_len;     ///< 2-octet, length of the BGP attributes field
    update_path_attrs            **bgp_attrs;         ///< List of BGP attributes
};

/**
  * RIB Entry Header Message format
  */
struct libparsebgp_rib_entry_header{
    uint32_t        sequence_number;                ///< 4-octet sequence number
    uint8_t         prefix_length;                  ///< 1-octet, length of the prefix
    char            prefix[46];                     ///< Prefix
    uint16_t        entry_count;                    ///< 2-octet entry count, number of RIB entries
    rib_entry*      rib_entries;                    ///< List of RIB Entries
};

/**
  * RIB generic entry header
  */
struct libparsebgp_rib_generic_entry_header{
    uint32_t        sequence_number;                ///< 4-octet sequence number
    uint16_t        address_family_identifier;      ///< 2-octet address family identifier
    uint8_t         subsequent_afi;                 ///< 1-octet Subsequent AFI (SAFI)
    struct nlri_entry{
        uint8_t     len;                        ///< 1-octet Length of prefix in bits
        string      prefix;                     ///< Address prefix
    }nlri_entry;                                          ///< single NLRI entry
    uint16_t        entry_count;                    ///< 2-octet entry count, number of RIB Entries
    rib_entry*      rib_entries;                    ///< List of RIB Entries
};

/**
  * BGP4MP State Change Format
  */
struct libparsebgp_bgp4mp_state_change{
    uint32_t    peer_asn;                           ///< 2-octet or 4-octet (depending on type) peer Autonomous System (AS) number
    uint32_t    local_asn;                          ///< 2-octet or 4-octet (depending on type) local Autonomous System (AS) number
    uint16_t    interface_index;                    ///< 2-octet interface index
    uint16_t    address_family;                     ///< 2-octet address family
    char        peer_ip[40];                        ///< 4-octet of 16-octet (depending on type) Peer IP address
    char        local_ip[40];                       ///< 4-octet of 16-octet (depending on type) local IP address
    uint16_t    old_state;                          ///< 2-octet old FSM state
    uint16_t    new_state;                          ///< 2-octet new FSM state
};

/**
 * Structure holding BGP4MP Messages
 */
struct libparsebgp_bgp4mp_msg{
    uint32_t                          peer_asn;         ///< 2-octet or 4-octet (depending on type) peer Autonomous System (AS) number
    uint32_t                          local_asn;        ///< 2-octet or 4-octet (depending on type) local Autonomous System (AS) number
    uint16_t                          interface_index;  ///< 2-octet interface index
    uint16_t                          address_family;   ///< 2-octet address family
    char                              peer_ip[40];      ///< 4-octet of 16-octet (depending on type) Peer IP address
    char                              local_ip[40];     ///< 4-octet of 16-octet (depending on type) local IP address
    libparsebgp_parse_bgp_parsed_data bgp_msg;          ///< Contains the BGP message
};

u_char mrt_data[MRT_PACKET_BUF_SIZE + 1];
int mrt_data_len;                   ///< Length/size of data in the data buffer
uint16_t mrt_sub_type;              ///< MRT sub type
uint32_t mrt_len;                   ///< Length of the BMP message - does not include the common header size

/*
 * Structure for table_dump_v2 type as per RFC 6396
 */
//union needed
struct libparsebgp_parsed_table_dump_v2 {
    libparsebgp_peer_index_table          peer_index_tbl;           ///< Contains parsed message of type PEER_INDEX_TABLE
    libparsebgp_rib_entry_header          rib_entry_hdr;            ///< Contains parsed messages of type RIB_IPV4_UNICAST and RIB_IPV6_UNICAST
    libparsebgp_rib_generic_entry_header  rib_generic_entry_hdr;    ///< Contains parsed messages of type RIB_GENERIC
};

/*
 * Structure for parsed MRT message as per RFC 6396
 */
struct libparsebgp_parse_mrt_parsed_data {
    libparsebgp_mrt_common_hdr c_hdr;                                   ///< MRT Common header
    //union needed:
    struct libparsebgp_parsed_mrt_data {                                ///< Union for the different types of MRT messages
        libparsebgp_table_dump_message   table_dump;                    ///< Message of type TABLE_DUMP
        libparsebgp_parsed_table_dump_v2 table_dump_v2;                 ///< Message of type TABLE_DUMP_V2
        //union needed
        struct libparsebgp_parsed_bgp4mp_msg {                          ///< Union for message of type BGP4MP
            libparsebgp_bgp4mp_msg          bgp4mp_msg;                 ///< Contains BGP4MP messages
            libparsebgp_bgp4mp_state_change bgp4mp_state_change_msg;    ///< Contains BGP4MP state change messages
        }bgp4mp;
    }parsed_data;
};

/**
 * Function to parse MRT message
 *
 * @param [in] mrt_parsed_data  Structure that contains parsed MRT message
 * @param [in] buffer           Contains the MRT message
 * @param [in] buf_len          Length of buffer
 *
 * @return number of bytes read
 */
ssize_t libparsebgp_parse_mrt_parse_msg(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data, unsigned char *buffer, int buf_len);

/**
 * Destructor function to free memory allocated to libparsebgp_parse_mrt_parsed_data
 * @param mrt_parsed_data   Structure that contains parsed MRT message
 */
void libparsebgp_parse_mrt_destructor (libparsebgp_parse_mrt_parsed_data *mrt_parsed_data);

#endif /* PARSEBMP_H_ */