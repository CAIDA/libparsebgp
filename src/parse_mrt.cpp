/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parse_mrt.h"
#include <sys/socket.h>
#include <arpa/inet.h>

// Wrapper for parseMRT
/*parseMRT parseMRTwrapper(unsigned char *buffer, int buf_len) {
    parseMRT pMRT;
    pMRT.parseMsg(buffer, buf_len);
    return pMRT;
}*/
libparsebgp_parse_mrt_parsed_data parse_mrt_wrapper(unsigned char *&buffer, int &buf_len) {
    libparsebgp_parse_mrt_parsed_data mrt_parsed_data;
    try {
        libparsebgp_parse_mrt_init(&mrt_parsed_data);
        if (libparsebgp_parse_mrt_parse_msg(buffer, buf_len, &mrt_parsed_data))
            cout << "Parsed successfully" << endl;
        else
            cout << "Error in parsing" << endl;
    }
    catch (char const *str) {
        throw str;
    }
    return mrt_parsed_data;
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
static void libparsebgp_parse_mrt_buffer_mrt_message(u_char *& buffer, int& buf_len) {
    if (mrt_len <= 0)
        return;

    if (mrt_len > sizeof(mrt_data)) {
        throw "MRT message length is too large for buffer, invalid MRT sender";
    }

    if ((mrt_data_len=extract_from_buffer(buffer, buf_len, mrt_data, mrt_len)) != mrt_len) { ;
        throw "Error while reading MRT data from buffer";
    }

    // Indicate no more data is left to read
    mrt_len = 0;
}


// Analogous to constructor of class
void libparsebgp_parse_mrt_init(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data){
    mrt_len = 0;
    mrt_data_len = 0;
}

static void libparsebgp_parse_mrt_parse_bgp4mp(unsigned char* buffer, int& buf_len, libparsebgp_parse_mrt_parsed_data *mrt_parsed_data) {
    string peer_info_key;
    /*switch (c_hdr.subType) {
        case BGP4MP_STATE_CHANGE: {
            //parseBGP4MPaux(&bgp_state_change, buffer, buf_len, false, true);
            break;
        }
        case BGP4MP_MESSAGE: {
            parseBGP4MPaux(&libparsebgp_bgp4mp_msg, buffer, buf_len, false, false);
            peer_info_key =  libparsebgp_bgp4mp_msg.peer_IP;
            //peer_info_key += p_entry.peer_rd;
            pBGP = new parseBGP(libparsebgp_bgp4mp_msg.peer_IP, libparsebgp_bgp4mp_msg.peer_AS_number, (libparsebgp_bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            //pBGP->parseBgpHeader(mrt_data, mrt_data_len, pBGP->bgpMsg->common_hdr);
            break;
        }
        case BGP4MP_MESSAGE_AS4: {
//            parseBGP4MPaux(&bgp4mp_msg_as4, buffer, buf_len, true, false);
//            peer_info_key =  bgp4mp_msg_as4.peer_IP;
//            //peer_info_key += p_entry.peer_rd;
//            pBGP = new parseBGP(bgp4mp_msg_as4.peer_IP, bgp4mp_msg_as4.peer_AS_number, (bgp4mp_msg_as4.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            parseBGP4MPaux(&libparsebgp_bgp4mp_msg, buffer, buf_len, true, false);
            peer_info_key =  libparsebgp_bgp4mp_msg.peer_IP;
            pBGP = new parseBGP(libparsebgp_bgp4mp_msg.peer_IP, libparsebgp_bgp4mp_msg.peer_AS_number, (libparsebgp_bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        case BGP4MP_STATE_CHANGE_AS4: {
            //parseBGP4MPaux(&bgp_state_change_as4, buffer, buf_len, true, true);
            break;
        }
        case BGP4MP_MESSAGE_LOCAL: {
//            parseBGP4MPaux(&bgp4mp_msg_local, buffer, buf_len, false, false);
//            peer_info_key =  bgp4mp_msg_local.peer_IP;
//            //peer_info_key += p_entry.peer_rd;
//            pBGP = new parseBGP(bgp4mp_msg_local.peer_IP, bgp4mp_msg_local.peer_AS_number, (bgp4mp_msg_local.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            parseBGP4MPaux(&libparsebgp_bgp4mp_msg, buffer, buf_len, true, false);
            peer_info_key =  libparsebgp_bgp4mp_msg.peer_IP;
            pBGP = new parseBGP(libparsebgp_bgp4mp_msg.peer_IP, libparsebgp_bgp4mp_msg.peer_AS_number, (libparsebgp_bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        case BGP4MP_MESSAGE_AS4_LOCAL: {
//            parseBGP4MPaux(&bgp4mp_msg_as4_local, buffer, buf_len, true, false);
//            peer_info_key =  bgp4mp_msg_as4_local.peer_IP;
//            //peer_info_key += p_entry.peer_rd;
//            pBGP = new parseBGP(bgp4mp_msg_as4_local.peer_IP, bgp4mp_msg_as4_local.peer_AS_number, (bgp4mp_msg_as4_local.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            parseBGP4MPaux(&libparsebgp_bgp4mp_msg, buffer, buf_len, true, false);
            peer_info_key =  libparsebgp_bgp4mp_msg.peer_IP;
            pBGP = new parseBGP(libparsebgp_bgp4mp_msg.peer_IP, libparsebgp_bgp4mp_msg.peer_AS_number, (libparsebgp_bgp4mp_msg.address_family == AFI_IPv4), c_hdr.timeStamp, c_hdr.microsecond_timestamp, &peer_info_map[peer_info_key]);
            break;
        }
        default: {
            throw "Subtype for BGP4MP not supported";
        }
    }*/

    switch (mrt_parsed_data->c_hdr.sub_type) {
        case BGP4MP_STATE_CHANGE:
        case BGP4MP_STATE_CHANGE_AS4: {
            int asn_len = (mrt_parsed_data->c_hdr.sub_type == BGP4MP_STATE_CHANGE_AS4) ? 8 : 4;
            int ip_addr_len = 4;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg, asn_len) != asn_len)  // ASNs
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.interface_index, 2) != 2)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.address_family, 2) != 2)
                throw;
            if (mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_ip, ip_addr_len) != ip_addr_len)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.local_ip, ip_addr_len) != ip_addr_len)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state, 2) != 2)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state, 2) != 2)
                throw;
            break;
        }
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4:
        case BGP4MP_MESSAGE_LOCAL:
        case BGP4MP_MESSAGE_AS4_LOCAL: {
            int asn_len = (mrt_parsed_data->c_hdr.sub_type == BGP4MP_MESSAGE_AS4 || mrt_parsed_data->c_hdr.sub_type == BGP4MP_MESSAGE_AS4_LOCAL) ? 8 : 4;
            int ip_addr_len = 4;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg, asn_len) != asn_len) //ASNs
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.interface_index, 2) != 2)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.address_family, 2) != 2)
                throw;
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_asn);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.local_asn);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.interface_index);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.address_family);
            if (mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_ip, ip_addr_len) != ip_addr_len)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.local_ip, ip_addr_len) != ip_addr_len)
                throw;
            /*int bgp_msg_len = mrt_data_len;
            if (extract_from_buffer(buffer, buf_len, &parsed_data.bgp4mp.libparsebgp_bgp4mp_msg.BGP_message, mrt_data_len) != bgp_msg_len)
                throw;*/
            if (mrt_data_len != buf_len)
                throw;
            memcpy(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.bgp_data, buffer, mrt_data_len);

            peer_info_key =  mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_ip;

            obj_bgp_peer p_entry;
            bzero(&p_entry, sizeof(obj_bgp_peer));
            memcpy(&p_entry.peer_addr, mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_ip, sizeof(p_entry.peer_addr));
            p_entry.is_ipv4 = (mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.address_family == AFI_IPv4);
            p_entry.peer_as = mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_asn;
            p_entry.timestamp_secs = mrt_parsed_data->c_hdr.time_stamp;
            p_entry.timestamp_us = mrt_parsed_data->c_hdr.microsecond_timestamp;

            //mrt_parsed_data->pbgp = new parseBGP(&p_entry, "", &mrt_parsed_data->peer_info_map[peer_info_key]);
            libparsebgp_parse_bgp_init(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.bgp_msg, &p_entry, "",
                                       &mrt_parsed_data->peer_info_map[peer_info_key]);
            uint32_t asn = (mrt_parsed_data->c_hdr.sub_type > 5) ? mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.local_asn :
                           mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_asn;
            if (libparsebgp_parse_bgp_parse_msg_from_mrt(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.bgp_msg, buffer,
                                                         mrt_data_len, asn, mrt_parsed_data->c_hdr.sub_type > 5) == BGP_MSG_OPEN) {
                /*mrt_parsed_data->up_event.local_asn = mrt_parsed_data->bgp4mp_mssg.local_asn;
                mrt_parsed_data->up_event.remote_asn = mrt_parsed_data->bgp4mp_mssg.peer_asn;
                memcpy(&mrt_parsed_data->up_event.local_ip, mrt_parsed_data->bgp4mp_mssg.local_ip, 40);*/
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

static void libparsebgp_parse_mrt_parse_common_header(u_char *& buffer, int& buf_len, libparsebgp_mrt_common_hdr *mrt_parsed_hdr) {

    if (extract_from_buffer(buffer, buf_len, &mrt_parsed_hdr, 12) != 12)
        throw "Error in parsing MRT common header";

    SWAP_BYTES(&mrt_parsed_hdr->len);
    SWAP_BYTES(&mrt_parsed_hdr->type);
    SWAP_BYTES(&mrt_parsed_hdr->sub_type);
    SWAP_BYTES(&mrt_parsed_hdr->time_stamp);

    mrt_len = mrt_parsed_hdr->len;
    if (mrt_parsed_hdr->type == mrt_type::BGP4MP_ET || mrt_parsed_hdr->type == mrt_type::ISIS_ET || mrt_parsed_hdr->type == mrt_type::OSPFv3_ET) {
        if (extract_from_buffer(buffer, buf_len, &mrt_parsed_hdr->microsecond_timestamp, 4) != 4)
            throw "Error in parsing MRT Common header: microsecond timestamp";
        SWAP_BYTES(&mrt_parsed_hdr->microsecond_timestamp);
        mrt_len -= 4;
    }
    else
        mrt_parsed_hdr->microsecond_timestamp = 0;

    mrt_sub_type = mrt_parsed_hdr->sub_type;
}

static void libparsebgp_parse_mrt_parse_table_dump(u_char *buffer, int& buf_len, libparsebgp_table_dump_message *table_dump_msg) {
    string peer_info_key;
    u_char local_addr[16];
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->view_number, 2) != 2)
        throw "Error in parsing view number";
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->sequence, 2) != 2)
        throw "Error in parsing sequence";

    //parsing prefix in local address variable
    if ( extract_from_buffer(buffer, buf_len, &local_addr, 16) != 16)
        throw "Error in parsing prefix in IPv4";

    switch (mrt_sub_type) {
        case AFI_IPv4:{
            snprintf(table_dump_msg->prefix, sizeof(table_dump_msg->prefix), "%d.%d.%d.%d",
                     local_addr[12], local_addr[13], local_addr[14],
                     local_addr[15]);
            break;
        }
        case AFI_IPv6:{
            inet_ntop(AF_INET6, local_addr, table_dump_msg->prefix, sizeof(table_dump_msg->prefix));
            break;
        }
        default: {
            throw "Address family is unexpected as per rfc6396";
        }
    }
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->prefix_len, 1) != 1)
        throw "Error in parsing prefix length";

    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->status, 1) != 1)
        throw "Error in parsing status";

    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->originated_time, 4) != 4)
        throw "Error in parsing originated time";

    //parsing prefix in local address variable
    if ( extract_from_buffer(buffer, buf_len, &local_addr, 16) != 16)
        throw "Error in parsing prefix in IPv4";

    switch (mrt_sub_type) {
        case AFI_IPv4:{
            snprintf(table_dump_msg->peer_ip, sizeof(table_dump_msg->peer_ip), "%d.%d.%d.%d",
                     local_addr[12], local_addr[13], local_addr[14],
                     local_addr[15]);
            break;
        }
        case AFI_IPv6:{
            inet_ntop(AF_INET6, local_addr, table_dump_msg->peer_ip, sizeof(table_dump_msg->peer_ip));
            break;
        }
        default: {
            throw "Address family is unexpected as per rfc6396";
        }
    }

    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->peer_as, 2) != 2)
        throw "Error in parsing peer AS";

    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->attribute_len, 2) != 2)
        throw "Error in parsing attribute length";

    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->bgp_attribute,
                            table_dump_msg->attribute_len) != table_dump_msg->attribute_len)
        throw "Error in parsing attribute";

//    //TODO: Need to change this after update message is fixed
//    peer_info_key =  mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_ip;
//    libparsebgp_update_msg_data u_msg;
//    libparsebgp_update_msg_init(&u_msg, table_dump_msg->peer_ip, "", &mrt_parsed_data->peer_info_map[peer_info_key]);
//    libparsebgp_update_msg_parse_attributes(&u_msg, table_dump_msg->bgp_attribute, table_dump_msg->attribute_len,
//                                            mrt_parsed_data->bgp_msg.parsed_data, mrt_parsed_data->bgp_msg.has_end_of_rib_marker);
}

static void libparsebgp_parse_mrt_parse_peer_index_table(unsigned char *buffer, int& buf_len, libparsebgp_peer_index_table *peer_index_table) {
    uint16_t count = 0;
    uint8_t  AS_num;
    uint8_t  Addr_fam;

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->collector_bgp_id, 4) != 4)
        throw "Error in parsing collector_BGPID";

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->view_name_length, 2) != 2)
        throw "Error in parsing view_name_length";

    if (peer_index_table->view_name_length) {
        if (extract_from_buffer(buffer, buf_len, &peer_index_table->view_name,
                                peer_index_table->view_name_length) !=
                peer_index_table->view_name_length)
            throw "Error in parsing view_name";
    }

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->peer_count, 2) != 2)
        throw "Error in parsing peer count";

    SWAP_BYTES(&peer_index_table->peer_count);

    while (count < peer_index_table->peer_count) {
        peer_entry *p_entry = new peer_entry;
        if (extract_from_buffer(buffer, buf_len, &p_entry->peer_type, 1) != 1)
            throw "Error in parsing collector_BGPID";

        AS_num = p_entry->peer_type & 0x02 ? 4 : 2; //using 32 bits and 16 bits.
        Addr_fam = p_entry->peer_type & 0x01 ? AFI_IPv6:AFI_IPv4;

        if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_bgp_id, 4) != 4)
            throw "Error in parsing local address in peer_BGPID";

        switch (Addr_fam) {
            case AFI_IPv4:{
                u_char local_addr[4];
                if ( extract_from_buffer(buffer, buf_len, &local_addr, 4) != 4)
                    throw "Error in parsing local address in IPv4";
//                inet_ntop(AF_INET, local_addr, p_entry->peer_IP, sizeof(local_addr));
                snprintf(p_entry->peer_ip, sizeof(p_entry->peer_ip), "%d.%d.%d.%d",
                         local_addr[0], local_addr[1], local_addr[2],
                         local_addr[3]);
                break;
            }
            case AFI_IPv6:{
                u_char local_addr[6];
                if ( extract_from_buffer(buffer, buf_len, &local_addr, 6) != 6)
                    throw "Error in parsing local address in IPv4";
                inet_ntop(AF_INET6, local_addr, p_entry->peer_ip, sizeof(local_addr));
                break;
            }
            default: {
                throw "Address family is unexpected as per rfc6396";
            }
        }
        if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_as32, AS_num) != AS_num)
            throw "Error in parsing local address in IPv4";

        peer_index_table->peer_entries.push_back(*p_entry);
        delete p_entry;
        count++;
    }
}

static void libparsebgp_parse_mrt_parse_rib_unicast(unsigned char *buffer, int& buf_len, libparsebgp_rib_entry_header *rib_entry_data) {
    uint16_t count = 0;
    string peer_info_key;

    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->sequence_number, 4) != 4)
        throw "Error in parsing sequence number";

    SWAP_BYTES(&rib_entry_data->sequence_number);

    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->prefix_length, 1) != 1)
        throw "Error in parsing view_name_length";

    u_char local_addr[rib_entry_data->prefix_length/8];

    if (extract_from_buffer(buffer, buf_len, &local_addr, rib_entry_data->prefix_length/8) !=
            rib_entry_data->prefix_length/8)
        throw "Error in parsing prefix";

    switch (mrt_sub_type) {
        case RIB_IPV4_UNICAST:
            inet_ntop(AF_INET, local_addr, rib_entry_data->prefix,
                      sizeof(rib_entry_data->prefix));
            break;
        case RIB_IPV6_UNICAST:
            inet_ntop(AF_INET6, local_addr, rib_entry_data->prefix,
                      sizeof(rib_entry_data->prefix));
            break;
    }
    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->entry_count, 2) != 2)
        throw "Error in parsing peer count";

    SWAP_BYTES(&rib_entry_data->entry_count);

    while (count < rib_entry_data->entry_count) {
        rib_entry *r_entry = new rib_entry;
        if (extract_from_buffer(buffer, buf_len, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        SWAP_BYTES(&r_entry->peer_index);

        if ( extract_from_buffer(buffer, buf_len, &r_entry->originated_time, 4) != 4)
            throw "Error in parsing originatedTime";

        SWAP_BYTES(&r_entry->originated_time);

        if ( extract_from_buffer(buffer, buf_len, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing attribute_len";

        SWAP_BYTES(&r_entry->attribute_len);

//        if ( extract_from_buffer(buffer, buf_len, &r_entry->bgp_attribute, r_entry->attribute_len) != r_entry->attribute_len)
//            throw "Error in parsing bgp_attribute";

        //TODO: waiting for update to be final
//        peer_info_key =  mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_ip; //TODO: Need to change this
//        libparsebgp_update_msg_data u_msg;
//        //TODO: peer_ip not present
//        libparsebgp_update_msg_init(&u_msg, mrt_parsed_data->parsed_data.table_dump_v2_msg.rib_entry_hdr.peer_ip, "",
//                                    &mrt_parsed_data->peer_info_map[peer_info_key]);
//        libparsebgp_update_msg_parse_attributes(&u_msg, buffer, r_entry->attribute_len, r_entry->parsed_data, r_entry->end_of_rib_marker);
//        //UpdateMsg *uMsg= new UpdateMsg(mrt_parsed_data->table_dump.peer_ip, &mrt_parsed_data->peer_info_map[peer_info_key]);
//        //uMsg->parseAttributes(buffer, r_entry->attribute_len, r_entry->parsed_data, r_entry->end_of_rib_marker);
//        //LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr, router_addr.c_str(), read_size, (size - read_size));

        rib_entry_data->rib_entries.push_back(*r_entry);
        delete r_entry;
        count++;
    }
}

static void libparsebgp_parse_mrt_parse_rib_generic(unsigned char *buffer, int& buf_len, libparsebgp_rib_generic_entry_header *rib_gen_entry_hdr) {
    uint16_t count = 0;
    uint8_t  IPlen;
    u_char* local_addr;
    string peer_info_key;

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->sequence_number, 4) != 4)
        throw "Error in parsing sequence number";

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->address_family_identifier, 2) != 2)
        throw "Error in parsing address_family_identifier";

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->subsequent_afi, 1) != 1)
        throw "Error in subsequent AFI";

    //TODO : nlri thing, have to check with the bgp code

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->entry_count, 2) != 2)
        throw "Error in parsing peer count";

    SWAP_BYTES(&rib_gen_entry_hdr->entry_count);

    while (count < rib_gen_entry_hdr->entry_count) {
        rib_entry *r_entry = new rib_entry;
        if (extract_from_buffer(buffer, buf_len, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        SWAP_BYTES(&r_entry->peer_index);

        if ( extract_from_buffer(buffer, buf_len, &r_entry->originated_time, 4) != 4)
            throw "Error in parsing originatedTime";

        SWAP_BYTES(&r_entry->originated_time);

        if ( extract_from_buffer(buffer, buf_len, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing attribute_len";

        SWAP_BYTES(&r_entry->attribute_len);

//        if ( extract_from_buffer(buffer, buf_len, &r_entry->bgp_attribute, r_entry->attribute_len) != r_entry->attribute_len)
//            throw "Error in parsing bgp_attribute";

        //TODO: waiting for update to be final
//        peer_info_key =  mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_mssg.peer_ip; //TODO: Need to change this
//        libparsebgp_update_msg_data u_msg;
//        //TODO: peer_ip not present
//        libparsebgp_update_msg_init(&u_msg, mrt_parsed_data->parsed_data.table_dump_v2_msg.rib_entry_hdr.peer_ip, "",
//                                    &mrt_parsed_data->peer_info_map[peer_info_key]);
//        libparsebgp_update_msg_parse_attributes(&u_msg, buffer, r_entry->attribute_len, r_entry->parsed_data, r_entry->end_of_rib_marker);
//        //UpdateMsg *uMsg= new UpdateMsg(mrt_parsed_data->table_dump.peer_ip, &mrt_parsed_data->peer_info_map[peer_info_key]);
//        //uMsg->parseAttributes(buffer, r_entry->attribute_len, r_entry->parsed_data, r_entry->end_of_rib_marker);
//        //LOG_NOTICE("%s: rtr=%s: Failed to parse the update message, read %d expected %d", p_entry->peer_addr, router_addr.c_str(), read_size, (size - read_size));

        rib_gen_entry_hdr->rib_entries.push_back(*r_entry);
        delete r_entry;
        count++;
    }
}

static void libparsebgp_parse_mrt_parse_table_dump_v2(u_char *buffer, int& buf_len, libparsebgp_parsed_table_dump_v2 *table_dump_v2_msg) {
    switch (mrt_sub_type) {
        case PEER_INDEX_TABLE:
            libparsebgp_parse_mrt_parse_peer_index_table(buffer,buf_len, &table_dump_v2_msg->peer_index_tbl);
            break;

        case RIB_IPV4_UNICAST:
            libparsebgp_parse_mrt_parse_rib_unicast(buffer,buf_len, &table_dump_v2_msg->rib_entry_hdr);
            break;
        case RIB_IPV6_UNICAST:
            libparsebgp_parse_mrt_parse_rib_unicast(buffer,buf_len, &table_dump_v2_msg->rib_entry_hdr);
            break;

        case RIB_IPV4_MULTICAST: //TO DO: due to lack of multicast data
        case RIB_IPV6_MULTICAST: //TO DO: due to lack of multicast data
        case RIB_GENERIC:
            libparsebgp_parse_mrt_parse_rib_generic(buffer,buf_len, &table_dump_v2_msg->rib_generic_entry_hdr);
            break;
    }
}

bool libparsebgp_parse_mrt_parse_msg(u_char *&buffer, int& buf_len, libparsebgp_parse_mrt_parsed_data *mrt_parsed_data) {
    //bool rval = true;
    try {
        libparsebgp_parse_mrt_parse_common_header(buffer, buf_len, &mrt_parsed_data->c_hdr);

        switch (mrt_parsed_data->c_hdr.type) {
            case OSPFv2 :     //do nothing
            case OSPFv3 :     //do nothing
            case OSPFv3_ET : { //do nothing
                break;
            }

            case TABLE_DUMP : {
                libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
                libparsebgp_parse_mrt_parse_table_dump(mrt_data, mrt_data_len, &mrt_parsed_data->parsed_data.table_dump);
                break;
            }

            case TABLE_DUMP_V2 : {
                libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
                libparsebgp_parse_mrt_parse_table_dump_v2(mrt_data, mrt_data_len, &mrt_parsed_data->parsed_data.table_dump_v2);
                break;
            }

            case BGP4MP :
            case BGP4MP_ET : {
                libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
                libparsebgp_parse_mrt_parse_bgp4mp(mrt_data, mrt_data_len, mrt_parsed_data);
                break;
            }

            case ISIS :
            case ISIS_ET : {
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
    //parseMRT *p = new parseMRT();
    int len = 99;
    libparsebgp_parse_mrt_parsed_data mrt_data;
    try {
        mrt_data = parse_mrt_wrapper(tmp, len);
        //if (p->libparsebgp_parse_mrt_parse_msg(tmp, len))
            cout << "Hello Ojas and Induja"<<endl;
        //else
        //    cout << "Oh no!"<<endl;
    }
    catch (char const *str) {
        cout << "Crashed!" << str <<endl;
    }
//    cout << "Peer Address" << int(.peer_index_tbl.peer_entries.begin()->peer_type);
   //cout<<"Peer Address "<<int(p->peer_index_table.peer_entries.begin()->peer_type);
//    cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
//    cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
    return 1;
}