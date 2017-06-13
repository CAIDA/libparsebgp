/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/parse_mrt.h"
#include <arpa/inet.h>

/**
 * Destructor function to free memory allocated to libparsebgp_parse_mrt_parsed_data
 */
void libparsebgp_parse_mrt_destructor(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data) {
    switch (mrt_parsed_data->c_hdr.type) {
        case TABLE_DUMP: {
            for (int i = 0; i < mrt_parsed_data->parsed_data.table_dump.bgp_attrs_count; ++i) {
                libparsebgp_parse_update_path_attrs_destructor(mrt_parsed_data->parsed_data.table_dump.bgp_attrs[i]);
            }
            free(mrt_parsed_data->parsed_data.table_dump.bgp_attrs);
            mrt_parsed_data->parsed_data.table_dump.bgp_attrs = NULL;
//            free(&mrt_parsed_data->parsed_data.table_dump);
            break;
        }
        case TABLE_DUMP_V2: {
            switch (mrt_parsed_data->c_hdr.sub_type) {
                case PEER_INDEX_TABLE: {
//                    free(mrt_parsed_data->parsed_data.table_dump_v2.peer_index_tbl.peer_entries);
//                    for (int i = 0; i < mrt_parsed_data->parsed_data.table_dump_v2.peer_index_tbl.peer_count; ++i) {
//                        free(&mrt_parsed_data->parsed_data.table_dump_v2.peer_index_tbl.peer_entries[i]);
//
//                    }
                    free(mrt_parsed_data->parsed_data.table_dump_v2.peer_index_tbl.peer_entries);
                    mrt_parsed_data->parsed_data.table_dump_v2.peer_index_tbl.peer_entries = NULL;
//                    free(&mrt_parsed_data->parsed_data.table_dump_v2.peer_index_tbl);
                    break;
                }
                case RIB_IPV4_UNICAST:
                case RIB_IPV6_UNICAST: {
                    for (int i = 0; i < mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.entry_count; ++i) {
                        for (int j = 0; j < mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs_count; ++j) {
                            libparsebgp_parse_update_path_attrs_destructor(
                                    mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[j]);
                        }
                        free(mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs);
                        mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs = NULL;
                    }
                    free(mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.rib_entries);
                    mrt_parsed_data->parsed_data.table_dump_v2.rib_entry_hdr.rib_entries = NULL;
                    break;
                }
                case RIB_GENERIC: {
                    for (int i = 0; i < mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.entry_count; ++i) {
                        for (int j = 0; j < mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs_count; ++j) {
                            libparsebgp_parse_update_path_attrs_destructor(
                                    mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]);
                        }
                        free(mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs);
                        mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs = NULL;
                    }
                    free(mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries);
                    mrt_parsed_data->parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries = NULL;
                    break;
                }
            }
            break;
        }
        case BGP4MP_ET:
        case BGP4MP: {
            switch (mrt_parsed_data->c_hdr.sub_type) {
                case BGP4MP_MESSAGE:
                case BGP4MP_MESSAGE_AS4:
                case BGP4MP_MESSAGE_LOCAL:
                case BGP4MP_MESSAGE_AS4_LOCAL: {
                    libparsebgp_parse_bgp_destructor(mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.bgp_msg);
                    break;
                }
            }
            break;
        }
    }
}

/**
 * Buffer remaining MRT message
 */
static ssize_t libparsebgp_parse_mrt_buffer_mrt_message(u_char *& buffer, int& buf_len) {
    if (mrt_len <= 0)
        return 0;

    if (mrt_len > sizeof(mrt_data)) {
        //throw "MRT message length is too large for buffer, invalid MRT sender";
        return INCOMPLETE_MSG;
    }

    if ((mrt_data_len=extract_from_buffer(buffer, buf_len, mrt_data, mrt_len)) != mrt_len) { ;
        //throw "Error while reading MRT data from buffer";
        return ERR_READING_MSG;
    }

    // Indicate no more data is left to read
    mrt_len = 0;
    return 0;
}

/**
 * Parse the BGP4MP message
 */
static ssize_t libparsebgp_parse_mrt_parse_bgp4mp(unsigned char* buffer, int& buf_len, libparsebgp_parse_mrt_parsed_data *mrt_parsed_data) {
    ssize_t read_size = 0, ret_val = 0;
    switch (mrt_parsed_data->c_hdr.sub_type) {
        case BGP4MP_STATE_CHANGE:
        case BGP4MP_STATE_CHANGE_AS4: {
            mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg ={0};
            int asn_len = (mrt_parsed_data->c_hdr.sub_type == BGP4MP_STATE_CHANGE_AS4) ? 4 : 2;
            int ip_addr_len = 4;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_asn, asn_len) != asn_len)
                return ERR_READING_MSG;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.local_asn, asn_len) != asn_len)
                return ERR_READING_MSG;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.interface_index, 2) != 2)
                return ERR_READING_MSG;
                //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.address_family, 2) != 2)
                return ERR_READING_MSG;
                //throw;
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_asn, asn_len);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.local_asn, asn_len);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.interface_index, 2);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.address_family, 2);
            if (mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_ip, ip_addr_len) != ip_addr_len)
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.local_ip, ip_addr_len) != ip_addr_len)
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state, 2) != 2)
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state, 2) != 2)
                return ERR_READING_MSG; //throw;
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state,2);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state,2);
            read_size += 2*asn_len + ip_addr_len*2 + 8;
            break;
        }
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4:
        case BGP4MP_MESSAGE_LOCAL:
        case BGP4MP_MESSAGE_AS4_LOCAL: {
            mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg = {0};
            int asn_len = (mrt_parsed_data->c_hdr.sub_type == BGP4MP_MESSAGE_AS4 || mrt_parsed_data->c_hdr.sub_type == BGP4MP_MESSAGE_AS4_LOCAL) ? 4 : 2;
            int ip_addr_len = 4;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.peer_asn, asn_len) != asn_len)
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.local_asn, asn_len) != asn_len) //Peer asn
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.interface_index, 2) != 2)
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.address_family, 2) != 2)
                return ERR_READING_MSG; //throw;
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.peer_asn, asn_len);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.local_asn, asn_len);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.interface_index,2);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.address_family,2);
            if (mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.peer_ip, ip_addr_len) != ip_addr_len)
                return ERR_READING_MSG; //throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.local_ip, ip_addr_len) != ip_addr_len)
                return ERR_READING_MSG; //throw;
            read_size += 2*asn_len + 2*ip_addr_len + 4;
            ret_val = libparsebgp_parse_bgp_parse_msg(mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.bgp_msg, buffer, buf_len,
                                                      mrt_parsed_data->c_hdr.sub_type > 5);
            if (ret_val < 0)
                return ret_val;
            read_size += ret_val;
            break;
        }
        default: {
            return INVALID_MSG;
            //throw "Subtype for BGP4MP not supported";
        }
    }
    return read_size;
}

/**
 * Process the incoming MRT message header
 */
static ssize_t libparsebgp_parse_mrt_parse_common_header(u_char *& buffer, int& buf_len, libparsebgp_mrt_common_hdr &mrt_parsed_hdr) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &mrt_parsed_hdr, 12) != 12)
        return ERR_READING_MSG; //throw "Error in parsing MRT common header";
    read_size+=12;
    SWAP_BYTES(&mrt_parsed_hdr.len, 4);
    SWAP_BYTES(&mrt_parsed_hdr.type, 2);
    SWAP_BYTES(&mrt_parsed_hdr.sub_type, 2);
    SWAP_BYTES(&mrt_parsed_hdr.time_stamp, 4);

    mrt_len = mrt_parsed_hdr.len;
    if (mrt_parsed_hdr.type == BGP4MP_ET || mrt_parsed_hdr.type == ISIS_ET || mrt_parsed_hdr.type == OSPFv3_ET) {
        if (extract_from_buffer(buffer, buf_len, &mrt_parsed_hdr.microsecond_timestamp, 4) != 4)
            return ERR_READING_MSG; //throw "Error in parsing MRT Common header: microsecond timestamp";
        read_size+=4;
        SWAP_BYTES(&mrt_parsed_hdr.microsecond_timestamp,4);
        mrt_len -= 4;
    }
    else
        mrt_parsed_hdr.microsecond_timestamp = 0;
    mrt_sub_type = mrt_parsed_hdr.sub_type;

    if(mrt_len > buf_len)       //checking if the complete message is contained in the buffer
        return INCOMPLETE_MSG;

    return read_size;
}

/**
 * Process the incoming Table Dump message
 */
static ssize_t libparsebgp_parse_mrt_parse_table_dump(u_char *buffer, int& buf_len, libparsebgp_table_dump_message *table_dump_msg) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg, 4) != 4)
        return ERR_READING_MSG; //throw "Error in parsing view number";
    read_size+=4;

    switch (mrt_sub_type) {
        case AFI_IPv4:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->prefix, 4) != 4)
                return ERR_READING_MSG; //throw "Error in parsing prefix in IPv4";
            read_size+=4;
            break;
        }
        case AFI_IPv6:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->prefix, 16) != 16)
                return ERR_READING_MSG; //throw "Error in parsing prefix in IPv6";
            read_size+=16;
            break;
        }
        default: {
            return INVALID_MSG; //throw "Address family is unexpected as per rfc6396";
        }
    }
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->prefix_len, 1) != 1)
        return ERR_READING_MSG; //throw "Error in parsing prefix length";
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->status, 1) != 1)
        return ERR_READING_MSG; //throw "Error in parsing status";
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->originated_time, 4) != 4)
        return ERR_READING_MSG; //throw "Error in parsing originated time";

    read_size+=6;

    switch (mrt_sub_type) {
        case AFI_IPv4:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->peer_ip, 4) != 4)
                return ERR_READING_MSG; //throw "Error in parsing prefix in IPv4";
            read_size+=4;
            break;
        }
        case AFI_IPv6:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->peer_ip, 16) != 16)
                return ERR_READING_MSG; //throw "Error in parsing prefix in IPv4";
            read_size+=16;
            break;
        }
        default: {
            return INVALID_MSG; //throw "Address family is unexpected as per rfc6396";
        }
    }

    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->peer_as, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing peer AS";
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg->attribute_len, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing attribute length";

    read_size+=4;

    bool has_end_of_rib_marker;
//    libparsebgp_addpath_map add_path_map;
    libparsebgp_update_msg_parse_attributes(table_dump_msg->bgp_attrs, buffer, table_dump_msg->attribute_len, has_end_of_rib_marker, &table_dump_msg->bgp_attrs_count);
    read_size += table_dump_msg->attribute_len;
    buf_len-=table_dump_msg->attribute_len;

    return read_size;
}

/**
 * Process the incoming Table Dump message
 */
static ssize_t libparsebgp_parse_mrt_parse_peer_index_table(unsigned char *buffer, int& buf_len, libparsebgp_peer_index_table *peer_index_table) {
    uint16_t count = 0;
    int  as_num = 0;
    uint8_t  addr_fam;
    int read_size=0;

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->collector_bgp_id, 4) != 4)
        return ERR_READING_MSG; //throw "Error in parsing collector_BGPID and view_name_length";
    read_size+=4;

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->view_name_length, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing collector_BGPID and view_name_length";
    read_size+=2;

    SWAP_BYTES(&peer_index_table->view_name_length);
    if (peer_index_table->view_name_length) {
        if (extract_from_buffer(buffer, buf_len, &peer_index_table->view_name, peer_index_table->view_name_length) !=
                peer_index_table->view_name_length)
            return ERR_READING_MSG; //throw "Error in parsing view_name";
        read_size+=peer_index_table->view_name_length;
    }

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->peer_count, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing peer count";
    read_size+=2;
    SWAP_BYTES(&peer_index_table->peer_count, 2);

    peer_index_table->peer_entries = (peer_entry *)malloc(peer_index_table->peer_count*sizeof(peer_entry));
    peer_entry *p_entry = (peer_entry *)malloc(sizeof(peer_entry));

    memset(peer_index_table->peer_entries ,0 , sizeof(peer_index_table->peer_entries));

    while (count < peer_index_table->peer_count) {
        memset(p_entry, 0, sizeof(peer_entry));

        if (extract_from_buffer(buffer, buf_len, &p_entry->peer_type, 1) != 1)
            return ERR_READING_MSG; //throw "Error in parsing collector_BGPID";
        read_size+=1;

        as_num = p_entry->peer_type & 0x02 ? 4 : 2; //using 32 bits and 16 bits.
        addr_fam = p_entry->peer_type & 0x01 ? AFI_IPv6:AFI_IPv4;

        if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_bgp_id, 4) != 4)
            return ERR_READING_MSG; //throw "Error in parsing local address in peer_BGPID";
        read_size+= 4;

        switch (addr_fam) {
            case AFI_IPv4:{
                if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_ip, 4) != 4)
                    return ERR_READING_MSG; //throw "Error in parsing local address in IPv4";
                read_size+=4;
                break;
            }
            case AFI_IPv6:{
                if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_ip, 16) != 16)
                    return ERR_READING_MSG; //throw "Error in parsing local address in IPv4";
                read_size+=16;
                break;
            }
            default: {
                return INVALID_MSG; //throw "Address family is unexpected as per rfc6396";
            }
        }
        if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_as, as_num) != as_num)
            return ERR_READING_MSG; //throw "Error in parsing local address in IPv4";
        read_size+=as_num;
        peer_index_table->peer_entries[count++] = *p_entry;
    }
    free(p_entry);
    return read_size;
}

/**
 * Process the incoming Table Dump message
 */
static ssize_t libparsebgp_parse_mrt_parse_rib_unicast(unsigned char *buffer, int& buf_len, libparsebgp_rib_entry_header *rib_entry_data) {
    uint16_t count = 0;
    int addr_bytes=0;
    int read_size=0;

    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->sequence_number, 4) != 4)
        return ERR_READING_MSG; //throw "Error in parsing sequence number";

    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->prefix_length, 1) != 1)
        return ERR_READING_MSG; //throw "Error in parsing sequence number";

    SWAP_BYTES(&rib_entry_data->sequence_number, 4);
    read_size+=5;

    if (rib_entry_data->prefix_length>0) {
        addr_bytes = rib_entry_data->prefix_length / 8;
        if (rib_entry_data->prefix_length % 8)
            ++addr_bytes;
        u_char local_addr[addr_bytes];


        if (extract_from_buffer(buffer, buf_len, &local_addr, addr_bytes) != addr_bytes)
            return ERR_READING_MSG; //throw "Error in parsing prefix";

        read_size += addr_bytes;

        switch (mrt_sub_type) {
            case RIB_IPV4_UNICAST:
                inet_ntop(AF_INET, local_addr, rib_entry_data->prefix,sizeof(rib_entry_data->prefix));
                break;
            case RIB_IPV6_UNICAST:
                inet_ntop(AF_INET6, local_addr, rib_entry_data->prefix,sizeof(rib_entry_data->prefix));
                break;
        }
    }
    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->entry_count, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing peer count";

    read_size+=2;
    SWAP_BYTES(&rib_entry_data->entry_count, 2);

    rib_entry_data->rib_entries = (rib_entry *)malloc(rib_entry_data->entry_count*sizeof(rib_entry));
    rib_entry *r_entry = (rib_entry *)malloc(sizeof(rib_entry));

    memset(rib_entry_data->rib_entries, 0, sizeof(rib_entry_data->rib_entries));

    while (count < rib_entry_data->entry_count) {
        memset(r_entry, 0, sizeof(rib_entry));

        if (extract_from_buffer(buffer, buf_len, &r_entry->peer_index, 2) != 2)
            return ERR_READING_MSG; //throw "Error in parsing peer Index";

        if (extract_from_buffer(buffer, buf_len, &r_entry->originated_time, 4) != 4)
            return ERR_READING_MSG; //throw "Error in parsing originated time";

        if (extract_from_buffer(buffer, buf_len, &r_entry->attribute_len, 2) != 2)
            return ERR_READING_MSG; //throw "Error in parsing attribute len";

        read_size+=8;

        SWAP_BYTES(&r_entry->peer_index, 2);
        SWAP_BYTES(&r_entry->originated_time, 4);
        SWAP_BYTES(&r_entry->attribute_len, 2);

        bool has_end_of_rib_marker;
//        libparsebgp_addpath_map add_path_map;
        libparsebgp_update_msg_parse_attributes(r_entry->bgp_attrs, buffer, r_entry->attribute_len, has_end_of_rib_marker, &r_entry->bgp_attrs_count);
        read_size += r_entry->attribute_len;
        buf_len-=r_entry->attribute_len;

        rib_entry_data->rib_entries[count++]=*r_entry;
    }
    free(r_entry);
    return read_size;
}

/**
 * Process the incoming RIB generic entry header
 */
static ssize_t libparsebgp_parse_mrt_parse_rib_generic(unsigned char *buffer, int& buf_len, libparsebgp_rib_generic_entry_header *rib_gen_entry_hdr) {
    uint16_t count = 0;
    int read_size=0;
    string peer_info_key;

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->sequence_number, 4) != 4)
        return ERR_READING_MSG; //throw "Error in parsing sequence number";
    read_size+=4;

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->address_family_identifier, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing sequence number";
    read_size+=2;

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->subsequent_afi, 1) != 1)
        return ERR_READING_MSG; //throw "Error in parsing sequence number";
    read_size+=1;

    rib_gen_entry_hdr->nlri_entry.len = *buffer++;
    read_size++;

    // Figure out how many bytes the bits requires
    int addr_bytes = rib_gen_entry_hdr->nlri_entry.len / 8;
    if (rib_gen_entry_hdr->nlri_entry.len % 8)
        ++addr_bytes;

    if (addr_bytes <= 4) {
        memcpy(&rib_gen_entry_hdr->nlri_entry.prefix, buffer, addr_bytes);
        read_size += addr_bytes;
        buffer += addr_bytes;
    }
    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->entry_count, 2) != 2)
        return ERR_READING_MSG; //throw "Error in parsing peer count";
    read_size+=2;

    SWAP_BYTES(&rib_gen_entry_hdr->entry_count, 2);

    rib_gen_entry_hdr->rib_entries = (rib_entry *)malloc(rib_gen_entry_hdr->entry_count*sizeof(rib_entry));
    rib_entry *r_entry = (rib_entry *)malloc(sizeof(rib_entry));

    memset(rib_gen_entry_hdr->rib_entries, 0, sizeof(rib_gen_entry_hdr->rib_entries));

    while (count < rib_gen_entry_hdr->entry_count) {
        memset(r_entry, 0, sizeof(rib_entry));

        if (extract_from_buffer(buffer, buf_len, &r_entry->peer_index, 2) != 2)
            return ERR_READING_MSG; //throw "Error in parsing peer Index";

        if (extract_from_buffer(buffer, buf_len, &r_entry->originated_time, 4) != 4)
            return ERR_READING_MSG; //throw "Error in parsing originated time";

        if (extract_from_buffer(buffer, buf_len, &r_entry->attribute_len, 2) != 2)
            return ERR_READING_MSG; //throw "Error in parsing attribute len";

        read_size+=8;

        SWAP_BYTES(&r_entry->peer_index, 2);
        SWAP_BYTES(&r_entry->originated_time, 4);
        SWAP_BYTES(&r_entry->attribute_len, 2);

        bool has_end_of_rib_marker;
//        libparsebgp_addpath_map add_path_map;
        libparsebgp_update_msg_parse_attributes(r_entry->bgp_attrs, buffer, r_entry->attribute_len, has_end_of_rib_marker, &r_entry->bgp_attrs_count);
        read_size += r_entry->attribute_len;
        buf_len-=r_entry->attribute_len;

        rib_gen_entry_hdr->rib_entries[count++]=*r_entry;
    }
    free(r_entry);
    return read_size;
}

/**
 * Process the incoming Table Dump v2 message
 */
static ssize_t libparsebgp_parse_mrt_parse_table_dump_v2(u_char *buffer, int& buf_len, libparsebgp_parsed_table_dump_v2 *table_dump_v2_msg) {
    int ret = 0, read_size = 0;
    switch (mrt_sub_type) {
        case PEER_INDEX_TABLE: {
            ret = libparsebgp_parse_mrt_parse_peer_index_table(buffer, buf_len, &table_dump_v2_msg->peer_index_tbl);
            if (ret < 0)
                return ret;
            read_size += ret;
            break;
        }
        case RIB_IPV4_UNICAST:
        case RIB_IPV6_UNICAST: {
            ret = libparsebgp_parse_mrt_parse_rib_unicast(buffer, buf_len, &table_dump_v2_msg->rib_entry_hdr);
            if (ret < 0)
                return ret;
            read_size += ret;
            break;
        }
        case RIB_IPV4_MULTICAST: //TODO: due to lack of multicast data
        case RIB_IPV6_MULTICAST: { //TODO: due to lack of multicast data
            break;
        }
        case RIB_GENERIC: {
            ret = libparsebgp_parse_mrt_parse_rib_generic(buffer, buf_len, &table_dump_v2_msg->rib_generic_entry_hdr);
            if (ret < 0)
                return ret;
            read_size += ret;
            break;
        }
        default:
            break;
    }
    return read_size;
}

/**
 * Function to parse MRT message
 */
ssize_t libparsebgp_parse_mrt_parse_msg(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data, unsigned char *buffer, int buf_len) {
    ssize_t read_size=0, ret_val = 0;
    ret_val = libparsebgp_parse_mrt_parse_common_header(buffer, buf_len, mrt_parsed_data->c_hdr);
    if (ret_val < 0) {
        //Error found, call destructor and return error code
        libparsebgp_parse_mrt_destructor(mrt_parsed_data);
        return ret_val;
    }
    read_size += ret_val;

    switch (mrt_parsed_data->c_hdr.type) {
        case OSPFv2 :     //do nothing
        case OSPFv3 :     //do nothing
        case OSPFv3_ET : {//do nothing
            break;
        }

        case TABLE_DUMP : {
            ret_val = libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
            if (ret_val < 0) {
                read_size = ret_val;
                break;
            }
            ret_val = libparsebgp_parse_mrt_parse_table_dump(mrt_data, mrt_data_len, &mrt_parsed_data->parsed_data.table_dump);
            if (ret_val < 0)
                read_size = ret_val;
            else
                read_size += ret_val;
            break;
        }

        case TABLE_DUMP_V2 : {
            if((ret_val = libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len))<0) {
                read_size = ret_val;
                break;
            }

            ret_val = libparsebgp_parse_mrt_parse_table_dump_v2(mrt_data, mrt_data_len, &mrt_parsed_data->parsed_data.table_dump_v2);
            if (ret_val < 0)
                read_size = ret_val;
            else
                read_size += ret_val;
            break;
        }

        case BGP4MP :
        case BGP4MP_ET : {
            ret_val = libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
            if (ret_val < 0) {
                read_size = ret_val;
                break;
            }

            ret_val = libparsebgp_parse_mrt_parse_bgp4mp(mrt_data, mrt_data_len, mrt_parsed_data);
            if (ret_val < 0)
                read_size = ret_val;
            else
                read_size += ret_val;
            break;
        }
        case ISIS :
        case ISIS_ET : {
            break;  //do nothing
        }
        default: {
            //throw "MRT type is unexpected as per rfc6396";
            read_size = INVALID_MSG;
        }
    }
    if (read_size < 0) {
        libparsebgp_parse_mrt_destructor(mrt_parsed_data);
    }

    return read_size;
}

int main() {
    //len = 109;
//    u_char temp[] = {0x58, 0xb6, 0x0f, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x03, 0x96, 0x80, 0xdf, 0x33, 0x66, 0x00,
//                     0x00, 0x00, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
//                     0x00, 0x00, 0x00, 0x00, 0x8c, 0xc0, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
//                     0xd8, 0x12, 0x1f, 0x66, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x45, 0xb8, 0xc1, 0x04, 0x45, 0xb8, 0xc1,
//                     0x00, 0x00, 0x0d, 0x1c, 0x02, 0x05, 0x65, 0x6e, 0x02, 0x05, 0x65, 0x6e, 0x02, 0x00, 0x03, 0x15, 0x22,
//                     0x02, 0x0c, 0x00, 0x01, 0x3f, 0x0c, 0x00, 0x01, 0x3f, 0x00, 0x00, 0x1b, 0x6a, 0x02, 0x44, 0x43, 0x21,
//                     0x63, 0x2d, 0x3d, 0x00, 0x55, 0x00, 0x00};

//    int len = 217;
//    u_char temp[] = {0x58, 0xb6, 0x0f, 0x00, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                     0x05, 0x00, 0x14, 0x58, 0xb5, 0xe3, 0x61, 0x00, 0x27, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02,
//                     0x02, 0x00, 0x00, 0x85, 0xb0, 0x00, 0x00, 0x0d, 0xdd, 0x40, 0x03, 0x04, 0x5e, 0x9c, 0xfc, 0x12, 0x80, 0x04,
//                     0x04, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x08, 0x04, 0x85, 0xb0, 0x01, 0x4d, 0x00, 0x2a, 0x58, 0xaf, 0x4f, 0x3b,
//                     0x00, 0x30, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00,
//                     0x0d, 0x1c, 0x40, 0x03, 0x04, 0xb9, 0x2c, 0x74, 0x01, 0xc0, 0x08, 0x14, 0x0d, 0x1c, 0x00, 0x02, 0x0d, 0x1c,
//                     0x02, 0x02, 0x0d, 0x1c, 0x08, 0x43, 0xbb, 0x00, 0x00, 0x06, 0xbb, 0x00, 0x0d, 0x1c, 0x00, 0x13, 0x58, 0x91,
//                     0x2d, 0x7f, 0x00, 0x19, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x79, 0x2b,
//                     0x00, 0x00, 0x99, 0x9e, 0x40, 0x03, 0x04, 0x5b, 0xe4, 0x97, 0x01, 0x00, 0x34, 0x58, 0x90, 0x94, 0x4e, 0x00,
//                     0x15, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x06, 0x02, 0x01, 0x00, 0x00, 0x46, 0xba, 0x40, 0x03, 0x04,
//                     0xca, 0x49, 0x28, 0x2d, 0x00, 0x0e, 0x58, 0xb5, 0x9c, 0xbd, 0x00, 0x19, 0x40, 0x01, 0x01, 0x00, 0x50, 0x02,
//                     0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x51, 0x23, 0x00, 0x00, 0x0d, 0x1c, 0x40, 0x03, 0x04, 0x50, 0xf1, 0xb0,
//                     0x1f};

    int len = 99;
    u_char temp[] = {0x58, 0xb6, 0x12, 0x84, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0xe4, 0x8f,
                     0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x00, 0x01, 0x67, 0xf7, 0x03, 0x2d, 0x80, 0xdf, 0x33, 0x66,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0x00, 0x43, 0x02, 0x00, 0x04, 0x18, 0xa8, 0xb5, 0x24, 0x00, 0x24, 0x40, 0x01, 0x01, 0x00, 0x40,
                     0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0xe4, 0x8f, 0x00, 0x00, 0x1b, 0x1b, 0x00, 0x04, 0x01, 0x04,
                     0x00, 0x00, 0x6e, 0xb7, 0x00, 0x04, 0x05, 0x73, 0x40, 0x03, 0x04, 0x67, 0xf7, 0x03, 0x2d, 0x18,
                     0xbf, 0x05, 0xaa};

//    int len = 75;
//    u_char temp[] = {0x58, 0x67, 0xb5, 0x31, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x07, 0x2c,
//                     0x00, 0x00, 0x31, 0x6e, 0x00, 0x00, 0x00, 0x02, 0x2a, 0x01, 0x02, 0xa8, 0x00, 0x00, 0x00, 0x00,
//                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x06, 0x7c, 0x02, 0xe8, 0x00, 0x02,
//                     0xff, 0xff, 0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04};

//    int len = 217;
//unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0x06, 0x04};
//len = 186;
//unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xdf, 0x33, 0x67, 0xd0, 0x40, 0x00, 0xb3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x41, 0x01, 0x04, 0x19, 0x2f, 0x02, 0x58, 0x80, 0xdf, 0x33, 0x67, 0x24, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x19, 0x2f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x35, 0x01, 0x04, 0x0d, 0x1c, 0x00, 0xb4, 0x04, 0x45, 0xb8, 0xc1, 0x18, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00};
//len = 228;
//unsigned char temp[] = {0x03, 0x00, 0x00, 0x00, 0xe4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x92, 0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x92, 0x03, 0x7f, 0xff, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xeb, 0x80, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xeb, 0x80, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x80, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x80, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x80, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xb4};
//len = 870;
//unsigned char temp[] = {0x03, 0x00, 0x00, 0x03, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x04, 0x45, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03, 0x36, 0x02, 0x00, 0x00, 0x00, 0x44, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x08, 0x02, 0x03, 0x0d, 0x1c, 0x0b, 0x62, 0x40, 0x7d, 0x40, 0x03, 0x04, 0x04, 0x45, 0xb8, 0xc1, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x08, 0x24, 0x0b, 0x62, 0x01, 0x9a, 0x0b, 0x62, 0x04, 0xb3, 0x0b, 0x62, 0x08, 0x99, 0x0b, 0x62, 0x0c, 0x80, 0x0d, 0x1c, 0x00, 0x03, 0x0d, 0x1c, 0x00, 0x56, 0x0d, 0x1c, 0x02, 0x3f, 0x0d, 0x1c, 0x02, 0x9a, 0x0d, 0x1c, 0x07, 0xdc, 0x17, 0x36, 0xe7, 0x82, 0x16, 0x34, 0xda, 0x40, 0x15, 0x34, 0xda, 0x38, 0x16, 0x34, 0xda, 0x34, 0x18, 0x36, 0xb6, 0xf4, 0x18, 0x34, 0xde, 0xf2, 0x17, 0x34, 0xde, 0xf0, 0x18, 0x34, 0xde, 0xef, 0x17, 0x34, 0xde, 0xec, 0x17, 0x34, 0xde, 0xe8, 0x16, 0x34, 0xde, 0xe4, 0x17, 0x34, 0xde, 0xe2, 0x18, 0x34, 0x54, 0x49, 0x18, 0x36, 0xef, 0x27, 0x18, 0x36, 0xef, 0x25, 0x18, 0x36, 0xef, 0x22, 0x18, 0x36, 0xef, 0x20, 0x18, 0x36, 0xe7, 0x9f, 0x18, 0x36, 0xe7, 0x9e, 0x18, 0x36, 0xe7, 0x9d, 0x18, 0x36, 0xe7, 0x9a, 0x18, 0x36, 0xe7, 0x99, 0x18, 0x36, 0xe7, 0x98, 0x18, 0x36, 0xe7, 0x97, 0x18, 0x36, 0xe7, 0x94, 0x18, 0x36, 0xe7, 0x93, 0x18, 0x36, 0xe7, 0x92, 0x18, 0x36, 0xe7, 0x91, 0x18, 0x36, 0xe7, 0x8e, 0x18, 0x36, 0xe7, 0x8d, 0x18, 0x36, 0xe7, 0x8b, 0x18, 0x36, 0xe7, 0x8a, 0x18, 0x36, 0xe7, 0x89, 0x18, 0x36, 0xe7, 0x87, 0x18, 0x36, 0xe7, 0x86, 0x18, 0x36, 0xe7, 0x84, 0x18, 0x36, 0xe7, 0x83, 0x18, 0x36, 0xe7, 0x81, 0x13, 0x36, 0xe7, 0x80, 0x18, 0x36, 0xe7, 0x80, 0x16, 0x36, 0xe6, 0x1c, 0x11, 0x36, 0xe5, 0x80, 0x11, 0x36, 0xe5, 0x00, 0x10, 0x36, 0xe4, 0x10, 0x36, 0xdc, 0x0f, 0x36, 0xd8, 0x10, 0x36, 0xc3, 0x10, 0x36, 0xc2, 0x16, 0x36, 0xc0, 0x1c, 0x17, 0x36, 0xb6, 0xf0, 0x18, 0x36, 0xb6, 0xc8, 0x18, 0x36, 0xb6, 0xc7, 0x18, 0x36, 0xb6, 0xc6, 0x17, 0x36, 0xb6, 0x90, 0x17, 0x36, 0xb6, 0x8e, 0x17, 0x36, 0xb6, 0x8c, 0x10, 0x36, 0xab, 0x10, 0x36, 0xaa, 0x10, 0x36, 0x9b, 0x10, 0x36, 0x9a, 0x10, 0x36, 0x4e, 0x0f, 0x36, 0x4c, 0x0f, 0x36, 0x4a, 0x10, 0x36, 0x49, 0x10, 0x36, 0x48, 0x18, 0x34, 0xda, 0x4f, 0x18, 0x34, 0xda, 0x4e, 0x18, 0x34, 0xda, 0x4b, 0x18, 0x34, 0xda, 0x4a, 0x18, 0x34, 0xda, 0x49, 0x18, 0x34, 0xda, 0x48, 0x18, 0x34, 0xda, 0x45, 0x18, 0x34, 0xda, 0x44, 0x18, 0x34, 0xda, 0x43, 0x18, 0x34, 0xda, 0x42, 0x18, 0x34, 0xda, 0x3f, 0x18, 0x34, 0xda, 0x3c, 0x18, 0x34, 0xda, 0x3b, 0x18, 0x34, 0xda, 0x3a, 0x18, 0x34, 0xda, 0x39, 0x18, 0x34, 0xda, 0x36, 0x18, 0x34, 0xda, 0x35, 0x18, 0x34, 0xda, 0x34, 0x18, 0x34, 0xda, 0x33, 0x18, 0x34, 0xda, 0x30, 0x18, 0x34, 0xda, 0x2d, 0x18, 0x34, 0xda, 0x2c, 0x18, 0x34, 0xda, 0x2b, 0x18, 0x34, 0xda, 0x2a, 0x18, 0x34, 0xda, 0x27, 0x18, 0x34, 0xda, 0x26, 0x18, 0x34, 0xda, 0x25, 0x18, 0x34, 0xda, 0x24, 0x18, 0x34, 0xda, 0x21, 0x18, 0x34, 0xda, 0x20, 0x18, 0x34, 0xda, 0x1e, 0x18, 0x34, 0xda, 0x1d, 0x18, 0x34, 0xda, 0x1c, 0x18, 0x34, 0xda, 0x1b, 0x18, 0x34, 0xda, 0x18, 0x18, 0x34, 0xda, 0x17, 0x18, 0x34, 0xda, 0x16, 0x18, 0x34, 0xda, 0x15, 0x18, 0x34, 0xda, 0x12, 0x18, 0x34, 0xda, 0x11, 0x18, 0x34, 0xda, 0x10, 0x18, 0x34, 0xda, 0x0f, 0x18, 0x34, 0xda, 0x0e, 0x18, 0x34, 0xda, 0x0d, 0x18, 0x34, 0xda, 0x0c, 0x18, 0x34, 0xda, 0x09, 0x18, 0x34, 0xda, 0x08, 0x18, 0x34, 0xda, 0x07, 0x18, 0x34, 0xda, 0x06, 0x18, 0x34, 0xda, 0x03, 0x18, 0x34, 0xda, 0x02, 0x18, 0x34, 0xda, 0x01, 0x11, 0x34, 0xda, 0x00, 0x18, 0x34, 0xda, 0x00, 0x0d, 0x34, 0xd0, 0x18, 0x34, 0x5f, 0xfd, 0x18, 0x34, 0x5f, 0xf4, 0x18, 0x34, 0x5f, 0x96, 0x18, 0x34, 0x5f, 0x95, 0x17, 0x34, 0x5f, 0x94, 0x18, 0x34, 0x5f, 0x94, 0x16, 0x34, 0x5f, 0x68, 0x15, 0x34, 0x5e, 0xd8, 0x16, 0x34, 0x5e, 0x70, 0x14, 0x34, 0x5e, 0x30, 0x14, 0x34, 0x5e, 0x20, 0x17, 0x34, 0x5e, 0x18, 0x18, 0x34, 0x5e, 0x0f, 0x18, 0x34, 0x5e, 0x05, 0x18, 0x34, 0x5c, 0x5b, 0x18, 0x34, 0x5c, 0x5a, 0x18, 0x34, 0x5c, 0x59, 0x16, 0x34, 0x5c, 0x58, 0x18, 0x34, 0x5c, 0x58, 0x15, 0x34, 0x5c, 0x28, 0x18, 0x34, 0x55, 0xc6, 0x17, 0x34, 0x55, 0xc4, 0x10, 0x34, 0x38, 0x0e, 0x34, 0x30, 0x0f, 0x34, 0x1e, 0x0f, 0x34, 0x12, 0x0f, 0x34, 0x10, 0x12, 0x2e, 0x89, 0x80, 0x11, 0x2e, 0x89, 0x00, 0x14, 0x2e, 0x33, 0xc0, 0x12, 0x2e, 0x33, 0x80, 0x18, 0xd8, 0x89, 0x39, 0x18, 0xd8, 0x89, 0x38, 0x18, 0xcc, 0xf6, 0xbd, 0x18, 0xb9, 0x8f, 0x10, 0x16, 0xb9, 0x30, 0x78, 0x14, 0xb2, 0xec, 0x00, 0x12, 0xb0, 0x22, 0xc0, 0x13, 0xb0, 0x22, 0xa0, 0x14, 0xb0, 0x22, 0x90, 0x14, 0xb0, 0x22, 0x80, 0x12, 0xb0, 0x22, 0x40, 0x15, 0xb0, 0x20, 0x68, 0x15, 0x57, 0xee, 0x50, 0x11, 0x4f, 0x7d, 0x00, 0x12, 0x4f, 0x7d, 0x00, 0x12, 0x36, 0xf7, 0xc0, 0x12, 0x36, 0xf7, 0x80, 0x11, 0x36, 0xf7, 0x00, 0x11, 0x36, 0xf6, 0x80, 0x11, 0x36, 0xf6, 0x00, 0x16, 0x36, 0xf0, 0xdc, 0x18, 0x36, 0xf0, 0xc5, 0x18, 0x36, 0xf0, 0x38, 0x16, 0x36, 0xf0, 0x34, 0x17, 0x36, 0xf0, 0x32, 0x15, 0x36, 0xf0, 0x00, 0x18, 0x36, 0xef, 0xdf, 0x18, 0x36, 0xef, 0xa6, 0x17, 0x36, 0xef, 0xa4, 0x18, 0x36, 0xef, 0x63, 0x15, 0x36, 0xef, 0x20, 0x16, 0x36, 0xe6, 0xc4, 0x16, 0x36, 0xc0, 0xc4, 0x18, 0x34, 0x55, 0x3f, 0x17, 0x34, 0x55, 0x3c, 0x17, 0x34, 0x55, 0x3a, 0x0d, 0x22, 0xf8};

    u_char *tmp;
    tmp = temp;
    libparsebgp_parse_mrt_parsed_data mrt_data;
    int read_size = libparsebgp_parse_mrt_parse_msg(&mrt_data, tmp, len);
    libparsebgp_parse_mrt_destructor(&mrt_data);
    cout << "Hello Ojas and Induja"<<endl;
    cout << read_size;

//    cout << "Peer Address" << int(.peer_index_tbl.peer_entries.begin()->peer_type);
    //cout<<"Peer Address "<<int(p->peer_index_table.peer_entries.begin()->peer_type);
//    cout<<p->bgpMsg.common_hdr.len<<" "<<int(p->bgpMsg.common_hdr.type)<<endl;
//    cout<<int(p->bgpMsg.adv_obj_rib_list[0].isIPv4)<<endl;
    return 1;
}