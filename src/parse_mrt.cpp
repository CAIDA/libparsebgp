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

/**
 * Buffer remaining MRT message
 *
 * \details This method will read the remaining amount of BMP data and store it in the instance variable bmp_data.
 *          Normally this is used to store the BGP message so that it can be parsed.
 *
 * \param buffer    containes the data
 * \param buf_len   has the length of buffer
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


static uint32_t libparsebgp_parse_mrt_parse_bgp4mp(unsigned char* buffer, int& buf_len, libparsebgp_parse_mrt_parsed_data *mrt_parsed_data) {
    uint32_t read_size = 0;
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
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_asn);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.local_asn);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.interface_index);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.address_family);
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
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state);
            read_size += 2*asn_len + ip_addr_len*2 + 8;
            break;
        }
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4:
        case BGP4MP_MESSAGE_LOCAL:
        case BGP4MP_MESSAGE_AS4_LOCAL: {
            int asn_len = (mrt_parsed_data->c_hdr.sub_type == BGP4MP_MESSAGE_AS4 || mrt_parsed_data->c_hdr.sub_type == BGP4MP_MESSAGE_AS4_LOCAL) ? 8 : 4;
            int ip_addr_len = 4;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg, asn_len) != asn_len) //ASNs
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.interface_index, 2) != 2)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.address_family, 2) != 2)
                throw;
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.peer_asn);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.local_asn);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.interface_index);
            SWAP_BYTES(&mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.address_family);
            if (mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.address_family == AFI_IPv6)
                ip_addr_len = 16;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.peer_ip, ip_addr_len) != ip_addr_len)
                throw;
            if (extract_from_buffer(buffer, buf_len, &mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.local_ip, ip_addr_len) != ip_addr_len)
                throw;
            read_size += 2*asn_len + 2*ip_addr_len + 4;
            read_size += libparsebgp_parse_bgp_parse_msg(mrt_parsed_data->parsed_data.bgp4mp.bgp4mp_msg.bgp_msg, buffer,
                                                         buf_len, mrt_parsed_data->c_hdr.sub_type > 5);
            break;
        }
        default: {
            throw "Subtype for BGP4MP not supported";
        }
    }
    return read_size;
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

static int libparsebgp_parse_mrt_parse_common_header(u_char *& buffer, int& buf_len, libparsebgp_mrt_common_hdr &mrt_parsed_hdr) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &mrt_parsed_hdr, 12) != 12)
        throw "Error in parsing MRT common header";
    read_size+=12;
    SWAP_BYTES(&mrt_parsed_hdr.len);
    SWAP_BYTES(&mrt_parsed_hdr.type);
    SWAP_BYTES(&mrt_parsed_hdr.sub_type);
    SWAP_BYTES(&mrt_parsed_hdr.time_stamp);

    mrt_len = mrt_parsed_hdr.len;
    if (mrt_parsed_hdr.type == BGP4MP_ET || mrt_parsed_hdr.type == ISIS_ET || mrt_parsed_hdr.type == OSPFv3_ET) {
        if (extract_from_buffer(buffer, buf_len, &mrt_parsed_hdr.microsecond_timestamp, 4) != 4)
            throw "Error in parsing MRT Common header: microsecond timestamp";
        read_size+=4;
        SWAP_BYTES(&mrt_parsed_hdr.microsecond_timestamp);
        mrt_len -= 4;
    }
    else
        mrt_parsed_hdr.microsecond_timestamp = 0;
    mrt_sub_type = mrt_parsed_hdr.sub_type;
    return read_size;
}

static int libparsebgp_parse_mrt_parse_table_dump(u_char *buffer, int& buf_len, libparsebgp_table_dump_message *table_dump_msg) {
    int read_size=0;
    if (extract_from_buffer(buffer, buf_len, &table_dump_msg, 4) != 4)
        throw "Error in parsing view number";
    read_size+=4;

    switch (mrt_sub_type) {
        case AFI_IPv4:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->prefix, 4) != 4)
                throw "Error in parsing prefix in IPv4";
            read_size+=4;
            break;
        }
        case AFI_IPv6:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->prefix, 16) != 16)
                throw "Error in parsing prefix in IPv6";
            read_size+=16;
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

    read_size+=6;

    switch (mrt_sub_type) {
        case AFI_IPv4:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->peer_ip, 4) != 4)
                throw "Error in parsing prefix in IPv4";
            read_size+=4;
            break;
        }
        case AFI_IPv6:{
            if ( extract_from_buffer(buffer, buf_len, &table_dump_msg->peer_ip, 16) != 16)
                throw "Error in parsing prefix in IPv4";
            read_size+=16;
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

    read_size+=4;

    bool has_end_of_rib_marker;
    libparsebgp_update_msg_parse_attributes(table_dump_msg->bgp_attrs, buffer, table_dump_msg->attribute_len, has_end_of_rib_marker);
    read_size += table_dump_msg->attribute_len;
    buf_len-=table_dump_msg->attribute_len;

    return read_size;
}

static int libparsebgp_parse_mrt_parse_peer_index_table(unsigned char *buffer, int& buf_len, libparsebgp_peer_index_table *peer_index_table) {
    uint16_t count = 0;
    int  AS_num;
    uint8_t  Addr_fam;
    int read_size=0;

    if (extract_from_buffer(buffer, buf_len, &peer_index_table, 6) != 6)
        throw "Error in parsing collector_BGPID and view_name_length";
    read_size+=6;

    if (peer_index_table->view_name_length) {
        if (extract_from_buffer(buffer, buf_len, &peer_index_table->view_name, peer_index_table->view_name_length) !=
                peer_index_table->view_name_length)
            throw "Error in parsing view_name";
        read_size+=peer_index_table->view_name_length;
    }

    if (extract_from_buffer(buffer, buf_len, &peer_index_table->peer_count, 2) != 2)
        throw "Error in parsing peer count";
    read_size+=2;
    SWAP_BYTES(&peer_index_table->peer_count);

    while (count < peer_index_table->peer_count) {
        peer_entry *p_entry = new peer_entry;
        if (extract_from_buffer(buffer, buf_len, &p_entry->peer_type, 1) != 1)
            throw "Error in parsing collector_BGPID";
        read_size+=1;

        AS_num = p_entry->peer_type & 0x02 ? 4 : 2; //using 32 bits and 16 bits.
        Addr_fam = p_entry->peer_type & 0x01 ? AFI_IPv6:AFI_IPv4;

        if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_bgp_id, 4) != 4)
            throw "Error in parsing local address in peer_BGPID";

        switch (Addr_fam) {
            case AFI_IPv4:{
                if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_ip, 4) != 4)
                    throw "Error in parsing local address in IPv4";
                read_size+=4;
                break;
            }
            case AFI_IPv6:{
                if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_ip, 16) != 16)
                    throw "Error in parsing local address in IPv4";
                read_size+=16;
                break;
            }
            default: {
                throw "Address family is unexpected as per rfc6396";
            }
        }
        if ( extract_from_buffer(buffer, buf_len, &p_entry->peer_as, AS_num) != AS_num)
            throw "Error in parsing local address in IPv4";
        read_size+=AS_num;
        peer_index_table->peer_entries.push_back(*p_entry);
        delete p_entry;
        count++;
    }
    return read_size;
}

static int libparsebgp_parse_mrt_parse_rib_unicast(unsigned char *buffer, int& buf_len, libparsebgp_rib_entry_header *rib_entry_data) {
    uint16_t count = 0;
    int addr_bytes=0;
    int read_size=0;

    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->sequence_number, 4) != 4)
        throw "Error in parsing sequence number";

    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->prefix_length, 1) != 1)
        throw "Error in parsing sequence number";

    SWAP_BYTES(&rib_entry_data->sequence_number);
    read_size+=5;

    if (rib_entry_data->prefix_length>0) {
        addr_bytes = rib_entry_data->prefix_length / 8;
        if (rib_entry_data->prefix_length % 8)
            ++addr_bytes;
        u_char local_addr[addr_bytes];


        if (extract_from_buffer(buffer, buf_len, &local_addr, addr_bytes) !=
            addr_bytes)
            throw "Error in parsing prefix";

        read_size += addr_bytes;

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
    }
    if (extract_from_buffer(buffer, buf_len, &rib_entry_data->entry_count, 2) != 2)
        throw "Error in parsing peer count";

    read_size+=2;
    SWAP_BYTES(&rib_entry_data->entry_count);

    while (count < rib_entry_data->entry_count) {
        rib_entry *r_entry = new rib_entry();

        if (extract_from_buffer(buffer, buf_len, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        if (extract_from_buffer(buffer, buf_len, &r_entry->originated_time, 4) != 4)
            throw "Error in parsing originated time";

        if (extract_from_buffer(buffer, buf_len, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing attribute len";

        read_size+=8;

        SWAP_BYTES(&r_entry->peer_index);
        SWAP_BYTES(&r_entry->originated_time);
        SWAP_BYTES(&r_entry->attribute_len);

        bool has_end_of_rib_marker;
        libparsebgp_update_msg_parse_attributes(r_entry->bgp_attrs, buffer, r_entry->attribute_len, has_end_of_rib_marker);
        read_size += r_entry->attribute_len;
        buf_len-=r_entry->attribute_len;

        rib_entry_data->rib_entries.push_back(*r_entry);
        delete r_entry;
        count++;
    }
    return read_size;
}

static int libparsebgp_parse_mrt_parse_rib_generic(unsigned char *buffer, int& buf_len, libparsebgp_rib_generic_entry_header *rib_gen_entry_hdr) {
    uint16_t count = 0;
    int read_size=0;
    string peer_info_key;

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr, 7) != 7)
        throw "Error in parsing sequence number";
    read_size+=7;

    //TODO : nlri thing, have to check with the bgp code

    if (extract_from_buffer(buffer, buf_len, &rib_gen_entry_hdr->entry_count, 2) != 2)
        throw "Error in parsing peer count";
    read_size+=2;

    SWAP_BYTES(&rib_gen_entry_hdr->entry_count);

    while (count < rib_gen_entry_hdr->entry_count) {
        rib_entry *r_entry = new rib_entry();
        if (extract_from_buffer(buffer, buf_len, &r_entry->peer_index, 2) != 2)
            throw "Error in parsing peer Index";

        if (extract_from_buffer(buffer, buf_len, &r_entry->originated_time, 4) != 4)
            throw "Error in parsing originated time";

        if (extract_from_buffer(buffer, buf_len, &r_entry->attribute_len, 2) != 2)
            throw "Error in parsing attribute len";

        read_size+=8;

        SWAP_BYTES(&r_entry->peer_index);
        SWAP_BYTES(&r_entry->originated_time);
        SWAP_BYTES(&r_entry->attribute_len);

        bool has_end_of_rib_marker;
        libparsebgp_update_msg_parse_attributes(r_entry->bgp_attrs, buffer, r_entry->attribute_len, has_end_of_rib_marker);
        read_size += r_entry->attribute_len;
        buf_len-=r_entry->attribute_len;

        rib_gen_entry_hdr->rib_entries.push_back(*r_entry);
        delete r_entry;
        count++;
    }
    return read_size;
}

static int libparsebgp_parse_mrt_parse_table_dump_v2(u_char *buffer, int& buf_len, libparsebgp_parsed_table_dump_v2 *table_dump_v2_msg) {
    int read_size=0;
    switch (mrt_sub_type) {
        case PEER_INDEX_TABLE:
            read_size+=libparsebgp_parse_mrt_parse_peer_index_table(buffer,buf_len, &table_dump_v2_msg->peer_index_tbl);
            break;

        case RIB_IPV4_UNICAST:
        case RIB_IPV6_UNICAST:
            read_size+=libparsebgp_parse_mrt_parse_rib_unicast(buffer,buf_len, &table_dump_v2_msg->rib_entry_hdr);
            break;

        case RIB_IPV4_MULTICAST: //TODO: due to lack of multicast data
        case RIB_IPV6_MULTICAST: //TODO: due to lack of multicast data
        case RIB_GENERIC:
            read_size+=libparsebgp_parse_mrt_parse_rib_generic(buffer,buf_len, &table_dump_v2_msg->rib_generic_entry_hdr);
            break;
        default:
            break;
    }
    return read_size;
}

int libparsebgp_parse_mrt_parse_msg(libparsebgp_parse_mrt_parsed_data *mrt_parsed_data, unsigned char *buffer, int buf_len) {
    int read_size=0;
    try {
        read_size+=libparsebgp_parse_mrt_parse_common_header(buffer, buf_len, mrt_parsed_data->c_hdr);

        switch (mrt_parsed_data->c_hdr.type) {
            case OSPFv2 :     //do nothing
            case OSPFv3 :     //do nothing
            case OSPFv3_ET : {//do nothing
                break;
            }

            case TABLE_DUMP : {
                libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
                read_size+=libparsebgp_parse_mrt_parse_table_dump(mrt_data, mrt_data_len, &mrt_parsed_data->parsed_data.table_dump);
                break;
            }

            case TABLE_DUMP_V2 : {
                libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
                read_size+=libparsebgp_parse_mrt_parse_table_dump_v2(mrt_data, mrt_data_len, &mrt_parsed_data->parsed_data.table_dump_v2);
                break;
            }

            case BGP4MP :
            case BGP4MP_ET : {
                libparsebgp_parse_mrt_buffer_mrt_message(buffer, buf_len);
                read_size += libparsebgp_parse_mrt_parse_bgp4mp(mrt_data, mrt_data_len, mrt_parsed_data);
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

    return read_size;
}

int main() {
    u_char temp[] = {0x58, 0xb6, 0x12, 0x84, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0xe4, 0x8f,
                     0x00, 0x00, 0x19, 0x2f, 0x00, 0x00, 0x00, 0x01, 0x67, 0xf7, 0x03, 0x2d, 0x80, 0xdf, 0x33, 0x66,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0x00, 0x43, 0x02, 0x00, 0x04, 0x18, 0xa8, 0xb5, 0x24, 0x00, 0x24, 0x40, 0x01, 0x01, 0x00, 0x40,
                     0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0xe4, 0x8f, 0x00, 0x00, 0x1b, 0x1b, 0x00, 0x04, 0x01, 0x04,
                     0x00, 0x00, 0x6e, 0xb7, 0x00, 0x04, 0x05, 0x73, 0x40, 0x03, 0x04, 0x67, 0xf7, 0x03, 0x2d, 0x18,
                     0xbf, 0x05, 0xaa};
    /*u_char temp[] = {0x58, 0x67, 0xb5, 0x31, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x07, 0x2c,
                     0x00, 0x00, 0x31, 0x6e, 0x00, 0x00, 0x00, 0x02, 0x2a, 0x01, 0x02, 0xa8, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x06, 0x7c, 0x02, 0xe8, 0x00, 0x02,
                     0xff, 0xff, 0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04};*/
    u_char *tmp;
    tmp = temp;
    //parseMRT *p = new parseMRT();
    int len = 99;
    libparsebgp_parse_mrt_parsed_data mrt_data;
    try {
        int read_size = libparsebgp_parse_mrt_parse_msg(&mrt_data, tmp, len);
        //if (p->libparsebgp_parse_mrt_parse_msg(tmp, len))
            cout << "Hello Ojas and Induja"<<endl;
        cout << read_size;
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