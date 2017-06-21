//#include <iostream.h>
#include "../include/lib_parse_common.h"

//using namespace std;
#define BUFFER_SIZE 2048

void file_read(FILE *fp, u_char *buffer, int position)
{
    char *array = (char *) malloc(BUFFER_SIZE*sizeof(char));
//    int array_size = 100, line = 0; // define the size of character array
//    char * array = new char[array_size]; // allocating an array of 1kb
//    int read_lines = 128;

    if(fp!=NULL)
    {
        fread(array, 1, BUFFER_SIZE, fp);
        for (int i = 0; i < BUFFER_SIZE; i ++) {
            buffer[position++] = array[i];
        }
//        cout << "File Opened successfully!!!. Reading data from file into array" << endl;
//        while(line<read_lines && !feof(fp))
//        {
//            fgets(array, 80 , fp);
//
//            for (int i = 10; i < 57; i += 3) {
//                int tmp;
//                if (i == 33)
//                    i++;
//                else {
//                    sscanf(array + i, "%2x", &tmp);
//                    buffer[position++] = tmp;
//                }
//            }
//            line++;
//        }
        printf("%d", position);
    }
    else //file could not be opened
        printf("File could not be opened.\n");
}

int shift(u_char *buffer, int bytes_read, int buf_len)
{
    for(int i = 0;i<(buf_len-bytes_read);i++)
    {
        buffer[i] = buffer[bytes_read+i];
    }
    memset(buffer+(buf_len-bytes_read), 0, (buf_len-bytes_read));
    return (buf_len-bytes_read);
}

void elem_generate(libparsebgp_parse_msg *parse_msg) {
    //<dump-type>|<elem-type>|<record-ts>|<project>|<collector>|<peer-ASn>|<peer-IP>|<prefix>|<next-hop-IP>|<AS-path>|
    //<origin-AS>|<communities>|<old-state>|<new-state>
//    int max_buf_len = 1000, len = 0;
//    u_char *out_buf = (u_char *)malloc(max_buf_len* sizeof(u_char));
    switch (parse_msg->msg_type) {
        case MRT_MESSAGE_TYPE: {
            switch (parse_msg->parsed_mrt_msg.c_hdr.type) {
                case TABLE_DUMP: {
                    printf("R|");
                    if (parse_msg->parsed_mrt_msg.has_end_of_rib_marker)
                        printf("E|");
                    else
                        printf("R|");
                    printf("%d|||%d|%s|%s|", parse_msg->parsed_mrt_msg.c_hdr.time_stamp, parse_msg->parsed_mrt_msg.parsed_data.table_dump.peer_as,
                                   parse_msg->parsed_mrt_msg.parsed_data.table_dump.peer_ip, parse_msg->parsed_mrt_msg.parsed_data.table_dump.prefix);
//                    out << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.table_dump.peer_as
//                            << "|" << (int)parse_msg->parsed_mrt_msg.parsed_data.table_dump.peer_ip << "|" << parse_msg->parsed_mrt_msg.parsed_data.table_dump.prefix
//                            << "|";
//                    int ip_len = parse_msg->parsed_mrt_msg.parsed_data.table_dump. == AFI_IPv6 ? 16 : 4;
//                    for(int i = 0;i<ip_len;i++ ) {
//                        if (i)
//                            out << ":";
//                        out<< (int)parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[i];
//                    }
                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                            printf("%s", parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.next_hop);
//                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.next_hop;
                            break;
                        }
                    }
//                    out << "|";
                    printf("|");
                    uint32_t origin_as = 0;
                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; i++) {
                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                            for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.count_as_path; ++j) {
                                for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path->count_seg_asn; ++k) {
//                                    out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k] << " ";
                                    printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k]);
                                    origin_as = parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k];
                                }
                            }
                            break;
                        }
                    }
//                    out << "|" << origin_as << "|";
                    printf("|%d|", origin_as);
                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                            for(int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.count_attr_type_comm; ++j) {
                                printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm[j]);
                            }
//                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm;
                            break;
                        }
                    }
                    printf("|");
                    break;
                }
                case TABLE_DUMP_V2: {
                    //<dump-type>|<elem-type>|<record-ts>|<project>|<collector>|<peer-ASn>|<peer-IP>|<prefix>|<next-hop-IP>|
                    //<AS-path>|<origin-AS>|<communities>|<old-state>|<new-state>
                    printf("R|");
//                    out << "R|";
                    if (parse_msg->parsed_mrt_msg.has_end_of_rib_marker)
                        printf("E|");
                    else
                        printf("R|");
                    switch (parse_msg->parsed_mrt_msg.c_hdr.sub_type) {
                        case PEER_INDEX_TABLE: {
                            printf("%d||%s|||||||||", parse_msg->parsed_mrt_msg.c_hdr.time_stamp, parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.peer_index_tbl.collector_bgp_id);
//                            out << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "||" << parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.peer_index_tbl.collector_bgp_id
//                                << "|||||||||";
                            break;
                        }
                        case RIB_IPV4_UNICAST:
                        case RIB_IPV6_UNICAST: {
                            bool found = false;
                            printf("%d||||||", parse_msg->parsed_mrt_msg.c_hdr.time_stamp);
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.entry_count && !found; ++i) {
                                for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs_count; ++j) {
                                    if (parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                                        printf("%s", parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_value.next_hop);
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            found = false;
                            printf("|");
                            uint32_t origin_as = 0;
                            for(int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.entry_count && !found; ++i) {
                                for(int l = 0; l < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs_count; ++l) {
                                    if (parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                                        for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.count_as_path; ++j) {
                                            for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.as_path->count_seg_asn; ++k) {
                                                printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.as_path[j].seg_asn[k]);
                                                origin_as = parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.as_path[j].seg_asn[k];
                                            }
                                        }
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            printf("|%d|", origin_as);
                            found = false;
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.entry_count && !found; ++i) {
                                for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs_count; ++j) {
                                    if (parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                                        for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_value.count_attr_type_comm; ++k) {
                                            printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_value.attr_type_comm[k]);
                                        }
//                                    out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm;
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            printf("||");
                            break;
                        }
                        case RIB_GENERIC: {
                            printf("%d|||||%s", parse_msg->parsed_mrt_msg.c_hdr.time_stamp, parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.nlri_entry.prefix);
//                            out << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||||" << parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.nlri_entry.prefix;
                            bool found = false;
                            printf("%d||||||", parse_msg->parsed_mrt_msg.c_hdr.time_stamp);
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.entry_count && !found; ++i) {
                                for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs_count; ++j) {
                                    if (parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                                        printf("%s", parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_value.next_hop);
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            found = false;
                            printf("|");
                            uint32_t origin_as = 0;
                            for(int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.entry_count && !found; ++i) {
                                for(int l = 0; l < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs_count; ++l) {
                                    if (parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                                        for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.count_as_path; ++j) {
                                            for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.as_path->count_seg_asn; ++k) {
                                                printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.as_path[j].seg_asn[k]);
                                                origin_as = parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[l]->attr_value.as_path[j].seg_asn[k];
                                            }
                                        }
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            printf("|%d|", origin_as);
                            found = false;
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.entry_count && !found; ++i) {
                                for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs_count; ++j) {
                                    if (parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                                        for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_value.count_attr_type_comm; ++k) {
                                            printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.rib_entries[i].bgp_attrs[j]->attr_value.attr_type_comm[k]);
                                        }
//                                    out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm;
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            printf("||");
                            break;
                        }
                    }
                    break;
                }
                case BGP4MP:
                case BGP4MP_ET: {
                    switch (parse_msg->parsed_mrt_msg.c_hdr.sub_type) {
                        case BGP4MP_STATE_CHANGE:
                        case BGP4MP_STATE_CHANGE_AS4: {
                            printf("U||%d|||%d|%s||||||%d|%d", parse_msg->parsed_mrt_msg.c_hdr.time_stamp,
                                   parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_asn, parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_ip,
                                   parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state, parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state);
//                            out << "U|S|" << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_asn
//                                << "|" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_ip << "||||||"
//                                << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state << "|"
//                                << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state;
                            break;
                        }
                        case BGP4MP_MESSAGE:
                        case BGP4MP_MESSAGE_LOCAL:
                        case BGP4MP_MESSAGE_AS4_LOCAL:
                        case BGP4MP_MESSAGE_AS4: {
                            switch (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.c_hdr.type) {
                                case BGP_MSG_OPEN: {
                                    printf("R|R|%d|||%d|%s|||||||", parse_msg->parsed_mrt_msg.c_hdr.time_stamp, parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_asn,
                                           parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip);
                                    break;
                                }
                                case BGP_MSG_UPDATE: {
                                    printf("U|");
                                    if (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.wdrawn_route_len > 0)
                                        printf("W|");
                                    else if (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.total_path_attr_len > 0)
                                        printf("A|");
                                    else
                                        printf("U|");
                                    printf("%d|||%d|%s|", parse_msg->parsed_mrt_msg.c_hdr.time_stamp, parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_asn,
                                           parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip);
//                                    int ip_len = parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.address_family == AFI_IPv6 ? 16 : 4;
//                                    for(int i = 0;i<ip_len;i++ ) {
//                                        if (i)
//                                            out << ":";
//                                        out<< (int)parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[i];
//                                    }
//                                    out<<"||";
                                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                                        if (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                                            printf("%s|", parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.next_hop);
                                            break;
                                        }
                                    }
                                    printf("|||");
                                    int origin_as = 0;
                                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                                        if (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                                            for(int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.count_as_path; ++j) {
                                                for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].count_seg_asn; ++k) {
                                                    printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].seg_asn[k]);
                                                    origin_as = parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].seg_asn[k];
                                                }
                                            }
                                            break;
                                        }
                                    }
                                    printf("|%d|", origin_as);
                                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                                        if (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                                            for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.count_attr_type_comm; ++j) {
                                                printf("%d ", parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.attr_type_comm[j]);
                                                break;
                                            }

                                        }
                                    }
                                    printf("||");
                                    break;
                                }
                                case BGP_MSG_NOTIFICATION: {
                                    printf("R|R|%d|||%d|%s|||||||", parse_msg->parsed_mrt_msg.c_hdr.time_stamp, parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_asn,
                                            parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
            }
            break;
        }
        case BMP_MESSAGE_TYPE: {
            switch (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_hdr.c_hdr_v3.type) {
                case TYPE_ROUTE_MON: {
                    if (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.has_end_of_rib_marker)
                        printf("R|E|"); //End of RIB
                    else
                        printf("U||");
                    printf("%d|||%d|%s||", parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs, parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as,
                           parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr);
                    for (int i = 0; i < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                            printf("%s|", parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.next_hop);
                            break;
                        }
                    }
                    printf("|||");
                    int origin_as = 0;
                    for (int i = 0; i < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                            for(int j = 0; j < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.count_as_path; ++j) {
                                for (int k = 0; k < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].count_seg_asn; ++k) {
                                    printf("%d ", parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].seg_asn[k]);
                                    origin_as = parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].seg_asn[k];
                                }
                            }
                            break;
                        }
                    }
                    printf("|%d|", origin_as);
                    for (int i = 0; i < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                            for (int j = 0; j < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.count_attr_type_comm; ++j) {
                                printf("%d ", parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.attr_type_comm[j]);
                                break;
                            }

                        }
                    }
                    printf("||");
                    break;
                }
                case TYPE_STATS_REPORT: {
                    break;
                }
                case TYPE_TERM_MSG: {
                    printf("R|R|%d|||%d|%s|||||||", parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs, parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as,
                            parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr);
                    break;
                }
                case TYPE_INIT_MSG: {
                    printf("R|R|%d|||%d|%s|||||||", parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs, parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as,
                           parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr);
                    break;
                }
                case TYPE_PEER_UP: {
                    printf("R|R|%d|||%d|%s|||||||", parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs, parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as,
                           parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr);
                    break;
                }
                case TYPE_PEER_DOWN: {
                    printf("R|R|%d|||%d|%s|||||||", parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs, parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as,
                           parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr);
                    break;
                }
            }
            break;
        }
        case BGP_MESSAGE_TYPE: {
            switch (parse_msg->parsed_bgp_msg.c_hdr.type) {
                case BGP_MSG_OPEN: {
                    printf("R|R||||||||||||");
                    break;
                }
                case BGP_MSG_UPDATE: {
                    if (parse_msg->parsed_bgp_msg.has_end_of_rib_marker)
                        printf("R|E|"); //End of RIB
                    else
                        printf("U||");
                    printf("|||||||");
                    for (int i = 0; i < parse_msg->parsed_bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                            printf("%s|", parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.next_hop);
                            break;
                        }
                    }
                    printf("|||");
                    int origin_as = 0;
                    for (int i = 0; i < parse_msg->parsed_bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                            for(int j = 0; j < parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.count_as_path; ++j) {
                                for (int k = 0; k < parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].count_seg_asn; ++k) {
                                    printf("%d ", parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].seg_asn[k]);
                                    origin_as = parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.as_path[j].seg_asn[k];
                                }
                            }
                            break;
                        }
                    }
                    printf("|%d|", origin_as);
                    for (int i = 0; i < parse_msg->parsed_bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                            for (int j = 0; j < parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.count_attr_type_comm; ++j) {
                                printf("%d ", parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.attr_type_comm[j]);
                                break;
                            }

                        }
                    }
                    printf("||");
                    break;
                }
                case BGP_MSG_NOTIFICATION: {
                    printf("R|R||||||||||||");
                    break;
                }
            }
            break;
        }
    }
    printf("\n");
}

int main(int argc, char * argv[]) {

    char file_path[20];
    int msg_type = 1;
    if (argc>1)
        strcpy(file_path, argv[1]);
    else
        strcpy(file_path, "../../updates.20170228.2335");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f")) {
            // We expect the next arg to be the filename
            if (i + 1 >= argc) {
                printf("INVALID ARG: -f expects the filename to be specified\n");
                return true;
            }

            // Set the new filename
            strcpy(file_path, argv[++i]);
        }
        else if (!strcmp(argv[i], "-t")) {
            // We expect the next arg to be the type of message
            if (i + 1 >= argc) {
                printf("INVALID ARG: -t expects the type to be specified\n");
                return true;
            }

            // Set the message type
            msg_type = atoi(argv[++i]);
        }
    }

    int position = 0, len = BUFFER_SIZE, count = 0;
    ssize_t bytes_read = 0;
    u_char *buffer= (u_char *)malloc(BUFFER_SIZE*sizeof(u_char));
    bool msg_read = true;
//    libparsebgp_parse_msg **all_parsed_msg = (libparsebgp_parse_msg **)malloc(sizeof(libparsebgp_parse_msg *));
    FILE *fp = fopen(file_path, "r");
    if (fp != NULL) {
        while (!feof(fp)) {
            if (position)
                buffer = (u_char *)realloc(buffer, (BUFFER_SIZE+position)*sizeof(u_char));
            file_read(fp, buffer, position);
            printf("\n");
            len = BUFFER_SIZE + position;
            int tlen = len;
            msg_read = true;
            position = 0;
            libparsebgp_parse_msg *parse_msg = (libparsebgp_parse_msg *)malloc(sizeof(libparsebgp_parse_msg));
            while (msg_read && len > 0) {
//                if(count)
//                    all_parsed_msg = (libparsebgp_parse_msg **)realloc(all_parsed_msg,(count+1)*sizeof(libparsebgp_parse_msg *));
                memset(parse_msg, 0, sizeof(parse_msg));
                bytes_read = libparsebgp_parse_msg_common_wrapper(parse_msg, buffer + position, len, msg_type);
                if (bytes_read < 0) {
                    msg_read = false;
                    printf("\n Crashed. Error code: %d\n", bytes_read);
                } else if (bytes_read == 0)
                    msg_read = false;
                else {
                    position += bytes_read;
                    printf("\nMessage %d Parsed Successfully\n", count+1);
                    len -= bytes_read;
                    printf("Bytes read in parsing this message: %d Remaining Length of Buffer: %d\n", bytes_read, len);
//                    all_parsed_msg[count] = (libparsebgp_parse_msg *)malloc(sizeof(libparsebgp_parse_msg));
//                    memcpy(all_parsed_msg[count], parse_msg, sizeof(libparsebgp_parse_msg));
//                    elem_generate(parse_msg);
                    count++;
                }
            }
            position = shift(buffer, position, tlen);
        }
        printf("*******File Parsed completely*******\n");
    } else
        printf("File could not be opened\n");

//    for (int i = 0; i < count; i++) {
//        cout<< "Message "<<i+1<<" Details"<<endl;
//        cout <<"length :"<< int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.len) << " Message type "
//             << int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.type) << " Message Sub type "
//             << int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.sub_type) << endl;
//    }
    return 0;
}
