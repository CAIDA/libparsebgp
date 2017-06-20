#include <iostream.h>
#include "../include/lib_parse_common.h"

//using namespace std;
#define BUFFER_SIZE 2048

void file_read(FILE *&fp, u_char *&buffer, int position)
{
    char * array = new char[BUFFER_SIZE];
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
        cout<<position;
    }
    else //file could not be opened
        cout << "File could not be opened." << endl;
}

int shift(u_char *&buffer, int bytes_read, int buf_len)
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
    stringstream out;
    switch (parse_msg->msg_type) {
        case MRT_MESSAGE_TYPE: {
            switch (parse_msg->parsed_mrt_msg.c_hdr.type) {
                case TABLE_DUMP: {
                    out << "R|";
                    if (parse_msg->parsed_mrt_msg.has_end_of_rib_marker)
                        out << "E|";
                    else
                        out << "R|";
                    out << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.table_dump.peer_as
                            << "|" << (int)parse_msg->parsed_mrt_msg.parsed_data.table_dump.peer_ip << "|" << parse_msg->parsed_mrt_msg.parsed_data.table_dump.prefix
                            << "|";
//                    int ip_len = parse_msg->parsed_mrt_msg.parsed_data.table_dump. == AFI_IPv6 ? 16 : 4;
//                    for(int i = 0;i<ip_len;i++ ) {
//                        if (i)
//                            out << ":";
//                        out<< (int)parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[i];
//                    }
                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.next_hop;
                            break;
                        }
                    }
                    out << "|"; //need to add as_path and origin-AS
                    uint32_t origin_as = "";
                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; i++) {
                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                            for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.count_as_path; ++j) {
                                for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path->count_seg_asn; ++k) {
                                    out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k] << " ";
                                    origin_as = parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k];
                                }
                            }
                            break;
                        }
                    }
                    out << "|" << origin_as << "|";
                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm;
                            break;
                        }
                    }
                    out << "||";
                    break;
                }
                case TABLE_DUMP_V2: {
                    //<dump-type>|<elem-type>|<record-ts>|<project>|<collector>|<peer-ASn>|<peer-IP>|<prefix>|<next-hop-IP>|
                    //<AS-path>|<origin-AS>|<communities>|<old-state>|<new-state>
                    out << "R|";
                    if (parse_msg->parsed_mrt_msg.has_end_of_rib_marker)
                        out << "E|";
                    else
                        out << "R|";
                    switch (parse_msg->parsed_mrt_msg.c_hdr.sub_type) {
                        case PEER_INDEX_TABLE: {
                            out << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "||" << parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.peer_index_tbl.collector_bgp_id
                                << "|||||||||";
                            break;
                        }
                        case RIB_IPV4_UNICAST:
                        case RIB_IPV6_UNICAST: {
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_entry_hdr.rib_entries; ++i) {
                                if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                                    out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.next_hop;
                                    break;
                                }
                            }
                            out << "|"; //need to add as_path and origin-AS
                            uint32_t origin_as = "";
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; i++) {
                                if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_AS_PATH) {
                                    for (int j = 0; j < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.count_as_path; ++j) {
                                        for (int k = 0; k < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path->count_seg_asn; ++k) {
                                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k] << " ";
                                            origin_as = parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.as_path[j].seg_asn[k];
                                        }
                                    }
                                    break;
                                }
                            }
                            out << "|" << origin_as << "|";
                            for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                                if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                                    out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm;
                                    break;
                                }
                            }
                            out << "||";
                            break;
                        }
                        case RIB_GENERIC: {
                            out << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||||" << parse_msg->parsed_mrt_msg.parsed_data.table_dump_v2.rib_generic_entry_hdr.nlri_entry.prefix;
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
                            out << "U|S|" << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_asn
                                << "|" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.peer_ip << "||||||"
                                << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.old_state << "|"
                                << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_state_change_msg.new_state << "|";
                            break;
                        }
                        case BGP4MP_MESSAGE:
                        case BGP4MP_MESSAGE_LOCAL:
                        case BGP4MP_MESSAGE_AS4_LOCAL:
                        case BGP4MP_MESSAGE_AS4: {
                            switch (parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.bgp_msg.c_hdr.type) {
                                case BGP_MSG_OPEN: {
                                    out << "R|R|" << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_asn
                                        << "|" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[0] << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[1] << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[2]<<parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[3] << "|||||||";
                                    break;
                                }
                                case BGP_MSG_UPDATE: {
                                    out << "U|";
                                    out << "R|" << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_asn
                                        << "|";
                                    int ip_len = parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.address_family == AFI_IPv6 ? 16 : 4;
                                    for(int i = 0;i<ip_len;i++ ) {
                                        if (i)
                                            out << ":";
                                        out<< (int)parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip[i];
                                    }
                                    out<<"||";
                                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.next_hop;
                                            break;
                                        }
                                    }
                                    out << "|||"; //need to add as_path and origin-AS
                                    for (int i = 0; i < parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs_count; ++i) {
                                        if (parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                                            out << parse_msg->parsed_mrt_msg.parsed_data.table_dump.bgp_attrs[i]->attr_value.attr_type_comm;
                                            break;
                                        }
                                    }
                                    out << "||";
                                    break;
                                }
                                case BGP_MSG_NOTIFICATION: {
                                    out << "R|" << parse_msg->parsed_mrt_msg.c_hdr.time_stamp << "|||" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_asn
                                        << "|" << parse_msg->parsed_mrt_msg.parsed_data.bgp4mp.bgp4mp_msg.peer_ip << "|||||||" ;
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
                        out << "R|E|"; //End of RIB
                    else
                        out << "U||";
                    out << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs << "|||" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as
                        << "|" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr << "||";
                    for (int i = 0; i < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                            out << parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.next_hop;
                            break;
                        }
                    }
                    out << "|||"; //need to add as_path and origin-AS
                    for (int i = 0; i < parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                            out << parse_msg->parsed_bmp_msg.libparsebgp_parsed_bmp_msg.parsed_rm_msg.parsed_data.update_msg.path_attributes[i]->attr_value.attr_type_comm;
                            break;
                        }
                    }
                    out << "||";
                    break;
                }
                case TYPE_STATS_REPORT: {
                    break;
                }
                case TYPE_TERM_MSG: {
                    out << "R|R|" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs << "|||" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as
                        << "|" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr << "|||||||";
                    break;
                }
                case TYPE_INIT_MSG: {

                    break;
                }
                case TYPE_PEER_UP: {
                    out << "R|R|" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.ts_secs << "|||" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_as
                        << "|" << parse_msg->parsed_bmp_msg.libparsebgp_parsed_peer_hdr.peer_addr << "|||||||";
                    break;
                }
                case TYPE_PEER_DOWN: {
                    break;
                }
            }
            break;
        }
        case BGP_MESSAGE_TYPE: {
            switch (parse_msg->parsed_bgp_msg.c_hdr.type) {
                case BGP_MSG_OPEN: {
                    out << "R|R||||||||||||";
                    break;
                }
                case BGP_MSG_UPDATE: {
                    if (parse_msg->parsed_bgp_msg.has_end_of_rib_marker)
                        out << "R|E|"; //End of RIB
                    else
                        out << "U||";
                    out << "|||||||";
                    for (int i = 0; i < parse_msg->parsed_bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_NEXT_HOP) {
                            out << parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.next_hop;
                            break;
                        }
                    }
                    out << "|||"; //need to add as_path and origin-AS
                    for (int i = 0; i < parse_msg->parsed_bgp_msg.parsed_data.update_msg.count_path_attr; ++i) {
                        if (parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_type.attr_type_code == ATTR_TYPE_COMMUNITIES) {
                            out << parse_msg->parsed_bgp_msg.parsed_data.update_msg.path_attributes[i]->attr_value.attr_type_comm;
                            break;
                        }
                    }
                    out << "||";
                    break;
                }
                case BGP_MSG_NOTIFICATION: {
                    out << "R|R||||||||||||";
                    break;
                }
            }
            break;
        }
    }
    cout << out.str() << endl;
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
                cout << "INVALID ARG: -f expects the filename to be specified" << endl;
                return true;
            }

            // Set the new filename
            strcpy(file_path, argv[++i]);
        }
        else if (!strcmp(argv[i], "-t")) {
            // We expect the next arg to be the type of message
            if (i + 1 >= argc) {
                cout << "INVALID ARG: -t expects the type to be specified" << endl;
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
            cout << endl;
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
                    cout <<endl <<"Crashed. Error code: " << bytes_read << endl;
                } else if (bytes_read == 0)
                    msg_read = false;
                else {
                    position += bytes_read;
//                    cout <<endl<< "Message "<< count+1<<" Parsed Successfully" << endl;
                    len -= bytes_read;
//                    cout <<"Bytes read in parsing this message: "<< bytes_read << " Remaining Length of Buffer: " << len << endl;
//                    all_parsed_msg[count] = (libparsebgp_parse_msg *)malloc(sizeof(libparsebgp_parse_msg));
//                    memcpy(all_parsed_msg[count], parse_msg, sizeof(libparsebgp_parse_msg));
                    elem_generate(parse_msg);
                    count++;
                }
            }
            position = shift(buffer, position, tlen);
        }
        cout<<"*******File Parsed completely*******"<<endl;
    } else
        cout << "File could not be opened";

//    for (int i = 0; i < count; i++) {
//        cout<< "Message "<<i+1<<" Details"<<endl;
//        cout <<"length :"<< int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.len) << " Message type "
//             << int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.type) << " Message Sub type "
//             << int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.sub_type) << endl;
//    }
    return 0;
}
