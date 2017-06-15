#include <iostream>
#include "../include/lib_parse_common.h"

using namespace std;
#define BUFFER_SIZE 2048

void file_read(FILE *&fp, u_char *&buffer, int position)
{
    int array_size = 100, line = 0; // define the size of character array
    char * array = new char[array_size]; // allocating an array of 1kb
    int read_lines = 128;

    if(fp!=NULL)
    {
        cout << "File Opened successfully!!!. Reading data from file into array" << endl;
        while(line<read_lines && !feof(fp))
        {
            fgets(array, 80 , fp);

            for (int i = 10; i < 57; i += 3) {
                int tmp;
                if (i == 33)
                    i++;
                else {
                    sscanf(array + i, "%2x", &tmp);
                    buffer[position++] = tmp;
                }
            }
            line++;
        }
        cout<<position;
    }
    else //file could not be opened
        cout << "File could not be opened." << endl;
//    return array2;
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

int main(int argc, char * argv[]) {

    char file_path[20];
    int msg_type = 1;
    if (argc>1)
        strcpy(file_path, argv[1]);
    else
        strcpy(file_path, "../testfile.txt");

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
    libparsebgp_parse_msg **all_parsed_msg = (libparsebgp_parse_msg **)malloc(sizeof(libparsebgp_parse_msg *));
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
                if(count)
                    all_parsed_msg = (libparsebgp_parse_msg **)realloc(all_parsed_msg,(count+1)*sizeof(libparsebgp_parse_msg *));
                memset(parse_msg, 0, sizeof(parse_msg));
                bytes_read = libparsebgp_parse_msg_common_wrapper(parse_msg, buffer + position, len, msg_type);
                if (bytes_read < 0) {
                    msg_read = false;
                    cout << "Crashed. Error code: " << bytes_read << endl;
                } else if (bytes_read == 0)
                    msg_read = false;
                else {
                    position += bytes_read;
                    cout <<endl<< "Message Parsed Successfully" << endl;
                    len -= bytes_read;
                    cout << bytes_read << " " << position << " " << len << endl;
                    all_parsed_msg[count] = (libparsebgp_parse_msg *)malloc(sizeof(libparsebgp_parse_msg));
                    memcpy(all_parsed_msg[count], parse_msg, sizeof(libparsebgp_parse_msg));
//                    cout<<int(parse_msg->parsed_mrt_msg.c_hdr.len)<<" "<<int(parse_msg->parsed_mrt_msg.c_hdr.time_stamp)<<endl;
//                    cout<<int(all_parsed_msg[count]->parsed_mrt_msg.c_hdr.len)<<" "<<int(all_parsed_msg[count]->parsed_mrt_msg.c_hdr.time_stamp)<<endl;
                    count++;
                }
            }
            position = shift(buffer, position, tlen);
        }
    } else
        cout << "File could not be opened";

    cout << count << endl;
    for (int i = 0; i < count; i++) {
        cout << int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.len) << " "
             << int(all_parsed_msg[i]->parsed_mrt_msg.c_hdr.time_stamp) << endl;
    }
    return 0;
}
