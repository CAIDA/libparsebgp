//
// Created by Induja on 4/6/2017.
//

#include "../include/parse_utils.h"

/**
 * Function to extract data from buffer
 * @param buffer    Containes the data
 * @param buf_len    Length of buffer provided
 * @param output_buf Data from buffer is stored into this
 * @param output_len Length to be stored in output buffer
 * @return  size of data stored in output_buf
 */
ssize_t  extract_from_buffer (unsigned char*& buffer, int &buf_len, void *output_buf, int output_len) {
    if (output_len > buf_len)
        return (output_len - buf_len);
    memcpy(output_buf, buffer, output_len);
    buffer = (buffer + output_len);
    buf_len -= output_len;
    return output_len;
}