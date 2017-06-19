//
// Created by Induja on 4/6/2017.
//

#ifndef PARSE_LIB_PARSEUTILS_H
#define PARSE_LIB_PARSEUTILS_H

#include <stdlib.h>

enum parse_msg_error {
    INCOMPLETE_MSG      = -1,        ///< Buffer does not contain the entire message
    LARGER_MSG_LEN      = -2,        ///< Message length is larger than the maximum possible message length
    CORRUPT_MSG         = -3,        ///< Message does not follow the formats specified in RFCs
    ERR_READING_MSG     = -4,        ///< Error in reading from buffer
    INVALID_MSG         = -5,        ///< Part of message is different from the expected values
    NOT_YET_IMPLEMENTED = -6         ///< A feature not yet implemented
};

ssize_t extract_from_buffer (unsigned char *buffer, int *buf_len, void *output_buf, ssize_t output_len);

/**
 *  Simple function to swap bytes around from network to host or
 *  host to networking.  This method will convert any size byte variable,
 *  unlike ntohs and ntohl.
 *
 * @param [in/out] var   Variable containing data to update
 * @param [in]     size  Size of var - Default is size of var
 */
void SWAP_BYTES(void *var, int size);

#endif //PARSE_LIB_PARSEUTILS_H
