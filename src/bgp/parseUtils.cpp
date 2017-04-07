//
// Created by Induja on 4/6/2017.
//

#include "../include/parseUtils.h"

/**
 * Function to extract data from buffer
 * @param buffer    Containes the data
 * @param bufLen    Length of buffer provided
 * @param outputbuf Data from buffer is stored into this
 * @param outputLen Length to be stored in output buffer
 * @return  size of data stored in outputbuf
 */
ssize_t  extractFromBuffer (unsigned char*& buffer, int &bufLen, void *outputbuf, int outputLen) {
    if (outputLen > bufLen)
        return (outputLen - bufLen);
    memcpy(outputbuf, buffer, outputLen);
    buffer = (buffer + outputLen);
    bufLen -= outputLen;
    return outputLen;
}