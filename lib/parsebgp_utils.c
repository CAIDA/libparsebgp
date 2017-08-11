//
// Created by Induja on 4/6/2017.
//

#include "parsebgp_utils.h"
#include "parsebgp.h"
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

/**
 * Function to extract data from buffer
 *
 * @param buffer    Containes the data
 * @param buf_len    Length of buffer provided
 * @param output_buf Data from buffer is stored into this
 * @param output_len Length to be stored in output buffer
 *
 * @return  size of data stored in output_buf
 */
ssize_t extract_from_buffer(uint8_t **buffer, int *buf_len, void *output_buf,
                            ssize_t output_len)
{
  if (output_len > *buf_len)
    return INCOMPLETE_MSG; // return (output_len - buf_len);
  memcpy(output_buf, *buffer, output_len);
  *buffer = (*buffer + output_len);
  *buf_len -= output_len;
  return output_len;
}

/**
 *  Simple function to swap bytes around from network to host or
 *  host to networking.  This method will convert any size byte variable,
 *  unlike ntohs and ntohl.
 *
 * @param [in/out] var   Variable containing data to update
 * @param [in]     size  Size of var - Default is size of var
 */
void SWAP_BYTES(void *var, int size)
{
  uint8_t *v = (uint8_t *)var;
  int i, i2;
  uint8_t buf[128];
  assert(size < 128);

  memcpy(buf, var, size);
  i2 = 0;
  for (i = size - 1; i >= 0; i--) {
    v[i2++] = buf[i];
  }
}

void *malloc_zero(const size_t size)
{
  return calloc(size, 1);
}
