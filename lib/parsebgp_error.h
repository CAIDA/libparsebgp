#ifndef __PARSEBGP_ERROR_H
#define __PARSEBGP_ERROR_H

// TODO: namespace these codes
typedef enum parsebgp_error {
  /** No error */
  OK = 0,

  /**  Buffer does not contain an entire message */
  INCOMPLETE_MSG = -1,

  /** Message length is larger than the maximum possible message length */
  LARGER_MSG_LEN = -2,

  /** Message is corrupted */
  CORRUPT_MSG = -3,

  /** Error reading message from buffer */
  ERR_READING_MSG = -4,

  /** Part of message is different from expected */
  INVALID_MSG = -5,

  /** Feature to be parsed is not currently implemented */
  NOT_IMPLEMENTED = -6,

} parsebgp_error_t;

#endif /* __PARSEBGP_ERROR_H */
