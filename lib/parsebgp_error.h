#ifndef __PARSEBGP_ERROR_H
#define __PARSEBGP_ERROR_H

typedef enum parsebgp_error {

  /** No error */
  PARSEBGP_OK = 0,

  /**  Buffer does not contain an entire message */
  PARSEBGP_PARTIAL_MSG = -1,

  /** Unexpected message structure or content */
  PARSEBGP_INVALID_MSG = -2,

  /** Feature to be parsed is not currently implemented */
  PARSEBGP_NOT_IMPLEMENTED = -3,

  /** Memory allocation failure */
  PARSEBGP_MALLOC_FAILURE = -4,

} parsebgp_error_t;

#endif /* __PARSEBGP_ERROR_H */
