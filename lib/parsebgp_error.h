#ifndef __PARSEBGP_ERROR_H
#define __PARSEBGP_ERROR_H

/**
 * Error codes returned by the parser
 *
 * Note: these codes must be kept in sync with the error codes in
 * parsebgp_error.c
 */
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

/**
 * Convert an error code to a human-readable error string
 *
 * @param err           Error code to convert to a string
 * @return borrowed pointer to a string representing the error code specified,
 * or "Unknown Error" if the code is not recognized.
 */
const char *parsebgp_strerror(parsebgp_error_t err);

#endif /* __PARSEBGP_ERROR_H */
