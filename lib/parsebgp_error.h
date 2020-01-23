/*
 * Copyright (C) 2017 The Regents of the University of California.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PARSEBGP_ERROR_H
#define __PARSEBGP_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

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

  /** Message does not contain an entire sub-message */
  PARSEBGP_TRUNCATED_MSG = -5,

  PARSEBGP_N_ERR = -6,

} parsebgp_error_t;

/**
 * Convert an error code to a human-readable error string
 *
 * @param err           Error code to convert to a string
 * @return borrowed pointer to a string representing the error code specified,
 * or "Unknown Error" if the code is not recognized.
 */
const char *parsebgp_strerror(parsebgp_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* __PARSEBGP_ERROR_H */
