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

#ifndef __PARSEBGP_H
#define __PARSEBGP_H

#include <inttypes.h>
#include <unistd.h>
#include "parsebgp_bgp.h"
#include "parsebgp_bmp.h"
#include "parsebgp_mrt.h"
#include "parsebgp_opts.h"

/**
 * Message types supported by libparsebgp
 */
typedef enum parsebgp_msg_type {
  PARSEBGP_MSG_TYPE_INVALID = 0,
  PARSEBGP_MSG_TYPE_BGP = 1,
  PARSEBGP_MSG_TYPE_BMP = 2,
  PARSEBGP_MSG_TYPE_MRT = 3,
} parsebgp_msg_type_t;

/** Convenience macro to allow iterating over all valid message types */
#define PARSEBGP_FOREACH_MSG_TYPE(iter)                                        \
  for ((iter) = PARSEBGP_MSG_TYPE_BGP; (iter) <= PARSEBGP_MSG_TYPE_MRT;        \
       (iter)++)

/** Structure into which a message is parsed */
typedef struct parsebgp_msg {

  /** Type of message parsed */
  parsebgp_msg_type_t type;

  struct {

    /** Parsed BGP message (only used if type is BGP, otherwise encapsulated BGP
        message is contained in MRT or BMP structures) */
    parsebgp_bgp_msg_t *bgp;

    /** Parsed BMP message */
    parsebgp_bmp_msg_t *bmp;

    /** Parsed MRT message */
    parsebgp_mrt_msg_t *mrt;

  } types;

} parsebgp_msg_t;

/**
 * Decode (parse) a single message of the given type from the given buffer into
 * the given message structure
 *
 * @param [in] opts     Options for the parser
 * @param [in] type     Type of message to parse
 * @param [in] msg      Pointer to a message structure to fill (created using
 *                      parsebgp_create_msg)
 * @param [in] buffer   Buffer containing the raw (unparsed) message

 * @param [in,out] len   Number of bytes in buffer. Updated with number of bytes
 *                       read from the buffer
 *
 * @return PARSEBGP_OK (0) if a message was parsed successfully, or an error
 code
 * otherwise
 */
parsebgp_error_t parsebgp_decode(parsebgp_opts_t opts, parsebgp_msg_type_t type,
                                 parsebgp_msg_t *msg, const uint8_t *buffer,
                                 size_t *len);

/**
 * Create an empty message structure
 *
 * @return pointer to a fresh message structure
 *
 * The caller owns the returned structure and must call parsebgp_destroy_msg to
 * free allocated memory.
 */
parsebgp_msg_t *parsebgp_create_msg(void);

/**
 * Clear the given message structure ready for reuse
 *
 * @param msg           Pointer to message structure to clear
 */
void parsebgp_clear_msg(parsebgp_msg_t *msg);

/**
 * Destroy the given message structure
 *
 * @param msg           Pointer to message structure to destroy
 */
void parsebgp_destroy_msg(parsebgp_msg_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed message to dump
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_dump_msg(const parsebgp_msg_t *msg);

#endif // __PARSEBGP_H
