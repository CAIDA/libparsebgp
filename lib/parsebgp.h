#ifndef __PARSEBGP_H
#define __PARSEBGP_H

#include "parsebgp_bgp.h"
#include "parsebgp_bmp.h"
#include "parsebgp_mrt.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <unistd.h>

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
    parsebgp_bgp_msg_t bgp;

    /** Parsed BMP message */
    parsebgp_bmp_msg_t bmp;

    /** Parsed MRT message */
    parsebgp_mrt_msg_t mrt;

  } types;

  /** Sanity check to ensure that a message structure is not reused */
  uint8_t used;

} parsebgp_msg_t;

/**
 * Decode (parse) a single message of the given type from the given buffer into
 * the given message structure
 *
 * @param [in] opts     Options for the parser
 * @param [in] type     Type of message to parse
 * @param [in] msg      Pointer to a message structure to fill (created using
 *                      parsebgp_msg_create)
 * @param [in] buffer   Buffer containing the raw (unparsed) message

 * @param [in,out] len   Number of bytes in buffer. Updated with number of bytes
 *                       read from the buffer
 *
 * @return PARSEBGP_OK (0) if a message was parsed successfully, or an error
 code
 * otherwise
 */
parsebgp_error_t parsebgp_decode(parsebgp_opts_t opts, parsebgp_msg_type_t type,
                                 parsebgp_msg_t *msg, uint8_t *buffer,
                                 size_t *len);

/**
 * Create an empty message structure
 *
 * @return pointer to a fresh message structure
 *
 * The caller owns the returned structure and must call parsebgp_msg_destroy to
 * free allocated memory.
 */
parsebgp_msg_t *parsebgp_create_msg();

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
void parsebgp_dump_msg(parsebgp_msg_t *msg);

#endif // __PARSEBGP_H
