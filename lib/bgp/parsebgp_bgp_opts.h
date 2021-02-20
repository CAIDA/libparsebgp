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

#ifndef __PARSEBGP_BGP_OPTS_H
#define __PARSEBGP_BGP_OPTS_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BGP Parsing Options
 */
typedef struct parsebgp_bgp_opts {

  /**
   * Has the 16-byte marker field been omitted from the message?
   *
   * If set, BGP messages are assumed to start from immediately after the marker
   * field. I.e., the first field in the message is the 2-byte length (that does
   * not count the 16 marker bytes).  In this case, the marker field in the
   * parsed structure will *not* be populated.
   */
  int marker_omitted;

  /**
   * Copy the marker field into the parsed message structure.
   *
   * Since the marker field bits MUST all always be set to 1, for normal parsing
   * this field has no use, so avoiding the memcpy from the buffer into the
   * result structure improves parsing efficiency. Users that want to inspect
   * the contents of this field should set this option to a non-zero value.
   */
  int marker_copy;

  /**
   * Does the BGP message to be parsed use 4-byte AS numbers?
   *
   * If set, messages are assumed to be encoded using 4-byte AS numbers,
   * otherwise the old 2-byte encoding is used.
   */
  int asn_4_byte;

  /**
   * Does the BGP message to be parsed carry path identifiers?
   * 
   * If set, messages are assumed to be encoded with a 4-byte path
   * identifier preceeding the update nlri
   */
  int add_path;

  /**
   * Has the AFI and SAFI been omitted from the MP_REACH attribute?
   *
   * This is used by the MRT parser since TABLE_DUMP_V2 decided to omit the AFI
   * and SAFI from the MP_REACH message. If this flag is set, the afi and safi
   * options MUST be set.
   */
  int mp_reach_no_afi_safi_reserved;

  /**
   * AFI to use when parsing the MP_REACH attribute
   */
  uint16_t afi;

  /**
   * SAFI to use when parsing the MP_REACH attribute
   */
  uint8_t safi;

  /**
   * Should only some UPDATE Path Attributes be parsed?
   *
   * If this is set, the path_attr_filter array is checked for each Path
   * Attribute type (ATTR_TYPE) found. If path_attr_filter[ATTR_TYPE] is set,
   * then the Path Attribute is parsed, otherwise it is skipped.
   */
  int path_attr_filter_enabled;

  /**
   * Path Attribute Filter array.
   *
   * There is one flag per Path Attribute Type, indicating whether the given
   * Path Attribute should be parsed (see documentation for
   * path_attr_filter_enabled for more information).
   */
  uint8_t path_attr_filter[UINT8_MAX];

  /**
   * Should some (select) UPDATE Path Attributes be parsed only in a superficial
   * manner?
   *
   * If this is set, the path_attr_raw array is checked for each Path
   * Attribute type (ATTR_TYPE) found. If path_attr_raw[ATTR_TYPE] is set,
   * then the Path Attribute is **not** fully parsed, and instead, a pointer to
   * a **copy** of the raw attribute data is set.
   *
   * This feature allows users to improve performance when they want to use
   * their own (optimized) parser to parse the attribute data.
   *
   * Note: currently only the PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH,
   * PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH and
   * PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES attributes support this
   * feature. All other attribute will be fully parsed (unless filtered out
   * using the above 'path_attr_filter').
   */
  int path_attr_raw_enabled;

  /**
   * Path Attribute raw-parsing config array
   *
   * There is one flag per Path Attribute Type, indicating whether the given
   * Path Attribute should be raw-parsed (see documentation for
   * path_attr_raw_enabled for more information).
   */
  uint8_t path_attr_raw[UINT8_MAX];

} parsebgp_bgp_opts_t;

/**
 * Initialize parser options to default values
 *
 * @param opts          pointer to an opts structure to initialize
 */
void parsebgp_bgp_opts_init(parsebgp_bgp_opts_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* __PARSEBGP_BGP_OPTS_H */
