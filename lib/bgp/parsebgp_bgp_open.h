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

#ifndef __PARSEBGP_BGP_OPEN_H
#define __PARSEBGP_BGP_OPEN_H

#include <inttypes.h>

/**
 * Supported BGP Capabilities
 * http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
 */
typedef enum {

  /** Multiprotocol Extensions for BGP-4 */
  PARSEBGP_BGP_OPEN_CAPABILITY_MPBGP = 1,

  /** Route Refresh Capability for BGP-4 */
  PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH = 2,

  /** Outbound Route Filtering Capability */
  PARSEBGP_BGP_OPEN_CAPABILITY_OUTBOUND_FILTER = 3,

  /** Graceful Restart Capability */
  PARSEBGP_BGP_OPEN_CAPABILITY_GRACEFUL_RESTART = 64,

  /** Support for 4-octet AS number capability */
  PARSEBGP_BGP_OPEN_CAPABILITY_AS4 = 65,

  /** Multisession BGP Capability */
  PARSEBGP_BGP_OPEN_CAPABILITY_MULTI_SESSION = 68,

  // TODO: add ADD-PATH capability

  /** Enhanced Route Refresh Capability */
  PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_ENHANCED = 70,

  /** Long-Lived Graceful Restart (LLGR) Capability */
  PARSEBGP_BGP_OPEN_CAPABILITY_LLGR = 71,

  /** Route Refresh Capability for BGP-4 */
  PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_OLD = 128,

} parsebgp_bgp_open_capability_code_t;

/**
 * MPBGP Capability
 */
typedef struct parsebgp_bgp_open_capability_mpbgp {

  /** AFI */
  uint16_t afi;

  /** Reserved (always 0) */
  uint8_t reserved;

  /** SAFI */
  uint8_t safi;

} parsebgp_bgp_open_capability_mpbgp_t;

/**
 * BGP Capability
 */
typedef struct parsebgp_bgp_open_capability {

  /** Code */
  uint8_t code;

  /** Length (in bytes) */
  uint8_t len;

  /** Capability Values */
  union {

    /** MPBGP AFI/SAFI */
    parsebgp_bgp_open_capability_mpbgp_t mpbgp;

    /** AS4 Capability */
    uint32_t asn;

    /** Raw data; access via BGPSTREAM_OPEN_CAPABILITY_RAW_DATA() */
    uint8_t *datap;

    /** Raw data; access via BGPSTREAM_OPEN_CAPABILITY_RAW_DATA() */
    uint8_t databuf[sizeof(uint8_t *)];

  } values;

} parsebgp_bgp_open_capability_t;

/** Determine if capability has raw (unparsed) data. */
#define BGPSTREAM_OPEN_CAPABILITY_IS_RAW(cap)                                  \
  ((cap)->len > 0 &&                                                           \
   (cap)->code != PARSEBGP_BGP_OPEN_CAPABILITY_MPBGP &&                        \
   (cap)->code != PARSEBGP_BGP_OPEN_CAPABILITY_AS4)

/** Get pointer to capability's raw data, or NULL if capability does not have
 * raw data. */
#define BGPSTREAM_OPEN_CAPABILITY_RAW_DATA(cap)                                \
  (!BGPSTREAM_OPEN_CAPABILITY_IS_RAW(cap) ? NULL :                             \
  (cap)->len > sizeof((cap)->values.databuf) ? (cap)->values.datap :           \
  &(cap)->values.databuf[0])

/**
 * BGP OPEN Message
 *
 * While there may be multiple parameters in the raw OPEN message, we only
 * support capabilities parameters, and as such merge all capability parameters
 * into a single array of capabilities.
 */
typedef struct parsebgp_bgp_open {

  /** Version (always 4) */
  uint8_t version;

  /** ASN of sender (2-byte only) */
  uint16_t asn;

  /** Hold Time */
  uint16_t hold_time;

  /** BGP ID of sender (Network byte order) */
  uint8_t bgp_id[4];

  /** Parameters Length (in bytes) */
  uint8_t param_len;

  /** Capabilities Parameters (no other parameter types are currently
      supported) */
  parsebgp_bgp_open_capability_t *capabilities;

  /** Number of allocated capabilities (INTERNAL) */
  int _capabilities_alloc_cnt;

  /** (Inferred) number of capabilities */
  int capabilities_cnt;

} parsebgp_bgp_open_t;

#endif /* __PARSEBGP_BGP_OPEN_H */
