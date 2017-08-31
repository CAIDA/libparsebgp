#ifndef __PARSEBGP_BGP_OPEN_H
#define __PARSEBGP_BGP_OPEN_H

#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

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

  } values;

} parsebgp_bgp_open_capability_t;

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

/** Decode an OPEN message */
parsebgp_error_t parsebgp_bgp_open_decode(parsebgp_opts_t *opts,
                                          parsebgp_bgp_open_t *msg,
                                          uint8_t *buf, size_t *lenp,
                                          size_t remain);

/** Destroy an OPEN message */
void parsebgp_bgp_open_destroy(parsebgp_bgp_open_t *msg);

/** Clear an OPEN message */
void parsebgp_bgp_open_clear(parsebgp_bgp_open_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed OPEN message to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_open_dump(parsebgp_bgp_open_t *msg, int depth);

#endif /* __PARSEBGP_BGP_OPEN_H */
