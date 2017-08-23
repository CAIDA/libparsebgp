#ifndef __PARSEBGP_BGP_ROUTE_REFRESH_H
#define __PARSEBGP_BGP_ROUTE_REFRESH_H

#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * BGP ROUTE-REFRESH Subtypes
 */
typedef enum {

  /** Normal ROUTE-REFRESH [RFC2918] */
  PARSEBGP_BGP_ROUTE_REFRESH_TYPE_NORMAL = 0,

  /** Demarcation of beginning of route refresh (BoRR) operation */
  PARSEBGP_BGP_ROUTE_REFRESH_TYPE_BEGIN = 1,

  /** Demarcation of ending of route refresh (BoRR) operation */
  PARSEBGP_BGP_ROUTE_REFRESH_TYPE_END = 2,

} parsebgp_bgp_route_refresh_subtype_t;

/**
 * BGP ROUTE-REFRESH Message
 *
 * Supports both ROUTE-REFRESH [RFC2918] and Enhanced ROUTE-REFRESH [RFC7313].
 */
typedef struct parsebgp_bgp_route_refresh {

  /** AFI */
  uint16_t afi;

  /** Subtype (Reserved in RFC2918) */
  uint8_t subtype;

  /** SAFI */
  uint8_t safi;

  /** Data (e.g., for ORF messages) */
  uint8_t *data;

  /** (Inferred) Data Length */
  int data_len;

} parsebgp_bgp_route_refresh_t;

/** Decode a ROUTE REFRESH message */
parsebgp_error_t
parsebgp_bgp_route_refresh_decode(parsebgp_opts_t *opts,
                                  parsebgp_bgp_route_refresh_t *msg,
                                  uint8_t *buf, size_t *lenp, size_t remain);

/** Destroy an ROUTE REFRESH message */
void parsebgp_bgp_route_refresh_destroy(parsebgp_bgp_route_refresh_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed ROUTE-REFRESH message to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_route_refresh_dump(parsebgp_bgp_route_refresh_t *msg,
                                     int depth);

#endif /* __PARSEBGP_BGP_ROUTE_REFRESH_H */
