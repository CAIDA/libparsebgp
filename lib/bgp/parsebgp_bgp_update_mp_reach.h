#ifndef __PARSEBGP_BGP_UPDATE_MP_REACH_H
#define __PARSEBGP_BGP_UPDATE_MP_REACH_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <inttypes.h>
#include <stdlib.h>

/**
 * MP_REACH_NLRI
 */
typedef struct parsebgp_bgp_update_mp_reach {

  /** AFI */
  uint16_t afi;

  /** SAFI */
  uint8_t safi;

  /** Next-Hop Length (bytes) */
  uint8_t next_hop_len;

  /** Next-Hop Address */
  uint8_t next_hop[16];

  /** Next-Hop Link-Local Address (only used for IPv6 and when next_hop_len is
      32) */
  uint8_t next_hop_ll[16];

  /** Reserved (always zero) */
  uint8_t reserved;

  /** NLRI information */
  parsebgp_bgp_prefix_t *nlris;

  /** Number of allocated NLRIs (INTERNAL) */
  int _nlris_alloc_cnt;

  /** (Inferred) number of NLRIs */
  int nlris_cnt;

} parsebgp_bgp_update_mp_reach_t;

/**
 * MP_UNREACH_NLRI
 */
typedef struct parsebgp_bgp_update_mp_unreach {

  /** AFI */
  uint16_t afi;

  /** SAFI */
  uint8_t safi;

  /** NLRI information */
  parsebgp_bgp_prefix_t *withdrawn_nlris;

  /** Number of allocated NLRIs (INTERNAL) */
  int _withdrawn_nlris_alloc_cnt;

  /** (Inferred) number of Withdrawn NLRIs */
  int withdrawn_nlris_cnt;

} parsebgp_bgp_update_mp_unreach_t;

/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_mp_reach_t *msg,
                                    uint8_t *buf, size_t *lenp, size_t remain);

/** Destroy an MP_REACH message */
void parsebgp_bgp_update_mp_reach_destroy(parsebgp_bgp_update_mp_reach_t *msg);

/** Clear an MP_REACH message */
void parsebgp_bgp_update_mp_reach_clear(parsebgp_bgp_update_mp_reach_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_REACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_reach_dump(parsebgp_bgp_update_mp_reach_t *msg,
                                       int depth);

/** Decode an MP_UNREACH message */
parsebgp_error_t parsebgp_bgp_update_mp_unreach_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_mp_unreach_t *msg, uint8_t *buf,
  size_t *lenp, size_t remain);

/** Destroy an MP_UNREACH message */
void parsebgp_bgp_update_mp_unreach_destroy(
  parsebgp_bgp_update_mp_unreach_t *msg);

/** Clear an MP_UNREACH message */
void parsebgp_bgp_update_mp_unreach_clear(
  parsebgp_bgp_update_mp_unreach_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_UNREACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_unreach_dump(parsebgp_bgp_update_mp_unreach_t *msg,
                                         int depth);

#endif /* __PARSEBGP_BGP_UPDATE_MP_REACH_H */
