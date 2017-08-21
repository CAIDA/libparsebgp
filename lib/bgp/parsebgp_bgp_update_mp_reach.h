#ifndef __PARSEBGP_BGP_UPDATE_MP_REACH_H
#define __PARSEBGP_BGP_UPDATE_MP_REACH_H

#include "parsebgp_bgp_common.h"
#include "parsebgp_bgp_opts.h"
#include "parsebgp_error.h"
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

  /** (Inferred) number of Withdrawn NLRIs */
  int withdrawn_nlris_cnt;

} parsebgp_bgp_update_mp_unreach_t;


/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_decode(parsebgp_bgp_opts_t opts,
                                    parsebgp_bgp_update_mp_reach_t *msg,
                                    uint8_t *buf, size_t *lenp, size_t remain);


/** Decode an MP_UNREACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_unreach_decode(parsebgp_bgp_update_mp_unreach_t *msg,
                                      uint8_t *buf, size_t *lenp,
                                      size_t remain);

#endif /* __PARSEBGP_BGP_UPDATE_MP_REACH_H */
