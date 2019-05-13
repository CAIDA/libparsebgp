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

#endif /* __PARSEBGP_BGP_UPDATE_MP_REACH_H */
