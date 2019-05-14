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

#ifndef __PARSEBGP_BGP_ROUTE_REFRESH_H
#define __PARSEBGP_BGP_ROUTE_REFRESH_H

#include <inttypes.h>
#include <stdlib.h>
#include "parsebgp_error.h"
#include "parsebgp_opts.h"

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

  /** Allocated Data Length (INTERNAL) */
  int _data_alloc_len;

  /** (Inferred) Data Length */
  int data_len;

} parsebgp_bgp_route_refresh_t;

#endif /* __PARSEBGP_BGP_ROUTE_REFRESH_H */
