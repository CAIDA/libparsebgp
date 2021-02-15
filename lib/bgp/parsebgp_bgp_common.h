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

#ifndef __PARSEBGP_BGP_COMMON_H
#define __PARSEBGP_BGP_COMMON_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BGP Address Families (AFI)
 */
typedef enum {

  /** IPv4 Address */
  PARSEBGP_BGP_AFI_IPV4 = 1,

  /** IPv6 Address */
  PARSEBGP_BGP_AFI_IPV6 = 2,

  // TODO: add support for L2VPN, BGPLS

} parsebgp_bgp_afi_t;

/**
 * BGP Subsequnt Address Families (SAFI)
 */
typedef enum {

  /** Unicast */
  PARSEBGP_BGP_SAFI_UNICAST = 1,

  /** Multicast */
  PARSEBGP_BGP_SAFI_MULTICAST = 2,

  // TODO: add support for EVPN, NLRI_LABEL

  /** MPLS */
  PARSEBGP_BGP_SAFI_MPLS = 128,

} parsebgp_bgp_safi_t;

/**
 * BGP Prefix Types (based on AFI/SAFI)
 */
typedef enum {

  /** Unicast IPv4 Prefix */
  PARSEBGP_BGP_PREFIX_UNICAST_IPV4 = 1,

  /** Unicast IPv6 Prefix */
  PARSEBGP_BGP_PREFIX_UNICAST_IPV6 = 2,

  /** Multicast IPv4 Prefix */
  PARSEBGP_BGP_PREFIX_MULTICAST_IPV4 = 1,

  /** Multicast IPv6 Prefix */
  PARSEBGP_BGP_PREFIX_MULTICAST_IPV6 = 2,

  // TODO: add support for BGPLS and L2VPN etc.
} parsebgp_bgp_prefix_type_t;

/**
 * BGP Prefix Tuple
 */
typedef struct parsebgp_bgp_prefix {

  /** Prefix Type (parsebgp_bgp_prefix_type_t) */
  uint8_t type;

  /** Prefix AFI */
  uint16_t afi;

  /** Prefix SAFI */
  uint8_t safi;

  /** Prefix Length (number of bits in the mask) */
  uint8_t len;

  /** Has additional path identifier? */
  uint8_t has_addl_path_id;

  /** Path Identifier differentiates between additional paths for the same
      prefix (RFC 7911, 8050) */
  uint32_t addl_path_id;

  /** Prefix Address */
  uint8_t addr[16];

} parsebgp_bgp_prefix_t;

#ifdef __cplusplus
}
#endif

#endif /* __PARSEBGP_BGP_COMMON_H */
