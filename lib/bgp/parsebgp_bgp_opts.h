#ifndef __PARSEBGP_BGP_OPTS_H
#define __PARSEBGP_BGP_OPTS_H

#include <inttypes.h>

/**
 * BGP Parsing Options
 */
typedef struct parsebgp_bgp_opts {

  /**
   * Does the BGP message to be parsed use 4-byte AS numbers?
   *
   * If set, messages are assumed to be encoded using 4-byte AS numbers,
   * otherwise the old 2-byte encoding is used.
   */
  int asn_4_byte;

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

} parsebgp_bgp_opts_t;

#endif /* __PARSEBGP_BGP_OPTS_H */
