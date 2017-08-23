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

} parsebgp_bgp_opts_t;

/**
 * Initialize parser options to default values
 *
 * @param opts          pointer to an opts structure to initialize
 */
void parsebgp_bgp_opts_init(parsebgp_bgp_opts_t *opts);

#endif /* __PARSEBGP_BGP_OPTS_H */
