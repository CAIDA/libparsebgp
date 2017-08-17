#ifndef __PARSEBGP_BGP_OPTS_H
#define __PARSEBGP_BGP_OPTS_H

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

} parsebgp_bgp_opts_t;

#endif /* __PARSEBGP_BGP_OPTS_H */
