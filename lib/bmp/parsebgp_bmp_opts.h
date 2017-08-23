#ifndef __PARSEBGP_BMP_OPTS_H
#define __PARSEBGP_BMP_OPTS_H

#include <inttypes.h>
#include "parsebgp_bgp_common.h"

/**
 * BMP Parsing Options
 */
typedef struct parsebgp_bmp_opts {

  /**
   * Peer IP Address Family
   *
   * This is based on the IPv6 flag in the Peer Header
   */
  parsebgp_bgp_afi_t peer_ip_afi;

} parsebgp_bmp_opts_t;

/**
 * Initialize parser options to default values
 *
 * @param opts          pointer to an opts structure to initialize
 */
void parsebgp_bmp_opts_init(parsebgp_bmp_opts_t *opts);

#endif /* __PARSEBGP_BMP_OPTS_H */
