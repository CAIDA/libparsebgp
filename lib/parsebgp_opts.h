#ifndef __PARSEBGP_OPTS_H
#define __PARSEBGP_OPTS_H

#include "parsebgp_bgp_opts.h"

/**
 * Parsing Options
 */
typedef struct parsebgp_opts {

  /**
   * Ignore Not-Implemented Errors
   *
   * If this is set, the parser will attempt to skip portions of messages that
   * contain unimplemented features. It will emit a warning that includes the
   * file and line number to aid with requesting support be added.
   *
   * If this is **not** set, the parser will abort if it finds a feature that it
   * does not recognize.
   *
   * Regardless of this setting, the parser will abort if it finds a malformed
   * message
   */
  int ignore_not_implemented;

  /** BGP-specific parsing options */
  parsebgp_bgp_opts_t bgp;

} parsebgp_opts_t;

/**
 * Initialize parser options to default values
 *
 * @param opts          pointer to an opts structure to initialize
 */
void parsebgp_opts_init(parsebgp_opts_t *opts);

#endif /* __PARSEBGP_OPTS_H */
