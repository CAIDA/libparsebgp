#ifndef __PARSEBGP_OPTS_H
#define __PARSEBGP_OPTS_H

#include "parsebgp_bgp_opts.h"
#include "parsebgp_bmp_opts.h"

/**
 * Parsing Options
 */
typedef struct parsebgp_opts {

  /**
   * Ignore Not-Implemented Errors
   *
   * If this is set, the parser will attempt to skip portions of messages that
   * contain unimplemented features. It will emit a warning that includes the
   * file and line number to aid with requesting support be added (see
   * silence_not_implemented to disable this warning).
   *
   * If this is **not** set, the parser will abort if it finds a feature that it
   * does not recognize.
   *
   * Regardless of this setting, the parser will abort if it finds a malformed
   * message
   */
  int ignore_not_implemented;

  /**
   * Silence Not-Implemented Warnings
   *
   * If this is set (and ignore_not_implemented is also set), the parser will
   * **not** emit warnings when an unknown message feature is encountered.
   */
  int silence_not_implemented;

  /**
   * Ignore Invalid-Message Errors (to the extent possible)
   *
   * If this is set, the parser will attempt to skip portions of messages that
   * contain invalid features. It will emit a warning that includes the file and
   * line number to aid with debugging malformed data (see silence_invalid to
   * disable this warning).
   *
   * If this is **not** set, the parser will abort if it finds a feature that it
   * determines to be malformed.
   *
   * Regardless of this setting, the parser will abort if it finds a malformed
   * message that it cannot skip safely.
   */
  int ignore_invalid;

  /**
   * Silence Invalid-Message Warnings
   *
   * If this is set (and ignore_invalid is also set), the parser will **not**
   * emit warnings when a malformed message feature is encountered.
   */
  int silence_invalid;

  /** BGP-specific parsing options */
  parsebgp_bgp_opts_t bgp;

  /** BMP-specific parsing options */
  parsebgp_bmp_opts_t bmp;

} parsebgp_opts_t;

/**
 * Initialize parser options to default values
 *
 * @param opts          pointer to an opts structure to initialize
 */
void parsebgp_opts_init(parsebgp_opts_t *opts);

#endif /* __PARSEBGP_OPTS_H */
