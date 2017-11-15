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
