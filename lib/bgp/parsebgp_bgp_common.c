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

#include "parsebgp_bgp_common_impl.h"
#include "parsebgp_utils.h"

void parsebgp_bgp_prefixes_dump(parsebgp_bgp_prefix_t *prefixes,
                                int prefixes_cnt, int depth)
{
  int i;
  parsebgp_bgp_prefix_t *tuple;
  for (i = 0; i < prefixes_cnt; i++) {
    tuple = &prefixes[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_prefix_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", tuple->type);
    PARSEBGP_DUMP_INT(depth, "AFI", tuple->afi);
    PARSEBGP_DUMP_INT(depth, "SAFI", tuple->safi);
    PARSEBGP_DUMP_PFX(depth, "Prefix", tuple->afi, tuple->addr, tuple->len);
  }
}
