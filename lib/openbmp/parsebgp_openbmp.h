/*
 * Copyright (C) 2019 The Regents of the University of California.
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

#ifndef __PARSEBGP_OPENBMP_H
#define __PARSEBGP_OPENBMP_H

#include "parsebgp_opts.h"  // the header includes all sub type opts including parsebgp_openbmp_opts.h
#include "parsebgp_bgp.h"   // BMP encapsulates BGP messages
#include "parsebgp_bmp.h"   // OpenBMP encapsulates BMP messages
#include "parsebgp_error.h" // for parsebgp_error_t
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#define STR_NAME_LEN 256

typedef struct parsebgp_openbmp_msg {
    // OpenBMP version numbers
    uint8_t ver_maj, ver_min;

    // OpenBMP msg flags
    uint8_t flags;
    //
    // OpenBMP topic type (collector or raw_bmp)
    uint8_t topic_type;

    // Collection time (seconds component)
    uint32_t time_sec;

    // Collection time (microseconds component)
    uint32_t time_usec;

    // Collector name
    int collector_name_len;
    char collector_name[STR_NAME_LEN];

    // Router name
    int router_name_len;
    char router_name[STR_NAME_LEN];

    // Router IP
    uint8_t router_ip[16];
    // Router IP Address AFI (based on openbmp header flags)
    parsebgp_bgp_afi_t router_afi;

    // Parsed bmp msg if full msg parsing is required
    parsebgp_bmp_msg_t *bmp_msg;

} parsebgp_openbmp_msg_t;

void parsebgp_openbmp_clear_msg(parsebgp_openbmp_msg_t *msg);

void parsebgp_openbmp_destroy_msg(parsebgp_openbmp_msg_t *msg);

void parsebgp_openbmp_dump_msg(const parsebgp_openbmp_msg_t *msg, int depth);

parsebgp_error_t parsebgp_openbmp_decode(parsebgp_opts_t *opts, parsebgp_openbmp_msg_t *msg,
                                         const uint8_t *buf, size_t *len);

#endif /* __PARSEBGP_OPENBMP_H */
