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

#ifndef __PARSEBGP_BGP_UPDATE_MP_REACH_IMPL_H
#define __PARSEBGP_BGP_UPDATE_MP_REACH_IMPL_H

#include "parsebgp_bgp_update_mp_reach.h"
#include "parsebgp_error.h"
#include "parsebgp_opts.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Decode an MP_REACH message */
parsebgp_error_t
parsebgp_bgp_update_mp_reach_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_mp_reach_t *msg,
                                    const uint8_t *buf, size_t *lenp, size_t remain);

/** Destroy an MP_REACH message */
void parsebgp_bgp_update_mp_reach_destroy(parsebgp_bgp_update_mp_reach_t *msg);

/** Clear an MP_REACH message */
void parsebgp_bgp_update_mp_reach_clear(parsebgp_bgp_update_mp_reach_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_REACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_reach_dump(
    const parsebgp_bgp_update_mp_reach_t *msg, int depth);

/** Decode an MP_UNREACH message */
parsebgp_error_t parsebgp_bgp_update_mp_unreach_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_mp_unreach_t *msg, const uint8_t *buf,
  size_t *lenp, size_t remain);

/** Destroy an MP_UNREACH message */
void parsebgp_bgp_update_mp_unreach_destroy(
  parsebgp_bgp_update_mp_unreach_t *msg);

/** Clear an MP_UNREACH message */
void parsebgp_bgp_update_mp_unreach_clear(
  parsebgp_bgp_update_mp_unreach_t *msg);

/**
 * Dump a human-readable version of the message to stdout
 *
 * @param msg           Pointer to the parsed MP_UNREACH attribute to dump
 * @param depth         Depth of the message within the overall message
 *
 * The output from these functions is designed to help with debugging the
 * library and also includes internal implementation information like the names
 * and sizes of structures. It may be useful to potential users of the library
 * to get a sense of their data.
 */
void parsebgp_bgp_update_mp_unreach_dump(
    const parsebgp_bgp_update_mp_unreach_t *msg, int depth);

#ifdef __cplusplus
}
#endif

#endif /* __PARSEBGP_BGP_UPDATE_MP_REACH_IMPL_H */
