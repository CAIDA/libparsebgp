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

#include "parsebgp_utils.h"
#include "parsebgp_openbmp.h"
#include "parsebgp_bmp.h"

void parsebgp_openbmp_clear_msg(parsebgp_openbmp_msg_t *msg) {
    // TODO: reset openbmp header values to zero
    parsebgp_bmp_clear_msg(msg->bmp_msg);
}

void parsebgp_openbmp_destroy_msg(parsebgp_openbmp_msg_t *msg) {
    parsebgp_bmp_destroy_msg(msg->bmp_msg);
    free(msg);
}

void parsebgp_openbmp_dump_msg(const parsebgp_openbmp_msg_t *msg, int depth) {
    // dump openbmp header fields
    PARSEBGP_DUMP_INT(depth, "Version major", msg->ver_maj);
    PARSEBGP_DUMP_INT(depth, "Version minor", msg->ver_min);
    PARSEBGP_DUMP_INT(depth, "Flags", msg->flags);
    PARSEBGP_DUMP_INT(depth, "Time.sec", msg->time_sec);
    PARSEBGP_DUMP_INT(depth, "Time.usec", msg->time_usec);
    PARSEBGP_DUMP_INFO(depth, "Collector name" ": %*s\n", 20 - (int)sizeof("Collector name" ":"), msg->collector_name);
    PARSEBGP_DUMP_INFO(depth, "Router name" ": %*s\n", 20 - (int)sizeof("Router name" ":"), msg->router_name);

    // dump bmp msg
    parsebgp_bmp_dump_msg(msg->bmp_msg, depth);
}

parsebgp_error_t parsebgp_openbmp_decode(parsebgp_opts_t *opts,
                                         parsebgp_openbmp_msg_t *msg,
                                         const uint8_t *buf, size_t *buf_len) {
    // remaining bytes in buffer
    size_t len = *buf_len;
    // how many bytes are read so far
    size_t nread = 0;
    int newln = 0;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    int name_len = 0;

    // we want at least a few bytes to do header checks
    if (len < 4) {
        *buf_len = 0;
        printf("we want at least a few bytes to do header checks\n");
        return 0;
    }

    // is this an OpenBMP ASCII header (either "text" or "legacy-text")?
    if (*buf == 'V') {
        // skip until we find double-newlines
        while ((len - nread) > 0) {
            if (newln == 2) {
                // this is the first byte of the payload
                *buf_len = nread - 1;
                return 0;
            }
            if (*buf == '\n') {
                newln++;
            } else {
                newln = 0;
            }
            nread++;
            buf++;
        }
        // if we reach here, then we've failed to parse the header. just give up
        *buf_len = 0;
        return 0;
    }

    // double-check the magic number
    if (memcmp(buf, "OBMP", 4) != 0) {
        // it's not a known OpenBMP header, assume that it is raw BMP
        *buf_len = 0;
        printf("it's not a known OpenBMP header, assume that it is raw BMP\n");
        return 0;
    }
    nread += 4;
    buf += 4;

    // Confirm the version number
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, msg->ver_maj);
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, msg->ver_min);
    if (msg->ver_maj != 1 || msg->ver_min != 7) {
        printf("Unrecognized OpenBMP header version (%" PRIu8 ".%" PRIu8 ")",
                msg->ver_maj, msg->ver_min);
        return 0;
    }

    // skip past the header length and the message length (since we'll parse the
    // entire header anyway).
    nread += 2 + 4;
    buf += 2 + 4;

    // read the flags
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, msg->flags);
    // check the flags
    // we only care about bmp raw messages, which are always router messages
    if (!(msg->flags & 0x80)) {
        return 0;
    }

    // check the object type
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, u8);
    if (u8 != 12) {
        // we only want BMP RAW messages, so skip this one
        return 0;
    }

    // load the time stamps into the record
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, u32);
    msg->time_sec = ntohl(u32);
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, u32);
    msg->time_usec = ntohl(u32);

    // skip past the collector hash
    nread += 16;
    buf += 16;

    // grab the collector admin ID as collector name
    // TODO: if there is no admin ID, use the hash
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, u16);
    u16 = ntohs(u16);
    // maybe truncate the collector name
    if (u16 < STR_NAME_LEN) {
        name_len = u16;
    } else {
        name_len = STR_NAME_LEN - 1;
    }
    // copy the collector name in
    if ((len - nread) < u16) {
        return -1;
    }
    msg->collector_name_len = name_len;
    memcpy(msg->collector_name, buf, name_len);
    msg->collector_name[name_len] = '\0';
    nread += u16;
    buf += u16;

    if ((len - nread) < 32) {
        // not enough buffer left for router hash and IP
        return -1;
    }

    // skip past the router hash
    nread += 16;
    buf += 16;

    // grab the router IP
    if (msg->flags & 0x40) { // IS_ROUTER_IPV6
        msg->router_ip_afi = PARSEBGP_BGP_AFI_IPV6;
    } else {
        msg->router_ip_afi = PARSEBGP_BGP_AFI_IPV4;
    }
    // this marco should automatically increment nread and buf
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, msg->router_ip);

    // router name
    // TODO: if there is no name, or it is "default", use the IP
    PARSEBGP_DESERIALIZE_VAL(buf, len - nread, nread, u16);
    u16 = ntohs(u16);
    // maybe truncate the router name
    if (u16 < STR_NAME_LEN) {
        name_len = u16;
    } else {
        name_len = STR_NAME_LEN - 1;
    }
    // copy the router name in
    if ((len - nread) < u16) {
        return -1;
    }
    msg->router_name_len = name_len;
    memcpy(msg->router_name, buf, name_len);
    msg->router_name[name_len] = '\0';
    nread += u16;
    buf += u16;

    // and then ignore the row count
    nread += 4;
    buf += 4;

    // see whether the raw bmp msg is parsed.
    size_t slen  = len - nread;
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->bmp_msg);
    parsebgp_error_t bmp_parse_err = parsebgp_bmp_decode(opts, msg->bmp_msg, buf, &slen);
    // return err msg from bmp parsing if any.
    if (bmp_parse_err != PARSEBGP_OK) {
        return bmp_parse_err;
    }
    // increment read len
    nread += slen;

    // set how many bytes were read to parse this openbmp msg.
    *buf_len = nread;
    // return an openbmp msg was parsed.
    return PARSEBGP_OK;
}
