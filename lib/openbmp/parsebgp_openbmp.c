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

#include "parsebgp_openbmp.h"
#include "parsebgp_utils.h"

#define BGPSTREAM_UTILS_STR_NAME_LEN 256
#define IS_ROUTER_MSG (flags & 0x80)
#define IS_ROUTER_IPV6 (flags & 0x40)
#define DESERIALIZE_VAL(to)                                                    \
  do {                                                                         \
    if (((len) - (nread)) < sizeof(to)) {                                      \
      return -1;                                                               \
    }                                                                          \
    memcpy(&(to), (buf), sizeof(to));                                          \
    nread += sizeof(to);                                                       \
    buf += sizeof(to);                                                         \
  } while (0)


parsebgp_error_t parsebgp_openbmp_decode(parsebgp_opts_t *opts,
                                         parsebgp_openbmp_msg_t *msg,
                                         const uint8_t *buf, size_t *buf_len) {
    parsebgp_error_t err;

    // remaining bytes in buffer
    size_t len = *buf_len;
    // how many bytes are read so far
    size_t nread = 0;
    int newln = 0;
    uint8_t ver_maj, ver_min, flags, u8;
    uint16_t u16;
    uint32_t u32;
    int name_len = 0;

    // we want at least a few bytes to do header checks
    if (len < 4) {
        *buf_len = 0;
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
        return 0;
    }
    nread += 4;
    buf += 4;

    // Confirm the version number
    DESERIALIZE_VAL(ver_maj);
    DESERIALIZE_VAL(ver_min);
    if (ver_maj != 1 || ver_min != 7) {
        /*
        bgpstream_log(BGPSTREAM_LOG_WARN,
                      "Unrecognized OpenBMP header version (%" PRIu8 ".%" PRIu8
                      ")",
                      ver_maj, ver_min);
                      */
        printf("Unrecognized OpenBMP header version (%" PRIu8 ".%" PRIu8 ")",
                ver_maj, ver_min);
        return 0;
    }

    // skip past the header length and the message length (since we'll parse the
    // entire header anyway).
    nread += 2 + 4;
    buf += 2 + 4;

    // read the flags
    DESERIALIZE_VAL(flags);
    // check the flags
    if (!IS_ROUTER_MSG) {
        // we only care about bmp raw messages, which are always router messages
        return 0;
    }

    // check the object type
    DESERIALIZE_VAL(u8);
    if (u8 != 12) {
        // we only want BMP RAW messages, so skip this one
        return 0;
    }

    // load the time stamps into the record
    DESERIALIZE_VAL(u32);
    // record->time_sec = ntohl(u32);
    DESERIALIZE_VAL(u32);
    // record->time_usec = ntohl(u32);

    // skip past the collector hash
    nread += 16;
    buf += 16;

    // grab the collector admin ID as collector name
    // TODO: if there is no admin ID, use the hash
    DESERIALIZE_VAL(u16);
    u16 = ntohs(u16);
    // maybe truncate the collector name
    if (u16 < BGPSTREAM_UTILS_STR_NAME_LEN) {
        name_len = u16;
    } else {
        name_len = BGPSTREAM_UTILS_STR_NAME_LEN - 1;
    }
    // copy the collector name in
    if ((len - nread) < u16) {
        return -1;
    }
    // memcpy(record->collector_name, buf, name_len);
    // record->collector_name[name_len] = '\0';
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
    // if (IS_ROUTER_IPV6) {
    //     bgpstream_ipv6_addr_init(&record->router_ip, buf);
    // } else {
    //     bgpstream_ipv4_addr_init(&record->router_ip, buf);
    // }
    nread += 16;
    buf += 16;

    // router name
    // TODO: if there is no name, or it is "default", use the IP
    DESERIALIZE_VAL(u16);
    u16 = ntohs(u16);
    // maybe truncate the router name
    if (u16 < BGPSTREAM_UTILS_STR_NAME_LEN) {
        name_len = u16;
    } else {
        name_len = BGPSTREAM_UTILS_STR_NAME_LEN - 1;
    }
    // copy the router name in
    if ((len - nread) < u16) {
        return -1;
    }
    // memcpy(record->router_name, buf, name_len);
    // record->router_name[name_len] = '\0';
    nread += u16;
    buf += u16;

    // and then ignore the row count
    nread += 4;
    buf += 4;

    *buf_len = nread;
    return 0;
}
