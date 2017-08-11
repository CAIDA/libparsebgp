#include "parsebgp_bmp.h"
#include "parsebgp_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BMP_HDR_V1V2_LEN 43 ///< BMP v1/2 header length
#define BMP_HDR_V3_LEN 6 ///< BMP v3 header length
#define BMP_PEER_HDR_LEN 42 ///< BMP peer header length

/* -------------------- Helper parser functions -------------------- */

static parsebgp_error_t parse_info_tlvs(parsebgp_bmp_info_tlv_t **tlvs,
                                        int *tlvs_cnt,
                                        uint8_t *buf, size_t *lenp,
                                        size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bmp_info_tlv_t *tlv = NULL;

  assert(remain <= len);
  *tlvs_cnt = 0;

  // read and realloc tlvs until we run out of message
  while (remain > 0) {
    // optimistically allocate a new TLV (if we fail to parse the message then
    // it will be partially/unfilled)
    if ((*tlvs = realloc(*tlvs, sizeof(parsebgp_bmp_info_tlv_t) *
                                  ((*tlvs_cnt) + 1))) == NULL) {
      return MALLOC_FAILURE;
    }
    tlv = &(*tlvs)[*tlvs_cnt];
    (*tlvs_cnt)++;

    // read the TLV header
    // Type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, tlv->type);
    tlv->type = ntohs(tlv->type);

    // Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, tlv->len);
    tlv->len = ntohs(tlv->len);

    remain -= sizeof(tlv->type) + sizeof(tlv->len);

    if (tlv->len > remain) {
      // the length field doesn't match what we saw in the common header
      return INVALID_MSG;
    }

    // allocate a buffer for the data
    if ((tlv->info = malloc(sizeof(uint8_t) * tlv->len)) == NULL) {
      return MALLOC_FAILURE;
    }
    // and then copy it in
    if (tlv->len > (len - nread)) {
      return INCOMPLETE_MSG;
    }
    memcpy(tlv->info, buf, tlv->len);
    nread += tlv->len;
    buf += tlv->len;
    remain -= tlv->len;

    fprintf(stderr, "DEBUG: TLV info: '%.*s'\n", tlv->len, tlv->info);
  }

  *lenp = nread;
  return OK;
}

static void destroy_info_tlvs(parsebgp_bmp_info_tlv_t **tlvs,
                              int *tlvs_cnt)
{
  int i;
  if (*tlvs_cnt == 0) {
    return;
  }

  for (i = 0; i < *tlvs_cnt; i++) {
    free((*tlvs)[i].info);
    (*tlvs)[i].info = NULL;
  }
  free(*tlvs);
  *tlvs = NULL;
  *tlvs_cnt = 0;
}


/* -------------------- BMP Message Type Parsers -------------------- */

// Type 1:
static parsebgp_error_t parse_stats_report(parsebgp_bmp_stats_report_t *msg,
                                           uint8_t *buf, size_t *lenp,
                                           size_t remain)
{
  size_t len = *lenp, nread = 0;
  uint64_t i;
  parsebgp_bmp_stats_counter_t *sc;

  // Stats Count
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->stats_count);
  msg->stats_count = ntohl(msg->stats_count);

  // Allocate enough counter structures
  if ((msg->counters = malloc_zero(sizeof(parsebgp_bmp_stats_counter_t) *
                                   msg->stats_count)) == NULL) {
    return MALLOC_FAILURE;
  }

  fprintf(stderr, "DEBUG: Stats with %"PRIu32" counters\n", msg->stats_count);

  // parse each stat
  for (i = 0; i < msg->stats_count; i++) {
    sc = &msg->counters[i];

    // Type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->type);
    sc->type = ntohs(sc->type);

    // Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->len);
    sc->len = ntohs(sc->len);

    if (sc->len > remain - nread) {
      // invalid length specification
      return INVALID_MSG;
    }

    // Read the data
    switch (sc->type) {
      // 32-bit counter types:
    case PARSEBGP_BMP_STATS_PREFIX_REJECTS:
    case PARSEBGP_BMP_STATS_PREFIX_DUPS:
    case PARSEBGP_BMP_STATS_WITHDRAW_DUP:
    case PARSEBGP_BMP_STATS_INVALID_CLUSTER_LIST:
    case PARSEBGP_BMP_STATS_INVALID_AS_PATH_LOOP:
    case PARSEBGP_BMP_STATS_INVALID_ORIGINATOR_ID:
    case PARSEBGP_BMP_STATS_INVALID_AS_CONFED_LOOP:
    case PARSEBGP_BMP_STATS_UPD_TREAT_AS_WITHDRAW:
    case PARSEBGP_BMP_STATS_PREFIX_TREAT_AS_WITHDRAW:
    case PARSEBGP_BMP_STATS_DUP_UPD:
      if (sc->len != sizeof(sc->data.counter_u32)) {
        return INVALID_MSG;
      }
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->data.counter_u32);
      sc->data.counter_u32 = ntohl(sc->data.counter_u32);
      break;

      // 64-bit gauge types:
    case PARSEBGP_BMP_STATS_ROUTES_ADJ_RIB_IN:
    case PARSEBGP_BMP_STATS_ROUTES_LOC_RIB:
      if (sc->len != sizeof(sc->data.gauge_u64)) {
        return INVALID_MSG;
      }
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->data.gauge_u64);
      SWAP_BYTES(&sc->data.gauge_u64, 8);
      break;

      // AFI/SAFI 64-bit gauge types:
    case PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_ADJ_RIB_IN:
    case PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_LOC_RIB:
      if (sc->len != 11) {
        return INVALID_MSG;
      }

      // AFI
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->data.afi_safi_gauge.afi);
      sc->data.afi_safi_gauge.afi = ntohs(sc->data.afi_safi_gauge.afi);

      // SAFI
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->data.afi_safi_gauge.safi);

      // u64 gauge
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, sc->data.afi_safi_gauge.gauge_u64);
      SWAP_BYTES(&sc->data.gauge_u64, 8);
      break;
    }

    fprintf(stderr, "DEBUG: Stat Counter: Type: %d, Length: %d\n", sc->type,
            sc->len);
    fprintf(stderr, "DEBUG: Stat data: u32: %" PRIu32 ", u64: %" PRIu64 "\n",
            sc->data.counter_u32, sc->data.gauge_u64);
  }

  *lenp = nread;
  return OK;
}

void destroy_stats_report(parsebgp_bmp_stats_report_t *msg) {
  free(msg->counters);
  msg->stats_count = 0;
}


// Type 2:
static parsebgp_error_t parse_peer_down(parsebgp_bmp_peer_down_t *msg,
                                        uint8_t *buf, size_t *lenp,
                                        size_t remain)
{
  size_t len = *lenp, nread = 0;

  // Reason
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->reason);

  // Read the data (if present)
  switch (msg->reason) {
    // Reasons with a BGP NOTIFICATION message
  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF:
  case PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF:
    // TODO: read bgp notficiation message
    return NOT_IMPLEMENTED;
    break;

  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE:
    // read the fsm code
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->data.fsm_code);
    msg->data.fsm_code = ntohs(msg->data.fsm_code);
    break;

  default:
    return NOT_IMPLEMENTED;
    break;
  }

  // we read too much, or too little data according to the common header length
  if (remain != nread) {
    return INVALID_MSG;
  }

  *lenp = nread;
  return OK;
}

void destroy_peer_down(parsebgp_bmp_peer_down_t *msg)
{
  switch (msg->reason) {
    // Reasons with a BGP NOTIFICATION message
  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF:
  case PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF:
    // TODO: destroy bgp notficiation message
    break;

  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE:
  default:
    // nothing to do
    break;
  }
}


// Type 3:
static parsebgp_error_t parse_peer_up(parsebgp_bmp_peer_up_t *msg,
                                      uint8_t *buf, size_t *lenp,
                                      size_t remain)
{
  size_t len = *lenp, nread = 0;

  // Local IP address
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->local_ip);

  // Local port
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->local_port);
  msg->local_port = ntohs(msg->local_port);

  // Remote port
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->remote_port);
  msg->remote_port = ntohs(msg->remote_port);

  fprintf(stderr, "DEBUG: Local Port: %"PRIu16", Remote Port: %"PRIu16"\n",
          msg->local_port, msg->remote_port);

  // TODO: parse the Sent OPEN
  // DEBUG: poke our nose into the BGP message to find out how long it is
  uint16_t fixme;
  memcpy(&fixme, buf+16, 2);
  fixme = htons(fixme);
  nread += fixme;
  buf += fixme;
  fprintf(stderr, "DEBUG: Sent OPEN len: %d\n", fixme);

  // TODO: parse the Recv OPEN
  memcpy(&fixme, buf+16, 2);
  fixme = htons(fixme);
  nread += fixme;
  buf += fixme;
  fprintf(stderr, "DEBUG: Recv OPEN len: %d\n", fixme);

  // Information TLVs (optional)
  parse_info_tlvs(&msg->tlvs, &msg->tlvs_cnt, buf, lenp, remain - nread);

  *lenp = nread;
  return OK;
}

static void destroy_peer_up(parsebgp_bmp_peer_up_t *msg)
{
  // TODO: destroy the sent OPEN
  // TODO: destroy the recv OPEN

  destroy_info_tlvs(&msg->tlvs, &msg->tlvs_cnt);
}


// Type 4:
static parsebgp_error_t parse_init_msg(parsebgp_bmp_init_msg_t *msg,
                                       uint8_t *buf, size_t *lenp,
                                       size_t remain)
{
  return parse_info_tlvs(&msg->tlvs, &msg->tlvs_cnt, buf, lenp, remain);
}

static void destroy_init_msg(parsebgp_bmp_init_msg_t *msg)
{
  destroy_info_tlvs(&msg->tlvs, &msg->tlvs_cnt);
}


// Type 5:
static parsebgp_error_t parse_term_msg(parsebgp_bmp_term_msg_t *msg,
                                       uint8_t *buf, size_t *lenp,
                                       size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bmp_term_tlv_t *tlv = NULL;

  // read and realloc tlvs until we run out of message
  while (remain > 0) {
    // optimistically allocate a new TLV (if we fail to parse the message then
    // it will be partially/unfilled)
    if ((msg->tlvs = realloc(msg->tlvs, sizeof(parsebgp_bmp_term_tlv_t) *
                             ((msg->tlvs_cnt) + 1))) == NULL) {
      return MALLOC_FAILURE;
    }
    tlv = &msg->tlvs[msg->tlvs_cnt];
    msg->tlvs_cnt++;

    // read the TLV header
    // Type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, tlv->type);
    tlv->type = ntohs(tlv->type);

    // Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, tlv->len);
    tlv->len = ntohs(tlv->len);

    remain -= sizeof(tlv->type) + sizeof(tlv->len);

    if (tlv->len > remain) {
      // the length field doesn't match what we saw in the common header
      return INVALID_MSG;
    }
    if (tlv->len > (len - nread)) {
      return INCOMPLETE_MSG;
    }

    // parse the info based on the type
    switch (tlv->type) {
    case PARSEBGP_BMP_TERM_INFO_TYPE_STRING:
      // allocate a string buffer for the data
      if ((tlv->info.string = malloc(sizeof(char) * (tlv->len + 1))) == NULL) {
        return MALLOC_FAILURE;
      }
      // and then copy it in
      memcpy(tlv->info.string, buf, tlv->len);
      tlv->info.string[tlv->len] = '\0';
      nread += tlv->len;
      buf += tlv->len;
      break;

    case PARSEBGP_BMP_TERM_INFO_TYPE_REASON:
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, tlv->info.reason);
      tlv->info.reason = ntohs(tlv->info.reason);
      break;

    default:
      return INVALID_MSG;
    }
    remain -= tlv->len;
  }

  *lenp = nread;
  return OK;
}

static void destroy_term_msg(parsebgp_bmp_term_msg_t *msg)
{
  int i;
  if (msg->tlvs_cnt == 0) {
    return;
  }

  for (i = 0; i < msg->tlvs_cnt; i++) {
    switch (msg->tlvs[i].type) {
    case PARSEBGP_BMP_TERM_INFO_TYPE_STRING:
      free(msg->tlvs[i].info.string);
      msg->tlvs[i].info.string = NULL;
      break;

    case PARSEBGP_BMP_TERM_INFO_TYPE_REASON:
    default:
      // nothing to do
      break;
    }
  }
  free(msg->tlvs);
  msg->tlvs = NULL;
  msg->tlvs_cnt = 0;
}


/* -------------------- BMP Header Parsers -------------------- */

static parsebgp_error_t parse_peer_hdr(parsebgp_bmp_peer_hdr_t *hdr,
                                       uint8_t *buf, size_t *lenp)
{
  size_t len = *lenp, nread = 0;

  // Type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->type);

  // Flags
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->flags);

  // Route distinguisher
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->dist_id);

  // IP Address
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->addr);

  // AS Number
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->asn);
  hdr->asn = ntohl(hdr->asn);

  // BGP ID
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->bgp_id);

  // Timestamp (seconds component)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->ts_sec);
  hdr->ts_sec = ntohl(hdr->ts_sec);

  // Timestamp (microseconds component)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->ts_usec);
  hdr->ts_usec = ntohl(hdr->ts_usec);

  assert(nread == BMP_PEER_HDR_LEN);
  *lenp = nread;
  return OK;
}

static parsebgp_error_t parse_common_hdr_v2(parsebgp_bmp_msg_t *msg,
                                            uint8_t *buf, size_t *lenp)
{
  parsebgp_error_t err;
  size_t len = *lenp, nread = 0, slen = 0;

  assert(msg->version == 2 || msg->version == 1);

  // Get the message type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->type);

  // All v1/2 messages include the peer header
  slen = len;
  if ((err = parse_peer_hdr(&msg->peer_hdr, buf, &slen)) != OK) {
    return err;
  }
  nread += slen;

  assert(nread == BMP_HDR_V1V2_LEN);
  *lenp = nread;
  return OK;
}

static parsebgp_error_t parse_common_hdr_v3(parsebgp_bmp_msg_t *msg,
                                            uint8_t *buf, size_t *lenp)
{
  parsebgp_error_t err;
  size_t len = *lenp, nread = 0;
  size_t slen;
  size_t bmplen = 0;

  // We know the version...
  assert(msg->version == 3);

  // Get the message length (including headers)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->len);
  msg->len = ntohl(msg->len);

  // Get the message type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->type);

  // do some quick sanity checks on the message length
  bmplen = msg->len - BMP_HDR_V3_LEN;
  if (bmplen > len) {
    return INCOMPLETE_MSG;
  }
  if (bmplen > BGP_MAX_MSG_SIZE) {
    return MSG_TOO_LONG;
  }

  // parse the per-peer header for those message that contain it
  switch(msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:    // Route monitoring
  case PARSEBGP_BMP_TYPE_STATS_REPORT: // Statistics Report
  case PARSEBGP_BMP_TYPE_PEER_UP:      // Peer Up notification
  case PARSEBGP_BMP_TYPE_PEER_DOWN:    // Peer down notification
    slen = len;
    if ((err = parse_peer_hdr(&msg->peer_hdr, buf, &slen)) != OK) {
      return err;
    }
    nread += slen;
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
  case PARSEBGP_BMP_TYPE_TERM_MSG:
    // no peer header
    break;

  default:
    return INVALID_MSG;
  }

  *lenp = nread;
  return OK;
}

static parsebgp_error_t parse_common_hdr(parsebgp_bmp_msg_t *msg, uint8_t *buf,
                                         size_t *lenp)
{
  parsebgp_error_t err;
  size_t len = *lenp, nread = 0;
  size_t slen;

  // Get the message version
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->version);

  switch (msg->version) {
  case 1:
    // Versions 1 and 2 use the same format, but v2 adds the Peer Up message
  case 2:
    slen = len - nread;
    if ((err = parse_common_hdr_v2(msg, buf, &slen)) != OK) {
      return err;
    }
    nread += slen;
    break;

  case 3:
    slen = len - nread;
    if ((err = parse_common_hdr_v3(msg, buf, &slen)) != OK) {
      return err;
    }
    nread += slen;
    break;

  default:
    return INVALID_MSG;
  }

  *lenp = nread;
  return OK;
}

/* -------------------- Main BMP Parser ----------------------------- */

parsebgp_error_t parsebgp_bmp_decode(parsebgp_bmp_msg_t *msg,
                                     uint8_t *buf, size_t *len)
{
  parsebgp_error_t err;
  size_t slen = 0, nread = 0, remain = 0;

  /* First, parse the message header */
  slen = *len;
  if ((err = parse_common_hdr(msg, buf, &slen)) != OK) {
    return err;
  }
  nread += slen;

  fprintf(stderr, "DEBUG: Got BMP message with version %" PRIu8 "\n",
          msg->version);
  fprintf(stderr, "DEBUG: Length: %"PRIu32"\n", msg->len);
  fprintf(stderr, "DEBUG: Type: %"PRIu32"\n", msg->type);
  fprintf(stderr, "DEBUG: Peer ASN: %"PRIu32"\n", msg->peer_hdr.asn);

  /* Continue to parse the message based on the type */
  slen = *len - nread; // number of bytes left in the buffer
  remain = msg->len - nread; // number of bytes left in the message

  fprintf(stderr, "DEBUG: nread: %d, remain: %d\n", (int)nread, (int)remain);

  assert(remain <= slen);
  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:
  case PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG:
    // DEBUG FIXME:
    fprintf(stderr, "WARN: Skipping route monitoring message. FIXME!\n");
    slen = msg->len - nread;
    /*
    err = parsebgp_bgp_decode_update(&msg->types.update_msg, buf + nread,
                                     &slen);
    */
    break;

  case PARSEBGP_BMP_TYPE_STATS_REPORT:
    err =
      parse_stats_report(&msg->types.stats_report, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_PEER_DOWN:
    err = parse_peer_down(&msg->types.peer_down, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_PEER_UP:
    err = parse_peer_up(&msg->types.peer_up, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
    err = parse_init_msg(&msg->types.init_msg, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_TERM_MSG:
    err = parse_term_msg(&msg->types.term_msg, buf + nread, &slen, remain);
    break;
  }
  if (err != OK) {
    // parser failed
    return err;
  }
  nread += slen;

  if (msg->version == 3) {
    assert(msg->len == nread);
  } else {
    msg->len = nread;
  }

  *len = nread;
  return OK;
}

void parsebgp_bmp_destroy_msg(parsebgp_bmp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // Common header has no dynamically allocated memory

  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:
  case PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG:
    // TODO: ask BGP parser to destroy update message
    break;

  case PARSEBGP_BMP_TYPE_STATS_REPORT:
    destroy_stats_report(&msg->types.stats_report);
    break;

  case PARSEBGP_BMP_TYPE_PEER_DOWN:
    destroy_peer_down(&msg->types.peer_down);
    break;

  case PARSEBGP_BMP_TYPE_PEER_UP:
    destroy_peer_up(&msg->types.peer_up);
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
    destroy_init_msg(&msg->types.init_msg);
    break;

  case PARSEBGP_BMP_TYPE_TERM_MSG:
    destroy_term_msg(&msg->types.term_msg);
    break;
  }
}
