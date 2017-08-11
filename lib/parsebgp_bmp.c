//
// Created by ojas on 4/22/17.
//

#include "parsebgp_bmp.h"
#include "parsebgp.h"
#include "parsebgp_utils.h"
#include <stdlib.h>
#include <string.h>

/**
 * Buffer remaining BMP message
 *
 * @details This method will read the remaining amount of BMP data and store it
 * in the instance variable bmp_data. Normally this is used to store the BGP
 * message so that it can be parsed.
 *
 * @param [in]  buffer       Buffer to read the message from
 * @param [in]  buf_len      Buffer length of the available buffer
 *
 * @return Returns the error code in buffering the message
 *
 */
static ssize_t libparsebgp_parse_bmp_buffer_bmp_message(unsigned char **buffer,
                                                        int *buf_len,
                                                        uint32_t *bmp_len,
                                                        uint8_t **bmp_data)
{

  ssize_t bmp_data_len = 0;
  // TO DO:
  if (*bmp_len <= 0)
    return 0;

  if (*bmp_len > BMP_PACKET_BUF_SIZE + 1)
    return LARGER_MSG_LEN; // BMP message length is too large for buffer,
                           // invalid BMP sender

  if ((bmp_data_len =
         extract_from_buffer(buffer, buf_len, *bmp_data, *bmp_len)) != *bmp_len)
    return ERR_READING_MSG; // Error while reading BMP data into buffer

  // Indicate no more data is left to read
  *bmp_len = 0;

  return bmp_data_len;
}

/**
 * Parse v3 BMP header
 *
 * @details
 *      v3 uses the same common header, but adds the Peer Up message type.
 *
 * @param [in]     parsed_peer_header    Reference to the peer header Message
 * structure
 * @param [in]     buffer                Pointer to the raw BMP Message header
 * @param [in]     buf_len               length of the data buffer (used to
 * prevent overrun)
 *
 * @returns  Bytes that have been successfully read by bmp parse peer header.
 *
 */
static ssize_t libparsebgp_parse_bmp_parse_peer_hdr(
  libparsebgp_parsed_peer_hdr_v3 *parsed_peer_header, unsigned char **buffer,
  int *buf_len)
{
  int read_size = 0;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->peer_type, 1) !=
      1)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->peer_flags,
                          1) != 1)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->peer_dist_id,
                          8) != 8)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->peer_addr,
                          16) != 16)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->peer_as, 4) !=
      4)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->peer_bgp_id,
                          4) != 4)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->ts_secs, 4) !=
      4)
    return ERR_READING_MSG;

  if (extract_from_buffer(buffer, buf_len, &parsed_peer_header->ts_usecs, 4) !=
      4)
    return ERR_READING_MSG;

  // Adding the peer header len to the read_size
  read_size += BMP_PEER_HDR_LEN;

  // Save the advertised timestamp
  SWAP_BYTES(&parsed_peer_header->peer_as, 4);
  SWAP_BYTES(&parsed_peer_header->ts_secs, 4);
  SWAP_BYTES(&parsed_peer_header->ts_usecs, 4);
  return read_size;
}

/**
 * Parse v1 and v2 BMP header
 *
 * @details
 *      v2 uses the same common header, but adds the Peer Up message type.
 *
 * @param [in]     parsed_msg       Pointer to the bmp parsed data structure
 * @param [in]     buffer           Pointer to the raw BMP Message header
 * @param [in]     buf_len          length of the data buffer (used to prevent
 * overrun)
 *
 * @returns Bytes that have been successfully read by the parse bmp v2.
 */
static ssize_t libparsebgp_parse_bmp_parse_bmp_v2(
  libparsebgp_parse_bmp_parsed_data *parsed_msg, unsigned char **buffer,
  int *buf_len, uint32_t *bmp_len)
{
  int read_size = 0;
  ssize_t i;
  char buf[256] = {0};

  *bmp_len = 0;

  if (extract_from_buffer(buffer, buf_len,
                          &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old,
                          BMP_HDRv1v2_LEN) != BMP_HDRv1v2_LEN)
    return ERR_READING_MSG;

  read_size += BMP_HDRv1v2_LEN;

  SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.peer_as, 4);

  // Save the advertised timestamp
  SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ts_secs, 4);
  SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ts_usecs, 4);

  // Process the message based on type
  switch (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type) {
  case 0: // Route monitoring

    // Get the length of the remaining message by reading the BGP length
    if ((i = extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
      uint16_t len;
      memcpy(&len, (buf + 16), 2);
      SWAP_BYTES(&len, 2);
      *bmp_len = len;
      read_size += i;

    } else
      return ERR_READING_MSG;
    break;

  case 1: // Statistics Report
    break;

  case 2: // Peer down notification
    // Get the length of the remaining message by reading the BGP length
    if ((i = extract_from_buffer(buffer, buf_len, buf, 1)) != 1) {

      // Is there a BGP message
      if (buf[0] == 1 || buf[0] == 3) {
        if ((i = extract_from_buffer(buffer, buf_len, buf, 18)) == 18) {
          memcpy(bmp_len, buf + 16, 2);
          SWAP_BYTES(bmp_len, 2);
          read_size += i;
        } else
          return ERR_READING_MSG;
      }
    } else
      return ERR_READING_MSG; // error in reading bgp length
    break;

  case 3:                       // Peer Up notification
    return NOT_YET_IMPLEMENTED; // ERROR: Will need to add support for peer up
                                // if it's really used.
  }

  if (*bmp_len > *buf_len)
    return INCOMPLETE_MSG;
  return read_size;
}

/**
 * Parse v3 BMP header
 *
 * @details
 *      v3 has a different header structure and changes the peer
 *      header format.
 *
 * @param [in]     parsed_msg    Pointer to the bmp parsed data structure
 * @param [in]     buffer        Pointer to the raw BMP Message header
 * @param [in]     buf_len       length of the data buffer (used to prevent
 * overrun)
 *
 * @return Bytes that have been successfully read by the parse bmp v3.
 */
static ssize_t libparsebgp_parse_bmp_parse_bmp_v3(
  libparsebgp_parse_bmp_parsed_data *parsed_msg, unsigned char **buffer,
  int *buf_len, uint32_t *bmp_len)
{

  ssize_t read_size = 0;
  // reading the length in the header
  if ((extract_from_buffer(buffer, buf_len,
                           &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len,
                           4)) != 4)
    return ERR_READING_MSG;

  read_size += 4;

  // reading the bmp type in the header
  if ((extract_from_buffer(
        buffer, buf_len, &parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type,
        1)) != 1)
    return ERR_READING_MSG;

  read_size += 1;

  // Change to host order
  SWAP_BYTES(&parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len, 4);

  // Adjust length to remove common header size
  *bmp_len =
    parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.len - 1 - BMP_HDRv3_LEN;

  if (*bmp_len > BGP_MAX_MSG_SIZE)
    return LARGER_MSG_LEN;

  if (*bmp_len > *buf_len)
    return INCOMPLETE_MSG;

  // Parsing per peer header for every type except init and term since these
  // messages doesn't contain peer headers
  switch (parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type) {
  case TYPE_ROUTE_MON:    // Route monitoring
  case TYPE_STATS_REPORT: // Statistics Report
  case TYPE_PEER_UP:      // Peer Up notification
  case TYPE_PEER_DOWN:    // Peer down notification
    read_size += libparsebgp_parse_bmp_parse_peer_hdr(
      &parsed_msg->libparsebgp_parsed_peer_hdr, buffer, buf_len);

    // Adjust the common header length to remove the peer header (as it's been
    // read)
    *bmp_len -= BMP_PEER_HDR_LEN;

    break;

  case TYPE_INIT_MSG:
  case TYPE_TERM_MSG:
    // Allowed
    break;

  default:
    return INVALID_MSG; // ERROR: BMP message type is not supported
  }
  return read_size;
}

/**
 * Process the incoming BMP message's header
 *
 * @details
 *      This function parses the header in a bmp message and further parses it
 * according to the version in the header
 *
 * @param [in]     parsed_msg    Pointer to the bmp parsed data structure
 * @param [in]     buffer        Pointer to the raw BMP Message header
 * @param [in]     buf_len       length of the data buffer (used to prevent
 * overrun)
 *
 * @return Bytes that have been successfully read by the parse bmp v3.
 *
 */
static ssize_t
libparsebgp_parse_bmp_msg_header(libparsebgp_parse_bmp_parsed_data *parsed_msg,
                                 unsigned char **buffer, int *buf_len,
                                 uint32_t *bmp_len)
{

  parsed_msg->version = 0;
  ssize_t read_size = 0, bytes_read = 0;

  // Reading the version to parse the header accordingly
  if (extract_from_buffer(buffer, buf_len, &parsed_msg->version, 1) != 1)
    return INVALID_MSG;

  read_size += 1;

  // check the version
  if (parsed_msg->version == 3) { // draft-ietf-grow-bmp-04 - 07
    parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.ver = parsed_msg->version;
    // parsing the rest of the message as per the version
    bytes_read =
      libparsebgp_parse_bmp_parse_bmp_v3(parsed_msg, buffer, buf_len, bmp_len);
    if (bytes_read < 0)
      return bytes_read;

    read_size += bytes_read;
    parsed_msg->bmp_type = parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_v3.type;
  }
  // Handle the older versions
  else if (parsed_msg->version == 1 || parsed_msg->version == 2) {
    parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.ver = parsed_msg->version;
    // parsing the rest of the message as per the version
    bytes_read =
      libparsebgp_parse_bmp_parse_bmp_v2(parsed_msg, buffer, buf_len, bmp_len);
    if (bytes_read < 0)
      return bytes_read;

    read_size += bytes_read;
    parsed_msg->bmp_type =
      parsed_msg->libparsebgp_parsed_bmp_hdr.c_hdr_old.type;

  } else
    return INVALID_MSG; // Invalid version in the message header

  return read_size;
}

/**
 * Parse and return back the initiation message and update the init message
 * structure
 *
 * @details
 *        This method will read the init message tlvs and then store them in the
 * init message structure.
 *
 * @param [in]     init_msg         Pointer to the initiation Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent
 * overrun)
 * @param [out]    init_msg         Reference to the initiation message (will be
 * updated with bmp message)
 *
 * @returns Bytes that have been successfully read by the handle initiation
 * message.
 */
static ssize_t
libparsebgp_parse_bmp_handle_init_msg(libparsebgp_parsed_bmp_init_msg *init_msg,
                                      unsigned char *buffer, int buf_len,
                                      uint32_t *bmp_data_len)
{
  int info_len = 0;
  ssize_t read_bytes = 0;

  uint32_t num_tlvs = *bmp_data_len / BMP_INIT_MSG_LEN, curr_tlv = 0;

  init_msg->init_msg_tlvs =
    (init_msg_v3_tlv *)malloc(num_tlvs * sizeof(init_msg_v3_tlv));
  init_msg_v3_tlv *init_msg_tlv =
    (init_msg_v3_tlv *)malloc(sizeof(init_msg_v3_tlv));

  memset(init_msg->init_msg_tlvs, 0, sizeof(*init_msg->init_msg_tlvs));
  /*
   * Loop through the init message (in buffer) to parse each TLV
   */
  for (int i = 0; i < *bmp_data_len; i += BMP_INIT_MSG_LEN) {
    memset(init_msg_tlv, 0, sizeof(init_msg_v3_tlv));

    memcpy(&init_msg_tlv->type, buffer, 2);
    read_bytes += 2;
    buffer += 2;

    memcpy(&init_msg_tlv->len, buffer, 2);
    read_bytes += 2;
    buffer += 2;

    memset(init_msg_tlv->info, 0, sizeof(init_msg_tlv->info));
    SWAP_BYTES(&init_msg_tlv->len, 2);
    SWAP_BYTES(&init_msg_tlv->type, 2);

    if (init_msg_tlv->len > 0) {
      info_len = sizeof(init_msg_tlv->info) < init_msg_tlv->len
                   ? sizeof(init_msg_tlv->info)
                   : init_msg_tlv->len;
      bzero(init_msg_tlv->info, sizeof(init_msg_tlv->info));
      memcpy(init_msg_tlv->info, buffer, info_len);
      read_bytes += info_len;
      buffer += info_len; // Move pointer past the info data
      i += info_len;      // Update the counter past the info data
    }

    init_msg->init_msg_tlvs[curr_tlv++] = *init_msg_tlv;
  }
  init_msg->num_tlvs = num_tlvs;
  free(init_msg_tlv);
  return read_bytes;
}

/**
 * Parse and return back the termination message and update the term message
 * structure
 *
 * @details
 *  This method will read the expected stat counts and then parse the stat info
 * messages.
 *
 * @param [in]     term_msg         Pointer to the termination Message structure
 * @param [in]     buffer           Pointer to the raw BGP message header
 * @param [in]     buf_len          length of the data buffer (used to prevent
 * overrun)
 * @param [out]    term_msg         Reference to the termination message (will
 * be updated with bmp message)
 *
 * @returns Bytes that have been successfully read by the handle termination
 * message.
 */
static ssize_t
libparsebgp_parse_bmp_handle_term_msg(libparsebgp_parsed_bmp_term_msg *term_msg,
                                      unsigned char *buffer, int buf_len,
                                      uint32_t *bmp_data_len)
{
  int info_len;
  ssize_t read_bytes = 0;

  uint32_t num_tlvs = *bmp_data_len / BMP_TERM_MSG_LEN, curr_tlv = 0;
  term_msg->term_msg_tlvs =
    (term_msg_v3_tlv *)malloc(num_tlvs * sizeof(term_msg_v3_tlv));
  memset(term_msg->term_msg_tlvs, 0, sizeof(*term_msg->term_msg_tlvs));
  /*
   * Loop through the term message (in buffer) to parse each TLV
   */
  term_msg_v3_tlv *term_msg_tlv =
    (term_msg_v3_tlv *)malloc(sizeof(term_msg_v3_tlv));

  for (int i = 0; i < *bmp_data_len; i += BMP_TERM_MSG_LEN) {
    memset(term_msg_tlv, 0, sizeof(term_msg_v3_tlv));

    memcpy(&term_msg_tlv->type, buffer, 2);
    buffer += 2;

    memcpy(&term_msg_tlv->len, buffer, 2);
    buffer += 2;

    read_bytes += BMP_TERM_MSG_LEN;

    memset(term_msg_tlv->info, 0, sizeof term_msg_tlv->info);
    SWAP_BYTES(&term_msg_tlv->len, 2);
    SWAP_BYTES(&term_msg_tlv->type, 2);

    buffer += BMP_TERM_MSG_LEN; // Move pointer past the info header

    if (term_msg_tlv->len > 0) {
      info_len = sizeof(term_msg_tlv->info) < term_msg_tlv->len
                   ? sizeof(term_msg_tlv->info)
                   : term_msg_tlv->len;
      bzero(term_msg_tlv->info, sizeof(term_msg_tlv->info));
      memcpy(term_msg_tlv->info, buffer, info_len);
      read_bytes += info_len;
      buffer += info_len; // Move pointer past the info data
      i += info_len;      // Update the counter past the info data
    }
    term_msg->term_msg_tlvs[curr_tlv++] = *term_msg_tlv;
  }
  term_msg->num_tlvs = num_tlvs;
  free(term_msg_tlv);
  return read_bytes;
}

/**
 * Parse and return back the stats report and update the stat rep structure
 *
 * @details
 *  This method will read the expected stat counts and then parse the stat info
 * messages.
 *
 * @param [in]     stat_rep_msg     Pointer to the stat report Message structure
 * @param [in]     buffer           Pointer to the raw BGP message header
 * @param [in]     buf_len          length of the data buffer (used to prevent
 * overrun)
 * @param [out]    stat_rep_msg     Reference to the stat report (will be
 * updated with bmp message)
 *
 * @returns Bytes that have been successfully read by the handle stats report.
 */
static ssize_t libparsebgp_parse_bmp_handle_stats_report(
  libparsebgp_parsed_bmp_stat_rep *stat_rep_msg, unsigned char *buffer,
  int buf_len)
{
  char b[8];
  ssize_t read_size = 0;

  if ((extract_from_buffer(&buffer, &buf_len, &stat_rep_msg->stats_count, 4)) !=
      4)
    return ERR_READING_MSG;

  SWAP_BYTES(&stat_rep_msg->stats_count, 4);
  read_size += 4;

  stat_rep_msg->total_stats_counter =
    (stat_counter *)malloc(stat_rep_msg->stats_count * sizeof(stat_counter));
  stat_counter *stat_info = (stat_counter *)malloc(sizeof(stat_counter));
  memset(stat_rep_msg->total_stats_counter, 0,
         sizeof(*stat_rep_msg->total_stats_counter));

  // Loop through each stats object
  for (unsigned long i = 0; i < stat_rep_msg->stats_count; i++) {
    memset(stat_info, 0, sizeof(*stat_info));

    bzero(b, 8);
    if ((extract_from_buffer(&buffer, &buf_len, &stat_info->stat_type, 2)) != 2)
      return ERR_READING_MSG;

    read_size += 2;
    if ((extract_from_buffer(&buffer, &buf_len, &stat_info->stat_len, 2)) != 2)
      return ERR_READING_MSG;

    read_size += 2;
    // convert integer from network to host bytes
    SWAP_BYTES(&stat_info->stat_type, 2);
    SWAP_BYTES(&stat_info->stat_len, 2);

    // check if this is a 32 bit number  (default)
    if (stat_info->stat_len == 4 || stat_info->stat_len == 8) {

      // Read the stats counter - 32/64 bits
      if ((extract_from_buffer(&buffer, &buf_len, b, stat_info->stat_len)) ==
          stat_info->stat_len) {
        read_size += stat_info->stat_len;
        // convert the bytes from network to host order
        SWAP_BYTES(b, stat_info->stat_len);
        memcpy(stat_info->stat_data, b, stat_info->stat_len);
      }

    } else {

      while (stat_info->stat_len-- > 0)
        extract_from_buffer(&buffer, &buf_len, &b[0], 1);
    }
    stat_rep_msg->total_stats_counter[i] = *stat_info;
  }

  free(stat_info);
  return read_size;
}

/**
 * Handles the up event by parsing the BGP open messages - Up event will be
 * updated
 *
 * @details
 *  This method will read the expected sent and receive open messages.
 *
 * @param [in]     up_event         Pointer to the Up Event Message structure
 * @param [in]     data             Pointer to the raw BGP message header
 * @param [in]     size             length of the data buffer (used to prevent
 * overrun)
 * @param [out]    up_event         Reference to the peer up event storage (will
 * be updated with bmp info)
 *
 * @returns Bytes that have been successfully read by the handle up event.
 */
static ssize_t libparsebgp_parse_bgp_handle_up_event(
  libparsebgp_parsed_bmp_peer_up_event *up_event, unsigned char *data,
  size_t size)
{
  ssize_t read_size = 0, bytes_read = 0;

  /*
   * Process the sent open message
   */
  if ((bytes_read = libparsebgp_parse_bgp_parse_header(
         &up_event->sent_open_msg.c_hdr, data, size)) > 0) {
    if (up_event->sent_open_msg.c_hdr.type == BGP_MSG_OPEN) {
      data += bytes_read;
      size -= bytes_read;
      read_size += bytes_read;

      bytes_read = libparsebgp_open_msg_parse_open_msg(
        &up_event->sent_open_msg.parsed_data.open_msg, data, size, 1);

      if (!bytes_read)
        return ERR_READING_MSG; // ERROR: Failed to read sent open message

      if (bytes_read < 0)
        return bytes_read; // has the error codes

      data += bytes_read; // Move the pointer pase the sent open message
      size -= bytes_read;
      read_size += bytes_read;
    } else
      return CORRUPT_MSG;
  } else
    return bytes_read; // ERROR: Invalid BGP MSG for BMP Received OPEN message,
                       // expected OPEN message.

  if ((bytes_read = libparsebgp_parse_bgp_parse_header(
         &up_event->sent_open_msg.c_hdr, data, size)) > 0) {
    if (up_event->sent_open_msg.c_hdr.type == BGP_MSG_OPEN) {
      data += bytes_read;
      size -= BGP_MSG_HDR_LEN;
      read_size += BGP_MSG_HDR_LEN;

      bytes_read = libparsebgp_open_msg_parse_open_msg(
        &up_event->received_open_msg.parsed_data.open_msg, data, size, 0);

      if (!bytes_read) {
        return ERR_READING_MSG; // throw "Failed to read received open message";
      }
      if (bytes_read < 0)
        return bytes_read; // has the error codes

      data += bytes_read; // Move the pointer pase the sent open message
      size -= bytes_read;
      read_size += bytes_read;
    } else
      return CORRUPT_MSG; // ERROR: Invalid BGP MSG for BMP Received OPEN
                          // message, expected OPEN message.
  } else
    return bytes_read;
  return read_size;
}

/**
 * Parse the v3 peer up BMP header
 *
 * @details This method will update the peer_up_event struct with BMP header
 * info.
 *
 * @param [in]     up_event         Pointer to the Up Event Message structure
 * @param [in]     buffer           Pointer to the raw BGP message header
 * @param [in]     buf_len          length of the data buffer (used to prevent
 * overrun)
 * @param [out]    up_event         Reference to the peer up event storage (will
 * be updated with bmp info)
 *
 * @returns Bytes that have been successfully read by the peer up header parser.
 */
static ssize_t libparsebgp_parse_bmp_parse_peer_up_event_hdr(
  libparsebgp_parsed_bmp_peer_up_event *up_event, unsigned char **buffer,
  int *buf_len, uint32_t *bmp_len)
{
  int is_parse_good = 1;
  ssize_t read_size = 0;

  // Get the local address
  if (extract_from_buffer(buffer, buf_len, &up_event->local_ip, 16) != 16)
    is_parse_good = 0;
  else
    read_size += 16;

  // Get the local port
  if (is_parse_good &&
      extract_from_buffer(buffer, buf_len, &up_event->local_port, 2) != 2)
    is_parse_good = 0;
  else if (is_parse_good) {
    read_size += 2;
    SWAP_BYTES(&up_event->local_port, 2);
  }

  // Get the remote port
  if (is_parse_good &&
      extract_from_buffer(buffer, buf_len, &up_event->remote_port, 2) != 2)
    is_parse_good = 0;
  else if (is_parse_good) {
    read_size += 2;
    SWAP_BYTES(&up_event->remote_port, 2);
  }

  // Update bytes read
  *bmp_len -= read_size;

  // Validate parse is still good, if not read the remaining bytes of the
  // message so that the next msg will work
  if (!is_parse_good)
    return CORRUPT_MSG;

  return read_size;
}

/**
 * Parses a BMP message by its various types
 *
 * @details
 *  This function will parse the header of the message and according to the type
 * of the BMP message, it parses the rest of the message.
 *
 * @param [in]     parsed_msg       Pointer to the BMP Message structure
 * @param [in]     buffer             Pointer to the raw BGP message header
 * @param [in]     buf_len             length of the data buffer (used to
 * prevent overrun)
 *
 * @returns Bytes that have been successfully read by the bmp parser.
 */

ssize_t
libparsebgp_parse_bmp_parse_msg(libparsebgp_parse_bmp_parsed_data *parsed_msg,
                                unsigned char *buffer, int buf_len)
{
  ssize_t read_size = 0, bytes_read = 0;

  uint8_t *bmp_data =
    (uint8_t *)malloc((BMP_PACKET_BUF_SIZE + 1) * sizeof(uint8_t));
  uint32_t bmp_data_len;
  uint32_t bmp_len;

  /*
   * Parsing the bmp message header: Version 1, 2, 3 are supported
   */
  if ((bytes_read = libparsebgp_parse_bmp_msg_header(parsed_msg, &buffer,
                                                     &buf_len, &bmp_len)) < 0) {
    free(bmp_data);
    return bytes_read; // checking for the error code returned in parsing bmp
                       // header.
  }

  read_size += bytes_read; // adding the bytes read from parsing the header

  /*
   * Parsing BMP message based on bmp type retrieved from the header
   */
  switch (parsed_msg->bmp_type) {
  case TYPE_PEER_DOWN: { // Parsing Peer down type
    if (extract_from_buffer(&buffer, &buf_len,
                            &parsed_msg->libparsebgp_parsed_bmp_msg
                               .parsed_peer_down_event_msg.bmp_reason,
                            1) == 1) {
      read_size += 1;
      bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(
        &buffer, &buf_len, &bmp_len, &bmp_data);
      if (bytes_read < 0) {
        read_size = bytes_read;
        break;
      }
      bmp_data_len = bytes_read;

      // Check if the reason indicates we have a BGP message that follows
      switch (parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg
                .bmp_reason) {
      case 1: { // Local system close with BGP notify
        bytes_read = libparsebgp_parse_bgp_handle_down_event(
          &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg
             .notify_msg,
          bmp_data, bmp_data_len);
        if (bytes_read < 0)
          read_size = bytes_read;
        else
          read_size += bytes_read;
        break;
      }
      case 2: // Local system close, no bgp notify
      {
        // Read two byte code corresponding to the FSM event
        uint16_t fsm_event = 0;
        memcpy(&fsm_event, bmp_data, 2);
        SWAP_BYTES(&fsm_event, 2);
        read_size += 2;
        break;
      }
      case 3: { // remote system close with bgp notify
        bytes_read = libparsebgp_parse_bgp_handle_down_event(
          &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_down_event_msg
             .notify_msg,
          bmp_data, bmp_data_len);
        if (bytes_read < 0)
          read_size = bytes_read;
        else
          read_size += bytes_read;
        break;
      }
      default: {
        read_size = INVALID_MSG;
        break;
      }
      }
    } else
      read_size = ERR_READING_MSG;
    break;
  }

  case TYPE_PEER_UP: // Parsing Peer up type
  {
    /*
     * Parsing the up event header except open messages
     */
    if ((bytes_read = libparsebgp_parse_bmp_parse_peer_up_event_hdr(
           &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg,
           &buffer, &buf_len, &bmp_len)) < 0) {
      libparsebgp_parse_bmp_destructor(parsed_msg);
      free(bmp_data);
      return bytes_read;
    }

    read_size += bytes_read;

    /*
     * Reading the message into buffer bmp_data
     */
    if ((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(
           &buffer, &buf_len, &bmp_len, &bmp_data)) < 0) {
      libparsebgp_parse_bmp_destructor(parsed_msg);
      free(bmp_data);
      return bytes_read;
    }
    bmp_data_len = bytes_read;

    /*
     * Parsing the received and sent open message in the up event message
     */
    if ((bytes_read = libparsebgp_parse_bgp_handle_up_event(
           &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg,
           bmp_data, bmp_data_len)) < 0)
      read_size = bytes_read;
    else
      read_size += bytes_read;
    break;
  }

  case TYPE_ROUTE_MON: { // Route monitoring type
    /*
     * Reading the message into buffer bmp_data
     */
    if ((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(
           &buffer, &buf_len, &bmp_len, &bmp_data)) < 0) {
      libparsebgp_parse_bmp_destructor(parsed_msg);
      return bytes_read;
    }
    bmp_data_len = bytes_read;

    /*
     * Parsing the bgp update message
     */
    if ((bytes_read = libparsebgp_parse_bgp_parse_msg(
           &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_rm_msg, bmp_data,
           bmp_data_len, 0)) < 0)
      read_size = bytes_read;
    else
      read_size += bytes_read;
    break;
  }

  case TYPE_STATS_REPORT: { // Stats Report
    /*
     * Reading the message into buffer bmp_data
     */
    if ((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(
           &buffer, &buf_len, &bmp_len, &bmp_data)) < 0) {
      free(bmp_data);
      libparsebgp_parse_bmp_destructor(parsed_msg);
      return bytes_read;
    }
    bmp_data_len = bytes_read;

    /*
     * Parsing the stats report message
     */
    if ((bytes_read = libparsebgp_parse_bmp_handle_stats_report(
           &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_stat_rep, bmp_data,
           bmp_data_len)) < 0)
      read_size = bytes_read;
    else
      read_size += bytes_read;
    break;
  }

  case TYPE_INIT_MSG: { // Initiation Message
    /*
     * Reading the message into buffer bmp_data
     */
    if ((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(
           &buffer, &buf_len, &bmp_len, &bmp_data)) < 0) {
      libparsebgp_parse_bmp_destructor(parsed_msg);
      return bytes_read;
    }
    bmp_data_len = bytes_read;

    /*
     * Parsing the init message tlvs
     */
    if ((bytes_read = libparsebgp_parse_bmp_handle_init_msg(
           &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_init_msg, bmp_data,
           bmp_data_len, &bmp_data_len)) < 0)
      read_size = bytes_read;
    else
      read_size += bytes_read;
    break;
  }

  case TYPE_TERM_MSG: { // Termination Message
    /*
     * Reading the message into buffer bmp_data
     */
    if ((bytes_read = libparsebgp_parse_bmp_buffer_bmp_message(
           &buffer, &buf_len, &bmp_len, &bmp_data)) < 0) {
      libparsebgp_parse_bmp_destructor(parsed_msg);
      return bytes_read;
    }
    bmp_data_len = bytes_read;

    /*
     * Parsing the term message tlvs
     */
    if ((bytes_read = libparsebgp_parse_bmp_handle_term_msg(
           &parsed_msg->libparsebgp_parsed_bmp_msg.parsed_term_msg, bmp_data,
           bmp_data_len, &bmp_data_len)) < 0)
      read_size = bytes_read;
    else
      read_size += bytes_read;
    break;
  }
  default:
    read_size = CORRUPT_MSG; // Invalid BMP message type
  }
  if (read_size < 0)
    libparsebgp_parse_bmp_destructor(parsed_msg);
  free(bmp_data);
  return read_size;
}

/**
 * Destructor function to free bmp_parsed_data
 */
void libparsebgp_parse_bmp_destructor(
  libparsebgp_parse_bmp_parsed_data *parsed_data)
{
  switch (parsed_data->bmp_type) {
  case TYPE_INIT_MSG: {
    free(parsed_data->libparsebgp_parsed_bmp_msg.parsed_init_msg.init_msg_tlvs);
    parsed_data->libparsebgp_parsed_bmp_msg.parsed_init_msg.init_msg_tlvs =
      NULL;
    break;
  }
  case TYPE_PEER_DOWN: {
    libparsebgp_parse_bgp_destructor(&parsed_data->libparsebgp_parsed_bmp_msg
                                        .parsed_peer_down_event_msg.notify_msg);
    break;
  }
  case TYPE_PEER_UP: {
    libparsebgp_parse_bgp_destructor(
      &parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg
         .received_open_msg);
    libparsebgp_parse_bgp_destructor(
      &parsed_data->libparsebgp_parsed_bmp_msg.parsed_peer_up_event_msg
         .sent_open_msg);
    break;
  }
  case TYPE_ROUTE_MON: {
    libparsebgp_parse_bgp_destructor(
      &parsed_data->libparsebgp_parsed_bmp_msg.parsed_rm_msg);
    break;
  }
  case TYPE_STATS_REPORT: {
    free(parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep
           .total_stats_counter);
    parsed_data->libparsebgp_parsed_bmp_msg.parsed_stat_rep
      .total_stats_counter = NULL;
    break;
  }
  case TYPE_TERM_MSG: {
    free(parsed_data->libparsebgp_parsed_bmp_msg.parsed_term_msg.term_msg_tlvs);
    parsed_data->libparsebgp_parsed_bmp_msg.parsed_term_msg.term_msg_tlvs =
      NULL;
    break;
  }
  }
}
