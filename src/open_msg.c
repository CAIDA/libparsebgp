/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include "open_msg.h"
#include "parse_utils.h"

/**
 * Parses capabilities from buffer
 *
 * \details
 *      Reads the capabilities from buffer.  The parsed data will be
 *      returned via the out params.
 *
 * \param [in]   data               Pointer to raw bgp payload data, starting at
 * the open/cap message \param [in]   size               Size of the data
 * available to read; prevent overrun when reading \param [in]
 * openMessageIsSent  If open message is sent. False if received
 *
 * \return negative values for error, otherwise a positive value indicating the
 * number of bytes read
 */
static ssize_t libparsebgp_open_msg_parse_capabilities(
  libparsebgp_open_msg_data *open_msg_data, u_char **data, size_t size,
  bool openMessageIsSent)
{
  int read_size = 0;
  u_char **buf_ptr = data;
  open_msg_data->count_opt_param = 1;
  open_param *opt_param = (open_param *)malloc(sizeof(open_param));
  open_msg_data->opt_param = (open_param *)malloc(sizeof(open_param));

  for (int i = 0; i < size;) {
    if (open_msg_data->count_opt_param - 1)
      open_msg_data->opt_param = (open_param *)realloc(
        open_msg_data->opt_param,
        (open_msg_data->count_opt_param) * sizeof(open_param));
    memset(opt_param, 0, sizeof(opt_param));

    open_msg_data->count_opt_param += 1;

    memcpy(&opt_param->param_type, *buf_ptr, 1);    // reading type
    memcpy(&opt_param->param_len, *buf_ptr + 1, 1); // reading length

    if (opt_param->param_type != BGP_CAP_PARAM_TYPE) {
      return INVALID_MSG;
    }

    /*
     * Process the capabilities if present
     */
    else if (opt_param->param_len >= 2 &&
             (read_size + 2 + opt_param->param_len) <= size) {
      u_char *cap_ptr = *buf_ptr + 2;
      opt_param->count_param_val = 0;
      open_capabilities *open_cap =
        (open_capabilities *)malloc(sizeof(open_capabilities));
      opt_param->param_values =
        (open_capabilities *)malloc(sizeof(open_capabilities));
      for (int c = 0; c < opt_param->param_len;) {
        if (opt_param->count_param_val)
          opt_param->param_values = (open_capabilities *)realloc(
            opt_param->param_values,
            (opt_param->count_param_val + 1) * sizeof(open_capabilities));

        opt_param->count_param_val += 1;
        memset(open_cap, 0, sizeof(open_cap));
        memcpy(&open_cap->cap_code, cap_ptr, 1);    // reading capability code
        memcpy(&open_cap->cap_len, cap_ptr + 1, 1); // reading capability length

        /*
         * Handle the capability
         */
        switch (open_cap->cap_code) {
        case BGP_CAP_4OCTET_ASN:
          if (open_cap->cap_len == 4) {
            memcpy(&open_cap->cap_values.asn, cap_ptr + 2, 4);
            SWAP_BYTES(&open_cap->cap_values.asn, 4);
            opt_param->param_values[opt_param->count_param_val - 1] = *open_cap;
          } else {
            return INVALID_MSG;
          }
          break;

        case BGP_CAP_ROUTE_REFRESH:
          break;

        case BGP_CAP_ROUTE_REFRESH_ENHANCED:
          break;

        case BGP_CAP_ROUTE_REFRESH_OLD:
          break;

        case BGP_CAP_ADD_PATH: {
          // cap_add_path_data data;

          /*
           * Move past the cap code and len, then iterate over all paths encoded
           */
          cap_ptr += 2;
          if (open_cap->cap_len >= 4) {

            add_path_capability *add_path =
              (add_path_capability *)malloc(sizeof(add_path_capability));
            open_cap->cap_values.add_path_data =
              (add_path_capability *)malloc(sizeof(add_path_capability));
            open_cap->count_add_path_capabilities = 0;
            for (int l = 0; l < open_cap->cap_len; l += 4) {
              memcpy(&add_path, cap_ptr, 4);
              cap_ptr += 4;

              SWAP_BYTES(&add_path->afi, 4);

              if (open_cap->count_add_path_capabilities)
                open_cap->cap_values.add_path_data =
                  (add_path_capability *)realloc(
                    open_cap->cap_values.add_path_data,
                    (open_cap->count_add_path_capabilities + 1) *
                      sizeof(add_path_capability));
              open_cap->count_add_path_capabilities += 1;
              open_cap->cap_values
                .add_path_data[open_cap->count_add_path_capabilities - 1] =
                *add_path;

              /*
//                                memcpy(&open_cap->cap_values.add_path_data,
cap_ptr, 4);
//                                cap_ptr += 4;
//
// SWAP_BYTES(&open_cap->cap_values.add_path_data.afi, 4);

              snprintf(capStr, sizeof(capStr), "ADD Path (%d) : afi=%d safi=%d
send/receive=%d", BGP_CAP_ADD_PATH, data.afi, data.safi, data.send_recieve);

              std::string decodeStr(capStr);
              decodeStr.append(" : ");

              decodeStr.append(GET_SAFI_STRING_BY_CODE(data.safi));
              decodeStr.append(" ");

              decodeStr.append(GET_AFI_STRING_BY_CODE(data.afi));
              decodeStr.append(" ");

              switch (data.send_recieve) {
                  case BGP_CAP_ADD_PATH_SEND :
                      decodeStr.append("Send");
                      break;

                  case BGP_CAP_ADD_PATH_RECEIVE :
                      decodeStr.append("Receive");
                      break;

                  case BGP_CAP_ADD_PATH_SEND_RECEIVE :
                      decodeStr.append("Send/Receive");
                      break;

                  default:
                      decodeStr.append("unknown");
                      break;
              }
              //TODO: figure out if following is needed
//
libparsebgp_addpath_add(open_msg_data->add_path_capability,
open_cap.cap_values.add_path_data.afi,
//
open_cap.cap_values.add_path_data.safi,
open_cap.cap_values.add_path_data.send_recieve, openMessageIsSent);
              //capabilities.push_back(decodeStr);
               */
            }
            opt_param->param_values[opt_param->count_param_val - 1] = *open_cap;
            free(add_path);
          }

          break;
        }

        case BGP_CAP_GRACEFUL_RESTART:
          break;

        case BGP_CAP_OUTBOUND_FILTER:
          break;

        case BGP_CAP_MULTI_SESSION:
          break;

        case BGP_CAP_MPBGP: {
          if (open_cap->cap_len == sizeof(open_cap->cap_values.mpbgp_data)) {
            memcpy(&open_cap->cap_values.mpbgp_data, (cap_ptr + 2),
                   sizeof(open_cap->cap_values.mpbgp_data));
            SWAP_BYTES(&open_cap->cap_values.mpbgp_data.afi,
                       sizeof(open_cap->cap_values.mpbgp_data));
            opt_param->param_values[opt_param->count_param_val - 1] = *open_cap;
          } else
            return INVALID_MSG;
          break;
        }

        default:
          break;
        }
        // Move the pointer to the next capability
        c += 2 + open_cap->cap_len;
        cap_ptr += 2 + open_cap->cap_len;
      }
      free(open_cap);
    }

    // Move index to next param
    i += 2 + opt_param->param_len;
    *buf_ptr += 2 + opt_param->param_len;
    read_size += 2 + opt_param->param_len;
    open_msg_data->opt_param[open_msg_data->count_opt_param - 2] = *opt_param;
  }

  free(opt_param);
  return read_size;
}
/**
 * Parses an open message
 *
 * \details
 *      Reads the open message from buffer.  The parsed data will be
 *      returned via the out params.
 *
 * \param [in]   data               Pointer to raw bgp payload data, starting at
 * the notification message \param [in]   size               Size of the data
 * available to read; prevent overrun when reading \param [in]
 * openMessageIsSent  If open message is sent. False if received
 *
 * \return ZERO is error, otherwise a positive value indicating the number of
 * bytes read for the open message
 */
ssize_t
libparsebgp_open_msg_parse_open_msg(libparsebgp_open_msg_data *open_msg_data,
                                    u_char *data, size_t size,
                                    bool openMessageIsSent)
{
  int read_size = 0;
  u_char *buf_ptr = data;
  int buf_size = size;

  /*
   * Make sure available size is large enough for an open message
   */
  if (size < 10) {
    //    LOG_WARN("%s: Cloud not read open message due to buffer having less
    //    bytes than open message size", peer_addr.c_str());
    return INCOMPLETE_MSG;
  }

  if (extract_from_buffer(&buf_ptr, &buf_size, &open_msg_data->ver, 1) != 1)
    return ERR_READING_MSG;
  if (extract_from_buffer(&buf_ptr, &buf_size, &open_msg_data->asn, 2) != 2)
    return ERR_READING_MSG;
  if (extract_from_buffer(&buf_ptr, &buf_size, &open_msg_data->hold_time, 2) !=
      2)
    return ERR_READING_MSG;
  if (extract_from_buffer(&buf_ptr, &buf_size, &open_msg_data->bgp_id, 4) != 4)
    return ERR_READING_MSG;
  if (extract_from_buffer(&buf_ptr, &buf_size, &open_msg_data->opt_param_len,
                          1) != 1)
    return ERR_READING_MSG;

  read_size = 10;

  // Change to host order
  SWAP_BYTES(&open_msg_data->hold_time, 2);
  SWAP_BYTES(&open_msg_data->asn, 2);

  /*
   * Make sure the buffer contains the rest of the open message, but allow a
   * zero length in case the data is missing on purpose (router implementation)
   */
  if (open_msg_data->opt_param_len == 0)
    return read_size;

  else if (open_msg_data->opt_param_len > (size - read_size)) {
    // Parse as many capabilities as possible
    libparsebgp_open_msg_parse_capabilities(
      open_msg_data, &buf_ptr, (size - read_size), openMessageIsSent);

    read_size += (size - read_size);

  } else {

    if (!libparsebgp_open_msg_parse_capabilities(open_msg_data, &buf_ptr,
                                                 open_msg_data->opt_param_len,
                                                 openMessageIsSent)) {
      return INVALID_MSG;
    }
    read_size += open_msg_data->opt_param_len;
  }
  return read_size;
}

void libparsebgp_parse_open_msg_destructor(
  libparsebgp_open_msg_data *open_msg_data)
{
  for (int i = 0; i < open_msg_data->count_opt_param; i++) {
    for (int j = 0; j < open_msg_data->opt_param[i].count_param_val; j++) {
      if (open_msg_data->opt_param[i].param_values[j].cap_code ==
          BGP_CAP_ADD_PATH) {
        for (int k = 0; k < open_msg_data->opt_param[i]
                              .param_values[j]
                              .count_add_path_capabilities;
             k++) {
          free(&open_msg_data->opt_param[i]
                  .param_values[j]
                  .cap_values.add_path_data[k]);
        }
      }
      free(&open_msg_data->opt_param[i].param_values[j]);
    }
  }
  free(open_msg_data->opt_param);
}
