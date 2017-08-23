#include "parsebgp.h"
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME "parsebgp"

// Read 1MB of the file at a time
#define BUFLEN (1024 * 1024)

char *type_strs[] = {
  NULL,  // PARSEBGP_MSG_TYPE_INVALID
  "bgp", // PARSEBGP_MSG_TYPE_BGP
  "bmp", // PARSEBGP_MSG_TYPE_BMP
  "mrt", // PARSEBGP_MSG_TYPE_MRT
};

static ssize_t refill_buffer(FILE *fp, uint8_t *buf, size_t buflen,
                             size_t remain)
{
  size_t len = 0;

  if (remain > 0) {
    // need to move remaining data to start of buffer
    memmove(buf, buf + buflen - remain, remain);
    len += remain;
  }

  if (feof(fp) != 0) {
    // nothing more to read
    return len;
  }

  // do a read, we should get something at least
  len += fread(buf + len, 1, buflen - len, fp);

  if (ferror(fp) != 0) {
    return -1;
  }

  return len;
}

static int parse(parsebgp_opts_t *opts, parsebgp_msg_type_t type, char *fname)
{
  uint8_t buf[BUFLEN];
  FILE *fp = NULL;

  ssize_t fill_len = 0, remain = 0;
  size_t dec_len = 0;
  uint8_t *ptr;

  parsebgp_msg_t *msg = NULL;
  parsebgp_error_t err = PARSEBGP_OK;

  uint64_t cnt = 0;

  if ((fp = fopen(fname, "r")) == NULL) {
    fprintf(stderr, "ERROR: Could not open %s (%s)\n", fname, strerror(errno));
    goto err;
  }

  buf[0] = '\0';

  while ((fill_len = refill_buffer(fp, buf, BUFLEN, remain)) > 0) {
    if (fill_len == remain) {
      // failed to read anything new from the file, so give up
      fprintf(stderr,
              "ERROR: Possibly corrupt file encountered. Trailing garbage of "
              "%ld bytes found\n",
              remain);
      break;
    }
    remain = fill_len;
    ptr = buf;

    while (remain > 0) {
      if (msg == NULL && (msg = parsebgp_create_msg()) == NULL) {
        fprintf(stderr, "ERROR: Failed to create message structure\n");
        goto err;
      }

      dec_len = remain;
      if ((err = parsebgp_decode(*opts, type, msg, ptr, &dec_len)) !=
          PARSEBGP_OK) {
        if (err == PARSEBGP_PARTIAL_MSG) {
          // refill the buffer and try again
          break;
        }
        // else: its a fatal error

        // TODO: add error code to string func
        fprintf(stderr, "ERROR: Failed to parse message (%d)\n", err);
        goto err;
      }
      // else: successful read
      assert(dec_len > 0);
      ptr += dec_len;
      remain -= dec_len;
      cnt++;

      parsebgp_dump_msg(msg);

      parsebgp_destroy_msg(msg);
      msg = NULL;
    }
  }

  if (fill_len < 0) {
    fprintf(stderr, "ERROR: Failed to read from %s (%s)\n", fname,
            strerror(errno));
    goto err;
  }

  fprintf(stderr, "INFO: Read %" PRIu64 " messages from %s\n", cnt, fname);

  if (fp != NULL) {
    fclose(fp);
  }

  parsebgp_destroy_msg(msg);

  return 0;

err:
  if (fp != NULL) {
    fclose(fp);
  }
  parsebgp_destroy_msg(msg);
  return -1;
}

static void usage()
{
  fprintf(stderr,
          "usage: %s [options] [type:]file [[type:]file...]\n"
          "         where 'type' is one of 'bmp', 'bgp', or 'mrt'\n"
          "         (only required if using non-standard file extensions)\n"
          "       -q                 Ignore unknown messages and attributes\n"
          "       -h                 Show this help message\n"
          "       -v                 Show version of the libparsebgp library\n",
          NAME);
}

int main(int argc, char **argv)
{
  int opt;
  int prevoptind;
  opterr = 0;

  parsebgp_opts_t opts;
  parsebgp_opts_init(&opts);

  while (prevoptind = optind, (opt = getopt(argc, argv, ":t:qvh?")) >= 0) {
    if (optind == prevoptind + 2 && (optarg == NULL || *optarg == '-')) {
      opt = ':';
      --optind;
    }
    switch (opt) {
    case 'q':
      opts.ignore_not_implemented = 1;
      break;

    case 'h':
    case '?':
      usage();
      return 0;
      break;

    case 'v':
      fprintf(stderr, "libparsebgp version %d.%d.%d\n",
              LIBPARSEBGP_MAJOR_VERSION, LIBPARSEBGP_MID_VERSION,
              LIBPARSEBGP_MINOR_VERSION);
      break;

    default:
      usage();
      return -1;
      break;
    }
  }

  if (optind >= argc) {
    usage();
    return -1;
  }

  int i, j;
  for (i = optind; i < argc; i++) {
    int type = 0; // undefined type
    char *fname, *tname, *freeme;
    fname = tname = freeme = strdup(argv[i]);
    assert(fname != NULL);

    if ((fname = strchr(fname, ':')) == NULL) {
      fname = tname;
      int len = strlen(fname);
      PARSEBGP_FOREACH_MSG_TYPE(j) {
        tname = fname;
        tname += (len - strlen(type_strs[j]));
        if (strcmp(tname, type_strs[j]) == 0) {
          type = j;
          break;
        }
      }
    } else {
      *(fname++) = '\0';
      PARSEBGP_FOREACH_MSG_TYPE(j) {
        if (strcmp(tname, type_strs[j]) == 0) {
          type = j;
          break;
        }
      }
    }

    if (type == 0) {
      fprintf(stderr,
              "ERROR: Could not identify type of %s, "
              "consider explicitly specifying type using type:file syntax\n",
              argv[i]);
      usage();
      free(freeme);
      return -1;
    }

    fprintf(stderr, "INFO: Parsing %s (Type: %s)\n", fname, type_strs[type]);

    if (parse(&opts, type, fname) != 0) {
      fprintf(stderr, "WARNING: Failed to parse %s%s\n", fname,
              (i == argc - 1) ? "" : ", moving on");
    }
    free(freeme);
  }

  return 0;
}
