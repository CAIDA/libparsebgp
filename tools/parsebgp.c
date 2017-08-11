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
  NULL,  // invalid
  "mrt", // MRT_MESSAGE_TYPE
  "bmp", // BMP_MESSAGE_TYPE
  "bgp", // BGP_MESSAGE_TYPE
};

static ssize_t refill_buffer(FILE *fp, uint8_t *buf, size_t buflen,
                             size_t remain)
{
  size_t len = 0;

  if (remain > 0) {
    // need to move remaining data to start of buffer
    memmove(buf, buf + buflen - remain, buflen - remain);
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

static int parse(enum libparsebgp_parse_msg_types type, char *fname)
{
  uint8_t buf[BUFLEN];
  FILE *fp = NULL;

  if ((fp = fopen(fname, "r")) == NULL) {
    fprintf(stderr, "ERROR: Could not open %s (%s)\n", fname, strerror(errno));
    goto err;
  }

  buf[0] = '\0';

  ssize_t len = 0, remain = 0;
  uint8_t *ptr;

  libparsebgp_parse_msg parse_msg;
  ssize_t parse_len = 0;
  uint64_t cnt = 0;

  while ((len = refill_buffer(fp, buf, BUFLEN, remain)) > 0) {
    if (len == remain) {
      // failed to read anything new from the file, so give up
      fprintf(stderr,
              "ERROR: Failed to read anything new from file, but %ld bytes "
              "remain. Giving up.\n",
              remain);
      break;
    }
    fprintf(stderr, "DEBUG: Refilled buffer with %ld bytes\n", len);
    remain = len;
    ptr = buf;

    while (remain > 0) {
      memset(&parse_msg, 0, sizeof(parse_msg));
      fprintf(stderr, "DEBUG: About to parse message (%ld bytes remain)\n",
              remain);
      if ((parse_len = libparsebgp_parse_msg_common_wrapper(
             &parse_msg, &ptr, remain, type)) < 0) {
        fprintf(stderr, "ERROR: Failed to parse message (%ld)\n", parse_len);
        goto err;
      } else if (parse_len == 0) {
        // eof or partial message in buffer, so break and we'll try and refill
        break;
      }
      // else: successful read
      fprintf(stderr, "DEBUG: Read message\n");
      cnt++;
      ptr += parse_len;
      remain -= parse_len;
      libparsebgp_parse_msg_common_destructor(&parse_msg);
    }
  }

  if (len < 0) {
    fprintf(stderr, "ERROR: Failed to read from %s (%s)\n", fname,
            strerror(errno));
    goto err;
  }

  fprintf(stderr, "INFO: Read %" PRIu64 " messages from %s\n", cnt, fname);

  if (fp != NULL) {
    fclose(fp);
  }

  return 0;

err:
  if (fp != NULL) {
    fclose(fp);
  }
  return -1;
}

static void usage()
{
  fprintf(stderr,
          "usage: %s [options] [type:]file [[type:]file...]\n"
          "         where 'type' is one of 'bmp', 'bgp', or 'mrt'\n"
          "         (only required if using non-standard file extensions)\n"
          "       -h                 Show this help message\n"
          "       -v                 Show version of the libparsebgp library\n",
          NAME);
}

int main(int argc, char **argv)
{
  int opt;
  int prevoptind;
  opterr = 0;

  while (prevoptind = optind, (opt = getopt(argc, argv, ":t:vh?")) >= 0) {
    if (optind == prevoptind + 2 && (optarg == NULL || *optarg == '-')) {
      opt = ':';
      --optind;
    }
    switch (opt) {
    // TODO add output format options (e.g., elem, bgpdump)

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
      for (j = MRT_MESSAGE_TYPE; j <= BGP_MESSAGE_TYPE; j++) {
        tname = fname;
        tname += (len - strlen(type_strs[j]));
        if (strcmp(tname, type_strs[j]) == 0) {
          type = j;
          break;
        }
      }
    } else {
      *(fname++) = '\0';
      for (j = MRT_MESSAGE_TYPE; j <= BGP_MESSAGE_TYPE; j++) {
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

    if (parse(type, fname) != 0) {
      fprintf(stderr, "WARNING: Failed to parse %s%s\n", fname,
              (i == argc - 1) ? "" : ", moving on");
    }
    free(freeme);
  }

  return 0;
}
