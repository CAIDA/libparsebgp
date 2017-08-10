#include "config.h"
#include "lib_parse_common.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define NAME "parsebgp"

char *type_strs[] = {
  NULL, // invalid
  "mrt", // MRT_MESSAGE_TYPE
  "bmp", // BMP_MESSAGE_TYPE
  "bgp", // BGP_MESSAGE_TYPE
};

static int parse(enum libparsebgp_parse_msg_types type, char *fname)
{
  return -1;
}

static void usage()
{
  fprintf(
    stderr,
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
  for (i=optind; i<argc; i++) {
    int type = 0; // undefined type
    char *fname, *tname;
    fname = tname = strdup(argv[i]);
    assert(fname != NULL);

    if ((fname = strchr(fname, ':')) == NULL) {
      fname = tname;
      int len = strlen(fname);
      for (j = MRT_MESSAGE_TYPE; j <= BGP_MESSAGE_TYPE; j++) {
        tname = fname;
        tname += (len - strlen(type_strs[j]));
        if(strcmp(tname, type_strs[j]) == 0) {
          type = j;
          break;
        }
      }
    } else {
      *(fname++) = '\0';
      for (j = MRT_MESSAGE_TYPE; j <= BGP_MESSAGE_TYPE; j++) {
        if(strcmp(tname, type_strs[j]) == 0) {
          type = j;
          break;
        }
      }
    }

    if (type == 0) {
      fprintf(stderr, "ERROR: Could not identify type of %s, "
              "consider explicitly specifying type using type:file syntax\n",
              argv[i]);
      usage();
      return -1;
    }

    fprintf(stderr, "INFO: Parsing %s (Type: %s)\n", fname, type_strs[type]);

    if (parse(type, fname) != 0) {
      fprintf(stderr, "WARNING: Failed to parse %s\n", fname);
    }
  }

  return 0;
}
