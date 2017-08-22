#include "parsebgp_bgp_opts.h"
#include <string.h>

void parsebgp_bgp_opts_init(parsebgp_bgp_opts_t *opts)
{
  memset(opts, 0, sizeof(*opts));
}
