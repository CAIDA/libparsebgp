#include "parsebgp_opts.h"
#include <string.h>

void parsebgp_opts_init(parsebgp_opts_t *opts)
{
  // TODO: allow the default for some of these to be configured at compile time
  memset(opts, 0, sizeof(*opts));

  parsebgp_bgp_opts_init(&opts->bgp);
}
