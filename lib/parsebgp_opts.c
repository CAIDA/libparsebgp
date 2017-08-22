#include "parsebgp_opts.h"

void parsebgp_opts_init(parsebgp_opts_t *opts)
{
  // TODO: allow the default for this to be configured at compile time
  opts->ignore_not_implemented = 0;

  parsebgp_bgp_opts_init(&opts->bgp);
}
