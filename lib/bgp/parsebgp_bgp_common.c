#include "parsebgp_bgp_common.h"
#include "parsebgp_utils.h"

void parsebgp_bgp_dump_prefixes(parsebgp_bgp_prefix_t *prefixes,
                                int prefixes_cnt, int depth)
{
  int i;
  parsebgp_bgp_prefix_t *tuple;
  for (i = 0; i < prefixes_cnt; i++) {
    tuple = &prefixes[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_prefix_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", tuple->type);
    PARSEBGP_DUMP_INT(depth, "AFI", tuple->afi);
    PARSEBGP_DUMP_INT(depth, "SAFI", tuple->safi);
    PARSEBGP_DUMP_PFX(depth, "Prefix", tuple->afi, tuple->addr, tuple->len);
  }
}
