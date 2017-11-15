#include "parsebgp_error.h"
#include <stdlib.h>

char *err_strings[] = {
  "No Error",        // PARSEBGP_OK
  "Partial Message", // PARSEBGP_PARTIAL_MSG
  "Invalid Message", // PARSEBGP_INVALID_MSG
  "Not Implemented", // PARSEBGP_NOT_IMPLEMENTED
  "Malloc Failure",  // PARSEBGP_MALLOC_FAILURE
};

const char *parsebgp_strerror(parsebgp_error_t err)
{
  if (err > 0 || err < PARSEBGP_MALLOC_FAILURE) {
    return "Unknown Error";
  }
  return err_strings[abs(err)];
}
