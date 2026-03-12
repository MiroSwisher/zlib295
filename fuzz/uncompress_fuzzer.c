/* libFuzzer harness for zlib uncompress (decompression of raw zlib stream).
 * Feeds fuzzer input directly to uncompress to stress the decoder.
 */

#include <stdint.h>
#include <stdlib.h>

#include "zlib.h"

#define OUT_BUF_SIZE (256 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 1024 * 1024)
    return 0;

  uint8_t *out = (uint8_t *)malloc(OUT_BUF_SIZE);
  if (!out)
    return 0;

  uLongf out_len = OUT_BUF_SIZE;
  int ret = uncompress(out, &out_len, data, (uLong)size);
  (void)ret;

  free(out);
  return 0;
}
