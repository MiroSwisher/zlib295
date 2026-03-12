/* Targeted harness for CVE-2018-25032 (zlib <= 1.2.11)
 *
 * Memory corruption in deflate when using Z_FIXED strategy with inputs
 * that produce many distant matches. The pending buffer overwrites the
 * distance symbol table it overlays, causing corrupted output and OOB
 * memory accesses.
 *
 * Key: Z_FIXED strategy + varied memLevel (especially low values).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

#define FUZZ_MAX_INPUT (256 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3 || size > FUZZ_MAX_INPUT)
    return 0;

  int level = (data[0] % 10);
  int window_bits = 9 + (data[1] % 7);
  int mem_level = 1 + (data[2] % 9);
  data += 3;
  size -= 3;
  if (size == 0)
    return 0;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.zalloc = Z_NULL;
  strm.zfree  = Z_NULL;

  if (deflateInit2(&strm, level, Z_DEFLATED, window_bits,
                   mem_level, Z_FIXED) != Z_OK)
    return 0;

  uLong bound = deflateBound(&strm, (uLong)size);
  uint8_t *comp = (uint8_t *)malloc(bound);
  if (!comp) {
    deflateEnd(&strm);
    return 0;
  }

  strm.next_in   = (z_const Bytef *)data;
  strm.avail_in  = (uInt)size;
  strm.next_out  = comp;
  strm.avail_out = (uInt)bound;

  int ret = deflate(&strm, Z_FINISH);
  uLong comp_size = strm.total_out;
  deflateEnd(&strm);

  if (ret == Z_STREAM_END && comp_size > 0) {
    z_stream inf_strm;
    memset(&inf_strm, 0, sizeof(inf_strm));
    inf_strm.zalloc = Z_NULL;
    inf_strm.zfree  = Z_NULL;

    if (inflateInit2(&inf_strm, window_bits) == Z_OK) {
      uint8_t *decomp = (uint8_t *)malloc(size);
      if (decomp) {
        inf_strm.next_in   = comp;
        inf_strm.avail_in  = (uInt)comp_size;
        inf_strm.next_out  = decomp;
        inf_strm.avail_out = (uInt)size;

        ret = inflate(&inf_strm, Z_FINISH);
        if (ret == Z_STREAM_END) {
          assert(inf_strm.total_out == size);
          assert(memcmp(data, decomp, size) == 0);
        }
        free(decomp);
      }
      inflateEnd(&inf_strm);
    }
  }

  free(comp);
  return 0;
}
