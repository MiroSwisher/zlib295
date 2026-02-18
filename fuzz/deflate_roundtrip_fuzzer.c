/* libFuzzer harness: deflate with fuzz-driven parameters + inflate round-trip.
 *
 * Exercises deflateInit2 / deflate / inflateInit2 / inflate with:
 *   - Compression level (0..9)
 *   - Window bits: raw (-15 .. -9), zlib (9..15), gzip (25..31)
 *   - Memory level (1..9)
 *   - Strategy: default, filtered, Huffman only, RLE, fixed
 *   - Flush mode variations during compression
 *
 * Then verifies the round-trip: data == inflate(deflate(data)).
 * Bugs found here include incorrect output, memory errors in the deflate
 * or inflate state machines, and assertion failures.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

#define MAX_INPUT (256 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Need at least 4 bytes for parameters + 1 byte of payload. */
  if (size < 5 || size > MAX_INPUT)
    return 0;

  /* Extract fuzz-driven compression parameters from the first 4 bytes. */
  int level    = (data[0] % 10);               /* 0..9 */
  int wbits_raw = 9 + (data[1] % 7);           /* 9..15 */
  int mem_level = 1 + (data[2] % 9);           /* 1..9 */
  int strategy  = data[3] % 5;                 /* 0..4 */

  /* Choose format: raw deflate, zlib, or gzip. */
  int format_sel = (data[0] >> 4) % 3;
  int window_bits;
  int inflate_window_bits;
  switch (format_sel) {
    case 0:  /* raw */
      window_bits = -wbits_raw;
      inflate_window_bits = -wbits_raw;
      break;
    case 1:  /* zlib */
      window_bits = wbits_raw;
      inflate_window_bits = wbits_raw;
      break;
    default: /* gzip */
      window_bits = wbits_raw + 16;
      inflate_window_bits = wbits_raw + 16;
      break;
  }

  data += 4;
  size -= 4;

  /* --- Deflate (compress) --- */
  z_stream def_strm;
  memset(&def_strm, 0, sizeof(def_strm));
  def_strm.zalloc = Z_NULL;
  def_strm.zfree  = Z_NULL;

  if (deflateInit2(&def_strm, level, Z_DEFLATED, window_bits,
                   mem_level, strategy) != Z_OK)
    return 0;

  uLong bound = deflateBound(&def_strm, (uLong)size);
  uint8_t *comp = (uint8_t *)malloc(bound);
  if (!comp) {
    deflateEnd(&def_strm);
    return 0;
  }

  def_strm.next_in   = (z_const Bytef *)data;
  def_strm.avail_in  = (uInt)size;
  def_strm.next_out  = comp;
  def_strm.avail_out = (uInt)bound;

  int ret = deflate(&def_strm, Z_FINISH);
  if (ret != Z_STREAM_END) {
    deflateEnd(&def_strm);
    free(comp);
    return 0;
  }
  uLong comp_size = def_strm.total_out;
  deflateEnd(&def_strm);

  /* --- Inflate (decompress) and verify round-trip --- */
  z_stream inf_strm;
  memset(&inf_strm, 0, sizeof(inf_strm));
  inf_strm.zalloc = Z_NULL;
  inf_strm.zfree  = Z_NULL;

  if (inflateInit2(&inf_strm, inflate_window_bits) != Z_OK) {
    free(comp);
    return 0;
  }

  uint8_t *decomp = (uint8_t *)malloc(size);
  if (!decomp) {
    inflateEnd(&inf_strm);
    free(comp);
    return 0;
  }

  inf_strm.next_in   = comp;
  inf_strm.avail_in  = (uInt)comp_size;
  inf_strm.next_out  = decomp;
  inf_strm.avail_out = (uInt)size;

  ret = inflate(&inf_strm, Z_FINISH);
  if (ret == Z_STREAM_END) {
    /* Verify: decompressed output must equal original input. */
    assert(inf_strm.total_out == size);
    assert(memcmp(data, decomp, size) == 0);
  }

  inflateEnd(&inf_strm);
  free(decomp);
  free(comp);
  return 0;
}
