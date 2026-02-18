/* libFuzzer harness: streaming inflate with fuzz-driven window bits.
 *
 * This is the most important harness for finding bugs in zlib. It exercises
 * the full inflate state machine (header parsing, Huffman decoding, distance
 * matching, checksums) by feeding raw fuzzer input to inflate() in small
 * chunks with varied parameters:
 *
 *   - Window bits: raw deflate (-15), zlib (15), gzip (31), auto-detect (47)
 *   - Flush modes: Z_NO_FLUSH, Z_SYNC_FLUSH, Z_BLOCK
 *   - Chunked feeding: small output buffer forces multiple inflate() calls,
 *     exercising the "need more output space" path repeatedly.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

#define OUT_CHUNK 1024
#define FUZZ_MAX_INPUT (1 * 1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > FUZZ_MAX_INPUT)
    return 0;

  /* Use the first byte to select window bits. */
  static const int window_bits_choices[] = {
    -15,  /* raw deflate */
     15,  /* zlib format */
     31,  /* gzip format */
     47,  /* auto-detect zlib/gzip */
  };
  int wb_idx = data[0] % 4;
  int window_bits = window_bits_choices[wb_idx];

  /* Use the second byte to select a flush mode for inflate(). */
  static const int flush_choices[] = {
    Z_NO_FLUSH,
    Z_SYNC_FLUSH,
    Z_BLOCK,
    Z_FINISH,
  };
  int flush_idx = data[1] % 4;
  int flush = flush_choices[flush_idx];

  data += 2;
  size -= 2;
  if (size == 0)
    return 0;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.zalloc = Z_NULL;
  strm.zfree  = Z_NULL;
  strm.opaque = Z_NULL;
  strm.next_in  = (z_const Bytef *)data;
  strm.avail_in = (uInt)size;

  if (inflateInit2(&strm, window_bits) != Z_OK)
    return 0;

  uint8_t out_buf[OUT_CHUNK];
  int ret;
  do {
    strm.next_out  = out_buf;
    strm.avail_out = OUT_CHUNK;
    ret = inflate(&strm, flush);
    /* Break on any error: Z_DATA_ERROR, Z_STREAM_ERROR, Z_MEM_ERROR, etc. */
    if (ret < 0)
      break;
  } while (ret != Z_STREAM_END && strm.avail_in > 0);

  inflateEnd(&strm);
  return 0;
}
