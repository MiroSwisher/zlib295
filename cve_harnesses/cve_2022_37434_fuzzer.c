/* Targeted harness for CVE-2022-37434 (zlib <= 1.2.12)
 *
 * Heap-based buffer over-read/overflow in inflate() triggered when
 * inflateGetHeader() is called and the gzip header extra field is
 * processed across multiple inflate() calls. The variable `len`
 * grows past `extra_max`, causing an underflow in the size argument
 * of zmemcpy and an out-of-bounds write to head->extra.
 *
 * Key: feed input in small chunks so the EXTRA state is re-entered
 * across multiple inflate() calls.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

#define OUT_CHUNK 4096
#define FUZZ_MAX_OUTPUT (64 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return 0;

  unsigned extra_buf_size = (data[0] % 64) + 1;
  unsigned chunk_size = (data[1] % 32) + 1;
  data += 2; size -= 2;

  if (size > 64 * 1024)
    return 0;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.zalloc = Z_NULL;
  strm.zfree  = Z_NULL;
  strm.opaque = Z_NULL;

  if (inflateInit2(&strm, 31) != Z_OK)
    return 0;

  gz_header header;
  memset(&header, 0, sizeof(header));
  uint8_t *extra = (uint8_t *)malloc(extra_buf_size);
  uint8_t name_buf[64];
  uint8_t comment_buf[64];
  if (!extra) {
    inflateEnd(&strm);
    return 0;
  }

  header.extra = extra;
  header.extra_max = extra_buf_size;
  header.name = name_buf;
  header.name_max = sizeof(name_buf);
  header.comment = comment_buf;
  header.comm_max = sizeof(comment_buf);

  inflateGetHeader(&strm, &header);

  uint8_t out_buf[OUT_CHUNK];
  size_t total_out = 0;
  const uint8_t *ptr = data;
  size_t remaining = size;
  int ret = Z_OK;

  /* Feed input in small chunks to trigger multi-call EXTRA processing. */
  while (remaining > 0 && ret != Z_STREAM_END) {
    size_t feed = remaining < chunk_size ? remaining : chunk_size;
    strm.next_in  = (z_const Bytef *)ptr;
    strm.avail_in = (uInt)feed;

    while (strm.avail_in > 0 && ret != Z_STREAM_END) {
      strm.next_out  = out_buf;
      strm.avail_out = OUT_CHUNK;
      ret = inflate(&strm, Z_NO_FLUSH);
      total_out += OUT_CHUNK - strm.avail_out;
      if (ret < 0)
        goto done;
      if (total_out >= FUZZ_MAX_OUTPUT)
        goto done;
    }

    ptr += feed;
    remaining -= feed;
  }

done:
  inflateEnd(&strm);
  free(extra);
  return 0;
}
