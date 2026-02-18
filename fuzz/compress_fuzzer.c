/* libFuzzer harness for zlib compress/uncompress and decompress paths.
 * Based on OSS-Fuzz zlib compress_fuzzer.c (Apache 2.0).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

static const uint8_t *data;
static size_t dataLen;

static void check_compress_level(uint8_t *compr, uLongf comprLen,
                                 uint8_t *uncompr, uLongf uncomprLen,
                                 int level) {
  uLongf comprLenOut = comprLen;
  uLongf uncomprLenOut = uncomprLen;
  if (compress2(compr, &comprLenOut, data, (uLong)dataLen, level) != Z_OK)
    return;
  if (uncompress(uncompr, &uncomprLenOut, compr, comprLenOut) != Z_OK)
    return;

  /* Make sure compress + uncompress gives back the input data. */
  assert(dataLen == uncomprLenOut);
  assert(0 == memcmp(data, uncompr, dataLen));
}

#define put_byte(s, i, c) do { (s)[i] = (unsigned char)(c); } while (0)

static void write_zlib_header(uint8_t *s, unsigned compression_method, unsigned flags) {
  unsigned int header = (Z_DEFLATED + ((flags) << 4)) << 8;
  header |= (compression_method << 6);
  header += 31 - (header % 31);

  put_byte(s, 0, (unsigned char)(header >> 8));
  put_byte(s, 1, (unsigned char)(header & 0xff));
}

static void check_decompress(uint8_t *out_buf, uLongf out_len,
                             unsigned compression_method, unsigned flags) {
  /* Copy input into a larger buffer and prepend a valid zlib header. */
  size_t copyLen = dataLen + 2;
  uint8_t *copy = (uint8_t *)malloc(copyLen);
  if (!copy) return;
  memcpy(copy + 2, data, dataLen);
  write_zlib_header(copy, compression_method, flags);

  (void)uncompress(out_buf, &out_len, copy, (uLong)copyLen);
  free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {
  if (size < 10 || size > 1024 * 1024)
    return 0;

  const int level = d[0] % 10;
  d++; size--;

  unsigned compression_method = d[0] % 5;
  if (compression_method == 4)
    compression_method = 8;
  d++; size--;
  unsigned flags = d[0] & (2 << 4);
  d++; size--;

  uLongf comprLen = (uLongf)compressBound((uLong)size);
  uLongf uncomprLen = (uLongf)size;
  uint8_t *compr = NULL, *uncompr = NULL;

  data = d;
  dataLen = size;
  compr = (uint8_t *)calloc(1, comprLen);
  if (!compr)
    goto err;
  uncompr = (uint8_t *)calloc(1, uncomprLen);
  if (!uncompr)
    goto err;

  check_compress_level(compr, comprLen, uncompr, uncomprLen, level);
  check_decompress(uncompr, uncomprLen, compression_method, flags);

err:
  free(compr);
  free(uncompr);
  return 0;
}
