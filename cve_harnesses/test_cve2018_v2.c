/* Direct test for CVE-2018-25032 — try all memLevel values too. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *data = malloc(size);
  fread(data, 1, size, f);
  fclose(f);

  printf("Input size: %ld bytes\n", size);

  int strategies[] = {Z_FIXED, Z_DEFAULT_STRATEGY};
  const char *strat_names[] = {"Z_FIXED", "Z_DEFAULT"};

  for (int si = 0; si < 2; si++) {
    for (int memLevel = 1; memLevel <= 9; memLevel++) {
      for (int level = 1; level <= 9; level++) {
        for (int wbits = 9; wbits <= 15; wbits++) {
          z_stream strm;
          memset(&strm, 0, sizeof(strm));

          int ret = deflateInit2(&strm, level, Z_DEFLATED, wbits,
                                 memLevel, strategies[si]);
          if (ret != Z_OK) continue;

          uLong bound = deflateBound(&strm, (uLong)size);
          uint8_t *comp = malloc(bound);

          strm.next_in = (Bytef *)data;
          strm.avail_in = (uInt)size;
          strm.next_out = comp;
          strm.avail_out = (uInt)bound;

          ret = deflate(&strm, Z_FINISH);
          uLong comp_size = strm.total_out;
          deflateEnd(&strm);

          if (ret == Z_STREAM_END && comp_size > 0) {
            z_stream inf;
            memset(&inf, 0, sizeof(inf));
            inflateInit2(&inf, wbits);
            uint8_t *decomp = malloc(size);
            inf.next_in = comp;
            inf.avail_in = (uInt)comp_size;
            inf.next_out = decomp;
            inf.avail_out = (uInt)size;
            ret = inflate(&inf, Z_FINISH);
            if (ret == Z_STREAM_END) {
              if (inf.total_out != (uLong)size ||
                  memcmp(data, decomp, size) != 0) {
                printf("*** CORRUPTION: strat=%s level=%d wbits=%d memLevel=%d ***\n",
                       strat_names[si], level, wbits, memLevel);
              }
            } else {
              printf("*** INFLATE FAIL: strat=%s level=%d wbits=%d memLevel=%d ret=%d msg=%s ***\n",
                     strat_names[si], level, wbits, memLevel,
                     ret, inf.msg ? inf.msg : "null");
            }
            inflateEnd(&inf);
            free(decomp);
          }
          free(comp);
        }
      }
    }
  }

  printf("Done.\n");
  free(data);
  return 0;
}
