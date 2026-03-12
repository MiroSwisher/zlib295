/* Direct test for CVE-2018-25032 using the known trigger input. */
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
  if (!f) {
    perror("fopen");
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *data = malloc(size);
  fread(data, 1, size, f);
  fclose(f);

  printf("Input size: %ld bytes\n", size);

  for (int level = 1; level <= 9; level++) {
    for (int wbits = 9; wbits <= 15; wbits++) {
      z_stream strm;
      memset(&strm, 0, sizeof(strm));

      int ret = deflateInit2(&strm, level, Z_DEFLATED, wbits, 8, Z_FIXED);
      if (ret != Z_OK) {
        printf("deflateInit2 failed: level=%d wbits=%d ret=%d\n", level, wbits, ret);
        continue;
      }

      uLong bound = deflateBound(&strm, (uLong)size);
      uint8_t *comp = (uint8_t *)malloc(bound);

      strm.next_in = (Bytef *)data;
      strm.avail_in = (uInt)size;
      strm.next_out = comp;
      strm.avail_out = (uInt)bound;

      printf("Deflating: level=%d wbits=%d ...", level, wbits);
      fflush(stdout);
      ret = deflate(&strm, Z_FINISH);
      printf(" ret=%d total_out=%lu\n", ret, strm.total_out);

      if (ret == Z_STREAM_END) {
        uLong comp_size = strm.total_out;
        deflateEnd(&strm);

        z_stream inf_strm;
        memset(&inf_strm, 0, sizeof(inf_strm));
        inflateInit2(&inf_strm, wbits);
        uint8_t *decomp = (uint8_t *)malloc(size);
        inf_strm.next_in = comp;
        inf_strm.avail_in = (uInt)comp_size;
        inf_strm.next_out = decomp;
        inf_strm.avail_out = (uInt)size;
        ret = inflate(&inf_strm, Z_FINISH);
        if (ret == Z_STREAM_END) {
          if (inf_strm.total_out != (uLong)size || memcmp(data, decomp, size) != 0) {
            printf("  *** DATA CORRUPTION DETECTED! ***\n");
          }
        } else {
          printf("  inflate failed: ret=%d msg=%s\n", ret, inf_strm.msg ? inf_strm.msg : "null");
        }
        inflateEnd(&inf_strm);
        free(decomp);
      } else {
        deflateEnd(&strm);
      }

      free(comp);
    }
  }

  free(data);
  return 0;
}
