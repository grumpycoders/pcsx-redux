#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

static uint32_t computeAdler(FILE* f) {
    uint8_t buffer[4096];
    uint32_t ret = adler32(0, 0, 0);
    while (!feof(f)) {
        size_t r = fread(buffer, 1, 4096, f);
        ret = adler32(ret, buffer, r);
    }
    return ret;
}

int main(int argc, char** argv) {
    if (argc <= 1) {
        printf("%08x\n", computeAdler(stdin));
    }
    for (int i = 1; i < argc; i++) {
        FILE* f = fopen(argv[i], "rb");
        if (!f) continue;
        printf("%08x %s\n", computeAdler(f), argv[i]);
        fclose(f);
    }
    return 0;
}
