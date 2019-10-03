#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char * binary_name = NULL;

static void error(const char * message) {
    fprintf(stderr, "%s\n", message);
    fprintf(stderr, "Usage: %s [-t size] <input_file> [output_file]\n", binary_name);
    fprintf(stderr, "Default tab size: 8\n\n");
}

int main(int argc, char ** argv) {
    FILE * in, * out;
    int TABSIZE = 8;
    int p, ts, i;
    char * in_name = NULL;
    char * out_name = NULL;
    char * out_template = NULL;
    char use_tmp_file = 1;

    binary_name = argv[0];

    for (i = 1; i < argc; i++) {
        switch(argv[i][0]) {
        case '-':
            switch(argv[i][1]) {
            case 't':
                if (argv[i][2]) {
                    TABSIZE = strtol(argv[i] + 2, NULL, 10);
                } else {
                    i++;
                    if (i == argc) {
                        error("Invalid -t argument");
                        return -1;
                    }
                    TABSIZE = strtol(argv[i], NULL, 10);
                }
                break;
            default:
                error("Invalid argument");
                return -1;
            }
            break;
        default:
            if (in_name) {
                if (out_name) {
                    error("Too many arguments");
                    return -1;
                }
                out_name = argv[i];
                use_tmp_file = 0;
            } else {
                in_name = argv[i];
            }
            break;
        }
    }

    if (!in_name) {
        error("Missing input filename");
        return -1;
    }

    if (!out_name) {
        size_t in_len = strlen(in_name);
        out_template = malloc(in_len + 8);
        memcpy(out_template, in_name, in_len);
        memcpy(out_template + in_len, ".XXXXXX", 8);
        out_name = mktemp(out_template);
    }

    if (!(in = fopen(in_name, "rb"))) {
        fprintf(stderr, "Can't open input file %s.\n", in_name);
        perror("");
        return -1;
    }

    if (!(out = fopen(out_name, "wb"))) {
        fprintf(stderr, "Can't open output file %s.\n", out_name);
        perror("");
        return -1;
    }

    ts = TABSIZE;
    while ((p = fgetc(in)) != EOF) {
        switch (p) {
        case '\n':
        case '\r':
            ts = TABSIZE;
            fputc(p, out);
            break;
        case '\t':
            for (i = 0; i < ts; i++) {
                fputc(' ', out);
            }
            ts = TABSIZE;
            break;
        default:
            fputc(p, out);
            ts--;
            if (ts == 0)
                ts = TABSIZE;
        }
    }

    fclose(out);
    fclose(in);

    if (use_tmp_file) {
        p = rename(out_name, in_name);
        if (!p) {
            remove(out_name);
        }
        free(out_template);
    }
}
