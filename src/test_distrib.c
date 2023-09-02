#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "distrib.h"

int main(int argc, char **argv) {
    long unsigned num_samples = 1000;
    pd_spec_t val = pd_build_fixed(10.0);

    --argc;
    ++argv;
    while (argc > 0) {
        if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
            printf("Usage: test_expon [-h|--help] [-n <num_samples> = 1000] [-d distrib = 10.0]\n");
            exit(0);
        } else if (strcmp(argv[0], "-n") == 0) {
            assert(argc >= 2);
            num_samples = atol(argv[1]);
            --argc;
            ++argv;
        } else if (strcmp(argv[0], "-d") == 0) {
            assert(argc >= 2);
            assert(pd_parse(&val, argv[1]));
            --argc;
            ++argv;
        }
        --argc;
        ++argv;
    }

    pd_init(time(NULL));

    printf("distrib=%s\n", pd_str(&val));
    for (int i = 0; i < num_samples; i++)
        printf("%g\n", pd_sample(&val));
}
