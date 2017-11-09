#include "expon.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(int argc, char **argv) {
  double avg = 10.0;
  long unsigned num_samples = 1000;

  --argc;  ++argv;
  while (argc > 0) {
    if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
      printf("Usage: test_expon [-h|--help] [-n <num_samples>] [-a <average>]\n");
      exit(0);
    } else if (strcmp(argv[0], "-n") == 0) {
      assert(argc >= 2);
      num_samples = atol(argv[1]);
      --argc;  ++argv;
    } else if (strcmp(argv[0], "-a") == 0) {
      assert(argc >= 2);
      avg = atof(argv[1]);
      --argc;  ++argv;
    }
    --argc;  ++argv;
  }
  
  struct drand48_data rnd_buf;
  srand48_r(time(NULL), &rnd_buf);
  if (argc == 2) {
    avg = atof(argv[1]);
  }
  printf("avg=%g\n", avg);
  for (int i = 0; i < num_samples; i++)
    printf("%g\n", expon(1.0 / avg, &rnd_buf));
}
