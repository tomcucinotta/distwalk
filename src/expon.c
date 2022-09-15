#include <math.h>
#include <stdlib.h>

double expon(double lambda, struct drand48_data *randBuffer) {
    double x;
    drand48_r(randBuffer, &x);
    return (-log(1 - x) / lambda);
}
