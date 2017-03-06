#ifndef __EXPON_H__
#define __EXPON_H__

#include <stdlib.h>

// Function to generate exponentially distributed random variables
// input: lambda parameter of distribution (inverse of mean), out:
// exponentially distributed random variable
double expon(double lambda, struct drand48_data *randBuffer);

#endif
