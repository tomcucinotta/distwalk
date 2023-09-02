#ifndef __EXPON_H__
#define __EXPON_H__

#include <math.h>
#include <stdlib.h>

// Probabilistic distribution types
typedef enum {
    FIXED,
    UNIF,
    EXPON,
} pd_type_t;

// Probabilistic distribution spec
typedef struct {
    pd_type_t prob;
    double val;        // usually, average of the distribution
    double min;        // lower-bound saturation if !isnan()
    double max;        // upper-bound saturation if !isnan()
} pd_spec_t;

double expon(double lambda);

// seed random number generator (use time(NULL) to randomize it)
void pd_init(long int seed);

static inline pd_spec_t pd_build_fixed(double val) { return (pd_spec_t) { .prob = FIXED, .val = val, .min = NAN, .max = NAN }; }

// sample probability distribution specified by *p
double pd_sample(pd_spec_t *p);

// stringify spec into static array and return it
char *pd_str(pd_spec_t *p);

// return 1 if probabilistic distribution successfully parsed from s
int pd_parse(pd_spec_t *p, const char *s);

#endif
