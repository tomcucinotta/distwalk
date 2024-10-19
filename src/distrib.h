#ifndef __EXPON_H__
#define __EXPON_H__

#include <math.h>
#include <stdlib.h>

// Probabilistic distribution types
typedef enum {
    FIXED,              // fixed value .val
    UNIF,               // uniformly distributed value in range [.min, .max)
    EXPON,              // exponentially distributed value with average .val
    NORM,               // Normal distribution with average .val and sigma .std
    GAMMA,              // Gamma distribution with average .val and sigma .std (can be specified as k, scale as well)
    ARITH_SEQ,          // Arithmetic/Linear ramp in range [.min, .max) with step .std
    GEO_SEQ,            // Geometric ramp in range [.min, .max) with step .std
    SFILE               // Samples read from pre-defined column in CSV file
} pd_type_t;

// Probabilistic distribution spec
typedef struct {
    pd_type_t prob;
    double val;        // average of the distribution
    double std;        // standard deviation of the distribution
    double min;        // lower-bound saturation if !isnan()
    double max;        // upper-bound saturation if !isnan()
    double *samples;   // trace-based samples (pre-loaded from file)
    int num_samples;   // number of elems in samples[]
    int cur_sample;    // index of next sampled elem in samples[]
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
int pd_parse(pd_spec_t *p, char *s);

// return natural length of samples that can be extracted from *p,
// defined only for ARITH_SEQ, GEO_SEQ and SFILE, or -1 for other pd types
int pd_len(pd_spec_t *p);

// return average of sequence or distribution generated from *p
double pd_avg(pd_spec_t *p);

#endif
