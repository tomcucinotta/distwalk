#include "distrib.h"

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

__thread struct drand48_data rnd_buf;

double expon(double lambda) {
    double x;
    drand48_r(&rnd_buf, &x);
    return (-log(1 - x) / lambda);
}

void pd_init(long int seed) {
    srand48_r(seed, &rnd_buf);
}

int pd_parse(pd_spec_t *p, const char *s) {
    *p = (pd_spec_t) { .prob = FIXED, .val = NAN, .min = NAN, .max = NAN };
    if (sscanf(s, "unif(%lf,%lf)", &p->min, &p->max) == 2) {
        p->prob = UNIF;
        return 1;
    } else if (sscanf(s, "unif(%lf)", &p->max) == 1) {
        p->min = 0;
        p->prob = UNIF;
        return 1;
    } else if (sscanf(s, "exp(%lf)", &p->val) == 1) {
        p->prob = EXPON;
        return 1;
    } else if (sscanf(s, "%lf", &p->val) == 1) {
        p->prob = FIXED;
        return 1;
    } else {
        return 0;
    }
}

double pd_sample(pd_spec_t *p) {
    double val;
    switch (p->prob) {
    case FIXED:
        val = p->val;
        break;
    case UNIF:
        double x;
        drand48_r(&rnd_buf, &x);
        // no need to check boundaries in this case
        return p->min + (p->max - p->min) * x;
    case EXPON:
        val = expon(1.0 / (p->val));
        break;
    default:
        fprintf(stderr, "Unexpected prob type: %d\n", p->prob);
        exit(1);
    }
    if (!isnan(p->min) && val < p->min)
        val = p->min;
    if (!isnan(p->max) && val > p->max)
        val = p->max;
    return val;
}

static char s[64];

// stringify spec into static array and return it
char *pd_str(pd_spec_t *p) {
    switch (p->prob) {
    case FIXED:
        sprintf(s, "%g", p->val);
        break;
    case UNIF:
        sprintf(s, "unif(%g,%g)", p->min, p->max);
        break;
    case EXPON:
        sprintf(s, "exp(%g)", p->val);
        break;
    default:
        fprintf(stderr, "Unexpected prob type: %d\n", p->prob);
        exit(1);
    }
    return s;
}
