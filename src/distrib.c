#include "distrib.h"
#include "dw_debug.h"

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

/* X~unif[0,1] -> E[X] = 1/2, sx^2 = E[(X-1/2)^2] = \int_0^1 x^2 dx - 1/4 = 1/3 - 1/4 = 1/12
 * Y = X_1 + ... + X_n -> my = n * mx, sy^2 = n * sx^2, sy = sqrt(n) * sx
 * E[(Y - my)^2] = E[Y^2] - my^2
 * = E[(X_1 + ... + X_n)*(X_1 + ... + X_n)] - my^2
 * = n * (mx^2 + sx^2) + (n^2 - n)*mx^2 - n^2 * mx^2
 * = n * sx^2
 */
double gaussian(double avg, double std) {
    double y = 0.0;
    const int N = 4;
    for (int i = 0; i < N*N; i++) {
        double x;
        drand48_r(&rnd_buf, &x);
        y += x - 0.5;
    }
    // y has mean 0, var N*N/12
    y *= sqrt(12)/N; // now y ~ N(0,1)
    return y * std + avg;
}

// Only works for small and integer values of 'k'
double distr_gamma(double avg, double std) {
    // avg = k * scale, std^2 = k * scale^2
    double scale = std*std / avg;
    int k = lrint(avg / scale);
    check(fabs(k - avg/scale) < 0.00001, "Using Gamma with non-integer k: %g", avg/scale);
    double x = 0.0;
    for (int i = 0; i < k; i++)
        x += expon(1.0 / scale);
    return x;
}

void pd_init(long int seed) {
    srand48_r(seed, &rnd_buf);
}

void pd_load_file(pd_spec_t *p, char *fname, int col) {
    FILE *f = fopen(fname, "r");
    check(f != NULL, "Could not open file: %s\n", fname);
    int n = 0;
    static char line[256];
    int n_max = 16;
    p->samples = malloc(n_max * sizeof(*p->samples));
    check(p->samples != NULL, "Could not allocate %lu bytes for file\n", n_max * sizeof(*p->samples));
    n = 0;
    while (fgets(line, sizeof(line), f)) {
        char *colstr;
        char *s = line;
        int c = col;
        do {
            colstr = strsep(&s, ",");
        } while (c-- > 0 && colstr != NULL);
        check(c == -1 && colstr != NULL, "Could not find col %d in line %d of file %s: %s\n", col, n, fname, line);
        double val;
        // ignore lines where values were not recognized
        if (sscanf(colstr, "%lf", &val) == 1) {
            if (n == n_max) {
                n_max *= 2;
                p->samples = realloc(p->samples, n_max * sizeof(*p->samples));
                check(p->samples != NULL, "Could not allocate %lu bytes for file\n", n_max * sizeof(*p->samples));
            }
            p->samples[n++] = val;
        }
    }
    fclose(f);

    // make allocated memory tight for the number of actually read samples n
    p->samples = realloc(p->samples, n * sizeof(*p->samples));
    check(p->samples != NULL, "Could not realloc memory to %lu bytes for file\n", n * sizeof(*p->samples));
    p->num_samples = n;
    p->cur_sample = 0;
}

int sscanf_unit(const char *str, const char *fmt, double *p_val) {
    int l = strlen(str);
    if (l == 0)
        return 0;
    int rv = sscanf(str, fmt, p_val);
    if (rv != 1)
        return rv;
    switch (str[l - 1]) {
    case 'k':
    case 'K':
        *p_val *= 1000;
        break;
    case 'm':
    case 'M':
        *p_val *= 1000000;
        break;
    case 'g':
    case 'G':
        *p_val *= 1000000000;
        break;
    }
    return rv;
}

int pd_parse(pd_spec_t *p, char *s) {
    *p = (pd_spec_t) { .prob = FIXED, .val = NAN, .std = NAN, .min = NAN, .max = NAN, .samples = NULL };
    char *tok = strsep(&s, ":");
    int col = 0;        // used by SFILE
    char *fname = NULL; // used by SFILE
    check(tok, "Wrong value/distribution syntax\n");
    if (strcmp(tok, "unif") == 0)
        p->prob = UNIF;
    else if (strcmp(tok, "exp") == 0)
        p->prob = EXPON;
    else if (strcmp(tok, "norm") == 0)
        p->prob = NORM;
    else if (strcmp(tok, "gamma") == 0)
        p->prob = GAMMA;
    else if (strcmp(tok, "aseq") == 0)
        p->prob = ARITH_SEQ;
    else if (strcmp(tok, "gseq") == 0)
        p->prob = GEO_SEQ;
    else if (strcmp(tok, "file") == 0)
        p->prob = SFILE;
    else if (sscanf_unit(tok, "%lf", &p->val) == 1)
        p->prob = FIXED;
    else {
        fprintf(stderr, "Wrong value/distribution syntax: %s\n", tok);
        exit(EXIT_FAILURE);
    }
    double k = NAN, scale = NAN; // for Gamma
    while ((tok = strsep(&s, ",")) != NULL) {
        dw_log("Processing tok: %s\n", tok);
        if (sscanf_unit(tok, "min=%lf", &p->min) == 1
            || sscanf_unit(tok, "max=%lf", &p->max) == 1
            || sscanf_unit(tok, "std=%lf", &p->std) == 1
            || sscanf_unit(tok, "k=%lf", &k) == 1
            || sscanf_unit(tok, "scale=%lf", &scale) == 1
            || sscanf_unit(tok, "avg=%lf", &p->val) == 1
            || ((p->prob == ARITH_SEQ || p->prob == GEO_SEQ) && sscanf_unit(tok, "step=%lf", &p->std) == 1)
            || (p->prob == SFILE && sscanf(tok, "col=%d", &col) == 1)
            || sscanf_unit(tok, "%lf", &p->val) == 1
            )
                continue;
        if (p->prob == SFILE) {
            fname = tok;
            continue;
        }
        fprintf(stderr, "Unrecognized token in value/distribution syntax: %s\n", tok);
        exit(EXIT_FAILURE);
    }
    if (p->prob == SFILE) {
        check(fname != NULL, "Missing filename for file: value/distribution syntax\n");
        pd_load_file(p, fname, col);
    }
    if (p->prob == GAMMA && !isnan(k) && !isnan(scale)) {
        p->val = k * scale;
        p->std = sqrt(k) * scale;
    }
    if ((p->prob == ARITH_SEQ) && isnan(p->std))
        p->std = 1;
    if ((p->prob == GEO_SEQ) && isnan(p->std))
        p->std = 2;

    if (p->prob == ARITH_SEQ && isnan(p->val))
        p->val = p->std >= 0 ? p->min : p->max;
    if (p->prob == GEO_SEQ && isnan(p->val))
        p->val = p->std >= 1 ? p->min : p->max;

    check(p->prob != FIXED || !isnan(p->val));
    check(p->prob != UNIF || (!isnan(p->min) && !isnan(p->max)));
    check(p->prob != EXPON || (!isnan(p->val) && isnan(p->std)));
    check(p->prob != NORM || (!isnan(p->val) && !isnan(p->std)));
    check(p->prob != GAMMA || (!isnan(p->val) && !isnan(p->std)));
    check(p->prob != ARITH_SEQ || (!isnan(p->val) && ( (p->std >= 0 && !isnan(p->max)) || (p->std < 0 && !isnan(p->min)) ) ));
    check(p->prob != GEO_SEQ || (!isnan(p->val) && ( (p->std >= 1 && !isnan(p->max)) || (p->std < 1 && !isnan(p->min)) ) ));
    return 1;
}

double pd_sample(pd_spec_t *p) {
    double val;
    double x;
 retry:
    switch (p->prob) {
    case FIXED:
        // no need to check boundaries in this case
        return p->val;
    case UNIF:
        drand48_r(&rnd_buf, &x);
        // no need to check boundaries in this case
        return p->min + (p->max - p->min) * x;
    case EXPON:
        val = expon(1.0 / (p->val));
        break;
    case NORM:
        val = gaussian(p->val, p->std);
        break;
    case GAMMA:
        val = distr_gamma(p->val, p->std);
        break;
    case ARITH_SEQ:
        val = p->val;
        p->val += p->std;
        if (p->val >= p->max)
            p->val = p->max;
        else if (p->val <= p->min)
            p->val = p->min;
        break;
    case GEO_SEQ:
        val = p->val;
        p->val *= p->std;
        if (p->val >= p->max)
            p->val = p->max;
        else if (p->val <= p->min)
            p->val = p->min;
        break;
    case SFILE:
        val = p->samples[p->cur_sample++];
        p->cur_sample %= p->num_samples;
        break;
    default:
        fprintf(stderr, "Unexpected prob type: %d\n", p->prob);
        exit(EXIT_FAILURE);
    }
    if ((!isnan(p->min) && val < p->min)
        || (!isnan(p->max) && val > p->max))
        goto retry;
    return val;
}


// stringify spec into static array and return it
char *pd_str(pd_spec_t *p) {
    static char s[64];
    double scale;
    int k;
    switch (p->prob) {
    case FIXED:
        sprintf(s, "%g", p->val);
        break;
    case UNIF:
        sprintf(s, "unif:");
        break;
    case EXPON:
        sprintf(s, "exp:%g", p->val);
        break;
    case NORM:
        sprintf(s, "norm:%g", p->val);
        break;
    case GAMMA:
        scale = p->std * p->std / p->val;
        k = lrint(p->val / scale);
        sprintf(s, "gamma:%g,k=%d,scale=%g", p->val, k, scale);
        break;
    case ARITH_SEQ:
    case GEO_SEQ:
        sprintf(s, "seq:step=%g", p->std);
        break;
    case SFILE:
        sprintf(s, "file:num_samples=%d,[0]=%g", p->num_samples, p->samples[0]);
        break;
    default:
        fprintf(stderr, "Unexpected prob type: %d\n", p->prob);
        exit(EXIT_FAILURE);
    }
    if (p->prob != FIXED && p->prob != ARITH_SEQ && p->prob != GEO_SEQ && !isnan(p->std))
        sprintf(s + strlen(s), ",std=%g", p->std);
    if (!isnan(p->min))
        sprintf(s + strlen(s), ",min=%g", p->min);
    if (!isnan(p->max))
        sprintf(s + strlen(s), ",max=%g", p->max);
    return s;
}

int pd_len(pd_spec_t *p) {
    int rv;
    switch (p->prob) {
    case ARITH_SEQ:
        rv = (p->max + p->std - p->min) / p->std;
        break;
    case GEO_SEQ:
        check(log(p->std) > 0);
        rv = (log(p->max / p->min) / log(p->std)) + 1;
        break;
    case SFILE:
        rv = p->num_samples;
        break;
    default:
        rv = -1;
    }
    return rv;
}

double pd_avg(pd_spec_t *p) {
    double rv;
    switch (p->prob) {
    case ARITH_SEQ:
        rv = (p->min + p->max) / 2;
        break;
    case GEO_SEQ:
        rv = sqrt(p->min * p->max);
        break;
    case SFILE:
        rv = 0.0;
        for (int i = 0; i < p->num_samples; i++)
            rv += p->samples[i];
        rv /= p->num_samples;
        break;
    default:
        rv = p->val;
    }
    return rv;
}
