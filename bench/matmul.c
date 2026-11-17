#include <stdio.h>
#include <stdlib.h>
int main(void) {
    size_t n = 400;
    double *a = malloc(n*n*8), *b = malloc(n*n*8), *c = calloc(n*n, 8);
    for (size_t i = 0; i < n*n; i++) { a[i] = (double)(i % 7) + 0.5; b[i] = (double)(i % 5) - 1.5; }
    for (size_t i = 0; i < n; i++) for (size_t k = 0; k < n; k++) { double aik = a[i*n+k]; for (size_t j = 0; j < n; j++) c[i*n+j] += aik * b[k*n+j]; }
    double sum = 0.0; for (size_t i = 0; i < n*n; i++) sum += c[i];
    printf("%.17g\n", sum);
    return 0;
}
