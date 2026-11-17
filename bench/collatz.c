#include <stdio.h>
#include <stdint.h>
static uint64_t steps(uint64_t n) { uint64_t s = 0; while (n != 1) { if (n % 2 == 0) n = n / 2; else n = 3 * n + 1; s++; } return s; }
int main(void) {
    uint64_t best = 0, arg = 0;
    for (uint64_t i = 1; i < 3000000; i++) { uint64_t s = steps(i); if (s > best) { best = s; arg = i; } }
    printf("%llu %llu\n", (unsigned long long)arg, (unsigned long long)best);
    return 0;
}
