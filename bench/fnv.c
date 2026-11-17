#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint64_t h = 14695981039346656037ULL, acc = 0;
    for (uint64_t i = 0; i < 300000000ULL; i++) { h = (h ^ (i & 255)) * 1099511628211ULL; acc += h >> 63; }
    printf("%llu %llu\n", (unsigned long long)h, (unsigned long long)acc);
    return 0;
}
