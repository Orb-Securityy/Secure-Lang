#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
int main(void) {
    size_t n = 20000000;
    bool *s = malloc(n + 1);
    for (size_t i = 0; i <= n; i++) s[i] = true;
    s[0] = s[1] = false;
    for (size_t i = 2; i * i <= n; i++) if (s[i]) for (size_t j = i * i; j <= n; j += i) s[j] = false;
    unsigned long long c = 0;
    for (size_t k = 0; k <= n; k++) if (s[k]) c++;
    printf("%llu\n", c);
    return 0;
}
