#include <stdio.h>
#include <stdlib.h>

struct {
    size_t total;
    size_t using;
} ctx;

#ifdef DEBUG_TEST
#define inc(t, u) do {                                                     \
      fprintf(stderr, "test: %s: inc(%d, %d)\n", __FUNCTION__, (t), (u));  \
      fflush(stderr);                                                      \
      ctx.total += (t);                                                    \
      ctx.using += (u);                                                    \
   } while(0)

#define pstat() do {                                                       \
   fprintf(stderr, "test: main: allocated %zu bytes, freed %zu bytes, "    \
      "still reachable: %zu bytes\n", ctx.total, ctx.total - ctx.using,    \
      ctx.using);                                                          \
   fflush(stderr);                                                         \
} while(0)
#else
#define inc(t, u) {}
#define pstat() {}
#endif

void t1(void)
{
    void *ptr = NULL;
    ptr = realloc(ptr, 64); inc(64, 64);
    ptr = realloc(ptr, 32); inc(0, -32);
    ptr = realloc(ptr, 128); inc(64, 96);
    free(ptr); inc(0, -128);
}

int main(void)
{
    void *ptr = NULL;

    ptr = realloc(ptr, 32); inc(32, 32);
    ptr = realloc(ptr, 64); inc(32, 32);
    free(ptr); inc(0, -64);

    ptr = malloc(8); inc(8, 8);
    ptr = realloc(ptr, 64); inc(56, 56);
    free(ptr); inc(0, -64);

    ptr = calloc(1, 16); inc(16, 16);
    ptr = realloc(ptr, 128); inc(112, 112);
    free(ptr); inc(0, -128);

    for (int i = 0; i < 100; ++i)
        t1();

    pstat();
    return 0;
}

