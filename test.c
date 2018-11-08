#include <stdio.h>
#include <stdlib.h>

void foo(void)
{
    void *ptr = NULL;
    ptr = realloc(ptr, 64);
    ptr = realloc(ptr, 32);
    free(ptr);
}

int main(void)
{
    void *ptr = NULL;

    ptr = realloc(ptr, 32);
    ptr = realloc(ptr, 64);
    free(ptr);

    ptr = malloc(8);
    ptr = realloc(ptr, 64);
    free(ptr);

    ptr = calloc(1, 16);
    ptr = realloc(ptr, 128);
    free(ptr);

    /* test call info */
    for (int i = 0; i < 100; ++i)
        foo();

    return 0;
}
