#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *ptr = malloc(8);
    ptr = realloc(ptr, 64);
    free(ptr);
    ptr = calloc(1, 16);
    ptr = realloc(ptr, 128);
    free(ptr);
    return 0;
}
