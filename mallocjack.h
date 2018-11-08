#ifndef LIBMALLOCJACK_H
#define LIBMALLOCJACK_H

#include <stdbool.h>
#include <list.h>

/**
 * Filters are executed before each native call. If true is returned then the
 * native call is not called and the hook returns error if not void.
 */
struct mjfilter {
    bool (*malloc)(size_t);
    bool (*calloc)(size_t, size_t);
    bool (*realloc)(void *, size_t);
    bool (*memalign)(size_t, size_t);
    bool (*free)(void *);

    struct list list;
};

void mjfilter_add(struct mjfilter *);

void mjfilter_del(struct mjfilter *);

/**
 * Traces are executed after the native call. The value returned by the native
 * call, if any, is passed as last argument.
 */
struct mjtrace {
    void (*malloc)(size_t, void *);
    void (*calloc)(size_t, size_t, void *);
    void (*realloc)(void *, size_t, void *);
    void (*memalign)(size_t, size_t, void *);
    void (*free)(void *);

    struct list list;
};

void mjtrace_add(struct mjtrace *);

void mjtrace_del(struct mjtrace *);

#endif /* LIBMALLOCJACK_H */
