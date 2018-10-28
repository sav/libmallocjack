#ifndef LIBMALLOCJACK_H
#define LIBMALLOCJACK_H

#include <stdbool.h>
#include <list.h>

/* Filters are executed before each native call. If true is returned
 * then the native call is not called and the hook returns the corresponding
 * error if any.
 */
struct mjack_filter {
    bool (*malloc)   (size_t);
    bool (*calloc)   (size_t, size_t);
    bool (*realloc)  (void *, size_t);
    bool (*memalign) (size_t, size_t);
    bool (*free)     (void *);

    struct list list;
};

void mjack_filter_add(struct mjack_filter *);

void mjack_filter_del(struct mjack_filter *);

/* Traces are executed after the native call. The value returned
 * by the native call, if any, is passed as last argument.
 */
struct mjack_trace {
    void (*malloc)   (size_t, void *);
    void (*calloc)   (size_t, size_t, void *);
    void (*realloc)  (void *, size_t, void *);
    void (*memalign) (size_t, size_t, void *);
    void (*free)     (void *);

    struct list list;
};

void mjack_trace_add(struct mjack_trace *);

void mjack_trace_del(struct mjack_trace *);

#endif /* LIBMALLOCJACK_H */
