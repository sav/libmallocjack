/* Copyright (C) 2018, Savio Machado <sav@loophole.cc>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>
#include <dlfcn.h>
#include <malloc.h>

#include <mallocjack.h>

#define BTLEN         1
#define MEMMAX        64
#define PRINTMAX      128

#define print_nobuf(fd, ...) do {                            \
    char buf[PRINTMAX];                                      \
    int n = snprintf(buf, PRINTMAX, __VA_ARGS__);            \
    (void) write((fd), buf, n);                              \
} while(0)

#define fail(fmt, ...) do {                                  \
    print_nobuf(STDERR_FILENO, "error! " fmt, __VA_ARGS__);  \
    exit(1);                                                 \
} while(0)

#define debug(...) print_nobuf(STDERR_FILENO, __VA_ARGS__)
    
struct mjack {
    void *(*malloc)   (size_t);
    void *(*calloc)   (size_t, size_t);
    void *(*realloc)  (void *, size_t);
    void *(*memalign) (size_t, size_t);
    void  (*free)     (void *);
};

struct mjack libc;
static bool started = false;

static void memstat_malloc(size_t size, void *ptr)
{
    debug("malloc(%zu) = %p\n", size, ptr);
}

static void memstat_calloc(size_t nmemb, size_t size, void *ret)
{
    debug("calloc(%zu, %zu) = %p\n", nmemb, size, ret);
}

static void memstat_realloc(void *ptr, size_t size, void *ret)
{
    debug("realloc(%p, %zu) = %p\n", ptr, size, ret);
}

static void memstat_memalign(size_t alignment, size_t size, void *ret)
{
    debug("memalign(%zu, %zu) = %p\n", alignment, size, ret);
}

static void memstat_free(void *ptr)
{
    debug("free(%p)\n", ptr);
}

static struct mjack_trace memstat = {
    .malloc    = memstat_malloc,
    .calloc    = memstat_calloc,
    .realloc   = memstat_realloc,
    .memalign  = memstat_memalign,
    .free      = memstat_free
};

static bool memlimit_malloc(size_t size)
{
    (void) size;
    return false;
}

static bool memlimit_calloc(size_t nmemb, size_t size)
{
    (void) nmemb;
    (void) size;
    return false;
}

static bool memlimit_realloc(void *ptr, size_t size)
{
    (void) ptr;
    (void) size;
    return false;
}

static bool memlimit_memalign(size_t alignment, size_t size)
{
    (void) alignment;
    (void) size;
    return false;
}

static bool memlimit_free(void *ptr)
{
    (void) ptr;
    return false;
}

static struct mjack_filter memlimit = {
    .malloc    = memlimit_malloc,
    .calloc    = memlimit_calloc,
    .realloc   = memlimit_realloc,
    .memalign  = memlimit_memalign,
    .free      = memlimit_free
};

LIST_HEAD(filters);

void mjack_filter_add(struct mjack_filter *filter)
{
    list_add(&filter->list, &filters);
}

void mjack_filter_del(struct mjack_filter *filter)
{
    list_del(&filter->list);
}

LIST_HEAD(traces);

void mjack_trace_add(struct mjack_trace *trace)
{
    list_add(&trace->list, &traces);
}

void mjack_trace_del(struct mjack_trace *trace)
{
    list_del(&trace->list);
}

static void init()
{
    started        = true;
    libc.malloc    = dlsym(RTLD_NEXT, "malloc");
    libc.calloc    = dlsym(RTLD_NEXT, "calloc");
    libc.realloc   = dlsym(RTLD_NEXT, "realloc");
    libc.memalign  = dlsym(RTLD_NEXT, "memalign");
    libc.free      = dlsym(RTLD_NEXT, "free");

    if (!libc.malloc || !libc.realloc || !libc.free ||
        !libc.calloc || !libc.memalign )
        fail("%s: dyld error: %s\n", __FUNCTION__, dlerror());

    mjack_filter_add(&memlimit);
    mjack_trace_add(&memstat);
}

/* Eventually `dlsym` can call `malloc` so we need to have our own
 * allocator until we're done loading all symbols. A few bytes and
 * a couple of calls, that's hopefully what we have to handle so 
 * the allocator can be the simplest and smallest possible.
 */

static char mempool[MEMMAX];
static size_t mempos;

static void *alloc(size_t size)
{
    void *ptr = mempool + mempos;
    if (mempos + size >= MEMMAX)
        fail("%s: out of memory", __FUNCTION__);
    mempos += size;
    return ptr;
}

/* GNU Libc declares these functions as weak symbols so it's possible
 * to link against the code below directly. If the target Libc doesn't
 * provide such facility though make a shared library and use LD_PRELOAD.
 */

void *malloc(size_t size)
{
    struct list *entry;
    struct mjack_filter *filter;
    struct mjack_trace *trace;
    void *ret;

    if (!libc.malloc && started) return alloc(size);
    else if (!libc.malloc) init();

    list_for_each(entry, &filters) {
        filter = list_entry(entry, struct mjack_filter, list);
        if (filter->malloc && filter->malloc(size))
            return NULL;
    }
    ret = libc.malloc(size);
    list_for_each(entry, &traces) {
        trace = list_entry(entry, struct mjack_trace, list);
        if (trace->malloc) trace->malloc(size, ret);
    }
    return ret;
}

void *calloc(size_t nmemb, size_t size)
{
    struct list *entry;
    struct mjack_filter *filter;
    struct mjack_trace *trace;
    void *ret;

    if (!libc.malloc) init();

    list_for_each(entry, &filters) {
        filter = list_entry(entry, struct mjack_filter, list);
        if (filter->calloc && filter->calloc(nmemb, size))
            return NULL;
    }
    ret = libc.calloc(nmemb, size);
    list_for_each(entry, &traces) {
        trace = list_entry(entry, struct mjack_trace, list);
        if (trace->calloc) trace->calloc(nmemb, size, ret);
    }
    return ret;
}

void *realloc(void *ptr, size_t size)
{
    struct list *entry;
    struct mjack_filter *filter;
    struct mjack_trace *trace;
    void *ret;

    if (!libc.realloc) init();

    list_for_each(entry, &filters) {
        filter = list_entry(entry, struct mjack_filter, list);
        if (filter->realloc && filter->realloc(ptr, size))
            return NULL;
    }
    ret = libc.realloc(ptr, size);
    list_for_each(entry, &traces) {
        trace = list_entry(entry, struct mjack_trace, list);
        if (trace->realloc) trace->realloc(ptr, size, ret);
    }
    return ret;
}

void free(void *ptr)
{
    struct list *entry;
    struct mjack_filter *filter;
    struct mjack_trace *trace;

    if (!libc.free) fail("%s: called before malloc", __FUNCTION__);

    list_for_each(entry, &filters) {
        filter = list_entry(entry, struct mjack_filter, list);
        if (filter->free && filter->free(ptr))
            return;
    }
    libc.free(ptr);
    list_for_each(entry, &traces) {
        trace = list_entry(entry, struct mjack_trace, list);
        if (trace->free) trace->free(ptr);
    }
}

void *memalign(size_t alignment, size_t size)
{
    struct list *entry;
    struct mjack_filter *filter;
    struct mjack_trace *trace;
    void *ret;

    if (!libc.memalign) init();

    list_for_each(entry, &filters) {
        filter = list_entry(entry, struct mjack_filter, list);
        if (filter->memalign && filter->memalign(alignment, size))
            return NULL;
    }
    ret = libc.memalign(alignment, size);
    list_for_each(entry, &traces) {
        trace = list_entry(entry, struct mjack_trace, list);
        if (trace->memalign) trace->memalign(alignment, size, ret);
    }
    return ret;
}
