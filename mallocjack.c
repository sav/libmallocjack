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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include <unistd.h>
#include <dlfcn.h>
#include <execinfo.h>

#ifndef __APPLE__
#include <malloc.h>
#endif

#define uthash_malloc(size)     libc.malloc(size)
#define uthash_free(ptr, size)  libc.free(ptr)

#include <uthash.h>
#include <list.h>
#include <mallocjack.h>

#define LOCALMEMSIZE    1024

#define BTMAX           32
#define BTKEYPART       64
#define BTKEYMAX        ((BTKEYPART + 1) * BTMAX)

#define debug(...) do {                 \
    unhook++;                           \
    fprintf(stderr, __VA_ARGS__);       \
    unhook--;                           \
} while(0)

#define err(fmt, ...) do {              \
    debug("error! " fmt, __VA_ARGS__);  \
} while(0)

#define fail(fmt, ...) do {             \
    err(fmt, __VA_ARGS__);              \
    exit(1);                            \
} while(0)

#define alignedsize(alignment, size)    \
    ((size + alignment - 1) & ~(alignment - 1))

static int unhook;

struct memstat_ctx {
    size_t total;
    size_t freed;
} stats;

struct meminfo {
    void *ptr;
    size_t size;
    UT_hash_handle hh;
};

struct meminfo *chunks;

struct callinfo {
    char *caller;
    size_t size;
    size_t freed;
    UT_hash_handle hh;
};

struct callinfo *callers;

struct hooks {
    void *(*malloc)(size_t);
    void *(*calloc)(size_t, size_t);
    void *(*realloc)(void *, size_t);
    void *(*memalign)(size_t, size_t);
    void (*free)(void *);
} libc;

static int callrcmpsize(struct callinfo *c1, struct callinfo *c2)
{
    return c2->size - c1->size;
}

void memstat_atexit(void)
{
    struct callinfo *ptr, *tmp;
    HASH_SORT(callers, callrcmpsize);
    HASH_ITER(hh, callers, ptr, tmp) {
        HASH_DEL(callers, ptr);
        debug("[+] caller allocated %zu bytes, freed %zu bytes:\n%s\n",
              ptr->size, ptr->freed, ptr->caller);
        libc.free(ptr->caller);
        libc.free(ptr);
    }
    debug("[=] allocated %zu bytes, freed %zu bytes. "
          "still reachable: %zu bytes\n", stats.total, stats.freed ,
          stats.total - stats.freed);
}

static char *callinfo_skey(size_t skip)
{
    void *stack[BTMAX];
    char buf[BTKEYMAX], **syms, *ptr, *ret;
    size_t i, n, pos, depth;

    ++unhook;
    depth = backtrace(stack, BTMAX);
    syms = backtrace_symbols(stack, depth);
    --unhook;

    for (i = 1 + skip, pos = 0; i < depth; i++) {
        ptr = strchr(syms[i], '+');
        if (!ptr)
            ptr = strchr(syms[i], ')');
        n = (size_t)(ptr - syms[i]);
        memcpy(buf + pos, syms[i], n);
        buf[pos + n] = ')';
        buf[pos + n + 1] = '\n';
        pos += n + 2;
    }
    buf[pos - 1] = '\0';
    libc.free(syms);
    ++unhook;
    ret = strdup(buf);
    --unhook;
    return ret;
}

static void callinfo_add(ssize_t size)
{
    struct callinfo *info;
    char *caller = callinfo_skey(3); /* this, previous and libc */
    HASH_FIND_STR(callers, caller, info);
    if (info) {
        libc.free(caller);
        info->size += size > 0 ? size : 0;
        info->freed += size < 0 ? -size : 0;
    } else {
        info = libc.malloc(sizeof(struct callinfo));
        info->caller = caller;
        info->size = size > 0 ? size : 0;
        info->freed = size < 0 ? -size : 0;
        HASH_ADD_STR(callers, caller, info);
    }    
}

static struct meminfo* meminfo_new(void *ptr, size_t size)
{
    struct meminfo *info = libc.malloc(sizeof(struct meminfo));
    if (info) {
        info->ptr = ptr;
        info->size = size;
    }
    return info;
}

static void memstat_malloc(size_t size, void *ret)
{
    struct meminfo *info;
    if (!ret)
        return;
    callinfo_add(size);
    stats.total += size;
    info = meminfo_new(ret, size);
    HASH_ADD_PTR(chunks, ptr, info);
}

static void memstat_calloc(size_t nmemb, size_t size, void *ret)
{
    struct meminfo *info;
    if (!ret)
        return;
    callinfo_add(nmemb * size);
    stats.total += nmemb * size;
    info = meminfo_new(ret, nmemb * size);
    HASH_ADD_PTR(chunks, ptr, info);
}

static void memstat_realloc(void *ptr, size_t size, void *ret)
{
    struct meminfo *info, *rep, *tmp;
    if (!ret)
        return;
    HASH_FIND_PTR(chunks, &ptr, info);
    if (!info) {
        callinfo_add(size);
        stats.total += size;
        info = meminfo_new(ret, size);
        HASH_ADD_PTR(chunks, ptr, info);
    } else {
        callinfo_add(size - info->size);
        stats.total -= info->size - size;
        rep = meminfo_new(ret, size);
        HASH_REPLACE_PTR(chunks, ptr, rep, tmp);
        libc.free(tmp);
    }
}

static void memstat_memalign(size_t align, size_t size, void *ret)
{
    struct meminfo *info;
    if (!ret)
        return;
    size = alignedsize(align, size);
    callinfo_add(size);
    stats.total += size;
    info = meminfo_new(ret, size);
    HASH_ADD_PTR(chunks, ptr, info);
}

static void memstat_free(void *ptr)
{
    struct meminfo *info;
    if (!ptr)
        return;
    HASH_FIND_PTR(chunks, &ptr, info);
    callinfo_add(-info->size);
    stats.freed += info->size;
    HASH_DEL(chunks, info);
    libc.free(info);
}

static struct mjtrace memstat = {
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

static bool memlimit_memalign(size_t align, size_t size)
{
    (void) align;
    (void) size;
    return false;
}

static bool memlimit_free(void *ptr)
{
    (void) ptr;
    return false;
}

static struct mjfilter memlimit = {
    .malloc    = memlimit_malloc,
    .calloc    = memlimit_calloc,
    .realloc   = memlimit_realloc,
    .memalign  = memlimit_memalign,
    .free      = memlimit_free
};

LIST_HEAD(filters);

void mjfilter_add(struct mjfilter *filter)
{
    list_add(&filter->list, &filters);
}

void mjfilter_del(struct mjfilter *filter)
{
    list_del(&filter->list);
}

LIST_HEAD(traces);

void mjtrace_add(struct mjtrace *trace)
{
    list_add(&trace->list, &traces);
}

void mjtrace_del(struct mjtrace *trace)
{
    list_del(&trace->list);
}

static void init()
{
    char *libpath;
    void *handle;
    if (unhook)
        return;

    unhook++;
    libpath        = getenv("MJ_PRELOAD");
    handle         = libpath ? dlopen(libpath, RTLD_LAZY) : RTLD_NEXT;
    libc.malloc    = dlsym(handle, "malloc");
    libc.calloc    = dlsym(handle, "calloc");
    libc.realloc   = dlsym(handle, "realloc");
    libc.memalign  = dlsym(handle, "memalign");
    libc.free      = dlsym(handle, "free");
    unhook--;

    if (!libc.malloc || !libc.realloc || !libc.free ||
        !libc.calloc || !libc.memalign )
        fail("%s: dyld error: %s\n", __FUNCTION__, dlerror());

    mjfilter_add(&memlimit);
    mjtrace_add(&memstat);
    atexit(memstat_atexit);
}

#define CALL_FILTERS(func, ...) {                              \
    struct list *entry;                                        \
    struct mjfilter *filter;                                   \
    list_for_each(entry, &filters) {                           \
        filter = list_entry(entry, struct mjfilter, list);     \
        if (filter->func && filter->func(__VA_ARGS__))         \
            return NULL;                                       \
    }                                                          \
}

#define CALL_TRACES(func, ...) {                               \
    struct list *entry;                                        \
    struct mjtrace *trace;                                     \
    list_for_each(entry, &traces) {                            \
        trace = list_entry(entry, struct mjtrace, list);       \
        if (trace->func) trace->func(__VA_ARGS__);             \
    }                                                          \
}

#define FREE_FILTER(func, ...) {                               \
    struct list *entry;                                        \
    struct mjfilter *filter;                                   \
    list_for_each(entry, &filters) {                           \
        filter = list_entry(entry, struct mjfilter, list);     \
        if (filter->func && filter->func(__VA_ARGS__))         \
            return;                                            \
    }                                                          \
}

#define FREE_TRACE(func, ...) {                                \
    struct list *entry;                                        \
    struct mjtrace *trace;                                     \
    list_for_each(entry, &traces) {                            \
        trace = list_entry(entry, struct mjtrace, list);       \
        if (trace->func) trace->func(__VA_ARGS__);             \
    }                                                          \
}

struct memloc {
    char buf[LOCALMEMSIZE];
    int pos;
} mem;

static void *local_alloc(size_t size)
{
    void *ptr = mem.buf + mem.pos;
    assert(mem.pos + size < LOCALMEMSIZE);
    mem.pos += size;
    return ptr;
}

void *malloc(size_t size)
{
    void *ret;
    if (!libc.malloc)
        init();
    if (unhook)
        return libc.malloc ? libc.malloc(size)
            : local_alloc(size);

    CALL_FILTERS(malloc, size);
    ret = libc.malloc(size);
    CALL_TRACES(malloc, size, ret);
    return ret;
}

void *calloc(size_t nmemb, size_t size)
{
    void *ret;
    if (!libc.calloc)
        init();
    if (unhook)
        return libc.calloc ? libc.calloc(nmemb, size)
            : local_alloc(size);

    CALL_FILTERS(calloc, nmemb, size);
    ret = libc.calloc(nmemb, size);
    CALL_TRACES(calloc, nmemb, size, ret);
    return ret;
}

void *realloc(void *ptr, size_t size)
{
    void *ret = NULL;
    if (!libc.realloc)
        init();
    if (unhook)
        return libc.realloc ? libc.realloc(ptr, size)
            : local_alloc(size);

    if (!ptr) {
        ptr = libc.malloc(size);
        ret = ptr;
    }
    CALL_FILTERS(realloc, ptr, size);
    if (!ret) ret = libc.realloc(ptr, size);
    CALL_TRACES(realloc, ptr, size, ret);
    return ret;
}

void free(void *ptr)
{
    if (!libc.free)
        init();
    if (unhook && libc.free)
        libc.free(ptr);
    else if (unhook)
        return;

    FREE_FILTER(free, ptr);
    libc.free(ptr);
    FREE_TRACE(free, ptr);
}

void *memalign(size_t align, size_t size)
{
    void *ret;
    if (!libc.memalign)
        init();
    if (unhook)
        return libc.memalign ? libc.memalign(align, size)
            : local_alloc(alignedsize(align, size));

    CALL_FILTERS(memalign, align, size);
    ret = libc.memalign(align, size);
    CALL_TRACES(memalign, align, size, ret);
    return ret;
}
