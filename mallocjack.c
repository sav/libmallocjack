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
#ifndef __APPLE__
#include <malloc.h>
#endif

#include <dlfcn.h>
#include <execinfo.h>

#define uthash_malloc(size)     libc.malloc(size)
#define uthash_free(ptr, size)  libc.free(ptr)
#include <uthash.h>

#include <mallocjack.h>

#define BTMAX       32 /* at least 4 */
#define BTKEYPART   64
#define BTKEYMAX    ((BTKEYPART + 1) * BTMAX)

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

struct hooks {
    void *(*malloc)(size_t);
    void *(*calloc)(size_t, size_t);
    void *(*realloc)(void *, size_t);
    void *(*memalign)(size_t, size_t);
    void (*free)(void *);
} libc;

static int unhook;

struct memstat_ctx {
    size_t total;
    size_t freed;
} stat;

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

void memstat_atexit(void)
{
    struct callinfo *ptr, *tmp;
    HASH_ITER(hh, callers, ptr, tmp) {
        HASH_DEL(callers, ptr);
        debug("[+] caller allocated %zu bytes, freed %zu bytes:\n%s\n",
              ptr->size, ptr->freed, ptr->caller);
        libc.free(ptr->caller);
        libc.free(ptr);
    }
    debug("[=] allocated %zu bytes, reed %zu bytes, leaked %zu bytes\n",
          stat.total, stat.freed , stat.total - stat.freed);
}

static char *callinfo_skey(size_t skip)
{
    void *stack[BTMAX];
    size_t i, n, pos, depth;
    char *ptr, **syms, buf[BTKEYMAX], *ret;

    ++unhook;
    depth = backtrace(stack, BTMAX);
    syms = backtrace_symbols(stack, depth);
    --unhook;

    for (i = 1 + skip, pos = 0; i < depth; i++) {
        ptr = strchr(syms[i], '+');
        if (!ptr) ptr = strchr(syms[i], ')');
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
    if (!ret) {
        err("%s: malloc failed\n", __FUNCTION__);
        return;
    }
    info = meminfo_new(ret, size);
    HASH_ADD_PTR(chunks, ptr, info);
    stat.total += size;
    callinfo_add(size);
}

static void memstat_calloc(size_t nmemb, size_t size, void *ret)
{
    struct meminfo *info;
    if (!ret) {
        err("%s: calloc failed\n", __FUNCTION__);
        return;
    }
    info = meminfo_new(ret, nmemb * size);
    HASH_ADD_PTR(chunks, ptr, info);
    stat.total += nmemb * size;
    callinfo_add(nmemb * size);
}

static void memstat_realloc(void *ptr, size_t size, void *ret)
{
    struct meminfo *info;
    if (!ret) {
        err("%s: calloc failed\n", __FUNCTION__);
        return;
    }
    HASH_FIND_PTR(chunks, &ptr, info);
    stat.total -= info->size - size;
    callinfo_add(size - info->size);
    HASH_DEL(chunks, info);
    libc.free(info);
    info = meminfo_new(ret, size);
    HASH_ADD_PTR(chunks, ptr, info);
}

static void memstat_memalign(size_t align, size_t size, void *ret)
{
    struct meminfo *info;
    if (!ret) {
        err("%s: memalign failed\n", __FUNCTION__);
        return; 
    }
    info = meminfo_new(ret, size);
    HASH_ADD_PTR(chunks, ptr, info);
    stat.total += size + (align - size % align) % align;
    callinfo_add(size + (align - size % align) % align);
}

static void memstat_free(void *ptr)
{
    struct meminfo *info;
    HASH_FIND_PTR(chunks, &ptr, info);
    stat.freed += info->size;
    callinfo_add(-info->size);
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
    unhook++;
    libc.malloc    = dlsym(RTLD_NEXT, "malloc");
    libc.calloc    = dlsym(RTLD_NEXT, "calloc");
    libc.realloc   = dlsym(RTLD_NEXT, "realloc");
    libc.memalign  = dlsym(RTLD_NEXT, "memalign");
    libc.free      = dlsym(RTLD_NEXT, "free");
    unhook--;
    
    if (!libc.malloc || !libc.realloc || !libc.free ||
        !libc.calloc || !libc.memalign )
        fail("%s: dyld error: %s\n", __FUNCTION__, dlerror());
    
    atexit(memstat_atexit);
    mjfilter_add(&memlimit);
    mjtrace_add(&memstat);
}

#define HOOK_CHECK(func, ...) {                                \
    if (!libc.func) init();                                    \
    if (unhook) return libc.func(__VA_ARGS__);                 \
}

#define ALLOC_FILTER(func, ...) {                              \
    struct list *entry;                                        \
    struct mjfilter *filter;                                   \
    list_for_each(entry, &filters) {                           \
        filter = list_entry(entry, struct mjfilter, list);     \
        if (filter->func && filter->func(__VA_ARGS__))         \
            return NULL;                                       \
    }                                                          \
}

#define ALLOC_TRACE(func, ...) {                               \
    struct list *entry;                                        \
    struct mjtrace *trace;                                     \
    list_for_each(entry, &traces) {                            \
        trace = list_entry(entry, struct mjtrace, list);       \
        if (trace->func) trace->func(__VA_ARGS__, ret);        \
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

void *malloc(size_t size)
{
    void *ret;

    if (!libc.malloc) init();
    if (unhook) return libc.malloc(size);

    ALLOC_FILTER(malloc, size);
    ret = libc.malloc(size);
    ALLOC_TRACE(malloc, size);
    return ret;
}

void *calloc(size_t nmemb, size_t size)
{
    void *ret;

    if (!libc.calloc) init();
    if (unhook) return libc.calloc(nmemb, size);

    ALLOC_FILTER(calloc, nmemb, size);
    ret = libc.calloc(nmemb, size);
    ALLOC_TRACE(calloc, nmemb, size);
    return ret;
}

void *realloc(void *ptr, size_t size)
{
    void *ret;

    if (!libc.realloc) init();
    if (unhook) return libc.realloc(ptr, size);

    ALLOC_FILTER(realloc, ptr, size);
    ret = libc.realloc(ptr, size);
    ALLOC_TRACE(realloc, ptr, size);
    return ret;
}

void free(void *ptr)
{
    if (!libc.free) init();
    if (unhook) return libc.free(ptr);

    FREE_FILTER(free, ptr);
    libc.free(ptr);
    FREE_TRACE(free, ptr);
}

void *memalign(size_t align, size_t size)
{
    void *ret;

    if (!libc.memalign) init();
    if (unhook) libc.memalign(align, size);

    ALLOC_FILTER(memalign, align, size);
    ret = libc.memalign(align, size);
    ALLOC_TRACE(memalign, align, size);
    return ret;
}
