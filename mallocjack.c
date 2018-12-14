/**
 * Copyright (c) 2018, Savio Machado <sav@loophole.cc>
 * This file is part of Libmallocjack
 *
 * Libmallocjack is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Libmallocjack is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Libmallocjack. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
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

#include <mallocjack.h>

#define LOCALMEMSIZE    4096
#define DFTLDLOPENMODE  (RTLD_LAZY)
#define DFTLSKIP        7

#define CALLMAX         32
#define CALLSTRPART     64
#define CALLSTRMAX      ((CALLSTRPART + 1) * CALLMAX)

#define safe(type, ...) ({  \
   type ret;                \
   ++unhook;                \
   ret = __VA_ARGS__;       \
   --unhook;                \
   ret;                     \
})

#define psafe(sout, fmt, ...) do {                    \
   (void) safe(int, fprintf(sout, fmt, __VA_ARGS__)); \
   (void) safe(int, fflush(sout));                    \
} while(0)

#define pout(fmt, ...)  psafe(stdout, fmt, __VA_ARGS__)
#define perr(fmt, ...)  psafe(stderr, fmt, __VA_ARGS__)

#ifdef DEBUG
#define msg(fmt, ...)   pout("%s: " fmt "\n", __FUNCTION__, __VA_ARGS__)
#else
#define msg(fmt, ...)   pout(fmt "\n", __VA_ARGS__)
#endif

#define wrn(fmt, ...) do {                                    \
   perr("warning! %s: " fmt "\n", __FUNCTION__, __VA_ARGS__); \
} while(0)

#define err(fmt, ...) do {                                    \
   perr("error! %s: " fmt "\n", __FUNCTION__, __VA_ARGS__);   \
} while(0)

#define die(fmt, ...) do {                                    \
   perr("fatal! %s: " fmt "\n", __FUNCTION__, __VA_ARGS__);   \
   exit(1);                                                   \
} while(0)

#ifdef DEBUG
#define dbg(fmt, ...) do {                                    \
   perr("debug: %s: " fmt "\n", __FUNCTION__, __VA_ARGS__);   \
} while(0)

#define logf(fmt, ...) do {                                   \
   perr("called: %s(" fmt ")\n", __FUNCTION__, __VA_ARGS__);  \
} while(0)
#else
#define dbg(...) {}

#define logf(...) {}
#endif

#define reterr(v, ...) ({ \
   err(__VA_ARGS__);      \
   v;                     \
})

#define errvoid(...) do { \
   err(__VA_ARGS__);      \
   return;                \
} while(0)

#define errnull(...)       reterr(NULL, __VA_ARGS__)

#define alignsz(al, sz)    ((sz + al - 1) & ~(al - 1))

static struct {
   void *(*malloc)(size_t);
   void *(*calloc)(size_t, size_t);
   void *(*realloc)(void *, size_t);
   void *(*memalign)(size_t, size_t);
   void (*free)(void *);
} libc;

static int unhook;

struct mstat_call;

struct mstat_alloc {
   const void *ptr;
   ssize_t size;
   struct mstat_alloc *was;
   struct mstat_call *calls;
   UT_hash_handle hh;
};

struct mstat_call {
   const char *key;
   size_t count;
   struct mstat_alloc *allocs;
   UT_hash_handle hh;
};

struct mstat_ctx {
   size_t total;
   size_t using;
   struct mstat_alloc *allocs;
   struct mstat_call *calls;
} ctx;

#define mstat_count(sz) do {      \
   dbg("mstat_count(%zi)", (sz)); \
   if ((sz) > 0)                  \
      ctx.total += (sz);          \
   ctx.using += (sz);             \
} while(0)

static char *mstat_call_str(void *const st[], size_t n)
{
   char b[CALLSTRMAX], *p, **ss;
   size_t i, len, pos = 0;

   ss = safe(char **, backtrace_symbols(st, n));
   for (i = 0; i < n; ++i) {
      p = strchr(ss[i], '+');
      if (!p)
         p = strchr(ss[i], ')');
      if (!p)
         return errnull("parsing \"%s\"", ss[i]);
      len = (size_t) (p - ss[i]);
      memcpy(b + pos, ss[i], len);
      b[pos + len] = ')';
      b[pos + len + 1] = '\n';
      pos += len + 2;
   }
   b[pos - 1] = '\0';
   libc.free(ss);
   return safe(char *, strdup(b));
}

static char *mstat_call_key(size_t d)
{
    void *st[CALLMAX];
    size_t n = safe(size_t, backtrace(st, CALLMAX - d)) - d;
    return mstat_call_str(&st[d], n);
}

#define mstat_alloc_find(p) ({           \
   struct mstat_alloc *ret;              \
   HASH_FIND_PTR(ctx.allocs, &(p), ret); \
   ret;                                  \
})

struct mstat_alloc *mstat_alloc_add(const void *r, size_t sz, const void *p)
{
   struct mstat_alloc *a = mstat_alloc_find(r);
   struct mstat_alloc *o = p ? mstat_alloc_find(p) : NULL;
   logf("%p -> %p, %zd, %p -> %p", r, a, sz, p, o);

   if (a) {
      if (a->size) {
         if (sz == 0)
            mstat_count(-a->size);
         else
            mstat_count(sz - a->size);
         a->size = sz;
      } else if (sz) {
         wrn("reusing history of %p", r);
         mstat_count(sz);
         a->size = sz;
      }
   } else if(sz) {
      mstat_count(sz - (o ? o->size : 0));
      a = libc.calloc(1, sizeof(*a));
      if (!a)
         return errnull("libc.calloc: %s", strerror(errno));
      a->ptr = r;
      a->size = sz;
      HASH_ADD_PTR(ctx.allocs, ptr, a);
   }
   if (o && o->ptr != r) {
      a->was = o;
      o->size = 0;
   }
   return a;
}

static struct mstat_call *mstat_call_add(size_t d)
{
   struct mstat_call *c;
   const char *k;

   k = mstat_call_key(d + 1);
   if (!k)
      die("parsing backtrace[%zd]: unkown format", d);

   HASH_FIND_STR(ctx.calls, k, c);
   if (!c) {
      c = libc.calloc(1, sizeof(*c));
      if (!c)
         return errnull("libc.calloc: %s", strerror(errno));
      c->key = k;
      HASH_ADD_STR(ctx.calls, key, c);
   }
   c->count++;
   dbg("called %zd times by:\n%s", c->count, k);
   return c;
}

#define mstat_alloc_call(a, c) do { \
   HASH_ADD_STR(a->calls, key, c);  \
} while(0)

#define mstat_call_alloc(c, a) do { \
   HASH_ADD_PTR(c->allocs, ptr, a); \
} while(0)

static void mstat_add(const void *r, ssize_t sz, const void *p)
{
   struct mstat_alloc *a;
   struct mstat_call *c;

   a = mstat_alloc_add(r, sz, p);
   if (!a)
      return;

   c = mstat_call_add(DFTLSKIP);
   if (!c)
      return;

   // XXX continue from here
   // mstat_call_alloc(c, a);
   // mstat_alloc_call(a, c);
}

static void mstat_malloc(size_t sz, void *r)
{
   logf("%zd, %p", sz, r);
   if (!r)
      err("libc.malloc(%zd) failed", sz);
   else
      mstat_add(r, sz, NULL);
}

static void mstat_calloc(size_t n, size_t sz, void *r)
{
   logf("%zd, %p", sz, r);
   if (!r)
      err("libc.calloc(%zd) failed", n * sz);
   else
      mstat_add(r, n * sz, NULL);
}

static void mstat_realloc(void *p, size_t sz, void *r)
{
   logf("%p, %zd, %p", p, sz, r);
   if (!r)
      err("libc.realloc(%p, %zd) failed", p, sz);
   else
      mstat_alloc_add(r, sz, p);
}

static void mstat_memalign(size_t al, size_t sz, void *r)
{
   logf("%zd, %zd, %p", al, sz, r);
   if (!r)
      err("memalign(%zd) failed", alignsz(al, sz));
   else
      mstat_add(r, alignsz(al, sz), NULL);
}

static void mstat_free(void *p)
{
   logf("%p", p);
   if (p)
      mstat_add(p, 0, NULL);
}

static struct mjtrace mstat = {
   .malloc    = mstat_malloc,
   .calloc    = mstat_calloc,
   .realloc   = mstat_realloc,
   .memalign  = mstat_memalign,
   .free      = mstat_free
};

static bool mlimit_malloc(size_t sz)
{
   (void) sz;
   return false;
}

static bool mlimit_calloc(size_t n, size_t sz)
{
   (void) n;
   (void) sz;
   return false;
}

static bool mlimit_realloc(void *p, size_t sz)
{
   (void) p;
   (void) sz;
   return false;
}

static bool mlimit_memalign(size_t al, size_t sz)
{
   (void) al;
   (void) sz;
   return false;
}

static bool mlimit_free(void *p)
{
   (void) p;
   return false;
}

static struct mjfilter mlimit = {
   .malloc    = mlimit_malloc,
   .calloc    = mlimit_calloc,
   .realloc   = mlimit_realloc,
   .memalign  = mlimit_memalign,
   .free      = mlimit_free
};

LIST_HEAD(filters);
LIST_HEAD(traces);

void mjfilter_add(struct mjfilter *f)
{
   list_add(&f->list, &filters);
}

void mjfilter_del(struct mjfilter *f)
{
   list_del(&f->list);
}

void mjtrace_add(struct mjtrace *t)
{
   list_add(&t->list, &traces);
}

void mjtrace_del(struct mjtrace *t)
{
   list_del(&t->list);
}

void mstat_atexit(void)
{
   msg("allocated %zd bytes, freed %zd bytes. still reachable: %zd bytes",
         ctx.total, ctx.total - ctx.using, ctx.using);
}

static void init()
{
   char *lib;
   void *h;

   if (unhook)
      return;

   ++unhook;
   lib            = getenv("MJ_PRELOAD");
   h              = lib ? dlopen(lib, DFTLDLOPENMODE) : RTLD_NEXT;
   if (!h)
      die("dlopen(\"%s\"): %s", lib, dlerror());
   libc.malloc    = dlsym(h, "malloc");
   libc.calloc    = dlsym(h, "calloc");
   libc.realloc   = dlsym(h, "realloc");
   libc.memalign  = dlsym(h, "memalign");
   libc.free      = dlsym(h, "free");
   --unhook;

   if (!libc.malloc || !libc.realloc || !libc.free ||
       !libc.calloc || !libc.memalign)
      die("dlsym(): %s", dlerror());

   assert(libc.malloc != malloc     &&
          libc.realloc != realloc   &&
          libc.calloc != calloc     &&
          libc.memalign != memalign &&
          libc.free != free);

   mjfilter_add(&mlimit);
   mjtrace_add(&mstat);

   if (atexit(mstat_atexit))
       err("atexit(%p) failed", mstat_atexit);

   if (lib && dlclose(h))
      err("dlclose(\"%s\"): %s", lib, dlerror());
}

#define CALL_FILTERS(func, ...) {                          \
   struct list *entry;                                     \
   struct mjfilter *filter;                                \
   list_for_each(entry, &filters) {                        \
       filter = list_entry(entry, struct mjfilter, list);  \
       if (filter->func && filter->func(__VA_ARGS__))      \
           return NULL;                                    \
   }                                                       \
}

#define CALL_TRACES(func, ...) {                           \
   struct list *entry;                                     \
   struct mjtrace *trace;                                  \
   list_for_each(entry, &traces) {                         \
       trace = list_entry(entry, struct mjtrace, list);    \
       if (trace->func) trace->func(__VA_ARGS__);          \
   }                                                       \
}

#define FREE_FILTER(func, ...) {                           \
   struct list *entry;                                     \
   struct mjfilter *filter;                                \
   list_for_each(entry, &filters) {                        \
       filter = list_entry(entry, struct mjfilter, list);  \
       if (filter->func && filter->func(__VA_ARGS__))      \
           return;                                         \
   }                                                       \
}

#define FREE_TRACE(func, ...) {                            \
   struct list *entry;                                     \
   struct mjtrace *trace;                                  \
   list_for_each(entry, &traces) {                         \
       trace = list_entry(entry, struct mjtrace, list);    \
       if (trace->func) trace->func(__VA_ARGS__);          \
   }                                                       \
}

struct memloc {
   char buf[LOCALMEMSIZE];
   int pos;
} mem;

static void *local_alloc(size_t sz)
{
   void *p;

   if (mem.pos + sz > LOCALMEMSIZE)
      return errnull("have %d bytes, need %zd",
         LOCALMEMSIZE - mem.pos, sz);

   p = mem.buf + mem.pos;
   mem.pos += sz;
   return p;
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

   CALL_FILTERS(realloc, ptr, size);
   ret = libc.realloc(ptr, size);
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
         : local_alloc(alignsz(align, size));

   CALL_FILTERS(memalign, align, size);
   ret = libc.memalign(align, size);
   CALL_TRACES(memalign, align, size, ret);
   return ret;
}

