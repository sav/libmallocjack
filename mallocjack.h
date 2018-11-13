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

#ifndef LIBMALLOCJACK_H
#define LIBMALLOCJACK_H

#include <stdbool.h>
#include <list.h>

/**
 * Filters are executed before each native call. If true is returned
 * then the native call is not called and the hook returns error if
 * not void.
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
 * Traces are executed after the native call. The value returned by
 * the native call, if any, is passed as last argument. It returns
 * zero on success, anything else otherwise.
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
