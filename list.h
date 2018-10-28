/**
 * Linux's double linked list ripped and slightly changed to fit in user space.
 * Original code: https://elixir.bootlin.com/linux/latest/source/include/linux/list.h
 */

#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <stddef.h> /* offsetof */

struct list {
    struct list *next, *prev;
};

#define LIST_HEAD_INIT(name) {&(name), &(name)}

#define LIST_HEAD(name) struct list name = LIST_HEAD_INIT(name)

#define container_of(ptr, type, member) ({       \
    void *__mptr = (void *)(ptr);                \
    ((type *)(__mptr - offsetof(type, member))); \
})

static inline void INIT_LIST_HEAD(struct list *list)
{
    list->next = list;
    list->prev = list;
}

static inline void list_add_between(struct list *new, struct list *first,
    struct list *second)
{
    second->prev = new;
    new->next = second;
    new->prev = first;
    first->next = new;
}

static inline void list_add(struct list *new, struct list *head)
{
    list_add_between(new, head, head->next);
}

static inline void list_add_tail(struct list *new, struct list *head)
{
    list_add_between(new, head->prev, head);
}

static inline void list_del_unlink(struct list *prev, struct list *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del_entry(struct list *entry)
{
    list_del_unlink(entry->prev, entry->next);
}

static inline void list_del(struct list *entry)
{
    list_del_unlink(entry->prev, entry->next);
    entry->prev = entry->next = NULL;
}

static inline void list_replace(struct list *old, struct list *new)
{
    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;
}

static inline void list_replace_init(struct list *old, struct list *new)
{
    list_replace(old, new);
    INIT_LIST_HEAD(old);
}

static inline void list_del_init(struct list *entry)
{
    list_del_entry(entry);
    INIT_LIST_HEAD(entry);
}

static inline void list_move(struct list *list, struct list *head)
{
    list_del_entry(list);
    list_add(list, head);
}

static inline void list_move_tail(struct list *list, struct list *head)
{
    list_del_entry(list);
    list_add_tail(list, head);
}

static inline int list_is_last(const struct list *list,
    const struct list *head)
{
    return list->next == head;
}

static inline int list_empty(const struct list *head)
{
    struct list *next = head->next;
    return next == head && next == head->prev;
}

static inline void list_rotate_left(struct list *head)
{
    struct list *first;
    if (!list_empty(head)) {
        first = head->next;
        list_move_tail(first, head);
    }
}

static inline int list_is_singular(const struct list *head)
{
    return !list_empty(head) && head->next == head->prev;
}

static inline void list_splice_unsafe(const struct list *list,
    struct list *prev, struct list *next)
{
    struct list *first = list->next;
    struct list *last = list->prev;
    first->prev = prev;
    prev->next = first;
    last->next = next;
    next->prev = last;
}

static inline void list_splice(const struct list *list, struct list *head)
{
    if (!list_empty(list))
        list_splice_unsafe(list, head, head->next);
}

static inline void list_splice_tail(struct list *list, struct list *head)
{
    if (!list_empty(list))
        list_splice_unsafe(list, head->prev, head);
}

static inline void list_splice_init(struct list *list, struct list *head)
{
    if (!list_empty(list)) {
        list_splice_unsafe(list, head, head->next);
        INIT_LIST_HEAD(list);
    }
}

static inline void list_splice_tail_init(struct list *list, struct list *head)
{
    if (!list_empty(list)) {
        list_splice_unsafe(list, head->prev, head);
        INIT_LIST_HEAD(list);
    }
}

#define list_entry(ptr, type, member)                            \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member)                      \
    list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member)                       \
    list_entry((ptr)->prev, type, member)

#define list_first_entry_or_null(ptr, type, member) ({           \
    struct list_head *head__ = (ptr);                            \
    struct list_head *pos__ = head__->next;                      \
    pos__ != head__ ? list_entry(pos__, type, member) : NULL;    \
})

#define list_next_entry(pos, member)                             \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member)                             \
    list_entry((pos)->member.prev, typeof(*(pos)), member)

#define list_for_each(pos, head)                                 \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_prev(pos, head)                            \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define list_for_each_safe(pos, n, head)                         \
    for (pos = (head)->next, n = pos->next; pos != (head);       \
         pos = n, n = pos->next)

#define list_for_each_prev_safe(pos, n, head)                    \
    for (pos = (head)->prev, n = pos->prev;                      \
         pos != (head); pos = n, n = pos->prev)

#define list_for_each_entry(pos, head, member)                   \
    for (pos = list_first_entry(head, typeof(*pos), member);     \
        &pos->member != (head);                                  \
        pos = list_next_entry(pos, member))

#define list_for_each_entry_reverse(pos, head, member)           \
    for (pos = list_last_entry(head, typeof(*pos), member);      \
         &pos->member != (head);                                 \
        pos = list_prev_entry(pos, member))

#define list_prepare_entry(pos, head, member)                    \
    ((pos) ? : list_entry(head, typeof(*pos), member))

#define list_for_each_entry_continue(pos, head, member)          \
    for (pos = list_next_entry(pos, member);                     \
         &pos->member != (head);                                 \
         pos = list_next_entry(pos, member))

#define list_for_each_entry_continue_reverse(pos, head, member)  \
    for (pos = list_prev_entry(pos, member);                     \
         &pos->member != (head);                                 \
         pos = list_prev_entry(pos, member))

#define list_for_each_entry_from(pos, head, member)              \
    for (; &pos->member != (head);                               \
         pos = list_next_entry(pos, member))

#define list_for_each_entry_from_reverse(pos, head, member)      \
    for (; &pos->member != (head);                               \
         pos = list_prev_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)           \
    for (pos = list_first_entry(head, typeof(*pos), member),     \
         n = list_next_entry(pos, member);                       \
         &pos->member != (head);                                 \
         pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_continue(pos, n, head, member)  \
    for (pos = list_next_entry(pos, member),                     \
        n = list_next_entry(pos, member);                        \
         &pos->member != (head);                                 \
         pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_from(pos, n, head, member)      \
    for (n = list_next_entry(pos, member);                       \
         &pos->member != (head);                                 \
         pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_reverse(pos, n, head, member)   \
    for (pos = list_last_entry(head, typeof(*pos), member),      \
         n = list_prev_entry(pos, member);                       \
         &pos->member != (head);                                 \
         pos = n, n = list_prev_entry(n, member))

#define list_safe_reset_next(pos, n, member)                     \
    n = list_next_entry(pos, member)

#endif /* LIST_H */
