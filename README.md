Libmallocjack
=============

This is a work in progress, it was barely tested only on glibc-2.27 and
still lacks thread-safeness.

Built-in modules
----------------

### memstat
Print overall process and function statistics. Define
MALLOCJACK_MEMSTAT_DISABLED to disable this module.

### memlimit
Limit memory usage by process and function. Define
MALLOCJACK_MEMLIMIT_DISABLED to disable this module.

