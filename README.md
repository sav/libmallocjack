Libmallocjack
=============

This is a work in progress, it was barely tested only on glibc-2.27 and
still lacks thread-safeness.

Compilation
-----------

To compile the library run `make`. To run the tests `make run`. Remember to
compile the code you want to debug with `-rdynamic` and `-funwind-tables`,
besides naturally your basic debugging options. When not compiled with the
last two compilation flags though you won't get string symbols for functions.

Built-in modules
----------------

### memstat
Print overall process and function statistics.

### memlimit
Limit memory usage by process and function.

