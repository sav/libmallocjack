LIBNAME := mallocjack

CC := clang -std=gnu99

CFLAGS += -ggdb -O0 -DDEBUG -D_GNU_SOURCE -I. -ldl -rdynamic \
		  -Wall -Werror -Wextra -funwind-tables

SRC := $(LIBNAME).c

all: lib$(LIBNAME).so test

lib$(LIBNAME).so:
	$(CC) -shared -fPIC $(SRC) -o lib$(LIBNAME).so $(CFLAGS)

test:
	$(CC) test.c $(SRC) -o test $(CFLAGS)
	$(CC) test.c -o test-ld $(CFLAGS)

run: test lib$(LIBNAME).so
	./test
	LD_PRELOAD=$(PWD)/lib$(LIBNAME).so ./test-ld

profile:
	valgrind -v --leak-check=full --show-reachable=yes ./test

clean:
	@rm -f lib$(LIBNAME).so test test-ld

.PHONY: test profile clean
