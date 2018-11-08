LIBNAME := mallocjack

CFLAGS += -ggdb -O0 -DDEBUG -D_GNU_SOURCE -I. \
		  -std=gnu99 -rdynamic -Wall -Werror -Wextra

SRC := $(LIBNAME).c

all: lib$(LIBNAME).so test

lib$(LIBNAME).so:
	@$(CC) -shared -fPIC $(SRC) -o lib$(LIBNAME).so $(CFLAGS) -I. -ldl

test:
	@$(CC) test.c $(SRC) -o test $(CFLAGS) -I. -ldl
	./test

clean:
	@rm -f lib$(LIBNAME).so test

.PHONY: test clean
