LIBNAME := mallocjack

CFLAGS += -Wall -Werror -Wextra -ggdb -O0 -DDEBUG -std=gnu99

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
