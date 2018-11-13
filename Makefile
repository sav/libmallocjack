LIBNAME := mallocjack

CFLAGS += -std=gnu99 -g -O0 -fPIC -funwind-tables -Wall -Werror -Wextra -DDEBUG \
	-D_GNU_SOURCE -I. -Wno-unused-function -Wno-unused-variable
LDFLAGS += -ldl

ifeq ($(CC),clang)
	LDFLAGS += -Wl,-export_dynamic
else
	LDFLAGS += -rdynamic
endif

SRC := $(LIBNAME).c
OBJ := $(SRC:.c=.o)

all: lib$(LIBNAME).so test test-ld

lib$(LIBNAME).so: $(OBJ)
	$(CC) $(CFLAGS) -shared -fPIC $(OBJ) -o lib$(LIBNAME).so $(LDFLAGS)

%.o: %.c Makefile
	${CC} ${CFLAGS} -c $<

test-ld:
	$(CC) test.c -o test-ld $(CFLAGS)

test: test-ld
	$(CC) test.c $(SRC) -o test $(CFLAGS) $(LDFLAGS) -DDEBUG_TEST

run: test lib$(LIBNAME).so
	./test
	LD_PRELOAD=$(PWD)/lib$(LIBNAME).so ./test-ld

profile:
	valgrind -v --leak-check=full --show-reachable=yes ./test

clean:
	@rm -rf *.o lib$(LIBNAME).so test test-ld *.dSYM

.PHONY: run profile clean
