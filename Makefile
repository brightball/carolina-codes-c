CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -pthread
CPPFLAGS += $(shell pkg-config --cflags libpq 2>/dev/null)
LDLIBS += $(shell pkg-config --libs libpq 2>/dev/null)
ifeq ($(strip $(LDLIBS)),)
  LDLIBS += -lpq
endif
LDLIBS += -pthread

.PHONY: all clean test

all: api

api: src/main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ src/main.c $(LDLIBS)

perf_test: src/main.c src/perf_test.c src/carolina.h
	$(CC) $(CFLAGS) -Wno-unused-function -DCAROLINA_TEST $(CPPFLAGS) -Isrc -o $@ src/main.c src/perf_test.c $(LDLIBS)

test: perf_test
	./perf_test

clean:
	rm -f api perf_test
