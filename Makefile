CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -pthread
CPPFLAGS += $(shell pkg-config --cflags libpq 2>/dev/null)
LDLIBS += $(shell pkg-config --libs libpq 2>/dev/null)
ifeq ($(strip $(LDLIBS)),)
  LDLIBS += -lpq
endif
LDLIBS += -pthread

.PHONY: all clean

all: api

api: src/main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ src/main.c $(LDLIBS)

clean:
	rm -f api
