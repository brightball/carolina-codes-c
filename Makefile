CC ?= gcc
# Sanitizers stay off the Fly image. -Werror and ASan/UBSan are test-only.
PROD_CFLAGS := -std=c11 -O2 -Wall -Wextra -pthread
TEST_CFLAGS := -std=c11 -O1 -Wall -Wextra -Werror -pthread -fno-omit-frame-pointer -fsanitize=address,undefined
TEST_LDFLAGS := -fsanitize=address,undefined
CPPFLAGS += $(shell pkg-config --cflags libpq 2>/dev/null)
LDLIBS += $(shell pkg-config --libs libpq 2>/dev/null)
ifeq ($(strip $(LDLIBS)),)
  LDLIBS += -lpq
endif
LDLIBS += -pthread

export PATH := $(HOME)/.local/bin:$(HOME)/.local/share/mise/shims:$(PATH)

SRC_C := src/main.c src/perf_test.c
SRC_H := src/carolina.h
SRC := $(SRC_C) $(SRC_H)

GITLEAKS ?= gitleaks
OSV_SCANNER ?= osv-scanner
CPPCHECK ?= cppcheck
CLANG_FORMAT ?= clang-format

.PHONY: all clean test fmt fmt-check sast vuln secrets check hooks

all: api

api: src/main.c src/carolina.h
	$(CC) $(PROD_CFLAGS) $(CPPFLAGS) -o $@ src/main.c $(LDLIBS) -s

perf_test: src/main.c src/perf_test.c src/carolina.h
	$(CC) $(TEST_CFLAGS) -DCAROLINA_TEST $(CPPFLAGS) -Isrc -o $@ src/main.c src/perf_test.c $(LDLIBS) $(TEST_LDFLAGS)

test: perf_test
	ASAN_OPTIONS=halt_on_error=1:detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 ./perf_test

fmt:
	$(CLANG_FORMAT) -i $(SRC)

fmt-check:
	$(CLANG_FORMAT) --dry-run --Werror $(SRC)

sast:
	$(CPPCHECK) --std=c11 --enable=warning,performance,portability \
		--error-exitcode=1 --inline-suppr \
		--suppress=missingIncludeSystem --suppress=missingInclude \
		--library=posix -U__has_include \
		src

vuln:
	$(OSV_SCANNER) scan source --recursive --lockfile sbom.cdx.json .

secrets:
	$(GITLEAKS) detect --source . --verbose --redact

check: test sast vuln secrets fmt-check

hooks:
	pre-commit install
	git config core.hooksPath .githooks

clean:
	rm -f api perf_test
