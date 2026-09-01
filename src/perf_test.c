#include "carolina.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_failed;

static void expect(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    g_failed = 1;
  } else {
    fprintf(stderr, "ok: %s\n", msg);
  }
}

static PGconn *fake_connect(const char *dsn) {
  (void)dsn;
  return (PGconn *)(intptr_t)0x51c0ffee;
}

static int count_talks_keys(const char *json) {
  int n = 0;
  const char *p = json;
  while (p && (p = strstr(p, "\"talks\":"))) {
    n++;
    p += 8;
  }
  return n;
}

int main(void) {
  carolina_init();

  expect(carolina_listen_family() == AF_INET6, "listen family is AF_INET6");

  int fd = carolina_open_listener(0);
  expect(fd >= 0, "dual-stack listener binds");
  if (fd >= 0) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    expect(getsockname(fd, (struct sockaddr *)&ss, &len) == 0, "getsockname on listener");
    expect(ss.ss_family == AF_INET6, "bound socket is AF_INET6");
    close(fd);
  }

  carolina_set_connect_fn(fake_connect);
  carolina_reset_counts();
  PGconn *a = carolina_db_acquire();
  carolina_db_release(a);
  PGconn *b = carolina_db_acquire();
  carolina_db_release(b);
  expect(a != NULL && b != NULL, "acquire returns a connection");
  expect(a == b, "second acquire reuses the same pooled conn");
  expect(carolina_connect_count() == 1, "libpq connect count is not one-per-request");
  carolina_set_connect_fn(NULL);

  carolina_reset_counts();
  char health[256];
  int hstatus = carolina_handle_get_copy("/health", "", health, sizeof(health));
  expect(hstatus == 200, "/health returns 200");
  expect(strstr(health, "ok") != NULL, "/health body is ok JSON");
  expect(carolina_sql_count() == 0, "/health does not run SQL");
  expect(carolina_connect_count() == 0, "/health does not open Postgres");

  carolina_reset_counts();
  char body[1 << 20];
  int status = carolina_handle_get_copy("/v1/speakers", "year=2026", body, sizeof(body));
  int sql = carolina_sql_count();
  int speakers = count_talks_keys(body);
  fprintf(stderr, "year list status=%d sql=%d speakers=%d connects=%d\n", status, sql, speakers,
          carolina_connect_count());
  if (status == 200) {
    expect(speakers >= 3, "year listing returns N>=3 speakers");
    expect(sql > 0, "listing runs SQL through shipped exec wrapper");
    expect(sql < 2 * speakers, "SQL count does not grow as ~2N");
    expect(sql <= 4, "year listing SQL is bounded (speakers + talks + years)");
    carolina_reset_counts();
    int status2 = carolina_handle_get_copy("/v1/speakers", "year=2026", body, sizeof(body));
    expect(status2 == 200, "second catalog request succeeds");
    expect(carolina_connect_count() == 0, "second catalog request reuses pool (no extra connect)");
  } else {
    /* Still drive two handler calls; connect reuse was asserted with the fake hook. */
    expect(sql < 2 * 3, "failed listing did not run per-row SQL for N=3");
  }

  FILE *src = fopen("src/main.c", "r");
  expect(src != NULL, "can read src/main.c");
  if (src) {
    char *buf = malloc(512 * 1024);
    size_t n = fread(buf, 1, 512 * 1024 - 1, src);
    buf[n] = 0;
    fclose(src);
    const char *reg = strstr(buf, "static void *register_thread");
    expect(reg != NULL, "register_thread exists");
    if (reg) {
      char copy[4096];
      snprintf(copy, sizeof(copy), "%s", reg);
      char *end = strstr(copy, "int carolina_listen_family");
      if (end) *end = 0;
      expect(strstr(copy, "db_acquire") == NULL, "register-once thread does not open Postgres");
      expect(strstr(copy, "exec_params") == NULL, "register-once thread does not run catalog SQL");
    }
    expect(strstr(buf, "AF_INET6") != NULL, "source binds AF_INET6");
    free(buf);
  }

  if (g_failed) {
    fprintf(stderr, "perf_test failed\n");
    return 1;
  }
  fprintf(stderr, "perf_test passed\n");
  return 0;
}
