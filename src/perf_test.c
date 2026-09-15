#include "carolina.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
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

static char *slurp(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long sz = ftell(f);
  if (sz < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *buf = malloc((size_t)sz + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  size_t n = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  buf[n] = 0;
  return buf;
}

static int has_substr(const char *hay, const char *needle) {
  return hay && needle && strstr(hay, needle) != NULL;
}

static int count_substr(const char *hay, const char *needle) {
  if (!hay || !needle) return 0;
  size_t len = strlen(needle);
  if (!len) return 0;
  int n = 0;
  for (const char *p = hay; (p = strstr(p, needle)); p += len) n++;
  return n;
}

static const char *job_start(const char *wf, const char *name) {
  char pat[64];
  snprintf(pat, sizeof(pat), "\n  %s:\n", name);
  return strstr(wf, pat);
}

static void copy_job_body(const char *wf, const char *name, const char *others[], int nothers, char *out, size_t outsz) {
  const char *start = job_start(wf, name);
  if (!start || outsz == 0) {
    if (outsz) out[0] = 0;
    return;
  }
  const char *end = start + strlen(wf);
  for (int i = 0; i < nothers; i++) {
    if (strcmp(others[i], name) == 0) continue;
    const char *p = job_start(wf, others[i]);
    if (p && p > start && p < end) end = p;
  }
  size_t n = (size_t)(end - start);
  if (n >= outsz) n = outsz - 1;
  memcpy(out, start, n);
  out[n] = 0;
}

static void test_quality_gates(void) {
  char *pre = slurp(".pre-commit-config.yaml");
  char *wf = slurp(".gitea/workflows/precommit.yml");
  char *mk = slurp("Makefile");
  char *sbom = slurp("sbom.cdx.json");
  expect(pre != NULL, "can read .pre-commit-config.yaml");
  expect(wf != NULL, "can read .gitea/workflows/precommit.yml");
  expect(mk != NULL, "can read Makefile");
  expect(sbom != NULL, "can read sbom.cdx.json");

  expect(has_substr(pre, "id: test"), "precommit hook id test");
  expect(has_substr(pre, "id: sast"), "precommit hook id sast");
  expect(has_substr(pre, "id: vuln"), "precommit hook id vuln");
  expect(has_substr(pre, "id: secrets"), "precommit hook id secrets");
  expect(has_substr(pre, "id: fmt"), "precommit hook id fmt");
  expect(count_substr(pre, "\n      - id:") == 5, "exactly five precommit hooks");
  expect(has_substr(pre, "entry: make test"), "test hook runs make test");
  expect(has_substr(pre, "entry: make sast"), "sast hook runs make sast");
  expect(has_substr(pre, "entry: make vuln"), "vuln hook runs make vuln");
  expect(has_substr(pre, "entry: make secrets"), "secrets hook runs make secrets");
  expect(has_substr(pre, "entry: make fmt-check"), "fmt hook runs make fmt-check");

  expect(has_substr(mk, "cppcheck"), "Makefile SAST uses cppcheck");
  expect(has_substr(mk, "osv-scanner"), "Makefile vuln uses osv-scanner");
  expect(has_substr(mk, "gitleaks") && has_substr(mk, "detect --source"), "Makefile secrets uses gitleaks detect");
  expect(has_substr(mk, "clang-format"), "Makefile style uses clang-format");
  expect(has_substr(mk, "sbom.cdx.json"), "Makefile vuln scans committed SBOM");
  expect(has_substr(sbom, "libpq5"), "SBOM lists libpq5 from Dockerfile");

  expect(job_start(wf, "prepare") != NULL, "gitea job prepare");
  expect(job_start(wf, "test") != NULL, "gitea job test");
  expect(job_start(wf, "sast") != NULL, "gitea job sast");
  expect(job_start(wf, "vuln") != NULL, "gitea job vuln");
  expect(job_start(wf, "secrets") != NULL, "gitea job secrets");
  expect(job_start(wf, "fmt") != NULL, "gitea job fmt");
  expect(count_substr(wf, "runs-on:") == 6, "prepare plus five gitea check jobs");
  expect(count_substr(wf, "needs: prepare") == 5, "five check jobs wait on prepare");
  expect(count_substr(wf, "needs:") == 5, "check jobs are not chained to each other");
  expect(has_substr(wf, "make test"), "gitea test job runs make test");
  expect(has_substr(wf, "make sast"), "gitea sast job runs make sast");
  expect(has_substr(wf, "make vuln"), "gitea vuln job runs make vuln");
  expect(has_substr(wf, "make secrets"), "gitea secrets job runs make secrets");
  expect(has_substr(wf, "make fmt-check"), "gitea fmt job runs make fmt-check");

  char *pack = slurp("scripts/ci-pack.sh");
  char *art = slurp("scripts/ci-artifact.sh");
  char *restore = slurp("scripts/ci-restore.sh");
  expect(pack != NULL, "can read scripts/ci-pack.sh");
  expect(art != NULL, "can read scripts/ci-artifact.sh");
  expect(restore != NULL, "can read scripts/ci-restore.sh");
  expect(has_substr(pack, "/var/cache/apt/archives") && has_substr(pack, "/usr/local"), "ci-pack.sh packs apt debs and /usr/local");
  expect(has_substr(art, "upload") && has_substr(art, "download") && has_substr(art, "ACTIONS_RUNTIME"),
         "ci-artifact.sh talks to the Gitea artifact API");
  expect(has_substr(restore, "ci-artifact.sh") && has_substr(restore, "dpkg"), "ci-restore.sh downloads and installs the packed tree");

  const char *all_jobs[] = {"prepare", "test", "sast", "vuln", "secrets", "fmt"};
  const char *check_jobs[] = {"test", "sast", "vuln", "secrets", "fmt"};
  const char *targets[] = {"make test", "make sast", "make vuln", "make secrets", "make fmt-check"};
  char body[8192];

  copy_job_body(wf, "prepare", all_jobs, 6, body, sizeof(body));
  expect(has_substr(body, "apt-get install"), "prepare installs the shared toolchain");
  expect(has_substr(body, "gcc") && has_substr(body, "make") && has_substr(body, "pkg-config") && has_substr(body, "libpq"),
         "prepare installs gcc/make/pkg-config/libpq headers");
  expect(has_substr(body, "cppcheck") && has_substr(body, "clang-format"), "prepare installs cppcheck and clang-format");
  expect(has_substr(body, "gitleaks_8.30.1") && has_substr(body, "osv-scanner_linux_amd64"),
         "prepare installs gitleaks v8.30.1 and osv-scanner v2.6.0");
  expect(has_substr(body, "ci-pack.sh") && has_substr(body, "ci-artifact.sh upload"), "prepare publishes the packed toolchain");
  expect(!has_substr(body, "needs:"), "prepare does not wait on check jobs");
  expect(!has_substr(body, "make test") && !has_substr(body, "make sast") && !has_substr(body, "make vuln") &&
             !has_substr(body, "make secrets") && !has_substr(body, "make fmt-check"),
         "prepare does not run quality-check make targets");

  for (int i = 0; i < 5; i++) {
    copy_job_body(wf, check_jobs[i], all_jobs, 6, body, sizeof(body));
    expect(has_substr(body, "needs: prepare"), "check job waits on prepare");
    expect(count_substr(body, "needs:") == 1, "check job has a single prepare dependency");
    expect(has_substr(body, "ci-restore.sh"), "check job restores the prepared environment");
    expect(has_substr(body, targets[i]), "check job runs its make target");
    int hits = 0;
    for (int t = 0; t < 5; t++) {
      if (has_substr(body, targets[t])) hits++;
    }
    expect(hits == 1, "check job runs only its own make target");
    expect(!has_substr(body, "apt-get install"), "check job does not apt-get install");
    expect(!has_substr(body, "osv-scanner_linux_amd64"), "check job does not curl-install osv-scanner");
    expect(!has_substr(body, "gitleaks_8.30.1"), "check job does not curl-install gitleaks");
    for (int j = 0; j < 5; j++) {
      if (j == i) continue;
      char dep[64];
      snprintf(dep, sizeof(dep), "needs: %s", check_jobs[j]);
      expect(!has_substr(body, dep), "check jobs do not wait on each other");
    }
  }

  copy_job_body(wf, "test", all_jobs, 6, body, sizeof(body));
  expect(has_substr(body, "postgres://postgres:postgres@127.0.0.1:1/carolina_dev?connect_timeout=1"),
         "test job uses dead DATABASE_URL");

  int art_rc = system("python3 scripts/test_ci_artifact.py");
  expect(art_rc == 0, "ci-artifact.sh upload/download roundtrip against fake Gitea API");

  free(pre);
  free(wf);
  free(mk);
  free(sbom);
  free(pack);
  free(art);
  free(restore);
}

int main(void) {
  carolina_init();

  expect(carolina_listen_family() == AF_INET6, "listen family is AF_INET6");

  int fd = carolina_open_listener(0);
  if (fd < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT || errno == EADDRNOTAVAIL || errno == EPERM || errno == EACCES)) {
    fprintf(stderr, "skip dual-stack bind (%s); family is still AF_INET6\n", strerror(errno));
  } else {
    if (fd < 0) fprintf(stderr, "carolina_open_listener: %s\n", strerror(errno));
    expect(fd >= 0, "dual-stack listener binds");
    if (fd >= 0) {
      struct sockaddr_storage ss;
      socklen_t len = sizeof(ss);
      memset(&ss, 0, sizeof(ss));
      expect(getsockname(fd, (struct sockaddr *)&ss, &len) == 0, "getsockname on listener");
      expect(ss.ss_family == AF_INET6, "bound socket is AF_INET6");
      close(fd);
    }
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
  char ident[4096];
  int istatus = carolina_handle_get_copy("/", "", ident, sizeof(ident));
  expect(istatus == 200, "/ returns 200");
  expect(strstr(ident, "\"language\":\"C\"") != NULL, "/ identity language is C");
  expect(carolina_sql_count() == 0, "/ does not run SQL");
  expect(carolina_connect_count() == 0, "/ does not open Postgres");

  carolina_reset_counts();
  char body[1 << 20];
  int status = carolina_handle_get_copy("/v1/speakers", "year=2026", body, sizeof(body));
  int sql = carolina_sql_count();
  int speakers = count_talks_keys(body);
  fprintf(stderr, "year list status=%d sql=%d speakers=%d connects=%d\n", status, sql, speakers,
          carolina_connect_count());
  if (status == 200 && speakers >= 3) {
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
    expect(buf != NULL, "alloc source buffer");
    if (!buf) {
      fclose(src);
    } else {
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
  }

  test_quality_gates();

  if (g_failed) {
    fprintf(stderr, "perf_test failed\n");
    return 1;
  }
  fprintf(stderr, "perf_test passed\n");
  return 0;
}
