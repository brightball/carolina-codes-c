#define _DEFAULT_SOURCE

#include "carolina.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
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
  const char *end = wf + strlen(wf);
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
  expect(has_substr(body, "libasan8") && has_substr(body, "libubsan1"),
         "prepare installs the ASan and UBSan runtimes");
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

  const char *prod = mk ? strstr(mk, "\nPROD_CFLAGS :=") : NULL;
  const char *prod_nl = prod ? strchr(prod + 1, '\n') : NULL;
  expect(prod && prod_nl, "PROD_CFLAGS is a fixed production line");
  if (prod && prod_nl) {
    char line[512];
    size_t n = (size_t)(prod_nl - prod);
    if (n >= sizeof(line)) n = sizeof(line) - 1;
    memcpy(line, prod, n);
    line[n] = 0;
    expect(strstr(line, "-O2") != NULL, "production CFLAGS are optimized");
    expect(strstr(line, "sanitize") == NULL, "production CFLAGS are not sanitized");
  }
  const char *tc = mk ? strstr(mk, "\nTEST_CFLAGS :=") : NULL;
  const char *tc_nl = tc ? strchr(tc + 1, '\n') : NULL;
  expect(tc && tc_nl, "TEST_CFLAGS is a fixed test line");
  if (tc && tc_nl) {
    char line[512];
    size_t n = (size_t)(tc_nl - tc);
    if (n >= sizeof(line)) n = sizeof(line) - 1;
    memcpy(line, tc, n);
    line[n] = 0;
    expect(strstr(line, "-Werror") != NULL, "test CFLAGS use -Werror");
    expect(strstr(line, "-fsanitize=address,undefined") != NULL, "test CFLAGS use ASan and UBSan");
  }
  expect(has_substr(mk, "$(LDLIBS) -s"), "production link strips the binary");

  char *fly = slurp("fly.toml");
  expect(fly != NULL, "can read fly.toml");
  expect(has_substr(fly, "auto_stop_machines = \"suspend\""), "fly suspends idle machines");
  expect(has_substr(fly, "auto_start_machines = true"), "fly autostart is on");
  expect(has_substr(fly, "min_machines_running = 0"), "fly scales to zero");
  expect(has_substr(fly, "memory = \"256mb\""), "fly vm memory stays within 2gb");
  expect(!has_substr(fly, "swap"), "fly config does not configure swap");
  expect(!has_substr(fly, "schedule"), "fly config does not configure a schedule");
  expect(has_substr(fly, "method = \"GET\"") && has_substr(fly, "path = \"/health\""), "fly check is GET /health");

  free(pre);
  free(wf);
  free(mk);
  free(sbom);
  free(pack);
  free(art);
  free(restore);
  free(fly);
}

static const char *kSpkNames[] = {
    "slug", "first_name", "last_name", "name", "tagline", "bio", "company",
    "location", "photo_path", "twitter_url", "linkedin_url", "website_url", "github_url", "featured"};
static const char *kTalkNames[] = {"slug", "title", "description", "format", "youtube_id",
                                   "year", "speaker_slug", "languages", "topics"};
static const char *kSponNames[] = {"slug", "name", "website", "logo_path", "description",
                                   "twitter_url", "linkedin_url", "youtube_url", "instagram_url", "facebook_url"};
static const char *kYearSponNames[] = {"slug", "name", "website", "logo_path", "description",
                                       "blurb", "tier", "featured", "year", "twitter_url",
                                       "linkedin_url", "youtube_url", "instagram_url", "facebook_url"};

typedef struct {
  const char *slug;
  const char *talk;
  const char *title;
  const char *year;
  const char *langs;
  const char *topics;
} TalkFix;

static const TalkFix kTalks[] = {
    {"ada-lovelace", "ada-c", "C for everyone", "2026", "[\"C\"]", "[\"compilers\"]"},
    {"ada-lovelace", "ada-notes", "Notes", "2025", "[\"C\"]", "[\"history\"]"},
    {"grace-hopper", "grace-cobol", "COBOL", "2026", "[\"COBOL\"]", "[\"compilers\"]"},
    {"ken-thompson", "ken-unix", "Unix", "2026", "[\"C\"]", "[\"unix\"]"},
};

static const char *qparam(int nparams, const char *const *params, int i) {
  if (!params || i < 0 || i >= nparams || !params[i]) return "";
  return params[i];
}

static int known_speaker(const char *slug) {
  return slug && (strcmp(slug, "ada-lovelace") == 0 || strcmp(slug, "grace-hopper") == 0 ||
                  strcmp(slug, "ken-thompson") == 0);
}

static void put_speaker_row(const char **cells, int row, const char *slug, const char *first, const char *last) {
  const char **c = cells + row * 14;
  for (int i = 0; i < 14; i++) c[i] = NULL;
  c[0] = slug;
  c[1] = first;
  c[2] = last;
  c[3] = last;
  c[13] = "f";
}

static CarolinaResult *speakers_three(void) {
  const char *cells[3 * 14];
  put_speaker_row(cells, 0, "ada-lovelace", "Ada", "Lovelace");
  put_speaker_row(cells, 1, "grace-hopper", "Grace", "Hopper");
  put_speaker_row(cells, 2, "ken-thompson", "Ken", "Thompson");
  return carolina_result_table(3, 14, kSpkNames, cells);
}

static CarolinaResult *speaker_one(const char *slug) {
  if (!known_speaker(slug)) return carolina_result_table(0, 14, kSpkNames, NULL);
  const char *first = "Ada";
  const char *last = "Lovelace";
  if (strcmp(slug, "grace-hopper") == 0) {
    first = "Grace";
    last = "Hopper";
  } else if (strcmp(slug, "ken-thompson") == 0) {
    first = "Ken";
    last = "Thompson";
  }
  const char *cells[14];
  put_speaker_row(cells, 0, slug, first, last);
  return carolina_result_table(1, 14, kSpkNames, cells);
}

static CarolinaResult *talks_matching(const char *slug, const char *year) {
  const char *cells[8 * 9];
  int n = 0;
  for (size_t i = 0; i < sizeof(kTalks) / sizeof(kTalks[0]); i++) {
    if (slug && strcmp(kTalks[i].slug, slug) != 0) continue;
    if (year && strcmp(kTalks[i].year, year) != 0) continue;
    const char **c = cells + n * 9;
    c[0] = kTalks[i].talk;
    c[1] = kTalks[i].title;
    c[2] = "";
    c[3] = "talk";
    c[4] = "";
    c[5] = kTalks[i].year;
    c[6] = kTalks[i].slug;
    c[7] = kTalks[i].langs;
    c[8] = kTalks[i].topics;
    n++;
  }
  return carolina_result_table(n, 9, kTalkNames, n ? cells : NULL);
}

static CarolinaResult *speaker_years(const char *slug) {
  const char *names[] = {"year"};
  const char *cells[4];
  int n = 0;
  for (size_t i = 0; i < sizeof(kTalks) / sizeof(kTalks[0]); i++) {
    if (!slug || strcmp(kTalks[i].slug, slug) != 0) continue;
    int seen = 0;
    for (int j = 0; j < n; j++) {
      if (strcmp(cells[j], kTalks[i].year) == 0) seen = 1;
    }
    if (seen) continue;
    cells[n++] = kTalks[i].year;
  }
  return carolina_result_table(n, 1, names, n ? cells : NULL);
}

static CarolinaResult *batch_speaker_years(void) {
  const char *names[] = {"speaker_slug", "year"};
  const char *cells[8 * 2];
  int n = 0;
  for (size_t i = 0; i < sizeof(kTalks) / sizeof(kTalks[0]); i++) {
    cells[n * 2] = kTalks[i].slug;
    cells[n * 2 + 1] = kTalks[i].year;
    n++;
  }
  return carolina_result_table(n, 2, names, cells);
}

static CarolinaResult *years_catalog(void) {
  const char *names[] = {"year", "slug", "name", "status"};
  const char *cells[] = {"2026", "2026", "Carolina", "announced", "2025", "2025", "Carolina", "archived"};
  return carolina_result_table(2, 4, names, cells);
}

static CarolinaResult *sponsor_acme(void) {
  const char *cells[] = {"acme", "Acme", "https://acme.example", NULL, "tools", NULL, NULL, NULL, NULL, NULL};
  return carolina_result_table(1, 10, kSponNames, cells);
}

static CarolinaResult *year_sponsor_acme(void) {
  const char *cells[] = {"acme", "Acme", "https://acme.example", NULL, "tools", "tools", "gold", "t",
                         "2026", NULL, NULL, NULL, NULL, NULL};
  return carolina_result_table(1, 14, kYearSponNames, cells);
}

static CarolinaResult *sponsor_years(const char *slug) {
  const char *names[] = {"year"};
  if (!slug || strcmp(slug, "acme") != 0) return carolina_result_table(0, 1, names, NULL);
  const char *cells[] = {"2026", "2024"};
  return carolina_result_table(2, 1, names, cells);
}

static CarolinaResult *sponsorship_rows(const char *slug) {
  const char *names[] = {"sponsor_slug", "year", "tier", "blurb", "featured"};
  if (!slug || strcmp(slug, "acme") != 0) return carolina_result_table(0, 5, names, NULL);
  const char *cells[] = {"acme", "2026", "gold", "tools", "t", "acme", "2024", "silver", "parts", "f"};
  return carolina_result_table(2, 5, names, cells);
}

static CarolinaResult *fixture_query(PGconn *conn, const char *sql, int nparams, const char *const *params) {
  (void)conn;
  const char *p0 = qparam(nparams, params, 0);
  const char *p1 = qparam(nparams, params, 1);
  if (sql && strstr(sql, "FROM v1_years")) return years_catalog();
  if (sql && strstr(sql, "FROM v1_year_sponsors WHERE year = $1 AND slug = $2")) {
    if (strcmp(p0, "2026") == 0 && strcmp(p1, "acme") == 0) return year_sponsor_acme();
    return carolina_result_table(0, 14, kYearSponNames, NULL);
  }
  if (sql && strstr(sql, "FROM v1_year_sponsors WHERE year = $1")) {
    if (strcmp(p0, "2026") == 0) return year_sponsor_acme();
    return carolina_result_table(0, 14, kYearSponNames, NULL);
  }
  if (sql && strstr(sql, "SELECT DISTINCT year FROM v1_sponsorships")) return sponsor_years(p0);
  if (sql && strstr(sql, "FROM v1_sponsorships WHERE sponsor_slug = $1")) return sponsorship_rows(p0);
  if (sql && strstr(sql, "FROM v1_sponsors WHERE slug = $1")) {
    if (strcmp(p0, "acme") == 0) return sponsor_acme();
    return carolina_result_table(0, 10, kSponNames, NULL);
  }
  if (sql && strstr(sql, "FROM v1_sponsors ORDER")) return sponsor_acme();
  if (sql && strstr(sql, "FROM v1_speakers WHERE slug = $1")) return speaker_one(p0);
  if (sql && strstr(sql, "FROM v1_speakers WHERE slug IN")) {
    if (strcmp(p0, "2026") == 0) return speakers_three();
    return carolina_result_table(0, 14, kSpkNames, NULL);
  }
  if (sql && strstr(sql, "FROM v1_speakers")) return speakers_three();
  if (sql && strstr(sql, "speaker_slug = ANY")) return batch_speaker_years();
  if (sql && strstr(sql, "FROM v1_talks WHERE speaker_slug = $1") && strstr(sql, "AND year = $2"))
    return talks_matching(p0, p1);
  if (sql && strstr(sql, "SELECT DISTINCT year FROM v1_talks WHERE speaker_slug = $1")) return speaker_years(p0);
  if (sql && strstr(sql, "FROM v1_talks WHERE speaker_slug = $1")) return talks_matching(p0, NULL);
  if (sql && strstr(sql, "FROM v1_talks WHERE year = $1")) return talks_matching(NULL, p0);
  fprintf(stderr, "unexpected SQL: %s\n", sql ? sql : "(null)");
  return carolina_result_fail("unexpected sql", 0);
}

static int g_soft_fail;
static PGconn *g_dead_conn;
static unsigned g_seq;

static CarolinaResult *soft_query(PGconn *conn, const char *sql, int nparams, const char *const *params) {
  if (g_soft_fail) {
    g_soft_fail = 0;
    return carolina_result_fail("relation missing", 0);
  }
  return fixture_query(conn, sql, nparams, params);
}

static PGconn *seq_connect(const char *dsn) {
  (void)dsn;
  g_seq++;
  PGconn *c = (PGconn *)(uintptr_t)(0xA1100000u + g_seq);
  if (!g_dead_conn) g_dead_conn = c;
  return c;
}

static CarolinaResult *stale_query(PGconn *conn, const char *sql, int nparams, const char *const *params) {
  if (g_dead_conn && conn == g_dead_conn) return carolina_result_fail("server closed the connection unexpectedly", 1);
  return fixture_query(conn, sql, nparams, params);
}

static void expect_http(const char *method, const char *target, int want, const char *needle, const char *msg) {
  char buf[1 << 16];
  int status = carolina_handle_http(method, target, buf, sizeof(buf));
  int good = status == want && (!needle || strstr(buf, needle) != NULL);
  if (!good) fprintf(stderr, "route %s %s -> %d body %.200s\n", method, target, status, buf);
  expect(good, msg);
}

static int maps_have(const char *needle) {
  FILE *f = fopen("/proc/self/maps", "r");
  if (!f) return 0;
  char line[1024];
  int found = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, needle)) {
      found = 1;
      break;
    }
  }
  fclose(f);
  return found;
}

static void test_routes_with_dead_database(void) {
  carolina_set_connect_fn(fake_connect);
  carolina_set_query_fn(fixture_query);

  carolina_reset_counts();
  char body[1 << 16];
  int status = carolina_handle_http("GET", "/v1/speakers?year=2026", body, sizeof(body));
  int sql = carolina_sql_count();
  int speakers = count_talks_keys(body);
  fprintf(stderr, "year list status=%d sql=%d speakers=%d connects=%d\n", status, sql, speakers,
          carolina_connect_count());
  expect(status == 200, "GET /v1/speakers?year= returns 200 without Postgres");
  expect(speakers >= 3, "year listing returns N>=3 speakers");
  expect(strstr(body, "\"talks\"") != NULL, "year listing returns talks");
  expect(strstr(body, "\"languages\"") != NULL, "year listing returns languages");
  expect(strstr(body, "\"topics\"") != NULL, "year listing returns topics");
  expect(strstr(body, "\"years\":[2026") != NULL, "year listing returns years");
  expect(sql > 0 && sql <= 3, "year listing uses at most 3 SQL statements");
  expect(sql < 2 * speakers, "SQL count does not grow as ~2N");
  carolina_reset_counts();
  int status2 = carolina_handle_http("GET", "/v1/speakers?year=2026", body, sizeof(body));
  expect(status2 == 200, "second catalog request succeeds");
  expect(carolina_connect_count() == 0, "second catalog request reuses pool (no extra connect)");

  carolina_reset_counts();
  expect_http("GET", "/v1/years", 200, "\"status\":\"announced\"", "GET /v1/years returns years");
  expect(carolina_sql_count() > 0, "GET /v1/years runs SQL through the shipped handler");

  carolina_reset_counts();
  expect_http("GET", "/v1/speakers", 200, "ada-lovelace", "GET /v1/speakers returns speakers");

  carolina_reset_counts();
  expect_http("GET", "/v1/speakers/ada-lovelace", 200, "\"talks\"", "GET /v1/speakers/:slug returns talks");

  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/speakers/2026/ada-lovelace", body, sizeof(body));
  sql = carolina_sql_count();
  fprintf(stderr, "speaker detail status=%d sql=%d\n", status, sql);
  expect(status == 200, "GET /v1/speakers/:year/:slug returns 200");
  expect(strstr(body, "\"talks\"") != NULL, "speaker detail returns talks");
  expect(strstr(body, "\"other_years\":[2025]") != NULL, "speaker detail returns other_years");
  expect(sql > 0 && sql <= 3, "speaker detail uses at most 3 SQL statements");

  carolina_reset_counts();
  expect_http("GET", "/v1/sponsors", 200, "acme", "GET /v1/sponsors returns sponsors");

  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/sponsors?year=2026", body, sizeof(body));
  expect(status == 200, "GET /v1/sponsors?year= returns 200");
  expect(strstr(body, "\"tier\":\"gold\"") != NULL, "GET /v1/sponsors?year= returns tier");
  expect(strstr(body, "\"blurb\":\"tools\"") != NULL, "GET /v1/sponsors?year= returns blurb");

  carolina_reset_counts();
  expect_http("GET", "/v1/sponsors/acme", 200, "\"sponsorships\"", "GET /v1/sponsors/:slug returns sponsorships");

  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/sponsors/2026/acme", body, sizeof(body));
  sql = carolina_sql_count();
  fprintf(stderr, "sponsor detail status=%d sql=%d\n", status, sql);
  expect(status == 200, "GET /v1/sponsors/:year/:slug returns 200");
  expect(strstr(body, "\"tier\":\"gold\"") != NULL, "sponsor detail returns tier");
  expect(strstr(body, "\"blurb\":\"tools\"") != NULL, "sponsor detail returns blurb");
  expect(strstr(body, "\"other_years\":[2024]") != NULL, "sponsor detail returns other_years");
  expect(sql > 0 && sql <= 2, "sponsor detail uses at most 2 SQL statements");

  carolina_reset_counts();
  expect_http("GET", "/v1/speakers/missing", 404, "not_found", "unknown speaker slug is 404");
  expect_http("GET", "/v1/sponsors/missing", 404, "not_found", "unknown sponsor slug is 404");
  expect_http("GET", "/v1/speakers/2026/missing", 404, "not_found", "unknown year-scoped speaker slug is 404");

  carolina_reset_counts();
  expect_http("POST", "/v1/years", 405, "method_not_allowed", "non-GET is 405");
  expect(carolina_sql_count() == 0 && carolina_connect_count() == 0, "405 does not open Postgres");

  g_soft_fail = 1;
  carolina_set_connect_fn(fake_connect);
  carolina_set_query_fn(soft_query);
  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/years", body, sizeof(body));
  expect(status == 500, "ordinary SQL error fails that request");
  expect(carolina_connect_count() == 1, "SQL error still used one pooled connection");
  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/years", body, sizeof(body));
  expect(status == 200, "ordinary SQL error keeps the pooled connection");
  expect(carolina_connect_count() == 0, "following request reuses the connection after a SQL error");
  expect(strstr(body, "announced") != NULL, "reused connection returns the catalog");

  g_seq = 0;
  g_dead_conn = NULL;
  carolina_set_connect_fn(seq_connect);
  carolina_set_query_fn(stale_query);
  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/years", body, sizeof(body));
  expect(status == 500, "a connection that fails on use fails that request");
  expect(carolina_connect_count() == 1, "failed use opened one connection");
  carolina_reset_counts();
  status = carolina_handle_http("GET", "/v1/years", body, sizeof(body));
  fprintf(stderr, "stale follow-up status=%d connects=%d body %.120s\n", status, carolina_connect_count(), body);
  expect(status == 200, "following catalog request succeeds on a replacement connection");
  expect(carolina_connect_count() == 1, "dead pooled connection was discarded and replaced");
  expect(strstr(body, "announced") != NULL, "replacement connection returns years");
}

static int connect_v4(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int recv_http(int fd, char *buf, size_t buflen) {
  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  size_t n = 0;
  while (n + 1 < buflen) {
    ssize_t r = recv(fd, buf + n, buflen - 1 - n, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (r == 0) break;
    n += (size_t)r;
    buf[n] = 0;
    const char *hdr = strstr(buf, "\r\n\r\n");
    const char *cl = strstr(buf, "Content-Length:");
    if (hdr && cl) {
      int len = atoi(cl + strlen("Content-Length:"));
      size_t have = n - (size_t)(hdr + 4 - buf);
      if (len >= 0 && have >= (size_t)len) break;
    }
  }
  buf[n] = 0;
  return (int)n;
}

static void *serve_thread(void *arg) {
  int lfd = *(int *)arg;
  carolina_serve(lfd);
  return NULL;
}

static void test_inflight_connections(void) {
  int lfd = carolina_open_listener(0);
  if (lfd < 0) {
    fprintf(stderr, "inflight listener: %s\n", strerror(errno));
    expect(0, "inflight listener binds");
    return;
  }
  struct sockaddr_in6 sa;
  socklen_t slen = sizeof(sa);
  memset(&sa, 0, sizeof(sa));
  expect(getsockname(lfd, (struct sockaddr *)&sa, &slen) == 0, "inflight getsockname");
  int port = ntohs(sa.sin6_port);

  pthread_t th;
  expect(pthread_create(&th, NULL, serve_thread, &lfd) == 0, "serve thread starts");

  enum { kHeld = 32 };
  int held[kHeld];
  for (int i = 0; i < kHeld; i++) held[i] = -1;
  int opened = 0;
  for (int i = 0; i < kHeld; i++) {
    held[i] = connect_v4(port);
    if (held[i] < 0) break;
    const char *partial = "GET /health HTTP/1.1\r\nHost: t\r\n";
    if (send(held[i], partial, strlen(partial), 0) < 0) break;
    opened++;
  }
  expect(opened == kHeld, "32 incomplete requests stay connected");

  int hfd = connect_v4(port);
  expect(hfd >= 0, "health connection opens while requests are incomplete");
  char resp[2048];
  resp[0] = 0;
  if (hfd >= 0) {
    const char *req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(hfd, req, strlen(req), 0);
    recv_http(hfd, resp, sizeof(resp));
    close(hfd);
  }
  fprintf(stderr, "inflight /health response:\n%s\n", resp);
  expect(strstr(resp, " 200 ") != NULL, "GET /health is 200 with 32 incomplete clients");
  expect(strstr(resp, "{\"ok\":true}") != NULL, "GET /health body is {\"ok\":true} with 32 incomplete clients");

  int rfd = connect_v4(port);
  resp[0] = 0;
  if (rfd >= 0) {
    const char *req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(rfd, req, strlen(req), 0);
    recv_http(rfd, resp, sizeof(resp));
    close(rfd);
  }
  expect(strstr(resp, "\"language\":\"C\"") != NULL, "GET / identifies C while clients are held");

  if (opened > 0 && held[0] >= 0) {
    int flags = fcntl(held[0], F_GETFL, 0);
    if (flags >= 0) fcntl(held[0], F_SETFL, flags | O_NONBLOCK);
    char tmp;
    ssize_t rr = recv(held[0], &tmp, 1, MSG_DONTWAIT);
    expect(rr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "incomplete request is still held open");
  }

  for (int i = 0; i < kHeld; i++) {
    if (held[i] >= 0) close(held[i]);
  }
  carolina_serve_stop();
  pthread_join(th, NULL);
  close(lfd);
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  setenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:1/carolina_dev?connect_timeout=1", 1);
  setenv("CAROLINA_URL", "http://127.0.0.1:1", 1);
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
  expect(strcmp(health, "{\"ok\":true}") == 0, "/health body is {\"ok\":true}");
  expect(carolina_sql_count() == 0, "/health does not run SQL");
  expect(carolina_connect_count() == 0, "/health does not open Postgres");

  carolina_reset_counts();
  char ident[4096];
  int istatus = carolina_handle_get_copy("/", "", ident, sizeof(ident));
  expect(istatus == 200, "/ returns 200");
  expect(strstr(ident, "\"language\":\"C\"") != NULL, "/ identity language is C");
  expect(carolina_sql_count() == 0, "/ does not run SQL");
  expect(carolina_connect_count() == 0, "/ does not open Postgres");

  test_routes_with_dead_database();
  test_inflight_connections();
  expect(maps_have("libasan"), "this process is running under AddressSanitizer");
  expect(maps_have("libubsan"), "this process is running under UndefinedBehaviorSanitizer");

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
      expect(strstr(buf, "MAX_INFLIGHT") != NULL, "in-flight connections are capped");
      expect(strstr(buf, "g_db_bad") != NULL, "pooled connections can be marked dead after a failed use");
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
