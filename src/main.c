#define _POSIX_C_SOURCE 200809L

#if defined(__has_include)
#if __has_include(<postgresql/libpq-fe.h>)
#include <postgresql/libpq-fe.h>
#else
#include <libpq-fe.h>
#endif
#else
#include <libpq-fe.h>
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "carolina.h"

static const char *kLanguage = "C";
static const char *kApiVersion = "0.2.0";
static const char *kFramework = "POSIX sockets";
static const int kCreatedYear = 2026;
static const int kSchemaVersion = 1;
#ifdef __VERSION__
static const char *kLanguageVersion = __VERSION__;
#else
static const char *kLanguageVersion = "C11";
#endif

static const char *kSpeakerCols =
    "slug, first_name, last_name, name, tagline, bio, company, location, "
    "photo_path, twitter_url, linkedin_url, website_url, github_url, featured";
static const char *kYearSponsorCols =
    "slug, name, website, logo_path, description, blurb, tier, featured, year, "
    "twitter_url, linkedin_url, youtube_url, instagram_url, facebook_url";
static const char *kSponsorCols =
    "slug, name, website, logo_path, description, twitter_url, linkedin_url, "
    "youtube_url, instagram_url, facebook_url";
static const char *kTalkSelect =
    "slug, title, description, format, youtube_id, year, speaker_slug, "
    "COALESCE(array_to_json(languages), '[]'::json)::text AS languages, "
    "COALESCE(array_to_json(topics), '[]'::json)::text AS topics";

static const char *kEndpointsJson =
    "["
    "{\"method\":\"GET\",\"path\":\"/\",\"query\":[]},"
    "{\"method\":\"GET\",\"path\":\"/health\",\"query\":[]},"
    "{\"method\":\"GET\",\"path\":\"/v1/years\",\"query\":[]},"
    "{\"method\":\"GET\",\"path\":\"/v1/speakers\",\"query\":[\"year\"]},"
    "{\"method\":\"GET\",\"path\":\"/v1/speakers/:slug\",\"query\":[]},"
    "{\"method\":\"GET\",\"path\":\"/v1/speakers/:year/:slug\",\"query\":[]},"
    "{\"method\":\"GET\",\"path\":\"/v1/sponsors\",\"query\":[\"year\"]},"
    "{\"method\":\"GET\",\"path\":\"/v1/sponsors/:slug\",\"query\":[]},"
    "{\"method\":\"GET\",\"path\":\"/v1/sponsors/:year/:slug\",\"query\":[]}"
    "]";

static char g_dsn[512];
static char g_port[16];

#define DB_POOL_SIZE 8

static pthread_mutex_t g_db_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_db_cv = PTHREAD_COND_INITIALIZER;
static PGconn *g_db_pool[DB_POOL_SIZE];
static int g_db_busy[DB_POOL_SIZE];
static int g_db_bad[DB_POOL_SIZE];
static int g_sql_count;
static int g_connect_count;
static PGconn *(*g_connect_fn)(const char *) = NULL;
static carolina_query_fn g_query_fn = NULL;
static volatile sig_atomic_t g_serve_stop;

/* Cap accepted-but-unfinished clients. A thread per connection would pin an
 * 8MB stack each and OOM the 256MB Fly machine under slow clients. */
#define MAX_INFLIGHT 64
#define REQ_MAX 4096
#define CONN_IDLE_MS 15000

struct CarolinaResult {
  int ok;
  int conn_failed;
  char *errmsg;
  int nrows;
  int ncols;
  char **names;
  char **cells;
};

static const char *env_or(const char *key, const char *fallback) {
  const char *v = getenv(key);
  return (v && *v) ? v : fallback;
}

typedef struct {
  char *s;
  size_t n, cap;
} Buf;

static void buf_init(Buf *b) {
  b->cap = 256;
  b->n = 0;
  b->s = malloc(b->cap);
  if (b->s) b->s[0] = 0;
}

static void buf_grow(Buf *b, size_t need) {
  size_t want = b->n + need + 1;
  if (want <= b->cap) return;
  size_t cap = b->cap ? b->cap : 256;
  while (cap < want) cap *= 2;
  char *ns = realloc(b->s, cap);
  if (!ns) abort();
  b->s = ns;
  b->cap = cap;
}

static void buf_append(Buf *b, const char *p, size_t n) {
  buf_grow(b, n);
  memcpy(b->s + b->n, p, n);
  b->n += n;
  b->s[b->n] = 0;
}

static void buf_puts(Buf *b, const char *s) { buf_append(b, s, strlen(s)); }

static void buf_printf(Buf *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if ((size_t)n < sizeof(tmp)) {
    buf_append(b, tmp, (size_t)n);
    return;
  }
  buf_grow(b, (size_t)n);
  if (!b->s) return;
  va_start(ap, fmt);
  vsnprintf(b->s + b->n, b->cap - b->n, fmt, ap);
  va_end(ap);
  b->n += (size_t)n;
}

static void buf_free(Buf *b) {
  free(b->s);
  b->s = NULL;
  b->n = b->cap = 0;
}

static void json_string(Buf *b, const char *v) {
  if (!v) {
    buf_puts(b, "null");
    return;
  }
  buf_puts(b, "\"");
  for (const unsigned char *p = (const unsigned char *)v; *p; ++p) {
    switch (*p) {
    case '"': buf_puts(b, "\\\""); break;
    case '\\': buf_puts(b, "\\\\"); break;
    case '\n': buf_puts(b, "\\n"); break;
    case '\r': buf_puts(b, "\\r"); break;
    case '\t': buf_puts(b, "\\t"); break;
    default:
      if (*p < 0x20) buf_printf(b, "\\u%04x", *p);
      else
        buf_append(b, (const char *)p, 1);
    }
  }
  buf_puts(b, "\"");
}

typedef struct {
  Buf *b;
  int first;
} Obj;

static void obj_begin(Obj *o, Buf *b) {
  o->b = b;
  o->first = 1;
  buf_puts(b, "{");
}

static void obj_sep(Obj *o) {
  if (!o->first) buf_puts(o->b, ",");
  o->first = 0;
}

static void obj_key(Obj *o, const char *k) {
  obj_sep(o);
  json_string(o->b, k);
  buf_puts(o->b, ":");
}

static void obj_str(Obj *o, const char *k, const char *v) {
  obj_key(o, k);
  json_string(o->b, v);
}

static void obj_bool(Obj *o, const char *k, int v) {
  obj_key(o, k);
  buf_puts(o->b, v ? "true" : "false");
}

static void obj_int(Obj *o, const char *k, long v) {
  obj_key(o, k);
  buf_printf(o->b, "%ld", v);
}

static void obj_raw(Obj *o, const char *k, const char *json) {
  obj_key(o, k);
  buf_puts(o->b, json ? json : "null");
}

static void obj_end(Obj *o) { buf_puts(o->b, "}"); }

static char *dup_text(const char *s) {
  char *d = strdup(s ? s : "");
  if (!d) abort();
  return d;
}

static char *dup_nullable(const char *s) {
  if (!s) return NULL;
  char *d = strdup(s);
  if (!d) abort();
  return d;
}

static void carolina_result_free(CarolinaResult *r) {
  if (!r) return;
  free(r->errmsg);
  if (r->names) {
    for (int i = 0; i < r->ncols; i++) free(r->names[i]);
    free(r->names);
  }
  if (r->cells) {
    int n = r->nrows * r->ncols;
    for (int i = 0; i < n; i++) free(r->cells[i]);
    free(r->cells);
  }
  free(r);
}

CarolinaResult *carolina_result_fail(const char *error, int conn_failed) {
  CarolinaResult *r = calloc(1, sizeof(*r));
  if (!r) abort();
  r->ok = 0;
  r->conn_failed = conn_failed ? 1 : 0;
  r->errmsg = dup_text(error && *error ? error : "query failed");
  return r;
}

CarolinaResult *carolina_result_table(int nrows, int ncols, const char **names, const char **cells) {
  CarolinaResult *r = calloc(1, sizeof(*r));
  if (!r) abort();
  r->ok = 1;
  if (nrows < 0) nrows = 0;
  if (ncols < 0) ncols = 0;
  r->nrows = nrows;
  r->ncols = ncols;
  if (ncols > 0) {
    r->names = calloc((size_t)ncols, sizeof(char *));
    if (!r->names) abort();
    for (int i = 0; i < ncols; i++) r->names[i] = dup_text(names ? names[i] : "");
  }
  int ncells = nrows * ncols;
  if (ncells > 0) {
    r->cells = calloc((size_t)ncells, sizeof(char *));
    if (!r->cells) abort();
    for (int i = 0; i < ncells; i++) {
      const char *cell = cells ? cells[i] : NULL;
      if (cell) r->cells[i] = dup_nullable(cell);
    }
  }
  return r;
}

static const char *q_col(const CarolinaResult *r, int row, const char *name) {
  if (!r || !r->ok || row < 0 || row >= r->nrows || !name) return NULL;
  int col = -1;
  for (int i = 0; i < r->ncols; i++) {
    if (r->names && r->names[i] && strcmp(r->names[i], name) == 0) {
      col = i;
      break;
    }
  }
  if (col < 0) return NULL;
  return r->cells ? r->cells[row * r->ncols + col] : NULL;
}

static int truthy(const char *v) { return v && (v[0] == 't' || v[0] == 'T' || v[0] == '1'); }

static int as_int(const char *v) { return v ? atoi(v) : 0; }

static int sqlstate_means_dead(const char *sqlstate) {
  if (!sqlstate || sqlstate[0] == 0 || sqlstate[1] == 0) return 0;
  if (sqlstate[0] == '0' && sqlstate[1] == '8') return 1;
  if (strcmp(sqlstate, "57P01") == 0 || strcmp(sqlstate, "57P02") == 0 || strcmp(sqlstate, "57P03") == 0) return 1;
  return 0;
}

static void db_mark_bad(PGconn *c) {
  if (!c) return;
  pthread_mutex_lock(&g_db_mu);
  for (int i = 0; i < DB_POOL_SIZE; i++) {
    if (g_db_pool[i] == c) g_db_bad[i] = 1;
  }
  pthread_mutex_unlock(&g_db_mu);
}

static void discard_pg(struct pg_result *pr) {
  if (pr) PQclear(pr);
}

static CarolinaResult *result_from_pg(PGconn *c, struct pg_result *pr) {
  if (!pr) {
    const char *msg = c ? PQerrorMessage(c) : NULL;
    CarolinaResult *r = carolina_result_fail(msg, 1);
    db_mark_bad(c);
    return r;
  }
  ExecStatusType st = PQresultStatus(pr);
  if (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK) {
    int nrows = PQntuples(pr);
    int ncols = PQnfields(pr);
    const char **names = NULL;
    const char **cells = NULL;
    if (ncols > 0) {
      names = calloc((size_t)ncols, sizeof(char *));
      if (!names) abort();
      for (int i = 0; i < ncols; i++) names[i] = PQfname(pr, i);
    }
    int ncells = nrows * ncols;
    if (ncells > 0) {
      cells = calloc((size_t)ncells, sizeof(char *));
      if (!cells) abort();
      for (int row = 0; row < nrows; row++) {
        for (int col = 0; col < ncols; col++) {
          if (PQgetisnull(pr, row, col)) continue;
          cells[row * ncols + col] = PQgetvalue(pr, row, col);
        }
      }
    }
    CarolinaResult *r = carolina_result_table(nrows, ncols, names, cells);
    free(names);
    free(cells);
    discard_pg(pr);
    return r;
  }
  const char *msg = PQresultErrorMessage(pr);
  const char *sqlstate = PQresultErrorField(pr, PG_DIAG_SQLSTATE);
  int dead = (c && !g_connect_fn && PQstatus(c) != CONNECTION_OK) || sqlstate_means_dead(sqlstate);
  CarolinaResult *r = carolina_result_fail(msg, dead);
  if (dead) db_mark_bad(c);
  discard_pg(pr);
  return r;
}

static CarolinaResult *run_query(PGconn *c, const char *sql, int nparams, const char **vals, int with_params) {
  g_sql_count++;
  if (g_query_fn) {
    CarolinaResult *r = g_query_fn(c, sql, with_params ? nparams : 0, with_params ? (const char *const *)vals : NULL);
    if (!r) r = carolina_result_fail("query failed", 1);
    if (r->conn_failed) db_mark_bad(c);
    return r;
  }
  struct pg_result *pr =
      with_params ? PQexecParams(c, sql, nparams, NULL, vals, NULL, NULL, 0) : PQexec(c, sql);
  return result_from_pg(c, pr);
}

static CarolinaResult *exec_params(PGconn *c, const char *sql, int n, const char **vals) {
  return run_query(c, sql, n, vals, 1);
}

static CarolinaResult *db_exec(PGconn *c, const char *sql) { return run_query(c, sql, 0, NULL, 0); }

static int conn_ok(PGconn *c) {
  if (!c) return 0;
  if (g_connect_fn) return 1;
  return PQstatus(c) == CONNECTION_OK;
}

static PGconn *do_connect(void) {
  g_connect_count++;
  if (g_connect_fn) return g_connect_fn(g_dsn);
  return PQconnectdb(g_dsn);
}

static PGconn *db_acquire(void) {
  pthread_mutex_lock(&g_db_mu);
  for (;;) {
    int busy = 0;
    for (int i = 0; i < DB_POOL_SIZE; i++) {
      if (g_db_busy[i]) {
        busy++;
        continue;
      }
      if (!conn_ok(g_db_pool[i])) {
        if (g_db_pool[i] && !g_connect_fn) PQfinish(g_db_pool[i]);
        g_db_pool[i] = do_connect();
      }
      if (conn_ok(g_db_pool[i])) {
        g_db_busy[i] = 1;
        PGconn *c = g_db_pool[i];
        pthread_mutex_unlock(&g_db_mu);
        return c;
      }
      g_db_pool[i] = NULL;
    }
    if (busy == 0) {
      pthread_mutex_unlock(&g_db_mu);
      return NULL;
    }
    pthread_cond_wait(&g_db_cv, &g_db_mu);
  }
}

static int real_conn_dead(PGconn *c) {
  if (!c || g_connect_fn) return 0;
  return PQstatus(c) != CONNECTION_OK;
}

static void db_release(PGconn *c) {
  if (!c) return;
  pthread_mutex_lock(&g_db_mu);
  for (int i = 0; i < DB_POOL_SIZE; i++) {
    if (g_db_pool[i] == c) {
      if (g_db_bad[i] || real_conn_dead(c)) {
        if (!g_connect_fn) PQfinish(c);
        g_db_pool[i] = NULL;
        g_db_bad[i] = 0;
      }
      g_db_busy[i] = 0;
      break;
    }
  }
  pthread_cond_signal(&g_db_cv);
  pthread_mutex_unlock(&g_db_mu);
}

static int res_ok(const CarolinaResult *r) { return r && r->ok; }

static void speaker_fields(Obj *o, CarolinaResult *r, int row) {
  obj_str(o, "slug", q_col(r, row, "slug"));
  obj_str(o, "first_name", q_col(r, row, "first_name"));
  obj_str(o, "last_name", q_col(r, row, "last_name"));
  obj_str(o, "name", q_col(r, row, "name"));
  obj_str(o, "tagline", q_col(r, row, "tagline"));
  obj_str(o, "bio", q_col(r, row, "bio"));
  obj_str(o, "company", q_col(r, row, "company"));
  obj_str(o, "location", q_col(r, row, "location"));
  obj_str(o, "photo_path", q_col(r, row, "photo_path"));
  obj_str(o, "twitter_url", q_col(r, row, "twitter_url"));
  obj_str(o, "linkedin_url", q_col(r, row, "linkedin_url"));
  obj_str(o, "website_url", q_col(r, row, "website_url"));
  obj_str(o, "github_url", q_col(r, row, "github_url"));
  obj_bool(o, "featured", truthy(q_col(r, row, "featured")));
}

static void year_sponsor_fields(Obj *o, CarolinaResult *r, int row) {
  obj_str(o, "slug", q_col(r, row, "slug"));
  obj_str(o, "name", q_col(r, row, "name"));
  obj_str(o, "website", q_col(r, row, "website"));
  obj_str(o, "logo_path", q_col(r, row, "logo_path"));
  obj_str(o, "description", q_col(r, row, "description"));
  obj_str(o, "blurb", q_col(r, row, "blurb"));
  obj_str(o, "tier", q_col(r, row, "tier"));
  obj_bool(o, "featured", truthy(q_col(r, row, "featured")));
  obj_int(o, "year", as_int(q_col(r, row, "year")));
  obj_str(o, "twitter_url", q_col(r, row, "twitter_url"));
  obj_str(o, "linkedin_url", q_col(r, row, "linkedin_url"));
  obj_str(o, "youtube_url", q_col(r, row, "youtube_url"));
  obj_str(o, "instagram_url", q_col(r, row, "instagram_url"));
  obj_str(o, "facebook_url", q_col(r, row, "facebook_url"));
}

static void sponsor_fields(Obj *o, CarolinaResult *r, int row) {
  obj_str(o, "slug", q_col(r, row, "slug"));
  obj_str(o, "name", q_col(r, row, "name"));
  obj_str(o, "website", q_col(r, row, "website"));
  obj_str(o, "logo_path", q_col(r, row, "logo_path"));
  obj_str(o, "description", q_col(r, row, "description"));
  obj_str(o, "twitter_url", q_col(r, row, "twitter_url"));
  obj_str(o, "linkedin_url", q_col(r, row, "linkedin_url"));
  obj_str(o, "youtube_url", q_col(r, row, "youtube_url"));
  obj_str(o, "instagram_url", q_col(r, row, "instagram_url"));
  obj_str(o, "facebook_url", q_col(r, row, "facebook_url"));
}

static void json_str_array_from_pgjson(Buf *b, const char *raw) {
  if (!raw || raw[0] != '[') {
    buf_puts(b, "[]");
    return;
  }
  buf_puts(b, raw);
}

static void collect_from_json_array(const char *raw, Buf *uniq_buf, int *count) {
  if (!raw || raw[0] != '[') return;
  const char *p = raw + 1;
  while (*p) {
    while (*p && (*p == ' ' || *p == ',' || *p == '\n')) p++;
    if (*p == ']') break;
    if (*p != '"') break;
    p++;
    char cur[256];
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < sizeof(cur)) {
      if (*p == '\\' && p[1]) {
        p++;
        cur[n++] = *p++;
      } else {
        cur[n++] = *p++;
      }
    }
    if (*p == '"') p++;
    cur[n] = 0;
    if (!n) continue;
    /* skip if already present as JSON string in uniq_buf */
    int found = 0;
    if (uniq_buf->s) {
      const char *q = uniq_buf->s;
      while (*q) {
        if (*q == '"') {
          q++;
          size_t m = 0;
          while (q[m] && q[m] != '"') m++;
          if (m == n && strncmp(q, cur, n) == 0) {
            found = 1;
            break;
          }
          q += m;
          if (*q == '"') q++;
        } else {
          q++;
        }
      }
    }
    if (found) continue;
    if (*count) buf_puts(uniq_buf, ",");
    json_string(uniq_buf, cur);
    (*count)++;
  }
}

static void talks_json(PGconn *c, const char *slug, const char *year, Buf *out, Buf *langs, Buf *topics,
                       int *ntalks) {
  char sql[1024];
  snprintf(sql, sizeof(sql), "SELECT %s FROM v1_talks WHERE speaker_slug = $1%s ORDER BY year DESC", kTalkSelect,
           year ? " AND year = $2" : "");
  const char *vals[2];
  int nparams = 1;
  vals[0] = slug;
  if (year) {
    vals[1] = year;
    nparams = 2;
  }
  CarolinaResult *r = exec_params(c, sql, nparams, vals);
  buf_puts(out, "[");
  *ntalks = 0;
  int nlang = 0, ntop = 0;
  if (res_ok(r)) {
    for (int i = 0; i < r->nrows; i++) {
      if (*ntalks) buf_puts(out, ",");
      Obj o;
      obj_begin(&o, out);
      obj_str(&o, "slug", q_col(r, i, "slug"));
      obj_str(&o, "title", q_col(r, i, "title"));
      obj_str(&o, "description", q_col(r, i, "description"));
      obj_str(&o, "format", q_col(r, i, "format"));
      obj_str(&o, "youtube_id", q_col(r, i, "youtube_id"));
      obj_int(&o, "year", as_int(q_col(r, i, "year")));
      obj_str(&o, "speaker_slug", q_col(r, i, "speaker_slug"));
      obj_key(&o, "languages");
      json_str_array_from_pgjson(out, q_col(r, i, "languages"));
      obj_key(&o, "topics");
      json_str_array_from_pgjson(out, q_col(r, i, "topics"));
      obj_end(&o);
      collect_from_json_array(q_col(r, i, "languages"), langs, &nlang);
      collect_from_json_array(q_col(r, i, "topics"), topics, &ntop);
      (*ntalks)++;
    }
  }
  buf_puts(out, "]");
  if (r) carolina_result_free(r);
}

/* One round trip fills both year arrays. other may be NULL. */
static void year_lists(PGconn *c, const char *sql, const char *slug, int skip_year, int have_skip, Buf *years,
                       Buf *other) {
  const char *vals[1] = {slug};
  CarolinaResult *r = exec_params(c, sql, 1, vals);
  buf_puts(years, "[");
  if (other) buf_puts(other, "[");
  int ny = 0, no = 0;
  if (res_ok(r)) {
    for (int i = 0; i < r->nrows; i++) {
      int y = as_int(q_col(r, i, "year"));
      if (ny) buf_puts(years, ",");
      buf_printf(years, "%d", y);
      ny++;
      if (other && (!have_skip || y != skip_year)) {
        if (no) buf_puts(other, ",");
        buf_printf(other, "%d", y);
        no++;
      }
    }
  }
  buf_puts(years, "]");
  if (other) buf_puts(other, "]");
  carolina_result_free(r);
}

typedef struct {
  Buf talks;
  Buf langs;
  Buf topics;
  Buf years;
  int ntalks, nlang, ntop, nyears;
} YearExtras;

static int speaker_row_for_slug(CarolinaResult *speakers, const char *slug) {
  if (!slug) return -1;
  for (int i = 0; i < speakers->nrows; i++) {
    const char *s = q_col(speakers, i, "slug");
    if (s && strcmp(s, slug) == 0) return i;
  }
  return -1;
}

static void pg_slug_array(CarolinaResult *speakers, Buf *out) {
  buf_puts(out, "{");
  int n = 0;
  for (int i = 0; i < speakers->nrows; i++) {
    const char *slug = q_col(speakers, i, "slug");
    if (!slug || !*slug) continue;
    if (n) buf_puts(out, ",");
    buf_puts(out, "\"");
    buf_puts(out, slug);
    buf_puts(out, "\"");
    n++;
  }
  buf_puts(out, "}");
}

static void load_year_extras(PGconn *c, const char *ybuf, CarolinaResult *speakers, YearExtras *ex) {
  int n = speakers->nrows;
  if (n <= 0) return;

  char talks_sql[1024];
  snprintf(talks_sql, sizeof(talks_sql),
           "SELECT %s FROM v1_talks WHERE year = $1 ORDER BY speaker_slug, year DESC", kTalkSelect);
  const char *tvals[1] = {ybuf};
  CarolinaResult *talks = exec_params(c, talks_sql, 1, tvals);
  if (res_ok(talks)) {
    for (int i = 0; i < talks->nrows; i++) {
      int row = speaker_row_for_slug(speakers, q_col(talks, i, "speaker_slug"));
      if (row < 0) continue;
      YearExtras *e = &ex[row];
      if (e->ntalks) buf_puts(&e->talks, ",");
      Obj o;
      obj_begin(&o, &e->talks);
      obj_str(&o, "slug", q_col(talks, i, "slug"));
      obj_str(&o, "title", q_col(talks, i, "title"));
      obj_str(&o, "description", q_col(talks, i, "description"));
      obj_str(&o, "format", q_col(talks, i, "format"));
      obj_str(&o, "youtube_id", q_col(talks, i, "youtube_id"));
      obj_int(&o, "year", as_int(q_col(talks, i, "year")));
      obj_str(&o, "speaker_slug", q_col(talks, i, "speaker_slug"));
      obj_key(&o, "languages");
      json_str_array_from_pgjson(&e->talks, q_col(talks, i, "languages"));
      obj_key(&o, "topics");
      json_str_array_from_pgjson(&e->talks, q_col(talks, i, "topics"));
      obj_end(&o);
      collect_from_json_array(q_col(talks, i, "languages"), &e->langs, &e->nlang);
      collect_from_json_array(q_col(talks, i, "topics"), &e->topics, &e->ntop);
      e->ntalks++;
    }
  }
  if (talks) carolina_result_free(talks);

  Buf slugs;
  buf_init(&slugs);
  pg_slug_array(speakers, &slugs);
  const char *yvals[1] = {slugs.s};
  CarolinaResult *yrs = exec_params(
      c,
      "SELECT DISTINCT speaker_slug, year FROM v1_talks WHERE speaker_slug = ANY($1::text[]) "
      "ORDER BY speaker_slug, year DESC",
      1, yvals);
  if (res_ok(yrs)) {
    for (int i = 0; i < yrs->nrows; i++) {
      int row = speaker_row_for_slug(speakers, q_col(yrs, i, "speaker_slug"));
      if (row < 0) continue;
      YearExtras *e = &ex[row];
      if (e->nyears) buf_puts(&e->years, ",");
      buf_printf(&e->years, "%d", as_int(q_col(yrs, i, "year")));
      e->nyears++;
    }
  }
  if (yrs) carolina_result_free(yrs);
  buf_free(&slugs);
}

static void write_year_speaker_list(PGconn *c, const char *ybuf, CarolinaResult *speakers, Buf *body) {
  int n = speakers->nrows;
  YearExtras *ex = calloc((size_t)(n > 0 ? n : 1), sizeof(*ex));
  if (!ex) abort();
  for (int i = 0; i < n; i++) {
    buf_init(&ex[i].talks);
    buf_init(&ex[i].langs);
    buf_init(&ex[i].topics);
    buf_init(&ex[i].years);
    buf_puts(&ex[i].talks, "[");
  }
  load_year_extras(c, ybuf, speakers, ex);

  Obj root;
  obj_begin(&root, body);
  obj_key(&root, "data");
  buf_puts(body, "[");
  for (int i = 0; i < n; i++) {
    if (i) buf_puts(body, ",");
    buf_puts(&ex[i].talks, "]");
    Buf langarr, toparr, years;
    buf_init(&langarr);
    buf_init(&toparr);
    buf_init(&years);
    buf_puts(&langarr, "[");
    if (ex[i].langs.s) buf_puts(&langarr, ex[i].langs.s);
    buf_puts(&langarr, "]");
    buf_puts(&toparr, "[");
    if (ex[i].topics.s) buf_puts(&toparr, ex[i].topics.s);
    buf_puts(&toparr, "]");
    buf_puts(&years, "[");
    if (ex[i].years.s) buf_puts(&years, ex[i].years.s);
    buf_puts(&years, "]");
    Obj o;
    obj_begin(&o, body);
    speaker_fields(&o, speakers, i);
    obj_int(&o, "year", atoi(ybuf));
    obj_raw(&o, "talks", ex[i].talks.s);
    obj_raw(&o, "languages", langarr.s);
    obj_raw(&o, "topics", toparr.s);
    obj_raw(&o, "years", years.s);
    obj_end(&o);
    buf_free(&langarr);
    buf_free(&toparr);
    buf_free(&years);
    buf_free(&ex[i].talks);
    buf_free(&ex[i].langs);
    buf_free(&ex[i].topics);
    buf_free(&ex[i].years);
  }
  buf_puts(body, "]");
  obj_end(&root);
  free(ex);
}

static void sponsorships_json(PGconn *c, const char *slug, Buf *out) {
  const char *vals[1] = {slug};
  CarolinaResult *r = exec_params(c,
                                  "SELECT sponsor_slug, year, tier, blurb, featured FROM v1_sponsorships "
                                  "WHERE sponsor_slug = $1 ORDER BY year DESC",
                                  1, vals);
  buf_puts(out, "[");
  int n = 0;
  if (res_ok(r)) {
    for (int i = 0; i < r->nrows; i++) {
      if (n) buf_puts(out, ",");
      Obj o;
      obj_begin(&o, out);
      obj_str(&o, "sponsor_slug", q_col(r, i, "sponsor_slug"));
      obj_int(&o, "year", as_int(q_col(r, i, "year")));
      obj_str(&o, "tier", q_col(r, i, "tier"));
      obj_str(&o, "blurb", q_col(r, i, "blurb"));
      obj_bool(&o, "featured", truthy(q_col(r, i, "featured")));
      obj_end(&o);
      n++;
    }
  }
  buf_puts(out, "]");
  if (r) carolina_result_free(r);
}

static void identity_json(Buf *b) {
  Obj o;
  obj_begin(&o, b);
  obj_str(&o, "language", kLanguage);
  obj_str(&o, "language_version", kLanguageVersion);
  obj_str(&o, "api_version", kApiVersion);
  obj_str(&o, "framework", kFramework);
  obj_int(&o, "created_year", kCreatedYear);
  obj_int(&o, "schema_version", kSchemaVersion);
  obj_raw(&o, "endpoints", kEndpointsJson);
  obj_end(&o);
}

static int all_digits(const char *s) {
  if (!s || !*s) return 0;
  for (; *s; s++)
    if (!isdigit((unsigned char)*s)) return 0;
  return 1;
}

static void url_decode(char *s) {
  char *d = s;
  while (*s) {
    if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
      char hex[3] = {s[1], s[2], 0};
      *d++ = (char)strtol(hex, NULL, 16);
      s += 3;
    } else if (*s == '+') {
      *d++ = ' ';
      s++;
    } else {
      *d++ = *s++;
    }
  }
  *d = 0;
}

static char *query_get(char *qs, const char *key) {
  if (!qs) return NULL;
  char *p = qs;
  while (p && *p) {
    char *amp = strchr(p, '&');
    if (amp) *amp = 0;
    char *eq = strchr(p, '=');
    if (eq) {
      *eq = 0;
      url_decode(p);
      url_decode(eq + 1);
      if (strcmp(p, key) == 0) return eq + 1;
    }
    p = amp ? amp + 1 : NULL;
  }
  return NULL;
}

static int split_path(char *path, char **parts, int max) {
  int n = 0;
  char *p = path;
  if (*p == '/') p++;
  if (!*p) return 0;
  while (*p && n < max) {
    parts[n++] = p;
    char *slash = strchr(p, '/');
    if (!slash) break;
    *slash = 0;
    p = slash + 1;
    if (!*p) break;
  }
  return n;
}

typedef struct {
  int status;
  Buf body;
} Reply;

static void reply_init(Reply *r, int status) {
  r->status = status;
  buf_init(&r->body);
}

static void connect_failed(Reply *out) {
  out->status = 500;
  buf_free(&out->body);
  buf_init(&out->body);
  Obj o;
  obj_begin(&o, &out->body);
  obj_str(&o, "error", "connect failed");
  obj_end(&o);
}

static void fail_sql(Reply *out, CarolinaResult *r) {
  out->status = 500;
  buf_free(&out->body);
  buf_init(&out->body);
  Obj o;
  obj_begin(&o, &out->body);
  obj_str(&o, "error", (r && r->errmsg && r->errmsg[0]) ? r->errmsg : "query failed");
  obj_end(&o);
}

static void not_found(Reply *out) {
  out->status = 404;
  buf_free(&out->body);
  buf_init(&out->body);
  buf_puts(&out->body, "{\"error\":\"not_found\"}");
}

static void handle_get(const char *path_in, const char *qs_in, Reply *out) {
  char path[1024];
  char qsbuf[1024];
  snprintf(path, sizeof(path), "%s", path_in ? path_in : "/");
  snprintf(qsbuf, sizeof(qsbuf), "%s", qs_in ? qs_in : "");
  url_decode(path);
  char *parts[8] = {0};
  int nparts = split_path(path, parts, 8);
  char *year_q = query_get(qsbuf, "year");

  reply_init(out, 200);

  if (nparts == 0) {
    identity_json(&out->body);
    return;
  }
  if (nparts == 1 && strcmp(parts[0], "health") == 0) {
    buf_puts(&out->body, "{\"ok\":true}");
    return;
  }

  PGconn *c = db_acquire();
  if (!c) {
    connect_failed(out);
    return;
  }

  if (nparts == 2 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "years") == 0) {
    CarolinaResult *r = db_exec(c, "SELECT year, slug, name, status FROM v1_years ORDER BY year DESC");
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    buf_puts(&out->body, "[");
    for (int i = 0; i < r->nrows; i++) {
      if (i) buf_puts(&out->body, ",");
      Obj o;
      obj_begin(&o, &out->body);
      obj_int(&o, "year", as_int(q_col(r, i, "year")));
      obj_str(&o, "slug", q_col(r, i, "slug"));
      obj_str(&o, "name", q_col(r, i, "name"));
      obj_str(&o, "status", q_col(r, i, "status"));
      obj_end(&o);
    }
    buf_puts(&out->body, "]");
    obj_end(&root);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  if (nparts == 2 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "speakers") == 0) {
    CarolinaResult *r;
    char ybuf[16] = {0};
    if (year_q && *year_q) {
      snprintf(ybuf, sizeof(ybuf), "%d", atoi(year_q));
      char sql[1024];
      snprintf(sql, sizeof(sql),
               "SELECT %s FROM v1_speakers WHERE slug IN (SELECT speaker_slug FROM v1_talks WHERE year = $1) "
               "ORDER BY last_name, first_name",
               kSpeakerCols);
      const char *vals[1] = {ybuf};
      r = exec_params(c, sql, 1, vals);
    } else {
      char sql[1024];
      snprintf(sql, sizeof(sql), "SELECT %s FROM v1_speakers ORDER BY last_name, first_name", kSpeakerCols);
      r = db_exec(c, sql);
    }
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    if (year_q && *year_q) {
      write_year_speaker_list(c, ybuf, r, &out->body);
      carolina_result_free(r);
      db_release(c);
      return;
    }
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    buf_puts(&out->body, "[");
    for (int i = 0; i < r->nrows; i++) {
      if (i) buf_puts(&out->body, ",");
      Obj o;
      obj_begin(&o, &out->body);
      speaker_fields(&o, r, i);
      obj_end(&o);
    }
    buf_puts(&out->body, "]");
    obj_end(&root);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  if (nparts == 4 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "speakers") == 0 && all_digits(parts[2])) {
    char ybuf[16];
    snprintf(ybuf, sizeof(ybuf), "%d", atoi(parts[2]));
    const char *slug = parts[3];
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT %s FROM v1_speakers WHERE slug = $1", kSpeakerCols);
    const char *vals[1] = {slug};
    CarolinaResult *r = exec_params(c, sql, 1, vals);
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    if (r->nrows == 0) {
      carolina_result_free(r);
      db_release(c);
      not_found(out);
      return;
    }
    Buf talks, langs, topics, years, other;
    buf_init(&talks);
    buf_init(&langs);
    buf_init(&topics);
    buf_init(&years);
    buf_init(&other);
    int nt = 0;
    talks_json(c, slug, ybuf, &talks, &langs, &topics, &nt);
    if (nt == 0) {
      buf_free(&talks);
      buf_free(&langs);
      buf_free(&topics);
      buf_free(&years);
      buf_free(&other);
      carolina_result_free(r);
      db_release(c);
      not_found(out);
      return;
    }
    year_lists(c, "SELECT DISTINCT year FROM v1_talks WHERE speaker_slug = $1 ORDER BY year DESC", slug, atoi(ybuf), 1,
               &years, &other);
    Buf langarr, toparr;
    buf_init(&langarr);
    buf_init(&toparr);
    buf_puts(&langarr, "[");
    if (langs.s) buf_puts(&langarr, langs.s);
    buf_puts(&langarr, "]");
    buf_puts(&toparr, "[");
    if (topics.s) buf_puts(&toparr, topics.s);
    buf_puts(&toparr, "]");
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    Obj o;
    obj_begin(&o, &out->body);
    speaker_fields(&o, r, 0);
    obj_int(&o, "year", atoi(ybuf));
    obj_raw(&o, "years", years.s);
    obj_raw(&o, "other_years", other.s);
    obj_raw(&o, "talks", talks.s);
    obj_raw(&o, "languages", langarr.s);
    obj_raw(&o, "topics", toparr.s);
    obj_end(&o);
    obj_end(&root);
    buf_free(&talks);
    buf_free(&langs);
    buf_free(&topics);
    buf_free(&years);
    buf_free(&other);
    buf_free(&langarr);
    buf_free(&toparr);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  if (nparts == 3 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "speakers") == 0) {
    const char *slug = parts[2];
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT %s FROM v1_speakers WHERE slug = $1", kSpeakerCols);
    const char *vals[1] = {slug};
    CarolinaResult *r = exec_params(c, sql, 1, vals);
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    if (r->nrows == 0) {
      carolina_result_free(r);
      db_release(c);
      not_found(out);
      return;
    }
    Buf talks, langs, topics, years;
    buf_init(&talks);
    buf_init(&langs);
    buf_init(&topics);
    buf_init(&years);
    int nt = 0;
    talks_json(c, slug, NULL, &talks, &langs, &topics, &nt);
    year_lists(c, "SELECT DISTINCT year FROM v1_talks WHERE speaker_slug = $1 ORDER BY year DESC", slug, 0, 0, &years,
               NULL);
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    Obj o;
    obj_begin(&o, &out->body);
    speaker_fields(&o, r, 0);
    obj_raw(&o, "talks", talks.s);
    obj_raw(&o, "years", years.s);
    obj_end(&o);
    obj_end(&root);
    buf_free(&talks);
    buf_free(&langs);
    buf_free(&topics);
    buf_free(&years);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  if (nparts == 2 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "sponsors") == 0) {
    CarolinaResult *r;
    if (year_q && *year_q) {
      char ybuf[16];
      snprintf(ybuf, sizeof(ybuf), "%d", atoi(year_q));
      char sql[1024];
      snprintf(sql, sizeof(sql), "SELECT %s FROM v1_year_sponsors WHERE year = $1 ORDER BY name", kYearSponsorCols);
      const char *vals[1] = {ybuf};
      r = exec_params(c, sql, 1, vals);
    } else {
      char sql[1024];
      snprintf(sql, sizeof(sql), "SELECT %s FROM v1_sponsors ORDER BY name", kSponsorCols);
      r = db_exec(c, sql);
    }
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    buf_puts(&out->body, "[");
    for (int i = 0; i < r->nrows; i++) {
      if (i) buf_puts(&out->body, ",");
      Obj o;
      obj_begin(&o, &out->body);
      if (year_q && *year_q) year_sponsor_fields(&o, r, i);
      else
        sponsor_fields(&o, r, i);
      obj_end(&o);
    }
    buf_puts(&out->body, "]");
    obj_end(&root);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  if (nparts == 4 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "sponsors") == 0 && all_digits(parts[2])) {
    char ybuf[16];
    snprintf(ybuf, sizeof(ybuf), "%d", atoi(parts[2]));
    const char *slug = parts[3];
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT %s FROM v1_year_sponsors WHERE year = $1 AND slug = $2", kYearSponsorCols);
    const char *vals[2] = {ybuf, slug};
    CarolinaResult *r = exec_params(c, sql, 2, vals);
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    if (r->nrows == 0) {
      carolina_result_free(r);
      db_release(c);
      not_found(out);
      return;
    }
    Buf years, other;
    buf_init(&years);
    buf_init(&other);
    year_lists(c, "SELECT DISTINCT year FROM v1_sponsorships WHERE sponsor_slug = $1 ORDER BY year DESC", slug,
               atoi(ybuf), 1, &years, &other);
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    Obj o;
    obj_begin(&o, &out->body);
    year_sponsor_fields(&o, r, 0);
    obj_raw(&o, "years", years.s);
    obj_raw(&o, "other_years", other.s);
    obj_end(&o);
    obj_end(&root);
    buf_free(&years);
    buf_free(&other);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  if (nparts == 3 && strcmp(parts[0], "v1") == 0 && strcmp(parts[1], "sponsors") == 0) {
    const char *slug = parts[2];
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT %s FROM v1_sponsors WHERE slug = $1", kSponsorCols);
    const char *vals[1] = {slug};
    CarolinaResult *r = exec_params(c, sql, 1, vals);
    if (!res_ok(r)) {
      fail_sql(out, r);
      if (r) carolina_result_free(r);
      db_release(c);
      return;
    }
    if (r->nrows == 0) {
      carolina_result_free(r);
      db_release(c);
      not_found(out);
      return;
    }
    Buf sps;
    buf_init(&sps);
    sponsorships_json(c, slug, &sps);
    Obj root;
    obj_begin(&root, &out->body);
    obj_key(&root, "data");
    Obj o;
    obj_begin(&o, &out->body);
    sponsor_fields(&o, r, 0);
    obj_raw(&o, "sponsorships", sps.s);
    obj_end(&o);
    obj_end(&root);
    buf_free(&sps);
    carolina_result_free(r);
    db_release(c);
    return;
  }

  db_release(c);
  not_found(out);
}

static const char *status_text(int code) {
  switch (code) {
  case 200: return "OK";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 500: return "Internal Server Error";
  default: return "OK";
  }
}

static int set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int send_all(int fd, const char *data, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = send(fd, data + off, n - off, 0);
    if (w < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, 5000) <= 0) return -1;
        continue;
      }
      return -1;
    }
    if (w == 0) return -1;
    off += (size_t)w;
  }
  return 0;
}

static long long mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void write_http(int fd, int status, const char *body, size_t n) {
  char hdr[512];
  int hn = snprintf(hdr, sizeof(hdr),
                    "HTTP/1.1 %d %s\r\n"
                    "Content-Type: application/json\r\n"
                    "X-Polyglot-Language: %s\r\n"
                    "X-Polyglot-Framework: %s\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    status, status_text(status), kLanguage, kFramework, n);
  if (hn > 0) {
    size_t nsend = (size_t)hn < sizeof(hdr) ? (size_t)hn : sizeof(hdr) - 1;
    send_all(fd, hdr, nsend);
  }
  if (n && body) send_all(fd, body, n);
}

static int method_ok(const char *method) {
  return method && (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0);
}

static int dispatch(const char *method, const char *target, Reply *reply) {
  if (!method_ok(method)) {
    reply_init(reply, 405);
    buf_puts(&reply->body, "{\"error\":\"method_not_allowed\"}");
    return 405;
  }
  char pathbuf[2048];
  snprintf(pathbuf, sizeof(pathbuf), "%s", target ? target : "/");
  char *qmark = strchr(pathbuf, '?');
  const char *qs = "";
  if (qmark) {
    *qmark = 0;
    qs = qmark + 1;
  }
  handle_get(pathbuf, qs, reply);
  return reply->status;
}

static void complete_request(int fd, const char *req) {
  char method[16] = {0}, target[2048] = {0}, ver[16] = {0};
  if (sscanf(req, "%15s %2047s %15s", method, target, ver) != 3) {
    write_http(fd, 400, "{\"error\":\"bad_request\"}", 24);
    return;
  }
  Reply reply;
  dispatch(method, target, &reply);
  size_t n = reply.body.n;
  if (strcmp(method, "HEAD") == 0) n = 0;
  write_http(fd, reply.status, reply.body.s ? reply.body.s : "", n);
  buf_free(&reply.body);
}

typedef struct {
  int fd;
  size_t n;
  long long last_ms;
  char buf[REQ_MAX];
} Slot;

static void slot_close(Slot *s) {
  if (s->fd >= 0) close(s->fd);
  s->fd = -1;
  s->n = 0;
  s->buf[0] = 0;
}

/* 1 = slot finished (responded or failed). 0 = need more bytes. */
static int slot_consume(Slot *s) {
  for (;;) {
    if (strstr(s->buf, "\r\n\r\n") || strstr(s->buf, "\n\n")) {
      complete_request(s->fd, s->buf);
      return 1;
    }
    if (s->n >= sizeof(s->buf) - 1) {
      write_http(s->fd, 400, "{\"error\":\"bad_request\"}", 24);
      return 1;
    }
    ssize_t r = recv(s->fd, s->buf + s->n, sizeof(s->buf) - 1 - s->n, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
      return 1;
    }
    if (r == 0) return 1;
    s->n += (size_t)r;
    s->buf[s->n] = 0;
    s->last_ms = mono_ms();
  }
}

void carolina_serve_stop(void) { g_serve_stop = 1; }

void carolina_serve(int lfd) {
  set_nonblock(lfd);
  Slot *slots = calloc(MAX_INFLIGHT, sizeof(Slot));
  if (!slots) abort();
  for (int i = 0; i < MAX_INFLIGHT; i++) slots[i].fd = -1;

  while (!g_serve_stop) {
    struct pollfd pfds[MAX_INFLIGHT + 1];
    int map[MAX_INFLIGHT + 1];
    int np = 0;
    pfds[np].fd = lfd;
    pfds[np].events = POLLIN;
    pfds[np].revents = 0;
    map[np] = -1;
    np++;
    long long now = mono_ms();
    for (int i = 0; i < MAX_INFLIGHT; i++) {
      if (slots[i].fd < 0) continue;
      if (slots[i].last_ms != 0 && now - slots[i].last_ms > CONN_IDLE_MS) {
        slot_close(&slots[i]);
        continue;
      }
      pfds[np].fd = slots[i].fd;
      pfds[np].events = POLLIN;
      pfds[np].revents = 0;
      map[np] = i;
      np++;
    }
    int pr = poll(pfds, (nfds_t)np, 200);
    if (pr < 0) {
      if (errno == EINTR) continue;
      perror("poll");
      break;
    }
    if (pfds[0].revents & POLLIN) {
      for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
          if (errno == EINTR) continue;
          break;
        }
        int slot = -1;
        for (int i = 0; i < MAX_INFLIGHT; i++) {
          if (slots[i].fd < 0) {
            slot = i;
            break;
          }
        }
        if (slot < 0) {
          close(cfd);
          continue;
        }
        set_nonblock(cfd);
        slots[slot].fd = cfd;
        slots[slot].n = 0;
        slots[slot].buf[0] = 0;
        slots[slot].last_ms = mono_ms();
        if (slot_consume(&slots[slot])) slot_close(&slots[slot]);
      }
    }
    for (int pi = 1; pi < np; pi++) {
      short ev = pfds[pi].revents;
      if (!ev) continue;
      int si = map[pi];
      if (si < 0 || slots[si].fd < 0) continue;
      if (ev & (POLLERR | POLLNVAL)) {
        slot_close(&slots[si]);
        continue;
      }
      if (ev & (POLLIN | POLLHUP)) {
        if (slot_consume(&slots[si])) slot_close(&slots[si]);
      }
    }
  }

  for (int i = 0; i < MAX_INFLIGHT; i++) slot_close(&slots[i]);
  free(slots);
}

#ifndef CAROLINA_TEST
static int http_post(const char *host, const char *port, const char *path, const char *token, const char *body) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) {
    freeaddrinfo(res);
    return -1;
  }
  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  if (set_nonblock(fd) != 0) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  int crc = connect(fd, res->ai_addr, res->ai_addrlen);
  if (crc != 0 && errno != EINPROGRESS) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  if (crc != 0) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, 1000);
    int err = 0;
    socklen_t elen = sizeof(err);
    if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
      close(fd);
      freeaddrinfo(res);
      return -1;
    }
  }
  freeaddrinfo(res);
  char hdr[1024];
  int hn = snprintf(hdr, sizeof(hdr),
                    "POST %s HTTP/1.1\r\n"
                    "Host: %s:%s\r\n"
                    "Authorization: Bearer %s\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    path, host, port, token, strlen(body));
  if (hn < 0 || send(fd, hdr, (size_t)hn, 0) < 0 || send(fd, body, strlen(body), 0) < 0) {
    close(fd);
    return -1;
  }
  char resp[256];
  ssize_t n = recv(fd, resp, sizeof(resp) - 1, 0);
  if (n > 0) {
    resp[n] = 0;
    char *sp = strchr(resp, ' ');
    fprintf(stderr, "registered with elixir: %s\n", sp ? sp + 1 : resp);
  }
  close(fd);
  return 0;
}

static void parse_origin(const char *url, char *host, size_t hsz, char *port, size_t psz) {
  snprintf(host, hsz, "127.0.0.1");
  snprintf(port, psz, "4000");
  const char *p = url;
  if (strncmp(p, "http://", 7) == 0) p += 7;
  else if (strncmp(p, "https://", 8) == 0)
    p += 8;
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s", p);
  char *slash = strchr(tmp, '/');
  if (slash) *slash = 0;
  char *colon = strrchr(tmp, ':');
  if (colon && colon != tmp && !(tmp[0] == '[' && colon[-1] != ']')) {
    *colon = 0;
    snprintf(host, hsz, "%s", tmp);
    snprintf(port, psz, "%s", colon + 1);
  } else {
    snprintf(host, hsz, "%s", tmp);
    snprintf(port, psz, "80");
  }
}

static void *register_thread(void *arg) {
  (void)arg;
  struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000000L};
  nanosleep(&ts, NULL);
  const char *url = getenv("CAROLINA_URL");
  const char *token = getenv("POLYGLOT_REGISTER_TOKEN");
  if (!url || !*url || !token || !*token) return NULL;
  char host[256], port[16], base[256];
  parse_origin(url, host, sizeof(host), port, sizeof(port));
  const char *pub = getenv("PUBLIC_BASE_URL");
  if (pub && *pub) snprintf(base, sizeof(base), "%s", pub);
  else
    snprintf(base, sizeof(base), "http://127.0.0.1:%s", g_port);
  Buf body;
  buf_init(&body);
  Obj o;
  obj_begin(&o, &body);
  obj_str(&o, "language", kLanguage);
  obj_str(&o, "language_version", kLanguageVersion);
  obj_str(&o, "api_version", kApiVersion);
  obj_str(&o, "framework", kFramework);
  obj_int(&o, "created_year", kCreatedYear);
  obj_int(&o, "schema_version", kSchemaVersion);
  obj_str(&o, "base_url", base);
  obj_raw(&o, "endpoints", kEndpointsJson);
  obj_end(&o);
  if (http_post(host, port, "/internal/api-endpoints/register", token, body.s) != 0)
    fprintf(stderr, "register: failed\n");
  buf_free(&body);
  return NULL;
}
#endif

int carolina_listen_family(void) { return AF_INET6; }

int carolina_open_listener(int port) {
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int yes = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  int no = 0;
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  addr.sin6_port = htons((uint16_t)port);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  if (listen(fd, 128) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

void carolina_init(void) {
  snprintf(g_dsn, sizeof(g_dsn), "%s",
           env_or("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/carolina_dev"));
  snprintf(g_port, sizeof(g_port), "%s", env_or("PORT", "4014"));
}

void carolina_reset_counts(void) {
  g_sql_count = 0;
  g_connect_count = 0;
}

int carolina_sql_count(void) { return g_sql_count; }

int carolina_connect_count(void) { return g_connect_count; }

void carolina_set_connect_fn(PGconn *(*fn)(const char *)) {
  pthread_mutex_lock(&g_db_mu);
  for (int i = 0; i < DB_POOL_SIZE; i++) {
    if (g_db_pool[i] && !g_connect_fn) PQfinish(g_db_pool[i]);
    g_db_pool[i] = NULL;
    g_db_busy[i] = 0;
    g_db_bad[i] = 0;
  }
  g_connect_fn = fn;
  pthread_mutex_unlock(&g_db_mu);
}

void carolina_set_query_fn(carolina_query_fn fn) { g_query_fn = fn; }

PGconn *carolina_db_acquire(void) { return db_acquire(); }

void carolina_db_release(PGconn *c) { db_release(c); }

int carolina_handle_get_copy(const char *path, const char *qs, char *buf, size_t buflen) {
  Reply reply;
  handle_get(path, qs, &reply);
  int status = reply.status;
  if (buf && buflen) snprintf(buf, buflen, "%s", reply.body.s ? reply.body.s : "");
  buf_free(&reply.body);
  return status;
}

int carolina_handle_http(const char *method, const char *target, char *buf, size_t buflen) {
  Reply reply;
  int status = dispatch(method, target, &reply);
  if (buf && buflen) {
    if (method && strcmp(method, "HEAD") == 0) buf[0] = 0;
    else
      snprintf(buf, buflen, "%s", reply.body.s ? reply.body.s : "");
  }
  buf_free(&reply.body);
  return status;
}

#ifndef CAROLINA_TEST
int main(void) {
  signal(SIGPIPE, SIG_IGN);
  carolina_init();
  int port = atoi(g_port);
  if (port <= 0) port = 4014;

  int fd = carolina_open_listener(port);
  if (fd < 0) {
    perror("bind");
    return 1;
  }

  pthread_t rt;
  pthread_create(&rt, NULL, register_thread, NULL);
  pthread_detach(rt);

  fprintf(stderr, "carolina-codes-c listening on :%d\n", port);
  carolina_serve(fd);
  close(fd);
  return 0;
}
#endif
