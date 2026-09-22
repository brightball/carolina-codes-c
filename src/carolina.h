#ifndef CAROLINA_H
#define CAROLINA_H

#include <stddef.h>
#if defined(__has_include)
#if __has_include(<postgresql/libpq-fe.h>)
#include <postgresql/libpq-fe.h>
#else
#include <libpq-fe.h>
#endif
#else
#include <libpq-fe.h>
#endif

typedef struct CarolinaResult CarolinaResult;

CarolinaResult *carolina_result_table(int nrows, int ncols, const char **names, const char **cells);
CarolinaResult *carolina_result_fail(const char *error, int conn_failed);

typedef CarolinaResult *(*carolina_query_fn)(PGconn *conn, const char *sql, int nparams, const char *const *params);

void carolina_init(void);
void carolina_reset_counts(void);
int carolina_sql_count(void);
int carolina_connect_count(void);
void carolina_set_connect_fn(PGconn *(*fn)(const char *));
void carolina_set_query_fn(carolina_query_fn fn);
PGconn *carolina_db_acquire(void);
void carolina_db_release(PGconn *c);
int carolina_listen_family(void);
int carolina_open_listener(int port);
int carolina_handle_get_copy(const char *path, const char *qs, char *buf, size_t buflen);
int carolina_handle_http(const char *method, const char *target, char *buf, size_t buflen);
void carolina_serve(int listen_fd);
void carolina_serve_stop(void);

#endif
