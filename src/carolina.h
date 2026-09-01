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

void carolina_init(void);
void carolina_reset_counts(void);
int carolina_sql_count(void);
int carolina_connect_count(void);
void carolina_set_connect_fn(PGconn *(*fn)(const char *));
PGconn *carolina_db_acquire(void);
void carolina_db_release(PGconn *c);
int carolina_listen_family(void);
int carolina_open_listener(int port);
int carolina_handle_get_copy(const char *path, const char *qs, char *buf, size_t buflen);

#endif
