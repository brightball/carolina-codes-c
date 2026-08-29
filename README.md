# carolina-codes-c

Read-only v1 polyglot API for Carolina Code Conference. C11 POSIX sockets + libpq.

Queries PostgreSQL `v1_*` views. Registers with Elixir once on boot.

```bash
make
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/carolina_dev \
CAROLINA_URL=http://127.0.0.1:4000 \
POLYGLOT_REGISTER_TOKEN=dev \
PUBLIC_BASE_URL=http://127.0.0.1:4014 \
PORT=4014 \
./api
```
