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

Quality gates (same commands locally, as pre-commit hooks, and as parallel Gitea jobs):

```bash
make test        # shipped C handler/unit tests
make sast        # cppcheck on src/
make vuln        # osv-scanner on Dockerfile/libpq SBOM
make secrets     # gitleaks detect
make fmt-check   # clang-format --dry-run --Werror
make check       # all five, sequentially
```

Install local pre-commit hooks once:

```bash
make hooks
```

That points `core.hooksPath` at `.githooks/` and installs the Python `pre-commit` runner so each of the five checks is its own hook from `.pre-commit-config.yaml`. Emergency skip: `SKIP=test,sast,vuln,secrets,fmt git commit`.
