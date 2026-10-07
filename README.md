# carolina-codes-c

Read-only v1 polyglot API for Carolina Code Conference.

The language standard is **C11** (`-std=c11`). There is no framework semver: the framework is **POSIX sockets**. Identity `language_version` is the compiler `__VERSION__` (Debian bookworm gcc in the image). API version is `0.2.0`.

Notable packages:

- **libpq** / **libpq5** `15.19-0+deb12u1` (Debian bookworm; the build image installs `libpq-dev` at the same version). The version is the one recorded in `sbom.cdx.json`.
- **cppcheck** — static analysis (`make sast`)
- **clang-format** — style check (`make fmt-check`)
- **osv-scanner** — dependency scan of the Dockerfile libpq SBOM (`make vuln`)
- **gitleaks** — secret scan (`make secrets`)

Queries PostgreSQL `v1_*` views. Registers with the CMS once on boot.

```bash
make
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/carolina_dev \
CAROLINA_URL=http://127.0.0.1:4000 \
POLYGLOT_REGISTER_TOKEN=dev \
PUBLIC_BASE_URL=http://127.0.0.1:4014 \
PORT=4014 \
./api
```

Quality gates (same commands locally, as pre-commit hooks, and as parallel CI jobs):

```bash
make test        # shipped C handler/unit tests
make sast        # cppcheck on src/
make vuln        # osv-scanner on Dockerfile/libpq SBOM
make secrets     # gitleaks detect
make fmt-check   # clang-format --dry-run --Werror
make check       # all five, sequentially
```

`make` builds the production binary unsanitized (`-O2`, stripped). ASan and UBSan run only under `make test`.

Install local pre-commit hooks once:

```bash
make hooks
```

That points `core.hooksPath` at `.githooks/` and installs the Python `pre-commit` runner so each of the five checks is its own hook from `.pre-commit-config.yaml`. Emergency skip: `SKIP=test,sast,vuln,secrets,fmt git commit`.

Agent constraints, routes, and environment variables are in `AGENTS.md`. Durable choices are in `DECISIONS.md`. Operational facts are in `MEMORY.md`.
