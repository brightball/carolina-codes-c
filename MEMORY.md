# Memory

Short index of operational facts that are easy to get wrong. Update this file when an operational fact changes. Append to `DECISIONS.md` when a durable choice is added or changed.

## Workspace

- This git root is the workspace. The CMS remote is `github.com/brightball/carolina-codes`. Do not assume a sibling checkout such as `../elixir` exists.
- Do not fold this tree into the CMS git remote.

## Contract and data

- The CMS owns the `v1_*` views and the contract (`priv/api/openapi.yaml`, `priv/api/AGENTS.md`).
- This process queries `v1_speakers`, `v1_sponsors`, `v1_years`, `v1_talks`, `v1_sponsorships`, and `v1_year_sponsors`. Never query Ash tables. Do not speak Ash JSON:API.
- Live HTTP against the views uses the CMS database, Postgres 16. Fake-catalog handler tests need no Postgres.
- This repo has no `openapi.yaml`, `db/`, Compose file, or seed images.

## Runtime

- Language standard is C11 (`-std=c11`). Framework string is `POSIX sockets` (no framework semver). API version is `0.2.0`. `schema_version` is 1. `created_year` is 2026.
- Identity `language_version` is the compiler `__VERSION__` from Debian bookworm gcc in the image. The source falls back to the string `C11` only when `__VERSION__` is absent.
- Runtime library is libpq. Image package `libpq5` is `15.19-0+deb12u1`, as recorded in `sbom.cdx.json` (build image installs `libpq-dev` at the same version).
- Production binary is unsanitized: `-O2`, no ASan, no UBSan, stripped with `-s`. ASan, UBSan, and `-Werror` are only on the test binary (`make test`).
- Listen family is `AF_INET6` with `IPV6_V6ONLY` off (Fly 6PN and IPv4-mapped clients).
- Register once on boot, then stop. No heartbeat. Registration no-ops when `CAROLINA_URL` or `POLYGLOT_REGISTER_TOKEN` is empty, and it logs and keeps serving if the POST fails or the CMS is down. The register thread does not open Postgres.
- `GET /health` returns `{"ok":true}` and does not connect or run SQL. `GET /` (identity) also skips the database.
- Process default `PORT` is `4014`. The container image and Fly set `8080`.
- Default `DATABASE_URL` is `postgres://postgres:postgres@127.0.0.1:5432/carolina_dev`.
- The libpq pool holds 8 connections. `MAX_INFLIGHT` is 64 so slow clients cannot exhaust the 256 MB Fly machine.

## Quality

- `make test`, `make sast` (cppcheck), `make vuln` (osv-scanner on `sbom.cdx.json`), `make secrets` (gitleaks), `make fmt-check` (clang-format), `make check`, `make hooks`.
