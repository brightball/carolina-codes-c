# carolina-codes-c

Read-only v1 polyglot API. This tree is a finished C11 server: POSIX sockets and libpq. See `README.md` for the language standard, why there is no framework semver, package versions, and the run commands.

`make check` (and `make hooks` for pre-commit) runs `test`, `sast`, `vuln`, `secrets`, and `fmt-check`: the shipped tests, cppcheck, osv-scanner, gitleaks, and clang-format `--dry-run`.

## Workspace

This git root is the workspace. The Phoenix CMS is a different remote (`github.com/brightball/carolina-codes`). Do not assume `../elixir` or any other sibling checkout exists. Do not fold this tree into the CMS git remote.

The HTTP contract is the CMS `priv/api/openapi.yaml` and `priv/api/AGENTS.md`. This repo does not ship `openapi.yaml`, `db/`, Compose, or seed images.

## Contract rules

These starter rules are what this API implements:

1. Query PostgreSQL `v1_*` views only. Never query Ash tables. Do not implement Ash JSON:API (`application/vnd.api+json`). Responses are ordinary JSON.
2. Serve the required v1 routes below. Unknown slugs return 404. There are no writes.
3. Register once on boot with the CMS. Do not heartbeat. If `CAROLINA_URL` is empty or the POST fails, registration no-ops when the CMS is down and the process keeps serving.
4. `GET /health` does not touch the database (no connect, no SQL). The body is `{"ok":true}`.

Views this process selects from: `v1_speakers`, `v1_sponsors`, `v1_years`, `v1_talks`, `v1_sponsorships`, `v1_year_sponsors`. The CMS database (Postgres 16) owns those views. Handler and unit tests use a fake catalog and do not need Postgres.

Year-scoped speaker rows come from `v1_speakers` filtered by `v1_talks` (languages and topics). Year-scoped sponsor rows come from `v1_year_sponsors` and include `tier` and `blurb`. `photo_path` and `logo_path` are returned as paths. This process does not serve image bytes.

## Routes

List payloads are `{ "data": [ ... ] }`.

- `GET /health` — `{"ok":true}`, no database
- `GET /` — identity (`language`, `language_version`, `api_version`, `framework`, `created_year`, `schema_version`, `endpoints`). No database.
- `GET /v1/years`
- `GET /v1/speakers` and `GET /v1/speakers?year=`
- `GET /v1/speakers/{slug}` and `GET /v1/speakers/{year}/{slug}`
- `GET /v1/sponsors` and `GET /v1/sponsors?year=`
- `GET /v1/sponsors/{slug}` and `GET /v1/sponsors/{year}/{slug}`

`framework` is the string `POSIX sockets` (no framework semver). `language_version` is the compiler `__VERSION__`.

## Register once

`POST {CAROLINA_URL}/internal/api-endpoints/register` with `Authorization: Bearer {POLYGLOT_REGISTER_TOKEN}` and `Content-Type: application/json`.

Body fields: `language`, `language_version`, `api_version`, `framework`, `created_year`, `base_url` (`PUBLIC_BASE_URL`), `schema_version` (1), `endpoints` (method, path, and query keys).

The register thread does not open Postgres. An empty `CAROLINA_URL` or `POLYGLOT_REGISTER_TOKEN` returns without posting. A failed POST logs `register: failed` and the listener stays up.

## Environment

| Variable | Example | Role |
|---|---|---|
| `DATABASE_URL` | `postgres://postgres:postgres@127.0.0.1:5432/carolina_dev` | CMS `v1_*` views |
| `CAROLINA_URL` | `http://127.0.0.1:4000` | CMS base URL (optional; registration no-ops if empty or the CMS is down) |
| `POLYGLOT_REGISTER_TOKEN` | `dev` | Bearer token for register |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:4014` | URL the CMS will call |
| `PORT` | `4014` | Listen port (the container image sets `8080`) |

For live HTTP against the views, start Postgres 16 and set those variables. Fake-catalog tests do not.

## Build

`make` (or `make api`) builds the production binary with `-std=c11 -O2` and links it stripped (`-s`). That binary is unsanitized. ASan, UBSan, and `-Werror` apply only to `make test` (`perf_test`).

The listener is IPv6 (`AF_INET6`, `IPV6_V6ONLY` off) so Fly 6PN and IPv4-mapped clients both reach it.

## Quality commands

```bash
make test
make sast
make vuln
make secrets
make fmt-check
make check
make hooks
```

## Decisions and memory

Plain C with POSIX sockets has no framework convention for agent memory. This repo keeps two files:

- `DECISIONS.md` records why a durable choice was made (status, context, decision, consequences). Append a record when a durable choice is added or changed. Leave an accepted record's text in place and supersede it with a newer record.
- `MEMORY.md` is a short index of operational facts that are easy to get wrong. Update it when an operational fact changes and no new choice was made.

Read both before changing listen behavior, SQL, registration, the production flags, or the contract boundary.
