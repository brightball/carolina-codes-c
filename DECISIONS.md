# Decisions

Durable choices for this API. C with POSIX sockets has no framework memory convention, so this file is the record. Each entry has a status, context, decision, and consequences.

Append a record when a durable choice is added or changed. Do not rewrite an accepted decision; supersede it with a newer record that names it. When a fact changes and the choice does not, edit `MEMORY.md` instead.

## D1. POSIX sockets instead of a C web framework

- Status: accepted
- Context: The starter is a replaceable language runtime, not a finished server. This API only needs a small read-only JSON surface. Pulling in a C HTTP framework would add a library the Debian bookworm image does not ship.
- Decision: Serve HTTP with POSIX sockets in `src/main.c`. The identity `framework` string is `POSIX sockets`. There is no framework semver.
- Consequences: Request limits, the idle timeout, and the poll loop live in this tree. `language_version` stays the compiler `__VERSION__`, not a framework release.

## D2. libpq against v1_* views

- Status: accepted
- Context: The CMS publishes read-only PostgreSQL `v1_*` views. Ash resource tables and Ash JSON:API are not the polyglot contract.
- Decision: Use libpq, and only SQL against `v1_speakers`, `v1_sponsors`, `v1_years`, `v1_talks`, `v1_sponsorships`, and `v1_year_sponsors`. Never query Ash tables.
- Consequences: Schema and view changes belong to the CMS. This repo does not ship `db/*.sql`. Handler tests inject a fake catalog and do not need Postgres.

## D3. ASan and UBSan only on the test binary

- Status: accepted
- Context: The Fly machine is 256 MB. Address and undefined-behavior sanitizers multiply memory use and do not belong in the image that serves traffic.
- Decision: Production `CFLAGS` are `-std=c11 -O2 -Wall -Wextra -pthread`, and the production link passes `-s`. The test binary adds `-Werror` and `-fsanitize=address,undefined`. `make test` runs that binary with ASan and UBSan halt options.
- Consequences: The production binary is unsanitized and stripped. Sanitizer findings show up in `make test`, not in the Fly process.

## D4. IPv6 listen for Fly 6PN

- Status: accepted
- Context: Fly private networking is IPv6. An IPv4-only listener is unreachable on 6PN.
- Decision: `carolina_listen_family` returns `AF_INET6`. The listener binds `in6addr_any` with `IPV6_V6ONLY` off so IPv4-mapped clients still connect.
- Consequences: Catalog routes and `GET /health` are dual-stack. Tests still assert the listen family when the host cannot bind IPv6.

## D5. Register once, fail-open

- Status: accepted
- Context: The CMS keeps at most one language API warm. The starter requires one register POST on boot and no heartbeat. A missing or down CMS must not stop HTTP.
- Decision: `main` starts `register_thread` once and detaches it. The thread returns without posting when `CAROLINA_URL` or `POLYGLOT_REGISTER_TOKEN` is empty. A failed POST logs `register: failed` and the server keeps serving. The thread does not open Postgres.
- Consequences: There is no retry loop and no heartbeat. Operators read stderr for a failed register. Routes keep responding.

## D6. Quality-gate tools

- Status: accepted
- Context: The same checks should run locally, as pre-commit hooks, and as parallel CI jobs.
- Decision: `make test` runs the shipped tests. `make sast` runs cppcheck. `make vuln` runs osv-scanner on `sbom.cdx.json`. `make secrets` runs gitleaks. `make fmt-check` runs clang-format `--dry-run --Werror`. `make check` runs all five. `make hooks` installs them.
- Consequences: Format, secret, SAST, and SBOM findings fail the gate on their own. Unit tests do not stand in for those tools.

## D7. Contract lives in the CMS

- Status: accepted
- Context: The starter ships `openapi.yaml`, Compose, and seed SQL for a fork that has not integrated yet. This API is already integrated with the CMS.
- Decision: The contract is the CMS `priv/api/openapi.yaml` and `priv/api/AGENTS.md`. This repo does not vendor that OpenAPI file, `db/`, Compose, or seed images.
- Consequences: Route and payload changes start in the CMS contract. Agents treat this git root as the workspace and do not fold the tree into the CMS remote. The `v1_*` views live in the CMS database (Postgres 16).
