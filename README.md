# pipesor-log-event-service

Log/Event Service registers and queries sanitized evidence, metadata and excerpts in PostgreSQL, preserving provenance and references to original GitHub workflow logs. Its canonical architecture ID is `log_event_service`; the planned runtime is Java / Spring Boot on Azure Container Apps.

This repository is a deployable Spring Boot service (Java 25, Spring Boot 4.1.2).
It consumes `protected_workflow_evidence` from Service Bus, confirms each
event with Pipeline, stores the sanitized evidence in PostgreSQL schema
`evidence`, and answers Correlation's scoped membership checks. Identity,
profiles and runtime inputs follow the platform identity contract v1 and the
runtime manifest in `pipesor-docs`. The [architecture
record](docs/architecture.md#first-evidence-registration-increment) describes
the selected identity, replay semantics and remaining integration decisions.

Log/Event exposes no human API in the MVP: the [MVP HTTP
API](https://github.com/pipesor-org/pipesor-docs/blob/main/docs/architecture/contracts/mvp-http-api-v1.md)
lists no Log/Event route for the dashboard, so no session scope is accepted
by any route.

## Routes

| Method and path | Caller | Notes |
|---|---|---|
| `POST /internal/v1/evidence/membership-checks` | workload `correlation`, role `Correlation.EvidenceMembership.Check` | Correlation evidence membership v1; `Cache-Control: no-store`; fixed `application/problem+json` errors |
| `GET /.well-known/jwks.json` | unauthenticated | public signing keys, `Cache-Control: public, max-age=300` |
| `GET /actuator/health/liveness`, `GET /actuator/health/readiness` | unauthenticated | readiness includes PostgreSQL and the Service Bus processor |

Every other route is denied. Missing or invalid tokens get `401`, a valid
token for another caller or role gets `403`, and a repeated or malformed
`Authorization` header gets `400`.

Outbound: `POST {PIPESOR_ENDPOINTS_PIPELINE}/internal/v1/evidence/operational-reference-checks`
with a workload token for target `pipeline`, role `Evidence.Check`.

## Messaging

Subscription `log-event` on topic `workflow-evidence` (filter
`eventType = 'protected_workflow_evidence'`, `schemaMajor` 2). Accepted body
versions: 2.0, 2.1 (single-line Verify locator) and 2.2 (generalized member,
up to 200 lines). Settlement:

| Result | Settlement |
|---|---|
| registered or identical replay | complete |
| Pipeline `NOT_READY` or unavailable, store unavailable | abandon (redelivery; the subscription's max delivery count bounds retries) |
| invalid envelope, unsupported event, conflict, `DENIED`, `MISMATCH` | dead-letter with a fixed reason (`INVALID_PROTECTED_EVIDENCE`, `UNSUPPORTED_EVENT`, `EVIDENCE_CONFLICT`, `EVIDENCE_DENIED`, `REFERENCE_MISMATCH`) |

Logs carry the outcome, message ID and correlation ID, never payloads,
excerpts, tokens or exception messages.

## Configuration

One image; the profile selects adapters. Values come from the environment.

| Variable | Profile | Meaning |
|---|---|---|
| `SPRING_PROFILES_ACTIVE` | both | `local` or `azure` |
| `PIPESOR_TENANT_ID` | both | environment tenant; membership requests for another tenant are `DENIED` |
| `PIPESOR_WORKLOAD_ID` | both | `log-event` |
| `PIPESOR_SECURITY_AUDIENCE` | both | `urn:pipesor:api:log-event` |
| `PIPESOR_SECURITY_TRUSTEDWORKLOADS_0_ID` / `_JWKSURI` / `_ROLES` | both | `correlation`, its JWKS URI, `Correlation.EvidenceMembership.Check` |
| `PIPESOR_ENDPOINTS_PIPELINE` | both | Pipeline base URL |
| `PIPESOR_DATABASE_URL`, `PIPESOR_DATABASE_USERNAME` | both | PostgreSQL database `pipesor` |
| `PIPESOR_DATABASE_PASSWORD` | local | password authentication |
| `PIPESOR_SIGNING_KEY_FILE` | local | PKCS#8 PEM, mode 0600 |
| `PIPESOR_SERVICE_BUS_CONNECTION_STRING` | local | emulator connection string |
| `PIPESOR_SIGNING_KEY_ID` | azure | Key Vault key `pipesor-log-event-signing` |
| `PIPESOR_SERVICE_BUS_NAMESPACE` | azure | fully qualified namespace; `DefaultAzureCredential` (managed identity) |
| `PIPESOR_SERVICE_BUS_TOPIC` / `_SUBSCRIPTION` | both | default `workflow-evidence` / `log-event` |
| `SERVER_PORT` | both | `8080` in the image; `8083` on the local stack |

Under `azure`, PostgreSQL uses Entra tokens through
`azure-identity-extensions` (`AzurePostgresqlAuthenticationPlugin`, `sslmode=require`);
no password is configured. A connection string or PEM key fails startup
outside `local`, and plain HTTP is allowed only to loopback hosts under `local`.
`PIPESOR_SECURITY_SESSION_JWKSURI` is accepted but unused, since no route takes
session tokens. Limits (event bytes, Pipeline timeout and response size,
membership deadline, body/header size and concurrency) are under
`pipesor.log-event.*` in `src/main/resources/application.yml`.

Flyway runs at startup on schema `evidence` with history table
`flyway_history_log_event`, `baseline-on-migrate=true` and
`baseline-version=0`, so V1 still runs when Correlation created the shared
schema first.

## Documentation

- [Documentation baseline](docs/documentation-baseline.md): audited source revisions, evidence limits and adoption after merge.

- [Architecture](docs/architecture.md): service boundaries, integration context and current sources in `pipesor-docs`.
- [Deployment contract](docs/deployment-contract.md): development baseline, delivery requirements and unresolved contracts.
- [AGENTS.md](AGENTS.md): repository instructions for coding agents.

## Development and verification

Use Java 25 and Docker (Testcontainers starts disposable PostgreSQL 17.11).
The [development baseline](docs/deployment-contract.md#development-baseline)
records dependency policy. Run the verified build with:

```bash
./mvnw -B -ntp verify
```

The checks cover input shape, the UUIDv5 vector already used by NLP,
authority before lookup/write, migration ownership, replay, conflicts,
concurrent insertion, scoped membership, protected 2.0/2.1/2.2 decoding,
Pipeline response binding, Service Bus settlement, platform token
verification and the full application under the `local` profile (Flyway
history, probes, JWKS, caller and role restrictions, fixed problems).

### Run locally against the shared stack

Start the stack from `pipesor-workspace` (`tools/local_stack.py init` and
`up`), then run the service with its generated environment file. The file is
not shell-safe for the Service Bus connection string (it contains `;`), so
export its lines verbatim instead of sourcing it, for example:

```bash
while IFS= read -r line; do [ -n "$line" ] && export "$line"; done < ~/.config/pipesor-local/env/log-event.env
./mvnw -B -ntp spring-boot:run
curl -s http://127.0.0.1:8083/actuator/health/readiness
curl -s http://127.0.0.1:8083/.well-known/jwks.json
```

Build the image after `verify` with `docker build -t pipesor-log-event-service .`.
CI (`.github/workflows/ci.yml`) runs the shared `java-verify` action, builds
and checks the image, and publishes the tested image from `main`.

For the current documentation foundation, check affected links and consistency with the referenced sources, then run:

```bash
git diff --check
```

For TOML configuration changes, run this syntax check with Python 3.11+ (the selected Python baseline supports `tomllib`):

```bash
python3 -c 'from pathlib import Path; import tomllib; [tomllib.loads(p.read_text()) for p in Path(".codex").rglob("*.toml")]; print("TOML syntax OK")'
```

Follow the organization [contribution policy](https://github.com/pipesor-org/.github/blob/main/CONTRIBUTING.md), [code of conduct](https://github.com/pipesor-org/.github/blob/main/CODE_OF_CONDUCT.md) and [security policy](https://github.com/pipesor-org/.github/blob/main/SECURITY.md). Licensing remains pending.

## Optional Codex setup

Start Codex from this repository root so its [repository instructions](AGENTS.md) are discovered. Project configuration is in [.codex/config.toml](.codex/config.toml); [evidence_reviewer](.codex/agents/evidence-reviewer.toml) defines a focused reviewer. Review roles do not create separate sandbox permissions.

After changing instructions, start a fresh session and ask it to identify its active instruction sources. See the official [instruction-discovery guide](https://learn.chatgpt.com/docs/agent-configuration/agents-md) and [subagent guide](https://learn.chatgpt.com/docs/agent-configuration/subagents). A successful TOML parse alone does not establish live discovery or reviewer execution.
