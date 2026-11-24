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

## CI/CD

[CI](.github/workflows/ci.yml) calls the shared [`service-ci.yml`](https://github.com/pipesor-org/pipesor-ci#catalog)
from [pipesor-ci](https://github.com/pipesor-org/pipesor-ci), pinned by commit SHA (Dependabot proposes updates):

1. **Conventions**: canonical commitlint/Lefthook configuration, PR title (at most 65 characters) and description,
   Conventional Commits for the PR range and for the integrated `main` commit, actionlint and zizmor.
2. **Build**: the tooling tests and `./mvnw -B -ntp clean verify`, then one `linux/amd64` image build tagged
   `ghcr.io/pipesor-org/pipesor-log-event-service:sha-<commit>-<run>-<attempt>`, the shared OCI revision/non-root checks and
   `tools/check_image.py`.
3. **Image assurance**: Trivy SBOM and vulnerability report (90-day evidence); fixable HIGH/CRITICAL vulnerabilities
   block. Reviewed exceptions go in `.trivyignore.yaml`.
4. **Publish** (pushes to `main` only): the exact tested archive is pushed to the private GHCR package without
   rebuilding and `candidate-<run>-<attempt>/candidate.json` records the source SHA, image, digest and CI run/attempt.
   Use **Re-run all jobs** after a publication failure; tags and artifacts include the attempt.

PRs are verified and scanned but never published. A ruleset protects `main`: changes arrive through squash-merged PRs.

The image check verifies user `10001:10001` and the expected OCI source and revision labels. It starts an isolated container with networking disabled and requires a Spring Boot startup failure for missing platform configuration. The check removes its container on exit.

Local checks before opening a PR (Java 25, Python 3, Bun 1.4.4, Docker):

```bash
bun install --frozen-lockfile && bun run setup:hooks
python3 -m unittest discover -s tools -p 'test_*.py'
./mvnw -B -ntp clean verify
revision="$(git rev-parse HEAD)"
docker build --platform linux/amd64 --build-arg "VCS_REF=$revision" --tag pipesor-log-event-service:local-ci .
GITHUB_SHA="$revision" python3 tools/check_image.py pipesor-log-event-service:local-ci
```

**Deployment.** This repository does not deploy. The environment's Terraform root in
[pipesor-iac](https://github.com/pipesor-org/pipesor-iac/blob/main/docs/dev-runtime-deployment.md) pins this service's
image by digest. Promote a candidate by using its `candidate.json` digest in the next environment's reviewed plan;
roll back with a new reviewed plan for the earlier digest.

**Releases.** [Release candidate](.github/workflows/release.yml) is manual and hard-disabled in source. It uses the
shared [release action](https://github.com/pipesor-org/pipesor-ci/tree/main/actions/release) to name an existing
candidate digest `vX.Y.Z[-rc.N]` with a GitHub Release, never rebuilding; stable requires retained preprod validation
for the same digest. See the [shared CI/CD guide](https://github.com/pipesor-org/pipesor-docs/blob/main/docs/development/cicd.md).

**Registry retention.** [Registry retention](.github/workflows/registry-retention.yml) runs weekly through the shared [pipesor-ci workflow](https://github.com/pipesor-org/pipesor-ci#registry-retention): it keeps every deployed or recently deployed digest (pipesor-iac `images.json` history), release digests, the newest and recent candidates and the children of kept image indexes, and reports the rest. It is a dry run until the repository variable `REGISTRY_RETENTION_DELETE` is `true`.

## Optional Codex setup

Start Codex from this repository root so its [repository instructions](AGENTS.md) are discovered. Project configuration is in [.codex/config.toml](.codex/config.toml); [evidence_reviewer](.codex/agents/evidence-reviewer.toml) defines a focused reviewer. Review roles do not create separate sandbox permissions.

After changing instructions, start a fresh session and ask it to identify its active instruction sources. See the official [instruction-discovery guide](https://learn.chatgpt.com/docs/agent-configuration/agents-md) and [subagent guide](https://learn.chatgpt.com/docs/agent-configuration/subagents). A successful TOML parse alone does not establish live discovery or reviewer execution.
