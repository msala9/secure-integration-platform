# Quick start

**Audience:** new adopters.
**Status:** CURRENT.

Start with [Evaluate SIP](evaluation.md) for the two separate candidate packages,
prerequisites, integrity checks and recovery.

## Running the Core locally

Use the [local Core pilot](local-pilot.md), the primary evaluation path:
it requires only Git, PowerShell and Linux Docker/Compose, with no host .NET SDK,
Node, npm, curl or PostgreSQL. It needs no cloud, FSE2, `.env`, SQL, store access
or host CA installation. From the checkout root:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

Result: a Direct .NET call crosses the Gateway and a Published Connector, reaches
an HTTPS/mTLS mock and returns a sanitized response with metadata-only audit.
The final marker is `ALPHA_GOLDEN_PATH_PASS`; the run removes its own resources.
If interrupted, run `./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop`.

## Windows / Local Broker path

The Direct pilot does not go through the Local Broker.
Use the self-contained [Windows package guide](../../deploy/windows/README.md)
for administrator setup and ordinary-account use, including registration of the
distinct adopter application. Historical real-service results keep their exact
source/package scope; they do not qualify a new delivery automatically.

## Optional FSE2 OfficialTest pilot

Use the [current validation/status pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md).
This optional pack requires a host .NET SDK, previously authorized A1/S1 material
and OfficialTest access: the Core's container-only application-tooling prerequisites
do not apply here. The runner handles local bootstrap, enrollment and roles;
it permits VERIFICA and lookup, not document publication.

CDA and workflow status after restart are live-qualified for the observed cases;
FHIR remains not live-qualified (HTTP 500, cause undetermined). See the
[capability and limitations summary](../../IMPLEMENTATION_STATUS.md#product-status).

Do not replace missing prerequisites with SQL, direct catalog access, endpoints copied
from evidence, integration tests or a hand-built `curl` command.

## Administration and Admin UI

Complete the local pilot first, then use the [administration guide](administration.md).
The milestone Admin quickstart is an inspection laboratory, not a second adoption path.
