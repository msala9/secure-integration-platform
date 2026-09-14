# Guided Connector onboarding

**Audience:** Security Administrator, Connector Editor and Connector Approver.
**Status:** CURRENT for the integrated Admin UI; the local laboratory uses only
synthetic data and does not qualify a production deployment.

The **Guided onboarding** page (`/admin/onboarding`) takes a new Installation from
empty state to a `Published`, invocable Connector version. The normal path requires
no UUIDs, checksums, binding JSON, provider references, SQL or store access.
The page always reads authoritative state and shows:

- current state and missing prerequisite;
- the role that must continue;
- the next authorized action;
- confirmation that reloading and retrying the same action are safe.

## The five actions

The next action appears first, with the required role and a link to its controls.
Completed action forms are hidden. When ready, the primary link opens the matching
Direct or Broker invocation procedure in the bundled Documentation page.

Each choice uses one searchable field: type a name or code and select a result.
Installation context and Connector selection have separate headings. Results come from the
server in pages of 50; matching names show their distinct codes, and selection uses
the immutable ID. Search is literal, case-insensitive and limited to 100 characters.
Applications and Environments remain shared catalogs under the existing global
read authorization. Installation choices are tenant-scoped and filtered by the
selected Application/Environment; their search accepts an Installation ID fragment.
Connector and version selectors also search their existing server catalogs.
Changing context clears the dependent Installation selection. A delayed search
response cannot replace a newer query, and reload resolves the selected identifiers
even when they are outside the first result page. No search grants additional access.

| # | Role | Primary action | Outcome |
|---|---|---|---|
| 1 | Security Administrator | Select Tenant, Application and Environment by name, choose Installation type and create the Installation. | The one-time enrollment handoff appears. |
| 2 | Connector Editor | Choose a normal `.json` file and press **Validate and import**. | The Gateway computes and verifies ID, version and checksum, then stores a `Validated` version. |
| 3 | Security Administrator | If needed, select endpoints and credentials from the catalog and press **Configure binding and grants**. | Complete bindings and exact grants are created from server-owned selections for the version reread by the server. |
| 4 | Connector Editor | Press **Request approval**. | The request is frozen for the exact version and binding digest. |
| 5 | Connector Approver | Read the actual review and press **Verify, approve and publish**. | The same Approver approves and publishes that exact version. |

The **Connectors** page retains the full JSON editor as an advanced path; it is
not required for the guided flow.

## Installation type

Guided onboarding and **Installations** use the same choice and descriptions:

- **Direct** (default for the Core pilot): application → Gateway, without a Local Broker.
- **Broker**: application → Windows Local Broker → Gateway.

Selecting an existing Installation reads its type from the server and hides the
completed creation form. It does not convert the Installation or change its Environment.
Application and Environment also show the selected Installation's server-owned
values, including after reload. Changing either selector clears the Installation
selection; it does not move an existing Installation into the new context.
Choosing Broker does not install the Windows service. Complete enrollment outside
the browser with the supported Broker or Direct client tooling before continuing.
The five administrative actions and role separation are the same for both types;
the Core pilot's Direct qualification is not a new Broker end-to-end qualification.

## One-time enrollment handoff

After the first action, the dialog shows these together:

- **Activation code ID**;
- **Activation code**;
- expiry.

ID and code have separate copy buttons. Hand them to the enrollment operator through
the approved secure channel and close the dialog after use. Do not put them in URLs,
logs, screenshots, tickets or evidence files. The browser does not save them in Web
Storage, and the Gateway does not allow them to be retrieved later.

## Resume and recovery

Each action rereads server-side state before mutating it. If a request is interrupted:

1. reload the same page;
2. check the displayed state, prerequisite and role;
3. repeat only the same indicated action.

A retry does not recreate an existing binding. The page rereads the authoritative
version and resubmits each canonical grant to the Admin API: an identical, already
enabled tuple with the same expiry is a no-op, not a second mutation or audit event.
A missing, different, `Draft`/`Retired` version or non-canonical operation is denied
before mutation. Do not wait for a window, log in again or restart from the beginning
unless the page reports a genuinely expired session. Endpoint or provider-resource
drift is denied: reload the authoritative catalog and submit a new configuration
through normal four-eyes approval.

## Final verification

The final banner proves that the version is `Published`; the selected Installation
must be `Active` and have an operation grant. Finish with one bounded invocation
through the supported Runtime API and check metadata-only audit. The page does not
turn the Admin UI into a proxy to arbitrary destinations.

A `Pending` Installation still requires enrollment even when the Connector is already
`Published`. The page must show the enrollment handoff action without a ready banner;
publishing a Connector does not activate an Installation.
