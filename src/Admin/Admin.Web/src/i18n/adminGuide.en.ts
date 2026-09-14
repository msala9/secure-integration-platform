// Canonical in-app operator guide. Keep prose here, not in page components or translated copies.
export interface GuideTopic {
  id: string;
  title: string;
  paragraphs?: readonly string[];
  steps?: readonly string[];
}

export interface GuideSection {
  id: string;
  title: string;
  navigationKey?: string;
  route?: string;
  topics: readonly GuideTopic[];
}

export const adminGuide = {
  title: 'Admin user guide',
  introduction: 'This guide describes the controls available in the Admin web application. It is included in the application build. All topics remain on this page so you can use the browser Find command (Ctrl+F or Command+F). The contents links and topic headings provide direct links that can be bookmarked. Access to this guide does not grant access to the operations it describes.',
  sections: [
    { id: 'session', title: 'First access, session and display preferences', topics: [
      { id: 'sign-in', title: 'Sign in and prerequisites', paragraphs: [
        'Open the Admin address supplied by your deployment administrator and choose Continue with identity provider. Use your configured organizational identity. The platform has no local administrator password registration or password reset screen. An authorized administrator must assign the required roles to your identity. If sign-in succeeds but an action is denied, check the role and its scope with that administrator.',
        'The Viewer, Editor, Approver, Operator and Security administrator login buttons belong to the synthetic Development environment. They are not production accounts and do not configure a production identity provider. Environments, endpoint catalogs and provider resources must already be provisioned by the deployment owner; the Admin pages select those resources but do not bootstrap a deployment.'
      ] },
      { id: 'session-lifetime', title: 'Session lifetime and sign out', paragraphs: [
        'The server maintains the authenticated session and issues a secure, HttpOnly cookie. Authorization and antiforgery checks apply to mutations. Do not copy session cookies or tokens between operators. Sign out ends the current Admin session; it does not revoke an Installation or its grants. Idle and absolute expiry are deployment settings, not controls on this page.',
        'An expired or revoked session returns you to sign-in. Unsaved forms, imported files not yet submitted, test messages and activation handoffs are transient. After signing in, reopen the target page and read persisted state before repeating a mutation. A real role assignment change revokes the affected principal’s sessions; assigning the same existing role and scope is a no-op. Keep each operator’s still-valid session for normal role handoffs instead of repeatedly signing in.'
      ] },
      { id: 'display', title: 'Language, theme, dates and navigation', paragraphs: [
        'The toolbar selects EN or IT and System, Light or Dark theme. These display preferences are saved in this browser. They do not change roles, API values or storage formats. The guide is canonical English even when its navigation is Italian. Runtime identifiers such as ConnectorEditor, operation IDs and reason codes retain their exact spelling.',
        'Dates use an unambiguous English month, for example 07 Sep 2026. Technical timestamps use a 24-hour UTC time, for example 07 Sep 2026, 14:30:00 UTC, in both interface languages. API and storage values remain ISO 8601. There is no date-format or timezone editor in the Admin. A dash represents unavailable metadata, not a successful check.',
        'On narrow screens, open Menu to navigate. Keyboard users can use the skip link to reach the main content. Lists and selectors have separate Previous and Next controls; an empty first page or an unselected tenant is not evidence that no resource exists. Only Connectors exposes a text filter. Where an unsaved-changes dialog appears, Stay preserves the current edit and Discard leaves it. Cancel closes a form without saving; do not rely on every screen or sign-out action to preserve unsaved work.'
      ] }
    ] },
    { id: 'roles', title: 'Roles and server authority', topics: [
      { id: 'role-responsibilities', title: 'Choose the correct operator', paragraphs: [
        'Viewer reads permitted administrative state. ConnectorEditor validates/imports definitions and requests approval. ConnectorApprover reviews and decides on exact publication bundles and can publish. Operator performs the controlled Connector test. SecurityAdministrator manages tenant/application records, Installations, bindings, grants and access assignments; it also has lifecycle administration actions. A user may hold more than one role, and assignments may be global or tenant-scoped.',
        'Reading resource selectors may also require Viewer; the Development editor, approver and operator identities include it. Global Connector administration and tenant-specific actions have different server policies. A visible menu entry or button is not proof of permission. The server checks the authenticated identity, role, scope, current revisions and lifecycle state on each action. A client-supplied tenant or Environment never overrides authenticated authority.',
        'Four-eyes approval requires a distinct authorized principal. The creator, requester, editor or binding author cannot approve their own publication bundle. Giving one person several roles does not remove this rule. The approver must inspect the actual definition and bindings, not just a checksum label. SecurityAdministrator is not an approval bypass.'
      ] }
    ] },
    { id: 'dashboard', title: 'Dashboard', navigationKey: 'dashboard', route: '/', topics: [
      { id: 'dashboard-reading', title: 'Read the current summary', paragraphs: [
        'Available to the administrative roles, the Dashboard shows Tenant and Application totals, PostgreSQL readiness, provider readiness and Last updated. It refreshes every 30 seconds. Healthy indicates that the corresponding readiness check succeeded at that time; unhealthy indicates a dependency that needs investigation.',
        'These totals are administrative inventory, not throughput or successful-invocation counts. A healthy provider does not prove that a specific binding, certificate, external service or operation works. If loading fails, use Retry after checking the displayed error. If Last updated is old, do not treat the displayed values as a current health observation.'
      ] }
    ] },
    { id: 'tenants', title: 'Tenants', navigationKey: 'tenants', route: '/tenants', topics: [
      { id: 'tenant-fields', title: 'Create and edit a tenant', paragraphs: [
        'A Tenant is the organizational boundary for Installations, grants and tenant audit. Authorized readers see Code, Name, Status and Created, with pagination. SecurityAdministrator can add, edit or disable a tenant.',
        'Code is the stable identifier: up to 64 letters, digits, underscores, dots or hyphens. Name is a human-readable label, required and at most 256 characters. For an innocuous example, use code sample-team and name Sample team. Code cannot be edited after creation.'
      ], steps: ['Choose Add tenant, enter Code and Name, then Create. The table reloads with the saved record.', 'Choose Edit to change Name, then Save. Cancel abandons the dialog. If another administrator changed the record, compare your value with the current value and use Reload current data before deliberately reapplying the edit.'] },
      { id: 'tenant-disable', title: 'Disable and recover', paragraphs: [
        'Disable is available for an Active tenant and suspends its use; it does not delete the record or its audit history. Runtime authorization requires an active tenant, so dependent calls can be denied. Check the exact row before selecting Disable: the page submits the action directly.',
        'There is no enable or delete control on this page. Do not assume that Edit will reactivate a disabled tenant. After a failed or conflicting disable, reload and inspect Status before taking another action. For a recovery outside the exposed controls, involve the authorized deployment owner through the supported administration process.'
      ] }
    ] },
    { id: 'applications', title: 'Applications', navigationKey: 'applications', route: '/applications', topics: [
      { id: 'application-fields', title: 'Register an application and its Broker version range', paragraphs: [
        'An Application identifies client software used by Installations. Authorized readers see Code, Name, Minimum Broker version and Status. SecurityAdministrator can add, edit and disable records. Application registration alone neither enrolls a client nor grants access to a Connector.',
        'Code and Name are required; the code is fixed after creation. Minimum Broker version is required in major.minor.patch form, for example 3.0.0. Maximum Broker version is optional; blank means no upper bound is supplied. These fields govern Broker compatibility and are not the Connector version or the Direct client version.'
      ], steps: ['Choose Add application, enter the identifying fields and the intended version range, then Create.', 'Use Edit to change the name or minimum/maximum versions, then Save. Check server validation for an inconsistent range. On a conflict, the dialog compares all mutable fields, Status and the observed revisions; Save is blocked until Reload current data. Reapply only the intended changes.'] },
      { id: 'application-disable', title: 'Disable an application', paragraphs: [
        'Disable submits immediately for an Active application. The record becomes suspended and runtime checks can deny its dependent Installations. This does not uninstall software, delete history or revoke an Admin login. The page provides no re-enable action. If the status changed concurrently, inspect the comparison and reload rather than repeatedly disabling the stale row.'
      ] }
    ] },
    { id: 'installations', title: 'Installations and activation handoff', navigationKey: 'installations', route: '/installations', topics: [
      { id: 'installation-create', title: 'Select the client identity', paragraphs: [
        'An Installation joins a Tenant, Application and Environment to an enrolled runtime client identity. Select a tenant to list its Installations. The table shows identifier, Broker or Direct kind, status, application, client version, public key fingerprint, Created and Last seen. A public fingerprint is identity metadata, not a private key. Last seen is the last recorded contact, not a continuous availability test.',
        'SecurityAdministrator creates an Installation by selecting Tenant, Application, Environment and kind, then Create installation. Both this page and Guided onboarding default to Direct for the Core pilot: the application connects directly to the Gateway. Choose Broker for application → Windows Local Broker → Gateway. This choice does not install the Windows service or complete enrollment. Existing Environment choices come from the server; choosing a kind or Environment for creation does not change an existing Installation.'
      ] },
      { id: 'activation-handoff', title: 'Deliver the one-time activation response', steps: [
        'After creation, the dialog displays Activation code ID, Activation code and expiry together. Use the separate copy buttons to hand both values to the enrollment operator through the approved secure channel.',
        'Complete enrollment with the supported Broker or Direct client tooling before expiry. This enrollment runs outside the Admin web page. Reload the Installation list or guided target and verify Active.',
        'Close the dialog after handoff and clear copied sensitive material according to your organization’s clipboard policy. Never put it in URLs, tickets, screenshots, logs or evidence.'
      ], paragraphs: [
        'Pending means enrollment has not completed; Active means the Installation has enrolled; Revoked denies further authorized use. The browser retains the activation response only in the open page’s memory and offers no retrieve-again action. Closing or reloading loses it, and clipboard contents are not automatically cleared by the dialog.',
        'A lost, expired or already-used activation response cannot be recovered from this list. Verify whether enrollment already succeeded. If it did not, the SecurityAdministrator can revoke the unusable Installation and create a replacement for a new handoff. Do not blindly retry Create after an interrupted response: first inspect the tenant’s list to avoid creating an extra Installation.'
      ] },
      { id: 'installation-revoke', title: 'Revoke runtime access', paragraphs: [
        'SecurityAdministrator can select Revoke for an Installation not already Revoked. It submits directly, using the page’s administrative revocation reason; there is no visible reason editor. Revocation prevents subsequent authorized runtime use of that identity even when grants exist. It does not sign out Admin operators or erase audit records. There is no un-revoke control; plan replacement enrollment when a new client identity is needed.'
      ] }
    ] },
    { id: 'onboarding', title: 'Guided onboarding', navigationKey: 'guidedOnboarding', route: '/onboarding', topics: [
      { id: 'onboarding-prerequisites', title: 'Prepare the supported path', paragraphs: [
        'Use this page for first configuration. The deployment owner must first provide an Environment and the correct endpoint/provider catalogs, and SecurityAdministrator must register the Tenant and Application. Obtain the intended Connector JSON definition from its maintainer. Do not insert credentials, operational payloads or concrete provider secrets in a definition.',
        'Current state, Missing prerequisite, Required role and Next action describe the selected target. Search resources by name or code using server-filtered pages of 50. Distinct codes identify matching names; Installation choices also follow the selected tenant/application/environment. The page carries the target in its URL; an authorized colleague can reopen that URL and resume their role’s step. The URL contains administrative identifiers, not enrollment material, and does not grant authority. Keep handoffs within authorized colleagues.',
        'When an existing Installation is selected, its server-owned Environment is authoritative. Select the intended Connector and version, or let the uploaded definition supply them. No manual UUID, checksum reconstruction, binding JSON, SQL or store access is needed for this workflow.'
      ] },
      { id: 'onboarding-five-actions', title: 'Five actions across three roles', steps: [
        'SecurityAdministrator: select Tenant, Application, Environment and Installation type, then create the Installation, or select an existing one. Direct is the Core pilot default; Broker uses the Windows Local Broker. A selected Installation shows its server-recorded kind, which cannot be changed here. Deliver the activation handoff and have the client operator complete enrollment with the matching client tooling outside the browser. Continue configuration only when that Installation is Active.',
        'ConnectorEditor: choose the .json definition file and press Validate and import. The page validates before importing, computes the checksum through the Gateway and validates the stored Draft. Expect Validated. For an already stored version, select it and resume without uploading again.',
        'SecurityAdministrator: select the catalog endpoint and credential/certificate for each logical binding. A single candidate is preselected; inspect it. Press Configure binding and grants. The page creates missing bindings and submits grants for every operation in the selected definition, using its exact stored version. Confirm that granting all those operations matches the intended access; use the separate Grants page when only selected operations are appropriate.',
        'ConnectorEditor: after bindings and grants exist, press Request approval. Hand the same target to a distinct ConnectorApprover. The request binds the exact definition and publication configuration.',
        'ConnectorApprover: inspect the displayed Connector, version, publication digest and operation destinations. For the full credential/certificate and canonical-diff review, use Approvals for that same Connector and version. Return to the guided target and press Verify, approve and publish. The server enforces independent approval and current authority before publishing.'
      ] },
      { id: 'onboarding-resume', title: 'Resume, missing catalogs and final verification', paragraphs: [
        'Reload the same target after an interruption and inspect persisted state and the indicated role. An unsubmitted file must be selected again. Existing bindings are not recreated by Configure binding and grants; identical enabled grant tuples with the same expiry are no-ops, including after partial completion. Request approval reuses an existing request/approval, and the final step can continue after approval if publication was interrupted. Installation creation and its one-time handoff need the separate recovery described above.',
        'If a catalog has no eligible choice, ask the deployment owner to provision or correct that resource. There is no provider bootstrap screen here. If a resource revision or binding changed, refresh and review the current authoritative configuration before a new approval. Do not solve stale authority by inventing identifiers or bypassing review. Use search and pagination to reach records outside the first page. No results means no match in the authorized current context; check that context before inferring absence.',
        'The completion banner confirms Published version state. Independently verify the selected Installation is Active and the intended grants exist. The next-action link opens the Direct or Broker invocation procedure. The page does not execute a runtime request and cannot certify external-service readiness. Finish with one bounded invocation through the supported client/runtime interface and inspect metadata-only audit; payload entry and a live invocation runner are not provided in this page.'
      ] }
    ] },
    { id: 'connectors', title: 'Connectors, versions and advanced editor', navigationKey: 'connectors', route: '/connectors', topics: [
      { id: 'connector-inventory', title: 'Browse and compare versions', paragraphs: [
        'Filter connectors by text, then choose the Connector code to open its version timeline. The summary shows name, Published version and total versions. The timeline lists version, state, shortened checksum and row revision. A shortened checksum is a display aid, not a value to reconstruct for approval.',
        'Choose Base version and Target version to compare canonical definitions by change, JSON path, old value and new value. The comparison choices come from the loaded version page; use timeline pagination to reach other versions. This definition comparison is not a complete publication-binding review; use Approvals for that purpose.'
      ] },
      { id: 'connector-editor', title: 'Validate JSON and import a Draft', paragraphs: [
        'ConnectorEditor or SecurityAdministrator can use the advanced JSON editor, which initially shows the server sample. Selecting a Connector in the table does not load its definition into the editor. The editor imports definitions; it does not edit a Published row in place. For first use, prefer Guided onboarding and a maintained definition file.',
        'The definition contains Connector identity/version, logical bindings and canonical operations. Runtime names are case-sensitive identifiers, not labels to translate. The supported schema and server validation define the allowed structure; arbitrary scripts, credentials and endpoint authority do not belong in this JSON.'
      ], steps: ['Enter the intended complete definition, then Validate. Client schema checks run before server validation. Review each issue code and JSON location and correct the definition.', 'After successful validation, Import draft becomes available and uses the returned checksum. Editing the JSON invalidates that validation; validate again before importing.', 'Select the imported Connector and its Draft version in the timeline, then Validate to validate the stored version. Expect Validated before configuring bindings and requesting approval. A local validation result alone does not publish or authorize runtime use.'] },
      { id: 'connector-lifecycle', title: 'Publish, rollback and retire', paragraphs: [
        'Draft is stored but not runtime-ready. Validated has passed stored validation but is not yet published. Published is the active immutable version selected by runtime resolution. A newer publication makes the previous one Superseded. Retired is no longer available for runtime use.',
        'ConnectorApprover or SecurityAdministrator sees Publish for a Validated version and Rollback for a Superseded version. Publication still requires a current distinct approval for the exact bundle. It changes the active version, not just a label. Rollback reactivates an already-published Superseded version without copying or editing its JSON; a current Published version must be available for the concurrency check. Inspect grants and bindings for the resulting active version.',
        'SecurityAdministrator can Retire a non-Retired version. These buttons submit directly. Retiring active authority prevents new runtime resolution; it is not an implicit rollback. New invocations recheck publication state and cannot fall back to stale cached authority. Changes already performed by an external service are not undone by retirement or rollback.',
        'On a stale revision or denied transition, reload the timeline and current approval state, then decide again. Do not edit an immutable version or force an old revision. Use a new version for a definition change.'
      ] },
      { id: 'connector-test', title: 'Controlled test and its limit', paragraphs: [
        'Operator or SecurityAdministrator can select an Environment, enter the exact canonical operation ID and choose Test connector after selecting a Connector. A successful result displays Connector, operation and resolved version. The server resolves the Published operation catalog and records the test audit event.',
        'This control is a configuration-resolution check. It does not submit a business payload, exercise the enrolled client/grant path or prove a successful call to a provider or external service. If it fails, check publication, operation ID and Environment. Use a supported runtime client for the final bounded invocation.'
      ] }
    ] },
    { id: 'bindings', title: 'Bindings', navigationKey: 'bindings', route: '/bindings', topics: [
      { id: 'binding-authority', title: 'Bind logical names to server-owned resources', paragraphs: [
        'Bindings supply the Environment-specific authority for a Connector version. SecurityAdministrator manages them. For normal first use, Guided onboarding provides catalog selectors. The separate Bindings page is an advanced form: enter exact Connector ID, version and Environment ID to inspect binding history and the available provider resource catalog. Its visible Save button does not override server authorization.',
        'Endpoints JSON maps logical endpoint names to HTTPS destinations under server policy. Secret resources and Certificate resources JSON map logical names to catalog selections, not secret values. Each selection uses providerId, resourceId and resourceType; the resource type must be Secret or ClientCertificate respectively. Optional version and publicMetadataRevision identify the expected resource metadata. Catalog rows display provider, logical resource ID, type and revision.',
        'Submit the complete intended set, including empty objects for unused categories. This form is not a partial patch editor and does not populate your JSON from a history row. If you do not have an approved complete configuration, use the guided selectors instead of reconstructing it. Never paste a password, private key, certificate file or provider locator into these maps.'
      ], steps: ['Select the exact target and inspect history and catalog metadata. Validate each logical name against the definition.', 'Enter the complete binding maps and Save. Expect Saved and a new/current history revision. History shows revision, state and shortened checksum with pagination.', 'A binding change invalidates previous publication approvals. Request and obtain review of the new exact bundle before publication. If the save conflicts or catalog authority is stale, reload the current data and reconcile the intended configuration before resubmitting.'] },
      { id: 'binding-drift', title: 'Resource drift and runtime consequences', paragraphs: [
        'Provider resources have separate capabilities: secret retrieval, certificate use, signing/key operations and health are not interchangeable. The browser receives catalog/public metadata, never secret values or private key material. Runtime callers cannot choose arbitrary endpoints or credential references.',
        'Changed endpoint/provider revisions can invalidate a previously reviewed bundle. Runtime denies stale authority before sensitive use rather than silently adopting the changed resource. Correct the authoritative configuration with the deployment owner and follow the normal review/publication lifecycle. A green health indicator does not repair binding drift.'
      ] }
    ] },
    { id: 'grants', title: 'Grants', navigationKey: 'grants', route: '/grants', topics: [
      { id: 'grant-create', title: 'Authorize a specific Installation operation', paragraphs: [
        'Grants are deny-by-default access for an Installation to a Connector/operation. Select a tenant to list Installation, Connector, Operation and Valid from, with pagination. SecurityAdministrator sees Add grant. Choose an Installation, enter the Connector ID, choose its version and enter the exact canonical operation ID, then Create.',
        'The server rereads that exact version: it must be Validated or Published and must contain the operation. The version authorizes grant creation; it is not a promise to pin runtime execution to that version. Runtime uses the current Published version and the Installation’s authenticated Environment. An identical enabled tuple with the same expiry is a no-op; success clears the creation fields and refreshes the list.',
        'If creation is denied, check the tenant scope, Installation and canonical operation in the stored version. Guided onboarding derives these selections and creates grants for every operation. This separate page exposes no grant expiry editor, disable, revoke or delete button. Existing grants cannot make a revoked Installation, suspended Tenant/Application or retired Connector usable. Use the authorized supported administration process for grant changes not exposed here.'
      ] }
    ] },
    { id: 'approvals', title: 'Approvals and publication review', navigationKey: 'approvals', route: '/approvals', topics: [
      { id: 'approval-review', title: 'Inspect what will be published', paragraphs: [
        'Enter the exact Connector ID and version to load approval history and the semantic publication review. ConnectorEditor or SecurityAdministrator can Request approval. ConnectorApprover or SecurityAdministrator can Approve or Reject, subject to server four-eyes checks. The optional decision comment is limited to 500 characters; keep it factual and free of sensitive data.',
        'Review the Connector/version and publication digest, each operation and Environment, destination scheme/host/port/path/query, authentication strategy and logical credential. Inspect authorization endpoints where shown, provider/resource type, version and scope, catalog/binding revisions and checksums. For certificates, inspect public fingerprint, subject, issuer, validity, key algorithm and size. These are public review metadata, not credential material.',
        'The canonical approval diff shows changes, JSON paths and previous/current values. Compare it with the intended change and actual destinations. A matching version label alone does not establish that bindings are unchanged. Never approve only because the page can display a digest.'
      ] },
      { id: 'approval-decide', title: 'Request, approve or reject', steps: ['After stored validation and binding configuration, Request approval for the target version. History records requester, shortened checksum and status.', 'A distinct approver reads the review and chooses Approve to submit the exact displayed digest, or Reject to refuse the proposed configuration. Requested is awaiting a decision; Approved records the accepted bundle; Rejected is not permission to publish. Stale/invalidated approval no longer authorizes publication.', 'Approval on this page does not itself publish. Publish from the Connector timeline, or continue the guided Verify, approve and publish step. Confirm Published afterward.'], paragraphs: [
        'If a version, binding or provider catalog changed between review and decision, the server rejects stale approval. Reload and review the new bundle; obtain a new valid request/decision as indicated by persisted state. If four-eyes fails, hand off to a different authorized principal who did not author/request that bundle. Do not add roles to the same principal to bypass it.'
      ] }
    ] },
    { id: 'access', title: 'Access control', navigationKey: 'access', route: '/access', topics: [
      { id: 'access-assign', title: 'Assign an external identity a role', paragraphs: [
        'Only SecurityAdministrator can use this page; other roles do not see its menu entry. This is role administration, not identity-provider user creation. Obtain the exact trusted issuer and stable subject from the identity administrator, not from a guessed email address.',
        'Issuer is the HTTPS identity-provider issuer (required, up to 512 characters). Subject is the stable identity key (required, up to 256). Name is a display label (required, up to 256). Select Viewer, ConnectorEditor, ConnectorApprover, Operator or SecurityAdministrator. Optional tenant scope uses the intended tenant identifier; blank means global scope, not no access. Do not leave it blank merely because the identifier is unknown.'
      ], steps: ['Verify the identity and intended scope, fill the form, choose the least role needed, then Assign role.', 'Expect Saved and the refreshed assignment list, which shows principal identifier, role and global/tenant scope. Use pagination to inspect further records.', 'Revoke on an assignment removes that role/scope and submits immediately. Confirm the exact assignment first. Other assignments may still grant access. A real privilege change invalidates that principal’s Admin sessions; they must sign in again.'] },
      { id: 'access-recovery', title: 'Avoid accidental loss of access', paragraphs: [
        'Coordinate another authorized administrator before changing your own administrative role. A role grant is not a four-eyes approval and does not activate runtime credentials. If the server denies an assignment or revocation, inspect its scope and current assignments through a still-authorized operator. There is no local password or emergency-account creation button on this page.'
      ] }
    ] },
    { id: 'audit', title: 'Audit and safe diagnostics', navigationKey: 'audit', route: '/audit', topics: [
      { id: 'audit-reading', title: 'Inspect a tenant’s metadata', paragraphs: [
        'Select a tenant to load its audit list; use Previous/Next to page through records. Columns show Action, Target type/identifier, Outcome and Reason. These labels describe recorded administrative/runtime events, not full external responses. This page has no time-range filter, free-text search, export, payload viewer or retry/replay button.',
        'A SecurityAdministrator scoped globally or to the selected tenant can also see safe failure diagnostics when the server supplies them. Other readers cannot use that column to obtain extra diagnostic data. The bounded fields are Gateway status, failure phase, upstream status, status category, and optional safe upstream/local codes. None means no diagnostic projection was supplied, not proof that no failure occurred.',
        'An upstream success HTTP status can coexist with a Gateway failure, for example when a response cannot be mapped safely. Read Gateway outcome and phase together. Do not interpret an upstream status as proof of completed business processing. Audit intentionally omits payloads, credentials, authorization headers, cookies, raw responses and stack traces.'
      ] },
      { id: 'error-recovery', title: 'Recover from common errors', paragraphs: [
        'Loading failures: use Retry where offered after addressing connectivity or service availability. An empty table may mean no selected tenant or no records on the current page. Authorization denied (403): verify the operator’s server-assigned role and scope; switching the UI language or editing a URL cannot grant access.',
        'Conflict or failed precondition (409/412): another writer or a lifecycle transition changed authority. Use the comparison/reload controls where available; otherwise reload the target and inspect the current state. Validation failure: fix the named field or schema issue before submitting again. Missing resource: verify the selected target and catalog rather than inventing a replacement identifier.',
        'Unavailable service (503): restore the required dependency through its owner and then reread state. Rate limiting (429): respect server guidance and investigate unexpected request bursts; do not loop retries, rotate identities or restart onboarding to evade the control. After an uncertain mutation response, check what actually persisted before repeating a documented retry-safe action.',
        'For support, report the displayed correlation ID, target, action, safe code and an explicit UTC time such as 07 Sep 2026, 14:30:00 UTC. Keep the report metadata-only. The UI may display a generic localized message instead of a detailed technical code; do not collect raw browser traffic or sensitive screenshots to compensate.'
      ] }
    ] },
    { id: 'health', title: 'Health', navigationKey: 'health', route: '/health', topics: [
      { id: 'health-scope', title: 'Understand the readiness view', paragraphs: [
        'Health reuses the Dashboard summary: Tenant/Application totals, database and provider readiness, and the UTC update time. It is read-only and available to the administrative roles. It does not expose per-endpoint probes, certificate renewal, restart, repair or provider configuration controls.',
        'At the deployment boundary, /health/live checks the process and /health/ready checks required dependencies. These are distinct from proving a particular Connector invocation. If readiness is unhealthy, involve the deployment owner, restore the failing dependency and verify a fresh summary before diagnosing a specific binding or operation. Neither a healthy summary nor this guide claims production qualification.'
      ] }
    ] }
  ] satisfies readonly GuideSection[]
} as const;
