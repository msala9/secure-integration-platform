import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const tenant = { id: '10000000-0000-0000-0000-000000000001', code: 'sample', displayName: 'Sample tenant', status: 'Active', createdAt: '2026-08-05T00:00:00Z', rowVersion: 1 };
async function fixtures(page: Page, role = 'SecurityAdministrator') {
  await page.route('**/admin/auth/me', route => route.fulfill({ json: { id: '20000000-0000-0000-0000-000000000001', displayName: role, roles: [{ role, tenantId: null }] } }));
  await page.route('**/admin/auth/csrf', route => route.fulfill({ json: { token: 'synthetic-csrf' } }));
  await page.route('**/admin/api/v1/dashboard', route => route.fulfill({ json: { tenants: 1, applications: 1, database: 'healthy', provider: 'healthy', generatedAtUtc: '2026-08-05T00:00:00Z' } }));
  await page.route('**/admin/api/v1/tenants**', route => route.request().method() === 'POST' ? route.fulfill({ status: 201, json: tenant }) : route.fulfill({ json: { items: [tenant], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/applications**', route => route.fulfill({ json: { items: [{ id: '30000000-0000-0000-0000-000000000001', code: 'sample-app', displayName: 'Sample application', status: 'Active', minimumBrokerVersion: '3.0.0', maximumBrokerVersion: null, createdAt: '2026-08-05T00:00:00Z', rowVersion: 1 }], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/environments**', route => route.fulfill({ json: { items: [{ id: '50000000-0000-0000-0000-000000000001', code: 'local', displayName: 'Local', productionControls: false }], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/provider-resources**', route => route.fulfill({ json: { items: [{ id: '51000000-0000-0000-0000-000000000001', providerId: 'synthetic', providerDisplayName: 'Synthetic vault', providerType: 'synthetic', resourceId: 'vendor-api-key', resourceType: 'Secret', displayName: 'Vendor API key', environmentId: '50000000-0000-0000-0000-000000000001', connectorScope: 'sample-secure-service', operationScope: 'submit', status: 'Active', version: null, revision: 1, publicMetadataRevision: null, certificateMetadata: null, checksumSha256: '8'.repeat(64), createdAt: '2026-08-05T00:00:00Z' }], offset: 0, limit: 100, total: 1 } }));
  await page.route('**/admin/api/v1/endpoint-resources**', route => route.fulfill({ json: { items: [{ endpointId: 'sample-vendor', displayName: 'Sample vendor', environmentId: '50000000-0000-0000-0000-000000000001', connectorScope: 'sample-secure-service', operationScope: 'submit', logicalBindingId: 'sample-vendor-endpoint', endpoint: 'https://vendor.example.test/', revision: 1, checksumSha256: '7'.repeat(64) }], offset: 0, limit: 100, total: 1 } }));
  await page.route('**/admin/api/v1/installations**', route => route.request().method() === 'POST' && !route.request().url().includes(':revoke') ? route.fulfill({ status: 201, json: { installationId: '40000000-0000-0000-0000-000000000002', activationCodeId: '70000000-0000-0000-0000-000000000001', activationCode: 'SYNTHETIC-ONE-TIME', expiresAt: '2026-08-05T01:00:00Z' } }) : route.request().url().includes(':revoke') ? route.fulfill({ json: { status: 'revoked' } }) : route.fulfill({ json: { items: [{ id: '40000000-0000-0000-0000-000000000001', tenantId: tenant.id, applicationId: '30000000-0000-0000-0000-000000000001', environmentId: '50000000-0000-0000-0000-000000000001', status: 'Active', installationKind: 'Direct', clientVersion: '1.0.0', credential: { credentialId: '71000000-0000-0000-0000-000000000001', status: 'Active', certificateSha256: 'A'.repeat(64), spkiSha256: 'B'.repeat(64), serialNumber: '01', notBefore: '2026-08-05T00:00:00Z', notAfter: '2026-09-05T00:00:00Z' }, createdAt: '2026-08-05T00:00:00Z', updatedAt: '2026-08-05T00:00:00Z' }], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/connectors?*', route => route.fulfill({ json: { items: [{ connectorId: 'sample-secure-service', displayName: 'Sample secure service', versions: 2, publishedVersion: '1.0.0', publicationRevision: 2 }], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/connectors:validate', route => route.fulfill({ json: { valid: true, checksumSha256: 'A'.repeat(64), errors: [] } }));
  await page.route('**/admin/api/v1/connectors:import', route => route.fulfill({ status: 201, json: { state: 'Draft' } }));
  await page.route('**/admin/api/v1/grants**', route => route.request().method() === 'POST' ? route.fulfill({ status: 201, json: { id: 'new-grant' } }) : route.fulfill({ json: { items: [{ id: 'g', installationId: 'i', tenantId: tenant.id, connectorId: 'sample-secure-service', operationId: 'submit', enabled: true, validFrom: '2026-08-05T00:00:00Z' }], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/audit**', route => route.fulfill({ json: { items: [{ id: 'a', occurredAt: '2026-08-05T00:00:00Z', action: 'connector.publish', targetType: 'connector', targetId: 'sample-secure-service', correlationId: '60000000-0000-0000-0000-000000000001', outcome: 'success', reasonCode: 'BGW-ADMIN-ACTION' }, { id: 'f', occurredAt: '2026-08-05T00:01:00Z', action: 'operation.invoke', targetType: 'operation', targetId: 'fse2/create', correlationId: '60000000-0000-0000-0000-000000000002', outcome: 'failure', reasonCode: 'BGW-EGRESS-UPSTREAM-REJECTED', failureDiagnostics: { failurePhase: 'LOCAL_RESPONSE_MAPPING_FAILURE', upstreamStatus: 202, statusCategory: 'SUCCESS', safeUpstreamCode: null, localSafeCode: 'FSE2_RESPONSE_INVALID' } }], offset: 0, limit: 50, total: 2 } }));
  await page.route('**/admin/api/v1/role-assignments**', route => route.request().method() === 'GET' ? route.fulfill({ json: { items: [], offset: 0, limit: 50, total: 0 } }) : route.fulfill({ json: { id: 'role-assignment' } }));
  await page.route('**/admin/api/v1/connectors/**', route => { const url = new URL(route.request().url()); if (url.pathname.endsWith('/schema')) return route.fulfill({ json: { type: 'object' } }); if (url.pathname.endsWith('/sample')) return route.fulfill({ json: { schemaVersion: '1.0', connectorId: 'sample-secure-service', version: '1.0.0' } }); if (url.pathname.endsWith('/versions')) return route.fulfill({ json: { items: [{ connectorId: 'sample-secure-service', version: '2.0.0', schemaVersion: '1.0', state: 'Validated', checksumSha256: 'B'.repeat(64), rowVersion: 2, createdAt: '2026-08-05T00:10:00Z' }, { connectorId: 'sample-secure-service', version: '1.0.0', schemaVersion: '1.0', state: 'Superseded', checksumSha256: 'A'.repeat(64), rowVersion: 3, createdAt: '2026-08-05T00:00:00Z' }], offset: 0, limit: 50, total: 2 } }); if (url.pathname.endsWith('/definition')) return route.fulfill({ json: { schemaVersion: '1.0', version: url.pathname.includes('2.0.0') ? '2.0.0' : '1.0.0' } }); if (url.pathname.endsWith('/bindings')) return route.request().method() === 'GET' ? route.fulfill({ json: { items: [{ id: 'binding', connectorId: 'sample-secure-service', connectorVersionId: 'version-id', environmentId: '50000000-0000-0000-0000-000000000001', endpoints: { endpoint: '[REDACTED]' }, secretResources: { secret: { providerId: 'synthetic', resourceId: 'vendor-key', resourceType: 'Secret', catalogRevision: 1, catalogChecksumSha256: 'F'.repeat(64) } }, certificateResources: { certificate: { providerId: 'synthetic', resourceId: 'client-cert', resourceType: 'ClientCertificate', catalogRevision: 1, publicMetadataRevision: 1, catalogChecksumSha256: '9'.repeat(64) } }, endpointChecksumSha256: 'E'.repeat(64), secretChecksumSha256: 'F'.repeat(64), certificateChecksumSha256: '9'.repeat(64), revision: 4, checksumSha256: 'C'.repeat(64), state: 'Active', updatedAt: '2026-08-05T00:00:00Z', updatedBy: 'editor' }], offset: 0, limit: 50, total: 1 } }) : route.fulfill({ json: { revision: 5 } }); if (url.pathname.includes(':test')) return route.fulfill({ json: { status: 'valid', connectorId: 'sample-secure-service', operationId: 'submit', connectorVersion: '1.0.0' } }); return route.fulfill({ json: { connectorId: 'sample-secure-service', version: '2.0.0', state: 'Published', rowVersion: 3 } }); });
  await page.route('**/admin/api/v1/connectors/*/versions/*/approvals?*', route => route.fulfill({ json: { items: [{ id: 'approval', connectorVersionId: 'version-id', checksumSha256: 'B'.repeat(64), bindingDigestSha256: 'D'.repeat(64), requestedBy: '20000000-0000-0000-0000-000000000002', status: 'Requested', requestedAt: '2026-08-05T00:00:00Z' }], offset: 0, limit: 50, total: 1 } }));
  await page.route('**/admin/api/v1/connectors/*/versions/*/approval-review', route => route.fulfill({ json: {
    artifact: { connector: { connectorId: 'sample-secure-service', version: '2.0.0', displayName: 'Sample secure service', schemaVersion: '1.0', canonicalDefinitionChecksumSha256: 'B'.repeat(64) }, operations: [{ operationId: 'submit', environment: '50000000-0000-0000-0000-000000000001', executionStrategy: 'default-http', protocol: 'HTTPS', endpoint: { logicalBindingId: 'sample-vendor-endpoint', bindingRevision: 4, scheme: 'https', hostname: 'vendor.example.test', port: 443, path: '/vendor/orders', query: '', allowedMethods: ['POST'], redirectPolicy: 'deny', tlsPolicy: 'validate-system-trust-and-hostname', endpointChecksumSha256: 'E'.repeat(64), bindingChecksumSha256: 'C'.repeat(64), destinationClassification: 'publicInternet' }, authorityEndpoints: [{ role: 'authorization', endpoint: { logicalBindingId: 'oauth-authorize', bindingRevision: 4, scheme: 'https', hostname: 'login.example.test', port: 443, path: '/authorize', query: '?tenant=synthetic', allowedMethods: ['GET'], redirectPolicy: 'deny', tlsPolicy: 'validate-system-trust-and-hostname', endpointChecksumSha256: '1'.repeat(64), bindingChecksumSha256: 'C'.repeat(64), destinationClassification: 'publicInternet' } }, { role: 'token', endpoint: { logicalBindingId: 'oauth-token', bindingRevision: 4, scheme: 'https', hostname: 'login.example.test', port: 443, path: '/token', query: '', allowedMethods: ['POST'], redirectPolicy: 'deny', tlsPolicy: 'validate-system-trust-and-hostname', endpointChecksumSha256: '2'.repeat(64), bindingChecksumSha256: 'C'.repeat(64), destinationClassification: 'publicInternet' } }], secretBindings: [{ logicalBindingId: 'sample-vendor-api-key', bindingRevision: 4, providerDisplayName: 'Synthetic vault', providerType: 'synthetic-vault', providerId: 'synthetic-vault', resourceLogicalId: 'vendor-api-key', resourceType: 'Secret', resourceVersion: '1', catalogRevision: 3, publicMetadataRevision: null, environment: '50000000-0000-0000-0000-000000000001', connectorScope: 'sample-secure-service', operationScope: 'submit', catalogChecksumSha256: 'F'.repeat(64), resourceBindingChecksumSha256: '6'.repeat(64), bindingChecksumSha256: 'C'.repeat(64) }], certificateBindings: [{ logicalBindingId: 'sample-vendor-client-certificate', bindingRevision: 4, providerDisplayName: 'Synthetic vault', providerType: 'synthetic-vault', providerId: 'synthetic-vault', certificateLogicalId: 'vendor-client-certificate', resourceType: 'ClientCertificate', resourceVersion: 'catalog-2', catalogRevision: 5, publicMetadataRevision: 7, publicFingerprintSha256: '7'.repeat(64), publicSubject: 'CN=Synthetic client', publicIssuer: 'CN=Synthetic issuer', notBefore: '2026-08-01T00:00:00Z', expiresAt: '2026-09-01T00:00:00Z', keyAlgorithm: 'ECDSA', publicKeySize: 256, certificateVersion: '3', environment: '50000000-0000-0000-0000-000000000001', connectorScope: 'sample-secure-service', operationScope: 'submit', catalogChecksumSha256: '9'.repeat(64), resourceBindingChecksumSha256: '5'.repeat(64), bindingChecksumSha256: 'C'.repeat(64) }] }] },
    canonicalJson: '{"redacted":true}', digestSha256: 'D'.repeat(64), revisions: [{ bindingId: 'binding', environmentId: '50000000-0000-0000-0000-000000000001', revision: 4, checksumSha256: 'C'.repeat(64) }], diff: [{ change: 'changed', path: '/operations/0/endpoint/hostname', previousValue: '"old.example.test"', currentValue: '"vendor.example.test"' }], riskIndicators: [{ code: 'PUBLIC_INTERNET_DESTINATION', severity: 'high', path: '/operations' }]
  } }));
}

test.describe('Authenticated admin', () => {
test.beforeEach(async ({ page }) => { await fixtures(page); await page.goto('./'); });
test('UI-MOCK-01 viewer navigates read-only dashboard', async ({ page }) => { await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible(); });
test('UI-MOCK-02 editor opens connector draft editor', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await expect(page.getByLabel('Connector JSON')).toBeVisible(); });
test('UI-MOCK-03 JSON validation reports success', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'Validate' }).click(); await expect(page.getByText(/Definition is valid/)).toBeVisible(); });
test('UI-MOCK-04 editor requests approval', async ({ page }) => { await page.getByRole('link', { name: 'Approvals' }).click(); await expect(page.getByRole('button', { name: 'Request approval' })).toBeVisible(); });
test('UI-MOCK-05 self approval failure is mapped safely', async ({ page }) => { await page.getByRole('link', { name: 'Approvals' }).click(); await page.route('**/admin/api/v1/connectors/*/versions/*/approvals', route => route.fulfill({ status: 403, json: { code: 'BGW-ADMIN-FOUR-EYES', correlationId: 'c' } })); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByLabel('Version').fill('1.0.0'); await page.getByRole('button', { name: 'Approve' }).click(); await expect(page.getByText(/not authorized/i)).toBeVisible(); });
test('UI-MOCK-06 distinct approver action is exposed', async ({ page }) => { await page.getByRole('link', { name: 'Approvals' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByLabel('Version').fill('1.0.0'); await expect(page.getByRole('button', { name: 'Approve' })).toBeEnabled(); });
test('UI-MOCK-07 approved version can be published with server revision', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await page.getByRole('button', { name: 'Publish' }).click(); await expect(page.getByText('Version timeline: sample-secure-service')).toBeVisible(); });
test('UI-MOCK-08 grant editor is tenant installation and server-version scoped', async ({ page }) => { await page.getByRole('link', { name: 'Grants' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await page.getByLabel('Installation').click(); await page.getByRole('option', { name: '40000000-0000-0000-0000-000000000001' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByLabel('Version').click(); await page.getByRole('option', { name: '2.0.0 · Validated' }).click(); await page.getByLabel('Operation').fill('submit'); await expect(page.getByRole('button', { name: 'Create' })).toBeEnabled(); });
test('UI-MOCK-09 controlled connector test is not an arbitrary proxy', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await page.getByLabel('Environment').click(); await page.getByRole('option', { name: 'Local' }).click(); await page.getByLabel('Operation').fill('submit'); await page.getByRole('button', { name: 'Run controlled test' }).click(); await expect(page.getByText(/sample-secure-service · submit/)).toBeVisible(); });
test('UI-MOCK-10 version history exposes rollback action', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await expect(page.getByRole('button', { name: 'Rollback' })).toBeVisible(); });
test('UI-MOCK-11 retire is an explicit authorized action', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await expect(page.getByRole('button', { name: 'Retire' }).first()).toBeVisible(); });
test('UI-MOCK-12 activation identifier and code are separate transient handoff values', async ({ page }) => { await page.getByRole('link', { name: 'Installations' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await page.getByLabel('Application').click(); await page.getByRole('option', { name: 'Sample application' }).click(); await page.getByLabel('Environment').click(); await page.getByRole('option', { name: 'Local' }).click(); await page.getByRole('button', { name: 'Create installation' }).click(); await expect(page.getByRole('textbox', { name: 'Activation code ID' })).toHaveValue('70000000-0000-0000-0000-000000000001'); await expect(page.getByRole('textbox', { name: 'Activation code', exact: true })).toHaveValue('SYNTHETIC-ONE-TIME'); await expect(page.getByRole('button', { name: 'Copy ID' })).toBeVisible(); await expect(page.getByRole('button', { name: 'Copy code' })).toBeVisible(); await page.getByRole('button', { name: 'Close' }).click(); await expect(page.getByText('SYNTHETIC-ONE-TIME')).toHaveCount(0); expect(await page.evaluate(() => `${JSON.stringify(localStorage)}${JSON.stringify(sessionStorage)}`)).not.toContain('SYNTHETIC-ONE-TIME'); });
test('UI-MOCK-13 installation inventory exposes revocation', async ({ page }) => { await page.getByRole('link', { name: 'Installations' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await expect(page.getByRole('button', { name: 'Revoke' })).toBeVisible(); });
test('M55-UI-MOCK Direct installation selection is authoritative and public metadata only', async ({ page }) => { await page.getByRole('link', { name: 'Installations' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await page.getByLabel('Application').click(); await page.getByRole('option', { name: 'Sample application' }).click(); await page.getByLabel('Environment').click(); await page.getByRole('option', { name: 'Local' }).click(); await page.getByLabel('Installation type').click(); await page.getByRole('option', { name: 'Direct' }).click(); const requestPromise = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/admin/api/v1/installations'); await page.getByRole('button', { name: 'Create installation' }).click(); const request = await requestPromise; expect(request.postDataJSON()).toMatchObject({ installationKind: 'Direct' }); await page.getByRole('button', { name: 'Close' }).click(); await expect(page.getByText('Direct').first()).toBeVisible(); await expect(page.getByText('B'.repeat(64))).toBeVisible(); await expect(page.getByText(/private key/i)).toHaveCount(0); });
test('UI-MOCK-14 concurrency conflict includes correlation id', async ({ page }) => { await page.route('**/admin/api/v1/connectors/*/versions/*:publish', route => route.fulfill({ status: 409, json: { code: 'BGW-CONCURRENCY', correlationId: 'conflict-correlation' } })); await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await page.getByRole('button', { name: 'Publish' }).click(); await expect(page.getByText(/conflict-correlation/)).toBeVisible(); });
test('UI-MOCK-15 binding form never retrieves a secret value', async ({ page }) => { await page.getByRole('link', { name: 'Bindings' }).click(); await expect(page.getByText(/never (shown|displayed)/).first()).toBeVisible(); });
test('UI-MOCK-16 audit action and reason are localized and redacted', async ({ page }) => { await page.getByRole('link', { name: 'Audit' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await expect(page.getByText('Publish connector')).toBeVisible(); await expect(page.getByText('Administrative action completed')).toBeVisible(); await expect(page.getByText(/Unknown value/)).toHaveCount(0); });
test('UI-MOCK-17 provider-neutral health is localized and green', async ({ page }) => { await page.getByRole('link', { name: 'Health' }).click(); await expect(page.getByText('Healthy').first()).toBeVisible(); });
test('UI-MOCK-18 language changes to Italian', async ({ page }) => { await page.getByLabel('Language').click(); await page.getByRole('option', { name: 'IT' }).click(); await expect(page.getByRole('link', { name: 'Panoramica' })).toBeVisible(); });
test('UI-MOCK-19 theme choice persists locally', async ({ page }) => { await page.getByLabel('Theme').click(); await page.getByRole('option', { name: 'Dark' }).click(); await expect.poll(() => page.evaluate(() => localStorage.getItem('sip.theme'))).toBe('dark'); });
test('UI-MOCK-20 opened forms have no serious accessibility violations', async ({ page }) => {
  for (const name of ['Tenants', 'Applications', 'Bindings', 'Connectors', 'Access control']) {
    await page.getByRole('link', { name }).click();
    if (name === 'Tenants') await page.getByRole('button', { name: 'Add tenant' }).click();
    if (name === 'Applications') await page.getByRole('button', { name: 'Add application' }).click();
    if (name === 'Tenants' || name === 'Applications') await page.getByRole('dialog').evaluate(async element => { await Promise.all(element.parentElement!.getAnimations().map(animation => animation.finished)); });
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? '')), name).toEqual([]);
    if (name === 'Tenants' || name === 'Applications') await page.getByRole('button', { name: 'Cancel' }).click();
  }
});
test('UI-MOCK-21 approver can explicitly reject an exact version', async ({ page }) => { await page.getByRole('link', { name: 'Approvals' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByLabel('Version').fill('2.0.0'); await expect(page.getByRole('button', { name: 'Reject' })).toBeEnabled(); });
test('UI-MOCK-22 security administrator sees localized provider-neutral roles and can assign one', async ({ page }) => { await page.getByRole('link', { name: 'Access control' }).click(); await page.getByLabel('Role').click(); await expect(page.getByRole('option', { name: 'Connector editor' })).toBeVisible(); await page.getByRole('option', { name: 'Connector editor' }).click(); await page.getByLabel('OIDC issuer').fill('https://issuer.example.test'); await page.getByLabel('OIDC subject').fill('reviewer'); await page.getByLabel('Name').fill('Reviewer'); await page.getByRole('button', { name: 'Assign role' }).click(); await expect(page.getByRole('status')).toHaveText('Saved.'); });
test('UI-MOCK-23 canonical version comparison shows a non-color path diff and never requests bindings', async ({ page }) => { const requested: string[] = []; page.on('request', request => requested.push(request.url())); await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await page.getByLabel('Base version').click(); await page.getByRole('option', { name: '1.0.0' }).click(); await page.getByLabel('Target version').click(); await page.getByRole('option', { name: '2.0.0' }).click(); const diff = page.getByRole('table', { name: 'Canonical JSON path differences' }); await expect(diff).toContainText('changed'); await expect(diff).toContainText('/version'); expect(requested.some(value => value.includes('/bindings'))).toBe(false); });
test('UI-MOCK-24 viewer does not see privileged access or approval actions', async ({ page }) => { await page.unroute('**/admin/auth/me'); await page.route('**/admin/auth/me', route => route.fulfill({ json: { id: '20000000-0000-0000-0000-000000000002', displayName: 'Viewer', roles: [{ role: 'Viewer', tenantId: null }] } })); await page.reload(); await expect(page.getByRole('link', { name: 'Access control' })).toHaveCount(0); await page.getByRole('link', { name: 'Approvals' }).click(); await expect(page.getByRole('button', { name: 'Request approval' })).toHaveCount(0); await expect(page.getByRole('button', { name: 'Approve' })).toHaveCount(0); await expect(page.getByRole('button', { name: 'Reject' })).toHaveCount(0); });
test('UI-MOCK-25 CodeMirror exposes accessibility attributes on the contenteditable element', async ({ page }) => { await page.getByRole('link', { name: 'Connectors' }).click(); await expect(page.locator('[contenteditable="true"][aria-label="Connector JSON"][aria-describedby*="connector-json-help"]')).toBeVisible(); });
test('UI-MOCK-26 dirty binding form can stay or explicitly discard through router navigation', async ({ page }) => { await page.getByRole('link', { name: 'Bindings' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByRole('link', { name: 'Grants' }).click(); await expect(page.getByRole('dialog', { name: 'Unsaved changes' })).toBeVisible(); await page.getByRole('button', { name: 'Stay' }).click(); await expect(page.getByRole('heading', { name: 'Bindings' })).toBeVisible(); await page.getByRole('link', { name: 'Grants' }).click(); await page.getByRole('button', { name: 'Discard' }).click(); await expect(page.getByRole('heading', { name: 'Grants' })).toBeVisible(); });
test('UI-MOCK-27 binding editor selects server catalog resources and atomically sends structured maps with If-Match', async ({ page }) => { let observed: { body?: string; ifMatch?: string | null } = {}; await page.route('**/admin/api/v1/connectors/sample-secure-service/bindings', async route => { if (route.request().method() === 'PUT') { observed = { body: route.request().postData() ?? undefined, ifMatch: route.request().headers()['if-match'] }; await route.fulfill({ json: { revision: 5 } }); } else await route.fallback(); }); await page.getByRole('link', { name: 'Bindings' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByLabel('Version').fill('1.0.0'); await page.getByLabel('Environment').fill('50000000-0000-0000-0000-000000000001'); await expect(page.getByRole('table', { name: 'Available catalog resources' })).toContainText('vendor-api-key'); await expect(page.getByText('CCCCCCCCCCCC')).toBeVisible(); await page.getByLabel('Endpoint bindings (JSON object)').fill('{"primary":"https://vendor.example","backup":"https://backup.example"}'); await page.getByLabel('Secret catalog resources (JSON object)').fill('{"apiKey":{"providerId":"synthetic","resourceId":"vendor-api-key","resourceType":"Secret"}}'); await page.getByLabel('Certificate catalog resources (JSON object)').fill('{"mtls":{"providerId":"synthetic","resourceId":"vendor-client-certificate","resourceType":"ClientCertificate","publicMetadataRevision":1}}'); await page.getByRole('button', { name: 'Save' }).click(); await expect(page.getByRole('status')).toHaveText('Saved.'); expect(observed.ifMatch).toBe('"4"'); const body = JSON.parse(observed.body ?? '{}'); expect(body.endpoints).toEqual({ backup: 'https://backup.example', primary: 'https://vendor.example' }); expect(body.secretResources.apiKey).toMatchObject({ providerId: 'synthetic', resourceId: 'vendor-api-key', resourceType: 'Secret' }); });
test('UI-MOCK-28 operational dialogs diffs filters and pagination have no serious accessibility violations', async ({ page }) => {
  test.setTimeout(90_000);
  const verify = async (surface: string) => {
    const dialog = page.getByRole('dialog');
    if (await dialog.count()) await dialog.evaluate(async element => {
      // Contrast is meaningful on the settled surface, not its entry fade.
      await Promise.allSettled(element.parentElement!.getAnimations().map(animation => animation.finished));
    });
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? '')), surface).toEqual([]);
  };
  await page.getByRole('link', { name: 'Approvals' }).click(); await expect(page.getByRole('heading', { name: 'Approvals' })).toBeVisible(); await verify('approval workflow');
  await page.getByRole('link', { name: 'Installations' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await page.getByLabel('Application').click(); await page.getByRole('option', { name: 'Sample application' }).click(); await page.getByLabel('Environment').click(); await page.getByRole('option', { name: 'Local' }).click(); await page.getByRole('button', { name: 'Create installation' }).click(); await expect(page.getByRole('dialog')).toBeVisible(); await verify('activation code dialog'); await page.getByRole('button', { name: 'Close' }).click();
  await page.getByRole('link', { name: 'Audit' }).click(); await page.getByLabel('Select a tenant').click(); await page.getByRole('option', { name: 'Sample tenant' }).click(); await expect(page.getByRole('heading', { name: 'Audit' })).toBeVisible(); await verify('audit filters');
  await page.getByRole('link', { name: 'Connectors' }).click(); await page.getByRole('button', { name: 'sample-secure-service' }).click(); await page.getByLabel('Base version').click(); await page.getByRole('option', { name: '1.0.0' }).click(); await page.getByLabel('Target version').click(); await page.getByRole('option', { name: '2.0.0' }).click(); await expect(page.getByRole('table', { name: 'Canonical JSON path differences' })).toBeVisible(); await verify('canonical diff');
  await page.unroute('**/admin/api/v1/tenants**'); await page.route('**/admin/api/v1/tenants**', route => route.fulfill({ json: { items: [tenant], offset: 0, limit: 50, total: 101 } })); await page.getByRole('link', { name: 'Tenants' }).click(); await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled(); await expect(page.getByRole('heading', { name: 'Tenants' })).toBeVisible(); await verify('pagination');
});
test('UI-MOCK-29 approval submits the exact semantic digest and never exposes a credential value', async ({ page }) => { await page.route('**/admin/api/v1/connectors/*/versions/*/approvals', route => route.fulfill({ json: { status: 'Approved' } })); await page.getByRole('link', { name: 'Approvals' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.getByLabel('Version').fill('2.0.0'); await expect(page.getByTestId('approval-publication-digest')).toHaveText('D'.repeat(64)); await expect(page.getByTestId('approval-semantic-sentence')).toContainText('https://vendor.example.test:443/vendor/orders'); await expect(page.getByTestId('approval-authority-endpoint-review')).toHaveCount(2); await expect(page.getByTestId('approval-authority-endpoint-review').first()).toContainText('Authorization endpoint'); await expect(page.getByTestId('approval-authority-endpoint-review').first()).toContainText('oauth-authorize'); await expect(page.getByTestId('approval-authority-endpoint-review').first()).toContainText('https://login.example.test:443/authorize?tenant=synthetic'); await expect(page.getByRole('table', { name: 'Canonical approval diff' })).toContainText('/operations/0/endpoint/hostname'); const submitted = page.waitForRequest(request => request.method() === 'POST' && /\/approvals$/.test(new URL(request.url()).pathname)); await page.getByRole('button', { name: 'Approve' }).click(); const approvalRequest = await submitted; expect(approvalRequest.postDataJSON()).toMatchObject({ approvalRequestId: 'approval', expectedDigestSha256: 'D'.repeat(64) }); await expect(page.getByText(/SYNTHETIC-CANARY-SECRET/)).toHaveCount(0); });
test('UI-MOCK-30 browser Back keeps dirty edits until explicit confirmation', async ({ page }) => { await page.getByRole('link', { name: 'Bindings' }).click(); await page.getByLabel('Connectors').fill('sample-secure-service'); await page.goBack(); await expect(page.getByRole('dialog', { name: 'Unsaved changes' })).toBeVisible(); await page.getByRole('button', { name: 'Stay' }).click(); await expect(page.getByLabel('Connectors')).toHaveValue('sample-secure-service'); });
test('UI-MOCK-31 paged selector reaches records 51 and 101 with keyboard-visible controls', async ({ page }) => { await page.unroute('**/admin/api/v1/tenants**'); await page.route('**/admin/api/v1/tenants**', route => { const offset = Number(new URL(route.request().url()).searchParams.get('offset') ?? 0); const number = offset + 1; return route.fulfill({ json: { items: [{ ...tenant, id: `10000000-0000-0000-0000-${String(number).padStart(12, '0')}`, displayName: `Tenant ${number}` }], offset, limit: 50, total: 101 } }); }); await page.getByRole('link', { name: 'Installations' }).click(); const pager = page.getByTestId('tenant-installations-pagination'); await pager.getByRole('button', { name: 'Next' }).focus(); await page.keyboard.press('Enter'); await page.getByRole('combobox', { name: 'Select a tenant' }).click(); await expect(page.getByRole('option', { name: 'Tenant 51' })).toBeVisible(); await page.keyboard.press('Escape'); await pager.getByRole('button', { name: 'Next' }).focus(); await page.keyboard.press('Enter'); await page.getByRole('combobox', { name: 'Select a tenant' }).click(); await page.getByRole('option', { name: 'Tenant 101' }).click(); await expect(page.getByRole('combobox', { name: 'Select a tenant' })).toHaveText(/Tenant 101/); });
test('UI-MOCK-32 remediation strings are localized in Italian without key fallback', async ({ page }) => { await page.getByLabel('Language').click(); await page.getByRole('option', { name: 'IT' }).click(); await page.getByRole('link', { name: 'Binding' }).click(); await expect(page.getByLabel('Binding endpoint (oggetto JSON)')).toBeVisible(); await expect(page.getByText(/Invia il set completo/)).toBeVisible(); });
test('UI-MOCK-33 Italian mode covers all runtime-code administrative surfaces without English fallback', async ({ page }) => { await page.getByLabel('Language').click(); await page.getByRole('option', { name: 'IT' }).click(); for (const [link, heading] of [['Tenant', 'Tenant'], ['Applicazioni', 'Applicazioni'], ['Installazioni', 'Installazioni'], ['Connettori', 'Connettori'], ['Binding', 'Binding'], ['Autorizzazioni', 'Autorizzazioni'], ['Audit', 'Audit'], ['Stato', 'Stato'], ['Controllo accessi', 'Controllo accessi']] as const) { await page.getByRole('link', { name: link, exact: true }).click(); await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible(); } await page.getByLabel('Ruolo').click(); await expect(page.getByRole('option', { name: 'Editor connettori' })).toBeVisible(); await page.keyboard.press('Escape'); await page.getByRole('link', { name: 'Approvazioni' }).click(); await page.getByLabel('Connettori').fill('sample-secure-service'); await page.getByLabel('Versione').fill('2.0.0'); await expect(page.getByText('Destinazione Internet pubblica').first()).toBeVisible(); await expect(page.getByText(/Questa operazione utilizzerà la credenziale logica/)).toBeVisible(); await expect(page.getByText(/Valore sconosciuto/)).toHaveCount(0); });
test('UI-MOCK-34 stale Tenant ETag opens a localized compare-and-reload conflict instead of overwriting', async ({ page }) => { await page.route(`**/admin/api/v1/tenants/${tenant.id}`, route => route.request().method() === 'PUT' ? route.fulfill({ status: 409, json: { code: 'BGW-CONCURRENCY-CONFLICT', correlationId: 'tenant-conflict' } }) : route.fulfill({ json: { ...tenant, displayName: 'Current server tenant', rowVersion: 2 } })); await page.getByRole('link', { name: 'Tenants' }).click(); await page.getByRole('button', { name: 'Edit' }).click(); await page.getByLabel('Name').fill('My stale edit'); await page.getByRole('button', { name: 'Save' }).click(); await expect(page.getByText(/Another administrator changed this resource/)).toBeVisible(); await expect(page.getByText(/Current server tenant/)).toBeVisible(); await page.getByRole('button', { name: 'Reload current data' }).click(); await expect(page.getByLabel('Name')).toHaveValue('Current server tenant'); });
test('UI-MOCK-35 stale Application ETag compares every mutable field and prevents blind overwrite', async ({ page }) => { const application = { id: '30000000-0000-0000-0000-000000000001', code: 'sample-app', displayName: 'Sample application', status: 'Active', minimumBrokerVersion: '3.0.0', maximumBrokerVersion: '3.9.0', createdAt: '2026-08-05T00:00:00Z', rowVersion: 1 }; let mutations = 0; await page.route(`**/admin/api/v1/applications/${application.id}`, route => { if (route.request().method() === 'PUT') { mutations += 1; return route.fulfill({ status: 409, json: { code: 'BGW-CONCURRENCY-CONFLICT', correlationId: 'application-conflict' } }); } return route.fulfill({ json: { ...application, status: 'Suspended', minimumBrokerVersion: '3.2.0', maximumBrokerVersion: '4.0.0', rowVersion: 2 } }); }); await page.getByRole('link', { name: 'Applications' }).click(); await page.getByRole('button', { name: 'Edit' }).click(); await page.getByLabel('Minimum Broker version').fill('3.1.0'); await page.getByLabel('Maximum Broker version').fill('3.8.0'); await page.getByRole('button', { name: 'Save' }).click(); const conflict = page.getByRole('table', { name: /another administrator changed/i }); await expect(conflict).toContainText('3.1.0'); await expect(conflict).toContainText('3.2.0'); await expect(conflict).toContainText('3.8.0'); await expect(conflict).toContainText('4.0.0'); await expect(conflict).toContainText('Active'); await expect(conflict).toContainText('Suspended'); await expect(page.getByText('Your ETag: "1"')).toBeVisible(); await expect(page.getByText('Server ETag: "2"')).toBeVisible(); await expect(page.getByText('Update application')).toBeVisible(); await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled(); expect(mutations).toBe(1); await page.getByRole('button', { name: 'Reload current data' }).click(); await expect(page.getByLabel('Minimum Broker version')).toHaveValue('3.2.0'); await expect(page.getByLabel('Maximum Broker version')).toHaveValue('4.0.0'); await expect(page.getByText(/The resource changed/)).toHaveCount(0); await page.getByRole('button', { name: 'Cancel' }).click(); await expect(page.getByRole('dialog')).toHaveCount(0); });
test('UI-MOCK-36 concurrent Application disable exposes the status conflict and reloads without another mutation', async ({ page }) => { const id = '30000000-0000-0000-0000-000000000001'; let mutations = 0; await page.route(`**/admin/api/v1/applications/${id}**`, route => { if (route.request().method() === 'POST') { mutations += 1; return route.fulfill({ status: 409, json: { code: 'BGW-CONCURRENCY-CONFLICT', correlationId: 'application-disable-conflict' } }); } return route.fulfill({ json: { id, code: 'sample-app', displayName: 'Sample application', status: 'Suspended', minimumBrokerVersion: '3.0.0', maximumBrokerVersion: null, createdAt: '2026-08-05T00:00:00Z', rowVersion: 2 } }); }); await page.getByRole('link', { name: 'Applications' }).click(); await page.getByRole('button', { name: 'Disable' }).click(); const conflict = page.getByRole('table', { name: /another administrator changed/i }); await expect(conflict).toContainText('Active'); await expect(conflict).toContainText('Suspended'); await expect(page.getByText('Disable application')).toBeVisible(); await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled(); expect(mutations).toBe(1); await page.getByRole('button', { name: 'Reload current data' }).click(); await expect(page.getByRole('button', { name: 'Save' })).toBeEnabled(); expect(mutations).toBe(1); });
test('UI-MOCK-37 safe failure diagnostics are SecurityAdministrator-only bounded and accessible', async ({ page }) => {
  await page.getByRole('link', { name: 'Audit' }).click();
  await page.getByLabel('Select a tenant').click();
  await page.getByRole('option', { name: 'Sample tenant' }).click();
  const diagnostics = page.getByRole('region', { name: 'Safe failure diagnostics' });
  await expect(diagnostics).toContainText('Gateway status: BGW-EGRESS-UPSTREAM-REJECTED');
  await expect(diagnostics).toContainText('Upstream status: 202');
  await expect(diagnostics).toContainText('LOCAL_RESPONSE_MAPPING_FAILURE');
  await expect(diagnostics).toContainText('FSE2_RESPONSE_INVALID');
  await expect(diagnostics).not.toContainText(/raw|header|token|certificate|exception|stack|retry|replay/i);
  const axe = await new AxeBuilder({ page }).include('[aria-label="Safe failure diagnostics"]').analyze();
  expect(axe.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);

  await page.unroute('**/admin/auth/me');
  await page.route('**/admin/auth/me', route => route.fulfill({ json: { id: '20000000-0000-0000-0000-000000000002', displayName: 'Viewer', roles: [{ role: 'Viewer', tenantId: null }] } }));
  await page.reload();
  await page.getByLabel('Select a tenant').click();
  await page.getByRole('option', { name: 'Sample tenant' }).click();
  await expect(page.getByRole('region', { name: 'Safe failure diagnostics' })).toHaveCount(0);
  await expect(page.getByText('FSE2_RESPONSE_INVALID')).toHaveCount(0);
});
test('UI-MOCK-38 guided onboarding starts from readable selectors and exposes only the current role action', async ({ page }) => {
  await page.getByRole('link', { name: 'Guided onboarding' }).click();
  await expect(page.getByRole('heading', { name: 'Guided onboarding' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Select a tenant', exact: true }).click(); await page.getByRole('option', { name: 'Sample tenant' }).click();
  await page.getByRole('combobox', { name: 'Application', exact: true }).click(); await page.getByRole('option', { name: 'Sample application' }).click();
  await page.getByRole('combobox', { name: 'Environment', exact: true }).click(); await page.getByRole('option', { name: 'Local' }).click();
  await expect(page.getByRole('button', { name: 'Create installation' })).toBeEnabled();
  await page.getByRole('link', { name: 'Go to the next action' }).click();
  await expect(page.locator('#guided-current-action')).toBeFocused();
  await expect(page.getByRole('heading', { name: /^2\./ })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: /^4\./ })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: /^5\./ })).toHaveCount(0);
  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);
});

test('UI-MOCK-46 guided server search is bounded and keyboard usable in a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const remote = { ...tenant, id: '10000000-0000-0000-0000-000000009999', code: 'remote-9999', displayName: 'Remote tenant' };
  const requests: URL[] = [];
  await page.route('**/admin/api/v1/tenants?*', route => {
    const url = new URL(route.request().url()); requests.push(url);
    const searching = url.searchParams.get('filter') === 'remote';
    return route.fulfill({ json: { items: searching ? [remote] : [tenant], offset: 0, limit: 50, total: searching ? 1 : 10000 } });
  });
  await page.route(`**/admin/api/v1/tenants/${remote.id}`, route => route.fulfill({ json: remote }));
  await page.goto('./onboarding');
  const search = page.getByRole('combobox', { name: 'Select a tenant', exact: true });
  await search.fill('remote');
  const selector = page.getByRole('combobox', { name: 'Select a tenant', exact: true });
  await expect.poll(() => requests.some(url => url.searchParams.get('filter') === 'remote')).toBe(true);
  await expect(selector).toBeEnabled();
  await expect(selector).toBeFocused();
  await selector.press('ArrowDown');
  await expect(page.getByRole('option', { name: 'Remote tenant · remote-9999' })).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(selector).toHaveValue('Remote tenant · remote-9999');
  await page.reload();
  await expect(selector).toHaveValue('Remote tenant · remote-9999');
  expect(requests.every(url => Number(url.searchParams.get('limit')) <= 50)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);
});

for (const screen of ['Installations', 'Guided onboarding']) {
  for (const kind of ['Direct', 'Broker']) {
    test(`UI-MOCK-43 ${screen} defaults to Direct and creates the selected ${kind} identity`, async ({ page }) => {
      await page.getByRole('link', { name: screen, exact: true }).click();
      const selector = page.getByRole('combobox', { name: 'Installation type', exact: true });
      await expect(selector).toHaveText('Direct');
      await expect(selector).toHaveAccessibleDescription('Application → Gateway. Default for the Core pilot; no Local Broker required.');
      await page.getByRole('combobox', { name: 'Select a tenant', exact: true }).click(); await page.getByRole('option', { name: 'Sample tenant' }).click();
      await page.getByLabel('Application', { exact: true }).click(); await page.getByRole('option', { name: 'Sample application' }).click();
      await page.getByLabel('Environment', { exact: true }).click(); await page.getByRole('option', { name: /^Local(?: ·|$)/ }).click();
      if (kind === 'Broker') {
        await selector.click(); await page.getByRole('option', { name: 'Broker', exact: true }).click();
        await expect(selector).toHaveAccessibleDescription('Application → Windows Local Broker → Gateway. Install and enroll the Broker outside this page.');
      }
      // Read-back reflects the server record; the type is not a resume URL parameter.
      const installationId = '40000000-0000-0000-0000-000000000002';
      await page.route(`**/admin/api/v1/installations/${installationId}?*`, route => route.fulfill({ json: {
        id: installationId, tenantId: tenant.id, applicationId: '30000000-0000-0000-0000-000000000001',
        environmentId: '50000000-0000-0000-0000-000000000001', installationKind: kind, status: 'Pending', createdAt: '2026-08-05T00:00:00Z'
      } }));
      const requestPromise = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/admin/api/v1/installations');
      await page.getByRole('button', { name: 'Create installation', exact: true }).click();
      expect((await requestPromise).postDataJSON()).toEqual({ tenantId: tenant.id,
        applicationId: '30000000-0000-0000-0000-000000000001', environmentId: '50000000-0000-0000-0000-000000000001', installationKind: kind });
      await expect(page.getByRole('textbox', { name: 'Activation code ID', exact: true })).toBeVisible();
      await page.getByRole('button', { name: 'Close', exact: true }).click();
      if (screen === 'Guided onboarding') {
        await expect(page.getByRole('combobox', { name: 'Installation', exact: true })).toHaveValue(new RegExp(kind));
        await expect(selector).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Create installation', exact: true })).toHaveCount(0);
      }
    });
  }
  test(`UI-MOCK-44 ${screen} does not expose installation creation to a viewer`, async ({ page }) => {
    await fixtures(page, 'Viewer');
    await page.reload();
    await page.getByRole('link', { name: screen, exact: true }).click();
    await expect(page.getByRole('heading', { name: screen, exact: true })).toBeVisible();
    await expect(page.getByRole('combobox', { name: 'Installation type', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Create installation', exact: true })).toHaveCount(0);
  });
}

test('UI-MOCK-45 guided resume keeps the existing server-owned Broker kind after reload', async ({ page }) => {
  const installationId = '40000000-0000-0000-0000-000000000001';
  await page.route(`**/admin/api/v1/installations/${installationId}?*`, route => route.fulfill({ json: {
    id: installationId, tenantId: tenant.id, applicationId: '30000000-0000-0000-0000-000000000001',
    environmentId: '50000000-0000-0000-0000-000000000001', installationKind: 'Broker', status: 'Active', createdAt: '2026-08-05T00:00:00Z'
  } }));
  let mutations = 0;
  page.on('request', request => { if (request.method() === 'POST') mutations++; });
  await page.goto(`./onboarding?tenant=${tenant.id}&installation=${installationId}&installationKind=Direct`);
  const selector = page.getByRole('combobox', { name: 'Installation', exact: true });
  await expect(selector).toHaveValue(/Broker/);

  await page.reload();
  await expect(selector).toHaveValue(/Broker/);

  await expect(page.getByRole('button', { name: 'Create installation', exact: true })).toHaveCount(0);
  expect(mutations).toBe(0);
});

for (const kind of ['Direct', 'Broker']) {
  test(`UI-MOCK-47 ready ${kind} target links to its invocation procedure without obsolete actions`, async ({ page }) => {
    const installationId = '40000000-0000-0000-0000-000000000001';
    await page.setViewportSize({ width: 390, height: 844 });
    await page.route(`**/admin/api/v1/installations/${installationId}?*`, route => route.fulfill({ json: {
      id: installationId, tenantId: tenant.id, applicationId: '30000000-0000-0000-0000-000000000001',
      environmentId: '50000000-0000-0000-0000-000000000001', installationKind: kind, status: 'Active', createdAt: '2026-09-14T23:30:00-02:00'
    } }));
    await page.goto(`./onboarding?tenant=${tenant.id}&installation=${installationId}&connector=sample-secure-service&version=2.0.0`);
    await expect(page.getByRole('combobox', { name: 'Installation', exact: true })).toHaveValue(new RegExp(`${kind} · Active · 15 Sep 2026`));
    await expect(page.getByRole('button', { name: 'Create installation', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Validate and import', exact: true })).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.getByRole('link', { name: `Open the ${kind} invocation procedure`, exact: true }).click();
    await expect(page.locator(`#invoke-${kind.toLowerCase()}`)).toBeFocused();
    await expect(page.getByRole('heading', { name: 'Documentation', exact: true })).toBeAttached();
  });
}

for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 900 }, { width: 390, height: 844 }]) {
  test(`UI-MOCK-41 installation controls and table stay within the ${viewport.width}px viewport`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    await page.goto('./installations');
    await expect(page.getByRole('heading', { name: 'Installations', exact: true })).toBeVisible();
    await expect(page.getByText('Choose a tenant to view its installations.', { exact: false })).toBeVisible();
    await expect(page.getByTestId('tenant-installations-pagination')).toHaveCount(0);
    await expect(page.getByText('No records found.')).toHaveCount(0);
    const main = await page.locator('main').boundingBox();
    expect(main?.x).toBe(viewport.width >= 900 ? 248 : 0);
    for (const control of [...await page.locator('main').getByRole('combobox').all(), page.getByRole('button', { name: 'Create installation' })]) {
      const box = await control.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(main!.x);
      expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
    await page.screenshot({ path: testInfo.outputPath(`installations-${viewport.width}.png`), fullPage: true });

    await page.getByRole('combobox', { name: 'Select a tenant' }).click();
    await page.getByRole('option', { name: 'Sample tenant' }).click();
    await expect(page.locator('[role="listbox"]')).toHaveCount(0);
    const table = page.getByRole('table', { name: 'Installations' });
    await expect(table).toContainText('05 Aug 2026, 00:00:00 UTC');
    await expect(table).toContainText('Sample application');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
    await page.screenshot({ path: testInfo.outputPath(`installations-table-${viewport.width}.png`), fullPage: true });

    if (viewport.width < 900) {
      await page.getByRole('button', { name: 'Open navigation' }).click();
      await page.getByRole('link', { name: 'Dashboard', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Installations', exact: true })).not.toBeVisible();
    }
  });
}

test('UI-MOCK-42 shared pages fit a compact desktop and dark theme remains accessible', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  for (const route of ['applications', 'tenants', 'onboarding', 'connectors', 'bindings', 'grants', 'approvals', 'access', 'audit', 'health']) {
    await page.goto(`./${route}`);
    await expect(page.locator('main h1')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth), route).toBeLessThanOrEqual(1024);
  }
  await page.goto('./installations');
  await page.getByLabel('Theme').click();
  await page.getByRole('option', { name: 'Dark', exact: true }).click();
  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath('installations-dark.png'), fullPage: true });
});
});

test('UI-MOCK-40 anonymous first access reaches login and completes the browser login flow', async ({ page }) => {
  // Configure anonymous responses before any app navigation; an in-flight session
  // from the authenticated setup can otherwise redirect while page.goto is loading.
  expect(page.url()).toBe('about:blank');
  await fixtures(page);
  let authenticated = false;
  await page.unroute('**/admin/auth/me');
  await page.route('**/admin/auth/me', route => authenticated
    ? route.fulfill({ json: { id: '20000000-0000-0000-0000-000000000001', displayName: 'Security administrator', roles: [{ role: 'SecurityAdministrator', tenantId: null }] } })
    : route.fulfill({ status: 401, json: { code: 'BGW-ADMIN-AUTHENTICATION-REQUIRED' } }));
  await page.route('**/admin/auth/development/login', route => {
    expect(route.request().postDataJSON()).toEqual({ userName: 'security-admin' });
    authenticated = true;
    return route.fulfill({ json: {} });
  });
  await page.goto('./login');
  await expect(page.getByRole('heading', { name: 'Administrative access' })).toBeVisible();
  await expect(page.getByRole('status')).toHaveCount(0);
  await page.getByRole('button', { name: 'Security administrator', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
});
