import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, randomBytes, randomUUID, sign, X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { promisify } from 'node:util';

type ApiResult<T> = { status: number; body: T; etag: string | null };
const execFileAsync = promisify(execFile);
const csrfTokens = new WeakMap<Page, string>();

async function login(context: BrowserContext, user: 'editor' | 'approver' | 'operator' | 'security-admin'): Promise<Page> {
  const baseUrl = process.env.M5_FULLSTACK_BASE_URL ?? 'https://localhost:8443/admin/';
  const csrfResponse = await context.request.get(new URL('auth/csrf', baseUrl).toString(), { headers: { Accept: 'application/json' } });
  expect(csrfResponse.status()).toBe(200);
  const csrf = await csrfResponse.json() as { token: string };
  const loginResponse = await context.request.post(new URL('auth/development/login', baseUrl).toString(), {
    headers: { Accept: 'application/json', 'X-CSRF-TOKEN': csrf.token },
    data: { userName: user }
  });
  expect(loginResponse.status()).toBe(200);
  const page = await context.newPage();
  await page.goto(baseUrl);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  return page;
}

async function api<T>(page: Page, path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<ApiResult<T>> {
  const mutation = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  if (mutation && !csrfTokens.has(page)) {
    const token = await page.evaluate(async () => {
      const response = await fetch('/admin/auth/csrf', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(`CSRF_${response.status}`);
      return ((await response.json()) as { token: string }).token;
    });
    csrfTokens.set(page, token);
  }
  if (mutation) headers['X-CSRF-TOKEN'] = csrfTokens.get(page)!;
  return page.evaluate(async ({ path, method, body, headers }) => {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null, etag: response.headers.get('etag') };
  }, { path, method, body, headers });
}

async function invokeRuntime(connectorId: string, operationId: string, correlationId: string, certificatePath = process.env.M5_FULLSTACK_CLIENT_CERT ?? '/m3-fixture/certificates/security-driver.crt', privateKeyPath = process.env.M5_FULLSTACK_CLIENT_KEY ?? '/m3-fixture/certificates/security-driver.key') {
  const target = `/v1/connectors/${encodeURIComponent(connectorId)}/operations/${encodeURIComponent(operationId)}:invoke`;
  const body = JSON.stringify({ protocolVersion: '1.0', payload: { contentType: 'application/json', encoding: 'base64', data: Buffer.from('{"synthetic":true}').toString('base64') }, correlationId });
  const timestamp = new Date().toISOString();
  const nonce = randomBytes(16).toString('base64url');
  const digest = createHash('sha256').update(body).digest('base64url');
  const privateKey = createPrivateKey(readFileSync(privateKeyPath));
  const signature = sign('sha256', Buffer.from(['BGW1', 'POST', target, timestamp, nonce, digest].join('\n')), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const traceparent = `00-${correlationId.replaceAll('-', '')}-${randomBytes(8).toString('hex')}-01`;
  const baseUrl = process.env.M5_FULLSTACK_BASE_URL ?? 'https://localhost:8443/admin/';
  const response = await execFileAsync('curl', [
    '--silent', '--show-error', '--cacert', process.env.M5_FULLSTACK_CA_CERT ?? '/m3-fixture/certificates/ca.crt',
    '--cert', certificatePath,
    '--key', privateKeyPath,
    '--request', 'POST', '--header', 'Content-Type: application/json', '--header', `X-BG-Timestamp: ${timestamp}`,
    '--header', `X-BG-Nonce: ${nonce}`, '--header', `X-BG-Content-SHA256: ${digest}`, '--header', `X-BG-Signature: ${signature}`,
    '--header', `traceparent: ${traceparent}`,
    '--data-binary', body, '--write-out', '\n%{http_code}', new URL(target, baseUrl).toString()
  ], { maxBuffer: 2 * 1024 * 1024 });
  const separator = response.stdout.lastIndexOf('\n');
  const text = response.stdout.slice(0, separator);
  return { status: Number(response.stdout.slice(separator + 1)), body: text ? JSON.parse(text) as Record<string, unknown> : {} };
}

async function enrollInstallation(context: BrowserContext, activationCodeId: string, activationCode: string): Promise<{ status: number; code?: string }> {
  const baseUrl = process.env.M5_FULLSTACK_BASE_URL ?? 'https://localhost:8443/admin/';
  const certificatePem = readFileSync('/m3-fixture/certificates/onboarding-driver.crt', 'utf8');
  const privateKey = createPrivateKey(readFileSync('/m3-fixture/certificates/onboarding-driver.key'));
  const certificate = new X509Certificate(certificatePem);
  const publicKeySpki = certificate.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const challengeResponse = await context.request.post(new URL('/v1/enrollments/challenges', baseUrl).toString(), {
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    data: { activationCodeId, publicKeySpki }
  });
  expect(challengeResponse.status()).toBe(200);
  const challenge = await challengeResponse.json() as { challengeId: string; challenge: string };
  const proof = Buffer.from(`BGW-ENROLL1\n${challenge.challengeId}\n${challenge.challenge}\n${activationCodeId}`);
  const proofSignature = sign('sha256', proof, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const activationResponse = await context.request.post(new URL('/v1/enrollments:activate', baseUrl).toString(), {
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    data: { challengeId: challenge.challengeId, activationCode, clientCertificate: certificate.raw.toString('base64'), proofSignature, clientVersion: '1.0.0' }
  });
  const status = activationResponse.status();
  const code = status === 200 ? undefined : ((await activationResponse.json()) as { code?: string }).code;
  return { status, code };
}

test('FULLSTACK-01 production Admin build persists and governs the connector lifecycle', async ({ browser }) => {
  const editorContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const approverContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const securityContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const operatorContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const editor = await login(editorContext, 'editor');
  const approver = await login(approverContext, 'approver');
  const security = await login(securityContext, 'security-admin');
  const operator = await login(operatorContext, 'operator');
  const browserEvidence: { console: string[]; network: string[] } = { console: [], network: [] };
  for (const observed of [editor, approver, security, operator]) {
    observed.on('console', message => browserEvidence.console.push(message.text()));
    observed.on('response', async response => {
      const pathname = new URL(response.url()).pathname;
      if ((pathname.startsWith('/admin/api/') || pathname.startsWith('/v1/')) && browserEvidence.network.length < 500) browserEvidence.network.push(`${response.request().method()} ${pathname} ${response.status()}`);
    });
  }

  const sample = await api<Record<string, unknown>>(editor, '/admin/api/v1/connectors/sample');
  expect(sample.status).toBe(200);
  const definition = structuredClone(sample.body);
  definition.version = '2.0.0';

  const validation = await api<{ valid: boolean; checksumSha256: string }>(editor, '/admin/api/v1/connectors:validate', 'POST', { definition });
  expect(validation.status).toBe(200);
  expect(validation.body.valid).toBe(true);
  const imported = await api<{ connectorId: string; version: string; rowVersion: number; state: string }>(editor, '/admin/api/v1/connectors:import', 'POST', { definition, expectedChecksumSha256: validation.body.checksumSha256 });
  expect(imported.status).toBe(201);
  expect(imported.body.state).toBe('Draft');
  const validated = await api<typeof imported.body>(editor, `/admin/api/v1/connectors/sample-secure-service/versions/2.0.0:validate`, 'POST', undefined, { 'If-Match': `"${imported.body.rowVersion}"` });
  expect(validated.status).toBe(200);
  expect(validated.body.state).toBe('Validated');

  const resources = await api<{ items: Array<{ providerId: string; resourceId: string; resourceType: string; environmentId: string; connectorScope: string; publicMetadataRevision?: number | null }> }>(security, '/admin/api/v1/provider-resources?offset=0&limit=100');
  expect(resources.status).toBe(200);
  const secretResource = resources.body.items.find(value => value.providerId === 'synthetic-vault' && value.resourceId === 'security-sample-vendor-api-key' && value.resourceType === 'Secret' && value.connectorScope === 'sample-secure-service');
  const certificateResource = resources.body.items.find(value => value.providerId === 'synthetic-vault' && value.resourceId === 'security-sample-vendor-client-certificate' && value.resourceType === 'ClientCertificate' && value.connectorScope === 'sample-secure-service');
  expect(secretResource).toBeTruthy();
  expect(certificateResource).toBeTruthy();
  expect(certificateResource!.environmentId).toBe(secretResource!.environmentId);
  const catalogEnvironmentId = secretResource!.environmentId;
  const tenants = await api<{ items: Array<{ id: string }> }>(security, '/admin/api/v1/tenants?offset=0&limit=50');
  let tenantId: string | undefined;
  let enrolled: { id: string; status: string; environmentId: string } | undefined;
  for (const tenant of tenants.body.items) {
    const installations = await api<{ items: Array<{ id: string; status: string; environmentId: string }> }>(security, `/admin/api/v1/installations?tenantId=${tenant.id}&offset=0&limit=50`);
    const grants = await api<{ items: Array<{ installationId: string; connectorId: string; operationId: string }> }>(security, `/admin/api/v1/grants?tenantId=${tenant.id}&offset=0&limit=50`);
    for (const active of installations.body.items.filter(value => value.status === 'Active' && value.environmentId === catalogEnvironmentId)) {
      const alreadyGranted = grants.body.items.some(value => value.installationId === active.id && value.connectorId === 'sample-secure-service' && value.operationId === 'submit');
      if (!alreadyGranted) {
        enrolled = active;
        tenantId = tenant.id;
        break;
      }
    }
    if (enrolled) break;
  }
  expect(tenantId, 'quick-start tenant containing an Active installation without the target grant must exist').toBeTruthy();
  expect(enrolled, 'quick-start challenge/PoP enrollment must persist an Active installation available for grant mutation').toBeTruthy();
  const environmentId = enrolled!.environmentId;
  expect(environmentId).toBeTruthy();
  const binding = await api<{ revision: number }>(security, '/admin/api/v1/connectors/sample-secure-service/bindings', 'PUT', {
    environmentId,
    connectorVersion: '2.0.0',
    endpoints: { 'sample-vendor-endpoint': 'https://vendor.m3.test:8443/' },
    secretResources: { 'sample-vendor-api-key': { providerId: secretResource!.providerId, resourceId: secretResource!.resourceId, resourceType: 'Secret' } },
    certificateResources: { 'sample-vendor-client-certificate': { providerId: certificateResource!.providerId, resourceId: certificateResource!.resourceId, resourceType: 'ClientCertificate', publicMetadataRevision: certificateResource!.publicMetadataRevision } }
  });
  expect(binding.status).toBe(200);
  expect(binding.body.revision).toBe(1);

  const requested = await api<{ id: string; status: string; bindingDigestSha256: string }>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approval-requests', 'POST');
  expect(requested.status).toBe(200);
  const review = await api<{ digestSha256: string; canonicalJson: string; artifact: { operations: Array<{ endpoint: { hostname: string; port: number; path: string; allowedMethods: string[] }; secretBindings: Array<{ providerId: string; resourceLogicalId: string }> }> } }>(approver, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approval-review');
  expect(review.status).toBe(200);
  expect(review.body.digestSha256).toBe(requested.body.bindingDigestSha256);
  expect(review.body.artifact.operations).toContainEqual(expect.objectContaining({ endpoint: expect.objectContaining({ hostname: 'vendor.m3.test', port: 8443, path: '/vendor/orders', allowedMethods: ['POST'] }), secretBindings: [expect.objectContaining({ providerId: 'synthetic-vault', resourceLogicalId: 'security-sample-vendor-api-key' })] }));
  expect(review.body.canonicalJson).not.toMatch(/secretValue|privateKey|clientSecret|passwordValue|connectionString|SYNTHETIC-CANARY/i);
  const approvalBody = { approvalRequestId: requested.body.id, expectedDigestSha256: review.body.digestSha256 };
  const selfApproval = await api<{ code: string }>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approvals', 'POST', approvalBody);
  expect(selfApproval.status).toBe(403);
  expect(selfApproval.body.code).toMatch(/^BGW-/);
  const approved = await api<{ status: string }>(approver, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0/approvals', 'POST', approvalBody);
  expect(approved.status).toBe(200);

  const connectors = await api<{ items: Array<{ connectorId: string; publicationRevision: number }> }>(approver, '/admin/api/v1/connectors?offset=0&limit=50');
  const summary = connectors.body.items.find(value => value.connectorId === 'sample-secure-service');
  expect(summary).toBeTruthy();
  const published = await api<typeof validated.body>(approver, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0:publish', 'POST', { expectedRowVersion: validated.body.rowVersion, expectedPublicationRevision: summary!.publicationRevision }, { 'If-Match': `"${validated.body.rowVersion}"` });
  expect(published.status).toBe(200);
  expect(published.body.state).toBe('Published');

  const controlledTest = await api<{ status: string; connectorVersion: string }>(operator, '/admin/api/v1/connectors/sample-secure-service:test', 'POST', { environmentId, operationId: 'submit' });
  expect(controlledTest.status).toBe(200);
  expect(controlledTest.body).toMatchObject({ status: 'valid', connectorVersion: '2.0.0' });

  const grant = await api<Record<string, unknown>>(security, '/admin/api/v1/grants', 'POST', { tenantId, installationId: enrolled!.id, connectorId: 'sample-secure-service', connectorVersion: '2.0.0', operationId: 'submit' });
  expect(grant.status).toBe(201);

  const correlationId = randomUUID();
  const invoked = await invokeRuntime('sample-secure-service', 'submit', correlationId);
  expect(invoked.status, `runtime invoke failed with ${JSON.stringify(invoked.body)}`).toBe(200);
  expect(invoked.body.connectorVersion).toBe('2.0.0');
  const sanitized = JSON.stringify(invoked.body);
  expect(sanitized).not.toMatch(/api.?key|certificate|secret|synthetic-vault/i);

  const v2 = await api<typeof published.body>(security, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0');
  const retired = await api<typeof published.body>(security, '/admin/api/v1/connectors/sample-secure-service/versions/2.0.0:retire', 'POST', undefined, { 'If-Match': `"${v2.body.rowVersion}"` });
  expect(retired.status).toBe(200);
  expect(retired.body.state).toBe('Retired');
  const deniedAfterRetire = await invokeRuntime('sample-secure-service', 'submit', randomUUID());
  expect(deniedAfterRetire.status).not.toBe(200);
  const audit = await api<{ total: number; items: Array<{ correlationId: string; action: string }> }>(security, `/admin/api/v1/audit?tenantId=${tenantId}&offset=0&limit=100`);
  expect(audit.status).toBe(200);
  expect(audit.body.total).toBeGreaterThan(0);
  expect(audit.body.items).toContainEqual(expect.objectContaining({ correlationId, action: 'operation.invoke' }));

  await security.goto('./connectors');
  await expect(security.getByRole('heading', { name: 'Connectors' })).toBeVisible();
  const accessibility = await new AxeBuilder({ page: security }).analyze();
  expect(accessibility.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);

  const replayCookies = await editorContext.cookies();
  const logout = await api<{ status: string }>(editor, '/admin/auth/logout', 'POST');
  expect(logout.status).toBe(200);
  const replayContext = await browser.newContext({ ignoreHTTPSErrors: true });
  await replayContext.addCookies(replayCookies);
  const replay = await replayContext.request.get(new URL('/admin/auth/me', editor.url()).toString(), { headers: { Accept: 'application/json' }, maxRedirects: 0 });
  expect(replay.status()).toBe(401);

  writeFileSync('test-results/browser-redaction-surfaces.json', JSON.stringify({
    dom: await Promise.all([editor, approver, security, operator].map(value => value.locator('body').innerText())),
    console: browserEvidence.console,
    network: browserEvidence.network
  }));

  await Promise.all([editorContext.close(), approverContext.close(), securityContext.close(), operatorContext.close(), replayContext.close()]);
});

test('FULLSTACK-02 guided onboarding reaches one real invocation in five resumable operator actions', async ({ browser }) => {
  const securityContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const editorContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const approverContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const security = await login(securityContext, 'security-admin');
  const editor = await login(editorContext, 'editor');
  const approver = await login(approverContext, 'approver');
  let operatorActionCount = 0;
  let tooManyRequestsCount = 0;
  let unauthorizedResponseCount = 0;
  for (const page of [security, editor, approver]) page.on('response', response => {
    if (response.status() === 429) tooManyRequestsCount++;
    if (response.status() === 401) unauthorizedResponseCount++;
  });
  const choose = async (page: Page, label: string, option: string) => {
    await page.getByRole('combobox', { name: label, exact: true }).click();
    await page.getByRole('option', { name: option, exact: false }).click();
  };

  await security.goto('./onboarding');
  await expect(security.getByRole('heading', { name: 'Guided onboarding' })).toBeVisible();
  await choose(security, 'Select a tenant', 'M3 Synthetic Tenant');
  await choose(security, 'Application', 'M3 Legacy Simulator');
  await choose(security, 'Environment', 'M3 Deterministic');
  await expect(security.getByRole('heading', { name: /^2\./ })).toHaveCount(0);
  await expect(security.getByRole('heading', { name: /^4\./ })).toHaveCount(0);
  await expect(security.getByRole('heading', { name: /^5\./ })).toHaveCount(0);

  operatorActionCount++;
  await security.getByRole('button', { name: 'Create installation' }).click();
  const activationCodeId = await security.getByRole('textbox', { name: 'Activation code ID' }).inputValue();
  const activationCode = await security.getByRole('textbox', { name: 'Activation code', exact: true }).inputValue();
  expect(activationCodeId).not.toBe(activationCode);
  const enrollment = await enrollInstallation(securityContext, activationCodeId, activationCode);
  await security.getByRole('button', { name: 'Close' }).click();
  await security.reload();
  expect(enrollment).toEqual({ status: 200, code: undefined });
  await expect(security.getByText('Connector definition required')).toBeVisible();
  const targetUrl = security.url();

  await editor.goto(targetUrl);
  await expect(editor.getByRole('heading', { name: /^1\./ })).toHaveCount(0);
  await expect(editor.getByRole('heading', { name: /^3\./ })).toHaveCount(0);
  await expect(editor.getByRole('heading', { name: /^5\./ })).toHaveCount(0);
  const sample = await api<Record<string, unknown>>(editor, '/admin/api/v1/connectors/sample');
  expect(sample.status).toBe(200);
  const definition = structuredClone(sample.body);
  definition.version = '3.0.0';
  await editor.getByLabel('Connector definition file').setInputFiles({
    name: 'sample-secure-service-3.0.0.connector.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(definition))
  });
  operatorActionCount++;
  await editor.getByRole('button', { name: 'Validate and import' }).click();
  await expect(editor.getByText('Binding or grants required')).toBeVisible();
  const configuredTargetUrl = editor.url();

  await security.goto(configuredTargetUrl);
  const endpoints = await api<{ items: Array<{ endpointId: string; environmentId: string; revision: number; checksumSha256: string }> }>(security, `/admin/api/v1/endpoint-resources?environmentId=${new URL(configuredTargetUrl).searchParams.get('environment')}&connectorId=sample-secure-service`);
  expect(endpoints.status).toBe(200);
  const endpoint = expectSingle(endpoints.body.items);
  const resources = await api<{ items: Array<{ id: string; providerId: string; resourceId: string; resourceType: string; environmentId: string; version?: string | null; revision: number; publicMetadataRevision?: number | null; checksumSha256: string }> }>(security, `/admin/api/v1/provider-resources?environmentId=${endpoint.environmentId}&offset=0&limit=100`);
  const secret = expectSingle(resources.body.items.filter(value => value.resourceId === 'vendor-api-key' && value.resourceType === 'Secret'));
  const certificate = expectSingle(resources.body.items.filter(value => value.resourceId === 'vendor-client-certificate' && value.resourceType === 'ClientCertificate'));
  const endpointAssertion = { endpointId: endpoint.endpointId, revision: endpoint.revision, checksumSha256: endpoint.checksumSha256 };
  const providerAssertion = (value: typeof secret) => ({ providerId: value.providerId, resourceId: value.resourceId, resourceType: value.resourceType, version: value.version, publicMetadataRevision: value.publicMetadataRevision, catalogRevision: value.revision, catalogChecksumSha256: value.checksumSha256 });
  const bindingRequest = {
    environmentId: endpoint.environmentId, connectorVersion: '3.0.0', endpoints: {}, endpointResources: { 'sample-vendor-endpoint': endpointAssertion },
    secretResources: { 'sample-vendor-api-key': providerAssertion(secret) }, certificateResources: { 'sample-vendor-client-certificate': providerAssertion(certificate) }
  };

  const editorCatalogDenied = await api<Record<string, unknown>>(editor, `/admin/api/v1/endpoint-resources?environmentId=${endpoint.environmentId}&connectorId=sample-secure-service`);
  expect(editorCatalogDenied.status).toBe(403);
  const wrongConnectorCatalog = await api<{ items: unknown[] }>(security, `/admin/api/v1/endpoint-resources?environmentId=${endpoint.environmentId}&connectorId=m3-vendor`);
  expect(wrongConnectorCatalog.status).toBe(200);
  expect(wrongConnectorCatalog.body.items).toEqual([]);
  const environments = await api<{ items: Array<{ id: string }> }>(security, '/admin/api/v1/environments?offset=0&limit=50');
  const otherEnvironment = environments.body.items.find(value => value.id !== endpoint.environmentId);
  expect(otherEnvironment).toBeTruthy();
  const securityEnvironmentCatalog = await api<{ items: Array<{ environmentId: string; logicalBindingId: string }> }>(security, `/admin/api/v1/endpoint-resources?environmentId=${otherEnvironment!.id}&connectorId=sample-secure-service`);
  expect(securityEnvironmentCatalog.body.items).toHaveLength(1);
  expect(securityEnvironmentCatalog.body.items[0]).toMatchObject({ environmentId: otherEnvironment!.id, logicalBindingId: 'sample-vendor-endpoint' });
  const wrongEnvironmentCatalog = await api<{ items: unknown[] }>(security, '/admin/api/v1/endpoint-resources?environmentId=00000000-0000-0000-0000-000000000099&connectorId=sample-secure-service');
  expect(wrongEnvironmentCatalog.body.items).toEqual([]);
  const endpointDrift = await api<Record<string, unknown>>(security, '/admin/api/v1/connectors/sample-secure-service/bindings', 'PUT', {
    ...bindingRequest, endpointResources: { 'sample-vendor-endpoint': { ...endpointAssertion, revision: endpointAssertion.revision + 1 } }
  });
  expect(endpointDrift.status).toBe(409);
  const providerDrift = await api<Record<string, unknown>>(security, '/admin/api/v1/connectors/sample-secure-service/bindings', 'PUT', {
    ...bindingRequest, secretResources: { 'sample-vendor-api-key': { ...providerAssertion(secret), catalogRevision: secret.revision + 1 } }
  });
  expect(providerDrift.status).toBe(409);

  let bindingPutCount = 0;
  security.on('request', request => { if (request.method() === 'PUT' && new URL(request.url()).pathname.endsWith('/sample-secure-service/bindings')) bindingPutCount++; });
  let failGrantOnce = true;
  await security.route('**/admin/api/v1/grants', route => {
    if (failGrantOnce && route.request().method() === 'POST') { failGrantOnce = false; return route.abort('failed'); }
    return route.continue();
  });
  operatorActionCount++;
  await security.getByRole('button', { name: 'Configure binding and grants' }).click();
  await expect(security.getByText('The request failed.')).toBeVisible();
  await security.unroute('**/admin/api/v1/grants');
  await security.reload();
  await expect(security.getByText('The complete binding is already present. Only missing grants will be created.')).toBeVisible();
  await security.getByRole('button', { name: 'Configure binding and grants' }).click();
  await expect(security.getByText('Approval request required')).toBeVisible();
  expect(bindingPutCount).toBe(1);

  const tenantId = new URL(configuredTargetUrl).searchParams.get('tenant')!;
  const installationId = new URL(configuredTargetUrl).searchParams.get('installation')!;
  const authoritativeBindings = await api<{ items: unknown[] }>(security, `/admin/api/v1/connectors/sample-secure-service/versions/3.0.0/bindings?environmentId=${endpoint.environmentId}&offset=0&limit=100`);
  const authoritativeGrants = await api<{ items: Array<{ installationId: string; connectorId: string; operationId: string }> }>(security, `/admin/api/v1/grants?tenantId=${tenantId}&offset=0&limit=100`);
  expect(authoritativeBindings.body.items).toHaveLength(1);
  expect(authoritativeGrants.body.items.filter(value => value.installationId === installationId && value.connectorId === 'sample-secure-service' && value.operationId === 'submit')).toHaveLength(1);
  const tenants = await api<{ items: Array<{ id: string }> }>(security, '/admin/api/v1/tenants?offset=0&limit=50');
  const otherTenant = tenants.body.items.find(value => value.id !== tenantId);
  expect(otherTenant).toBeTruthy();
  const crossTenantGrant = await api<Record<string, unknown>>(security, '/admin/api/v1/grants', 'POST', { tenantId: otherTenant!.id, installationId, connectorId: 'sample-secure-service', connectorVersion: '3.0.0', operationId: 'submit' });
  expect(crossTenantGrant.status).toBe(404);

  await editor.goto(configuredTargetUrl);
  operatorActionCount++;
  await editor.getByRole('button', { name: 'Request approval' }).click();
  await expect(editor.getByText('Approval and publication required')).toBeVisible();
  const approvals = await api<{ items: Array<{ id: string; bindingDigestSha256: string; status: string }> }>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/3.0.0/approvals?offset=0&limit=100');
  const requested = expectSingle(approvals.body.items.filter(value => value.status === 'Requested'));
  const selfApproval = await api<Record<string, unknown>>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/3.0.0/approvals', 'POST', { approvalRequestId: requested.id, expectedDigestSha256: requested.bindingDigestSha256 });
  expect(selfApproval.status).toBe(403);
  const version = await api<{ rowVersion: number }>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/3.0.0');
  const summaries = await api<{ items: Array<{ connectorId: string; publicationRevision: number }> }>(editor, '/admin/api/v1/connectors?offset=0&limit=100');
  const summary = expectSingle(summaries.body.items.filter(value => value.connectorId === 'sample-secure-service'));
  const unauthorizedPublish = await api<Record<string, unknown>>(editor, '/admin/api/v1/connectors/sample-secure-service/versions/3.0.0:publish', 'POST', { expectedRowVersion: version.body.rowVersion, expectedPublicationRevision: summary.publicationRevision }, { 'If-Match': `"${version.body.rowVersion}"` });
  expect(unauthorizedPublish.status).toBe(403);

  await approver.goto(configuredTargetUrl);
  await expect(approver.getByRole('heading', { name: /^1\./ })).toHaveCount(0);
  await expect(approver.getByRole('heading', { name: /^2\./ })).toHaveCount(0);
  await expect(approver.getByRole('heading', { name: /^3\./ })).toHaveCount(0);
  await expect(approver.getByRole('heading', { name: /^4\./ })).toHaveCount(0);
  await expect(approver.getByLabel('Exact publication review')).toContainText('vendor.m3.test');
  operatorActionCount++;
  await approver.getByRole('button', { name: 'Verify, approve and publish' }).click();
  await expect(approver.getByText('The connector version is published and the selected Installation is ready for a bounded invocation.')).toBeVisible();

  const accessibility = await new AxeBuilder({ page: approver }).analyze();
  expect(accessibility.violations.filter(value => ['critical', 'serious'].includes(value.impact ?? ''))).toEqual([]);
  const invoked = await invokeRuntime('sample-secure-service', 'submit', randomUUID(), '/m3-fixture/certificates/onboarding-driver.crt', '/m3-fixture/certificates/onboarding-driver.key');
  expect(invoked.status).toBe(200);
  expect(invoked.body.connectorVersion).toBe('3.0.0');
  expect(operatorActionCount).toBe(5);
  expect(tooManyRequestsCount).toBe(0);
  expect(unauthorizedResponseCount).toBe(0);
  writeFileSync('test-results/guided-onboarding-metrics.json', JSON.stringify({
    operatorActionCount, loginCount: 3, tooManyRequestsCount, reloginCount: 0, manualWaitCount: 0,
    supportInterventionCount: 0, duplicateMutationCount: 0, resumeCount: 1
  }));

  await Promise.all([securityContext.close(), editorContext.close(), approverContext.close()]);
});

function expectSingle<T>(values: T[]): T {
  expect(values).toHaveLength(1);
  return values[0];
}
