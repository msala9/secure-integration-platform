import type { components, paths } from './schema';

export type AdminSession = components['schemas']['AdminSession'];
export type Dashboard = components['schemas']['Dashboard'];
export type Tenant = components['schemas']['Tenant'];
export type Page<T> = Omit<components['schemas']['Page'], 'items'> & { items: T[] };
export type TenantPage = Page<Tenant>;
export type Application = components['schemas']['Application'];
export type ApplicationPage = Page<Application>;
export type EnvironmentPage = Page<components['schemas']['Environment']>;
export type InstallationPage = Page<components['schemas']['Installation']>;
export type GrantPage = Page<components['schemas']['Grant']>;
export type AuditPage = Page<components['schemas']['AuditEvent']>;
export type AuditEvent = components['schemas']['AuditEvent'];
export type SafeFailureDiagnostics = components['schemas']['SafeFailureDiagnostics'];
export type ConnectorSummary = components['schemas']['ConnectorSummary'];
export type Installation = components['schemas']['Installation'];
export type Environment = components['schemas']['Environment'];
export type ProvisionedActivation = components['schemas']['ProvisionedActivation'];
export type ConnectorVersion = components['schemas']['ConnectorVersion'];
export type Approval = components['schemas']['Approval'];
export type ApprovalReview = components['schemas']['ApprovalReviewResult'];
export type ConnectorBinding = components['schemas']['ConnectorBinding'];
export type ConnectorBindingRequest = components['schemas']['ConnectorBindingRequest'];
export type RoleAssignment = components['schemas']['RoleAssignment'];
export type ProviderResourceCatalog = components['schemas']['ProviderResourceCatalog'];
export type ProviderResourceCatalogPage = Page<ProviderResourceCatalog>;
export type EndpointResourceCatalog = components['schemas']['EndpointResourceCatalog'];
export type EndpointResourceCatalogPage = Page<EndpointResourceCatalog>;
export type Grant = components['schemas']['Grant'];

export class ApiProblem extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly correlationId?: string) {
    super(code);
  }
}

let csrfToken: string | undefined;
let unauthorizedHandler: (() => void) | undefined;

export function setUnauthorizedHandler(handler?: () => void): void { unauthorizedHandler = handler; }
export function clearCsrf(): void { csrfToken = undefined; }

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { code?: string; correlationId?: string };
    if (response.status === 401) { clearCsrf(); unauthorizedHandler?.(); }
    throw new ApiProblem(response.status, body.code ?? 'BGW-ADMIN-UNEXPECTED', body.correlationId);
  }
  return response.status === 204 ? undefined as T : await response.json() as T;
}

export async function csrf(): Promise<string> {
  const response = await fetch('/admin/auth/csrf', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  csrfToken = (await parse<{ token: string }>(response)).token;
  return csrfToken;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const mutation = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body) headers.set('Content-Type', 'application/json');
  if (mutation) headers.set('X-CSRF-TOKEN', csrfToken ?? await csrf());
  return parse<T>(await fetch(path, { ...init, headers, credentials: 'same-origin' }));
}

type HttpMethod = 'get' | 'post' | 'put' | 'delete' | 'patch';
type ContractMethod<Path extends keyof paths> = {
  [Method in HttpMethod]: Method extends keyof paths[Path]
    ? paths[Path][Method] extends undefined | never ? never : Method
    : never
}[HttpMethod];

interface ContractRequest {
  path?: Record<string, string>;
  query?: Record<string, string | number | boolean | null | undefined>;
  headers?: HeadersInit;
  body?: unknown;
}

/** Executes only operations declared by the generated OpenAPI paths contract. */
export function openApi<T, Path extends keyof paths>(template: Path, method: ContractMethod<Path>, request: ContractRequest = {}): Promise<T> {
  let target = String(template);
  for (const [name, value] of Object.entries(request.path ?? {})) target = target.replace(`{${name}}`, encodeURIComponent(value));
  if (/\{[^}]+\}/.test(target)) throw new Error('BGW-ADMIN-CLIENT-PATH-PARAMETER');
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(request.query ?? {})) if (value !== undefined && value !== null && value !== '') query.set(name, String(value));
  if (query.size > 0) target += `?${query.toString()}`;
  return api<T>(target, {
    method: method.toUpperCase(),
    headers: request.headers,
    body: request.body === undefined ? undefined : JSON.stringify(request.body)
  });
}

export const adminApi = {
  session: () => openApi<AdminSession, '/admin/auth/me'>('/admin/auth/me', 'get'),
  dashboard: () => openApi<Dashboard, '/admin/api/v1/dashboard'>('/admin/api/v1/dashboard', 'get'),
  tenants: (offset = 0, limit = 50, filter = '') => openApi<TenantPage, '/admin/api/v1/tenants'>('/admin/api/v1/tenants', 'get', { query: { offset, limit, filter } }),
  tenant: (id: string) => openApi<Tenant, '/admin/api/v1/tenants/{tenantId}'>('/admin/api/v1/tenants/{tenantId}', 'get', { path: { tenantId: id } }),
  applications: (offset = 0, limit = 50, filter = '') => openApi<ApplicationPage, '/admin/api/v1/applications'>('/admin/api/v1/applications', 'get', { query: { offset, limit, filter } }),
  application: (id: string) => openApi<Application, '/admin/api/v1/applications/{applicationId}'>('/admin/api/v1/applications/{applicationId}', 'get', { path: { applicationId: id } }),
  environments: (offset = 0, limit = 50, filter = '') => openApi<EnvironmentPage, '/admin/api/v1/environments'>('/admin/api/v1/environments', 'get', { query: { offset, limit, filter } }),
  installations: (tenantId: string, offset = 0, limit = 50, filter = '', applicationId = '', environmentId = '') => openApi<InstallationPage, '/admin/api/v1/installations'>('/admin/api/v1/installations', 'get', { query: { tenantId, offset, limit, filter, applicationId, environmentId } }),
  installation: (tenantId: string, installationId: string) => openApi<Installation, '/admin/api/v1/installations/{installationId}'>('/admin/api/v1/installations/{installationId}', 'get', { path: { installationId }, query: { tenantId } }),
  grants: (tenantId: string, offset = 0, limit = 50) => openApi<GrantPage, '/admin/api/v1/grants'>('/admin/api/v1/grants', 'get', { query: { tenantId, offset, limit } }),
  audit: (tenantId: string, offset = 0, limit = 50) => openApi<AuditPage, '/admin/api/v1/audit'>('/admin/api/v1/audit', 'get', { query: { tenantId, offset, limit } }),
  connectors: (offset = 0, limit = 50, filter = '') => openApi<Page<ConnectorSummary>, '/admin/api/v1/connectors'>('/admin/api/v1/connectors', 'get', { query: { offset, limit, filter } }),
  providerResources: (environmentId = '', resourceType = '', offset = 0, limit = 100) => openApi<ProviderResourceCatalogPage, '/admin/api/v1/provider-resources'>('/admin/api/v1/provider-resources', 'get', { query: { environmentId, resourceType, offset, limit } }),
  endpointResources: (environmentId: string, connectorId: string) => openApi<EndpointResourceCatalogPage, '/admin/api/v1/endpoint-resources'>('/admin/api/v1/endpoint-resources', 'get', { query: { environmentId, connectorId } }),
  createTenant: (value: components['schemas']['CreateTenant']) => openApi<Tenant, '/admin/api/v1/tenants'>('/admin/api/v1/tenants', 'post', { body: value }),
  updateTenant: (id: string, value: components['schemas']['UpdateTenant'], rowVersion: number) => openApi<Tenant, '/admin/api/v1/tenants/{tenantId}'>('/admin/api/v1/tenants/{tenantId}', 'put', { path: { tenantId: id }, headers: { 'If-Match': `"${rowVersion}"` }, body: value }),
  disableTenant: (id: string, rowVersion: number) => openApi<Tenant, '/admin/api/v1/tenants/{tenantId}:disable'>('/admin/api/v1/tenants/{tenantId}:disable', 'post', { path: { tenantId: id }, headers: { 'If-Match': `"${rowVersion}"` } }),
  createApplication: (value: components['schemas']['CreateApplication']) => openApi<Application, '/admin/api/v1/applications'>('/admin/api/v1/applications', 'post', { body: value }),
  updateApplication: (id: string, value: components['schemas']['UpdateApplication'], rowVersion: number) => openApi<Application, '/admin/api/v1/applications/{applicationId}'>('/admin/api/v1/applications/{applicationId}', 'put', { path: { applicationId: id }, headers: { 'If-Match': `"${rowVersion}"` }, body: value }),
  disableApplication: (id: string, rowVersion: number) => openApi<Application, '/admin/api/v1/applications/{applicationId}:disable'>('/admin/api/v1/applications/{applicationId}:disable', 'post', { path: { applicationId: id }, headers: { 'If-Match': `"${rowVersion}"` } }),
  createInstallation: (value: components['schemas']['CreateInstallation']) => openApi<ProvisionedActivation, '/admin/api/v1/installations'>('/admin/api/v1/installations', 'post', { body: value }),
  revokeInstallation: (tenantId: string, installationId: string, reason: string) => openApi<{ status: string }, '/admin/api/v1/installations/{installationId}:revoke'>('/admin/api/v1/installations/{installationId}:revoke', 'post', { path: { installationId }, query: { tenantId }, body: { reason } }),
  createGrant: (value: components['schemas']['CreateGrant']) => openApi<Grant, '/admin/api/v1/grants'>('/admin/api/v1/grants', 'post', { body: value }),
  connectorSchema: () => openApi<object, '/admin/api/v1/connectors/schema'>('/admin/api/v1/connectors/schema', 'get'),
  connectorSample: () => openApi<object, '/admin/api/v1/connectors/sample'>('/admin/api/v1/connectors/sample', 'get'),
  validateConnector: (definition: object) => openApi<components['schemas']['ConnectorValidationResult'], '/admin/api/v1/connectors:validate'>('/admin/api/v1/connectors:validate', 'post', { body: { definition } }),
  importConnector: (definition: object, expectedChecksumSha256: string) => openApi<ConnectorVersion, '/admin/api/v1/connectors:import'>('/admin/api/v1/connectors:import', 'post', { body: { definition, expectedChecksumSha256 } }),
  connectorVersions: (id: string, offset = 0, limit = 50, filter = '') => openApi<Page<ConnectorVersion>, '/admin/api/v1/connectors/{connectorId}/versions'>('/admin/api/v1/connectors/{connectorId}/versions', 'get', { path: { connectorId: id }, query: { offset, limit, filter } }),
  connectorVersion: (id: string, version: string) => openApi<ConnectorVersion, '/admin/api/v1/connectors/{connectorId}/versions/{version}'>('/admin/api/v1/connectors/{connectorId}/versions/{version}', 'get', { path: { connectorId: id, version } }),
  approvals: (id: string, version: string, offset = 0, limit = 50) => openApi<Page<Approval>, '/admin/api/v1/connectors/{connectorId}/versions/{version}/approvals'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/approvals', 'get', { path: { connectorId: id, version }, query: { offset, limit } }),
  approvalReview: (id: string, version: string) => openApi<ApprovalReview, '/admin/api/v1/connectors/{connectorId}/versions/{version}/approval-review'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/approval-review', 'get', { path: { connectorId: id, version } }),
  bindings: (id: string, version: string, environmentId = '', offset = 0, limit = 50) => openApi<Page<ConnectorBinding>, '/admin/api/v1/connectors/{connectorId}/versions/{version}/bindings'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/bindings', 'get', { path: { connectorId: id, version }, query: { offset, limit, environmentId } }),
  putBindings: (id: string, value: ConnectorBindingRequest, revision?: number) => openApi<{ revision: number }, '/admin/api/v1/connectors/{connectorId}/bindings'>('/admin/api/v1/connectors/{connectorId}/bindings', 'put', { path: { connectorId: id }, headers: revision === undefined ? undefined : { 'If-Match': `"${revision}"` }, body: value }),
  roleAssignments: (offset = 0, limit = 50, principalId = '', tenantId = '') => openApi<Page<RoleAssignment>, '/admin/api/v1/role-assignments'>('/admin/api/v1/role-assignments', 'get', { query: { offset, limit, principalId, tenantId } }),
  connectorDefinition: (id: string, version: string) => openApi<Record<string, unknown>, '/admin/api/v1/connectors/{connectorId}/versions/{version}/definition'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/definition', 'get', { path: { connectorId: id, version } }),
  validateStored: (id: string, version: ConnectorVersion) => openApi<ConnectorVersion, '/admin/api/v1/connectors/{connectorId}/versions/{version}:validate'>('/admin/api/v1/connectors/{connectorId}/versions/{version}:validate', 'post', { path: { connectorId: id, version: version.version }, headers: { 'If-Match': `"${version.rowVersion}"` } }),
  requestApproval: (id: string, version: string) => openApi<Approval, '/admin/api/v1/connectors/{connectorId}/versions/{version}/approval-requests'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/approval-requests', 'post', { path: { connectorId: id, version } }),
  approve: (id: string, version: string, approvalRequestId: string, expectedDigestSha256: string, comment?: string) => openApi<Approval, '/admin/api/v1/connectors/{connectorId}/versions/{version}/approvals'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/approvals', 'post', { path: { connectorId: id, version }, body: { approvalRequestId, expectedDigestSha256, comment: comment || null } }),
  reject: (id: string, version: string, comment?: string) => openApi<Approval, '/admin/api/v1/connectors/{connectorId}/versions/{version}/rejections'>('/admin/api/v1/connectors/{connectorId}/versions/{version}/rejections', 'post', { path: { connectorId: id, version }, body: { comment: comment || null } }),
  assignRole: (value: components['schemas']['RoleAssignmentRequest']) => openApi<Record<string, unknown>, '/admin/api/v1/role-assignments'>('/admin/api/v1/role-assignments', 'post', { body: value }),
  revokeRole: (assignmentId: string) => openApi<void, '/admin/api/v1/role-assignments/{assignmentId}'>('/admin/api/v1/role-assignments/{assignmentId}', 'delete', { path: { assignmentId } }),
  publish: (id: string, version: ConnectorVersion, expectedPublicationRevision: number) => openApi<ConnectorVersion, '/admin/api/v1/connectors/{connectorId}/versions/{version}:publish'>('/admin/api/v1/connectors/{connectorId}/versions/{version}:publish', 'post', { path: { connectorId: id, version: version.version }, headers: { 'If-Match': `"${version.rowVersion}"` }, body: { expectedRowVersion: version.rowVersion, expectedPublicationRevision } }),
  rollback: (id: string, targetVersion: string, expectedActiveRowVersion: number) => openApi<ConnectorVersion, '/admin/api/v1/connectors/{connectorId}:rollback'>('/admin/api/v1/connectors/{connectorId}:rollback', 'post', { path: { connectorId: id }, body: { targetVersion, expectedActiveRowVersion } }),
  retire: (id: string, version: ConnectorVersion) => openApi<ConnectorVersion, '/admin/api/v1/connectors/{connectorId}/versions/{version}:retire'>('/admin/api/v1/connectors/{connectorId}/versions/{version}:retire', 'post', { path: { connectorId: id, version: version.version }, headers: { 'If-Match': `"${version.rowVersion}"` } }),
  testConnector: (id: string, environmentId: string, operationId: string) => openApi<{ status: string; connectorId: string; operationId: string; connectorVersion: string }, '/admin/api/v1/connectors/{connectorId}:test'>('/admin/api/v1/connectors/{connectorId}:test', 'post', { path: { connectorId: id }, body: { environmentId, operationId } }),
  logout: () => openApi<{ status: string }, '/admin/auth/logout'>('/admin/auth/logout', 'post'),
  developmentLogin: (userName: string) => openApi<{ status: string }, '/admin/auth/development/login'>('/admin/auth/development/login', 'post', { body: { userName } })
};
