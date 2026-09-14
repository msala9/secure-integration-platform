import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Router } from 'react-router-dom';
import { createMemoryHistory } from 'history';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { adminApi, type AdminSession, type Approval, type ApprovalReview, type ConnectorBinding, type ConnectorVersion, type Grant, type Installation, type Page, type ProvisionedActivation } from '../../api/client';
import i18n from '../../i18n';
import { GuidedOnboardingPage } from './GuidedOnboardingPage';

const session: AdminSession = { id: 'principal', displayName: 'Test operator', roles: [{ role: 'Viewer', tenantId: null }, { role: 'ConnectorEditor', tenantId: null }] };
vi.mock('../../auth/SessionContext', async importOriginal => ({ ...await importOriginal<object>(), useSession: () => session }));
const installation: Installation = { id: 'installation-51', tenantId: 'tenant', applicationId: 'application', environmentId: 'authoritative-environment', status: 'Active', installationKind: 'Direct', createdAt: '2026-09-06T00:00:00Z' };
const version: ConnectorVersion = { connectorId: 'sample', version: '1.0.51', schemaVersion: '1.0', state: 'Validated', checksumSha256: 'A'.repeat(64), rowVersion: 2, createdAt: '2026-09-06T00:00:00Z' };
const binding = { environmentId: installation.environmentId } as ConnectorBinding;
const grant = { installationId: installation.id, connectorId: 'sample', operationId: 'submit', enabled: true } as Grant;
const definition = { connectorId: 'sample', version: version.version, bindings: { endpoints: [{ name: 'endpoint' }], secrets: [] }, operations: [{ operationId: 'submit' }] };
const target = `/onboarding?tenant=tenant&installation=${installation.id}&connector=sample&version=${version.version}&environment=untrusted-url-environment`;
function page<T>(items: T[], offset = 0, total = items.length): Page<T> { return { items, offset, limit: 50, total }; }
function mount(path = target) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: 0 }, mutations: { retry: false } } });
  const history = createMemoryHistory({ initialEntries: [path] });
  const view = render(<QueryClientProvider client={cache}><Router history={history}><GuidedOnboardingPage /></Router></QueryClientProvider>);
  return { ...view, cache, history };
}

beforeEach(async () => {
  vi.restoreAllMocks();
  await i18n.changeLanguage('en');
  session.roles = [{ role: 'Viewer', tenantId: null }, { role: 'ConnectorEditor', tenantId: null }];
  vi.spyOn(adminApi, 'tenants').mockResolvedValue(page([]));
  vi.spyOn(adminApi, 'applications').mockResolvedValue(page([]));
  vi.spyOn(adminApi, 'environments').mockResolvedValue(page([]));
  vi.spyOn(adminApi, 'connectors').mockResolvedValue(page([]));
  vi.spyOn(adminApi, 'installations').mockImplementation(async (_, offset = 0) => page(offset ? [installation] : [], offset, 51));
  vi.spyOn(adminApi, 'installation').mockResolvedValue(installation);
  vi.spyOn(adminApi, 'connectorVersions').mockImplementation(async (_, offset = 0) => page(offset ? [version] : [], offset, 51));
  vi.spyOn(adminApi, 'connectorVersion').mockResolvedValue(version);
  vi.spyOn(adminApi, 'connectorDefinition').mockResolvedValue(definition);
  vi.spyOn(adminApi, 'bindings').mockResolvedValue(page([binding]));
  vi.spyOn(adminApi, 'grants').mockResolvedValue(page([grant]));
  vi.spyOn(adminApi, 'approvals').mockResolvedValue(page([]));
  vi.spyOn(adminApi, 'endpointResources').mockResolvedValue(page([]));
  vi.spyOn(adminApi, 'providerResources').mockResolvedValue(page([]));
});
afterEach(cleanup);

describe('guided selection and targeted refresh', () => {
  it.each(['Pending', 'Active'] as const)('keeps Published readiness consistent with %s enrollment after reload', async status => {
    vi.mocked(adminApi.installation).mockResolvedValue({ ...installation, status });
    vi.mocked(adminApi.connectorVersion).mockResolvedValue({ ...version, state: 'Published' });
    const assertReadiness = async () => {
      const action = status === 'Active' ? 'guidedActionComplete' : 'guidedActionEnrollmentHandoff';
      expect(await screen.findByText(i18n.t(action), { exact: false })).toBeVisible();
      if (status === 'Active') expect(screen.getByText(i18n.t('guidedPublishedActive'))).toBeVisible();
      else expect(screen.queryByText(i18n.t('guidedPublishedActive'))).not.toBeInTheDocument();
    };
    const first = mount();
    await assertReadiness();
    const resume = first.history.location.pathname + first.history.location.search;
    first.unmount(); first.cache.clear();
    mount(resume);
    await assertReadiness();
  });

  it('keeps authoritative selections visible while changing list pages', async () => {
    mount();
    expect(await screen.findByRole('button', { name: i18n.t('requestApproval') })).toBeEnabled();
    expect(screen.getByRole('combobox', { name: i18n.t('version') })).toHaveTextContent('1.0.51');
    expect(screen.getByRole('combobox', { name: i18n.t('installation') })).toHaveTextContent('Direct');
    expect(adminApi.bindings).toHaveBeenCalledWith('sample', version.version, installation.environmentId);
    expect(adminApi.bindings).not.toHaveBeenCalledWith('sample', version.version, 'untrusted-url-environment');
    fireEvent.click(within(screen.getByTestId('guided-version-pagination')).getByRole('button', { name: i18n.t('nextPage') }));
    await waitFor(() => expect(adminApi.connectorVersions).toHaveBeenCalledWith('sample', 50));
    await waitFor(() => expect(within(screen.getByTestId('guided-version-pagination')).getByRole('button', { name: i18n.t('previousPage') })).toBeEnabled());
    fireEvent.click(within(screen.getByTestId('guided-version-pagination')).getByRole('button', { name: i18n.t('previousPage') }));
    fireEvent.click(within(screen.getByTestId('guided-installation-pagination')).getByRole('button', { name: i18n.t('nextPage') }));
    await waitFor(() => expect(adminApi.installations).toHaveBeenCalledWith('tenant', 50));
    expect(screen.getByRole('combobox', { name: i18n.t('version') })).toHaveTextContent('1.0.51');
    expect(screen.getByRole('combobox', { name: i18n.t('installation') })).toHaveTextContent('Direct');
  });

  it('resolves deep-link selections again after reload with a new query cache', async () => {
    const first = mount();
    expect(await screen.findByRole('button', { name: i18n.t('requestApproval') })).toBeEnabled();
    const resume = first.history.location.pathname + first.history.location.search;
    first.unmount(); first.cache.clear();
    mount(resume);
    expect(await screen.findByRole('button', { name: i18n.t('requestApproval') })).toBeEnabled();
    expect(screen.getByRole('combobox', { name: i18n.t('installation') })).toHaveTextContent('Direct');
    expect(screen.getByRole('combobox', { name: i18n.t('version') })).toHaveTextContent('1.0.51');
    expect(adminApi.installation).toHaveBeenCalledTimes(2);
    expect(adminApi.connectorVersion).toHaveBeenCalledTimes(2);
    expect(adminApi.bindings).not.toHaveBeenCalledWith('sample', version.version, 'untrusted-url-environment');
  });

  it('selects a version from page 2 and loads its definition through the point lookup', async () => {
    mount(`/onboarding?tenant=tenant&installation=${installation.id}&connector=sample`);
    fireEvent.click(within(await screen.findByTestId('guided-version-pagination')).getByRole('button', { name: i18n.t('nextPage') }));
    await waitFor(() => expect(within(screen.getByTestId('guided-version-pagination')).getByRole('button', { name: i18n.t('previousPage') })).toBeEnabled());
    fireEvent.mouseDown(screen.getByRole('combobox', { name: i18n.t('version') }));
    fireEvent.click(await screen.findByRole('option', { name: '1.0.51 · Validated' }));
    expect(await screen.findByRole('button', { name: i18n.t('requestApproval') })).toBeEnabled();
    expect(adminApi.connectorVersion).toHaveBeenCalledWith('sample', '1.0.51');
    expect(adminApi.connectorDefinition).toHaveBeenCalledWith('sample', '1.0.51');
  });

  it('refreshes only approval state/review after a request, not unrelated resources', async () => {
    vi.spyOn(adminApi, 'requestApproval').mockResolvedValue({ status: 'Requested' } as Approval);
    const { cache } = mount();
    const invalidate = vi.spyOn(cache, 'invalidateQueries');
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('requestApproval') }));
    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(2));
    expect(invalidate.mock.calls.map(([options]) => options?.queryKey)).toEqual([
      ['approvals', 'sample', version.version], ['approval-review', 'sample', version.version]
    ]);
    expect(adminApi.installations).toHaveBeenCalledTimes(1);
    expect(adminApi.connectorDefinition).toHaveBeenCalledTimes(1);
  });

  it('rereads installation authority before binding/grants and refreshes their dependent approval data', async () => {
    session.roles = [{ role: 'Viewer', tenantId: null }, { role: 'SecurityAdministrator', tenantId: null }];
    vi.spyOn(adminApi, 'createGrant').mockResolvedValue(grant);
    const { cache } = mount();
    const invalidate = vi.spyOn(cache, 'invalidateQueries');
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('guidedConfigureBindingGrant') }));
    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(4));
    expect(adminApi.installation).toHaveBeenCalledTimes(2);
    expect(invalidate.mock.calls.map(([options]) => options?.queryKey)).toEqual([
      ['bindings', 'sample', version.version], ['grants', 'tenant'], ['approvals', 'sample', version.version], ['approval-review', 'sample', version.version]
    ]);
    expect(adminApi.connectorDefinition).toHaveBeenCalledTimes(1);
  });

  it('refreshes only the tenant installation list after creation', async () => {
    session.roles = [{ role: 'Viewer', tenantId: null }, { role: 'SecurityAdministrator', tenantId: null }];
    vi.spyOn(adminApi, 'createInstallation').mockResolvedValue({ installationId: installation.id, expiresAt: '2026-09-06T12:00:00Z' } as ProvisionedActivation);
    const { cache } = mount('/onboarding?tenant=tenant&application=application&environment=environment');
    const invalidate = vi.spyOn(cache, 'invalidateQueries');
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('createInstallation') }));
    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(1));
    expect(invalidate.mock.calls[0][0]?.queryKey).toEqual(['installations', 'tenant']);
  });

  it('refreshes version and definition state after validating a stored draft', async () => {
    vi.mocked(adminApi.connectorVersion).mockResolvedValue({ ...version, state: 'Draft' });
    vi.spyOn(adminApi, 'validateStored').mockResolvedValue(version);
    const { cache } = mount();
    const invalidate = vi.spyOn(cache, 'invalidateQueries');
    const action = await screen.findByRole('button', { name: i18n.t('guidedValidateImport') });
    await waitFor(() => expect(action).toBeEnabled()); fireEvent.click(action);
    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(4));
    expect(invalidate.mock.calls.map(([options]) => options?.queryKey)).toEqual([
      ['connectors'], ['connector-versions', 'sample'], ['connector-version', 'sample', version.version], ['connector-definition', 'sample', version.version]
    ]);
  });

  it('refreshes publication cross-version state without reloading immutable definitions or installations', async () => {
    session.roles = [{ role: 'Viewer', tenantId: null }, { role: 'ConnectorApprover', tenantId: null }];
    vi.mocked(adminApi.approvals).mockResolvedValue(page([{ status: 'Approved' } as Approval]));
    vi.mocked(adminApi.connectors).mockResolvedValue(page([{ connectorId: 'sample', displayName: 'Sample', versions: 1, publicationRevision: 1 }]));
    vi.spyOn(adminApi, 'approvalReview').mockResolvedValue({ artifact: { connector: { displayName: 'Sample', version: version.version }, operations: [] }, digestSha256: 'A'.repeat(64) } as unknown as ApprovalReview);
    vi.spyOn(adminApi, 'publish').mockResolvedValue({ ...version, state: 'Published' });
    const { cache } = mount();
    const invalidate = vi.spyOn(cache, 'invalidateQueries');
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('guidedVerifyApprovePublish') }));
    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(6));
    expect(invalidate.mock.calls.map(([options]) => options?.queryKey)).toEqual([
      ['connectors'], ['connector-versions', 'sample'], ['connector-version', 'sample', version.version], ['bindings', 'sample'], ['approvals', 'sample'], ['approval-review', 'sample']
    ]);
    expect(adminApi.connectorDefinition).toHaveBeenCalledTimes(1);
    expect(adminApi.installation).toHaveBeenCalledTimes(1);
  });

  it('denies a newly revoked selected installation before any mutation', async () => {
    session.roles = [{ role: 'Viewer', tenantId: null }, { role: 'SecurityAdministrator', tenantId: null }];
    vi.mocked(adminApi.installation).mockResolvedValueOnce(installation).mockResolvedValue({ ...installation, status: 'Revoked' });
    const create = vi.spyOn(adminApi, 'createGrant'); const put = vi.spyOn(adminApi, 'putBindings');
    mount();
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('guidedConfigureBindingGrant') }));
    await waitFor(() => expect(adminApi.installation).toHaveBeenCalledTimes(2));
    expect(create).not.toHaveBeenCalled(); expect(put).not.toHaveBeenCalled();
  });
});
