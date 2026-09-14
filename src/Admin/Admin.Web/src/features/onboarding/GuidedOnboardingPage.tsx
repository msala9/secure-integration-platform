import { formatDate } from '../../i18n/dateTime';
import { Alert, Box, Button, Card, CardContent, Chip, FormControl, InputLabel, MenuItem, Select, Stack, Typography } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useHistory, useLocation } from 'react-router-dom';
import { adminApi, ApiProblem, type EndpointResourceCatalog, type Installation, type ProviderResourceCatalog, type ProvisionedActivation } from '../../api/client';
import { hasRole, useSession } from '../../auth/SessionContext';
import { ActivationHandoffDialog } from '../../components/ActivationHandoffDialog';
import { ErrorState, LoadingState } from '../../components/AsyncState';
import { PageTitle } from '../../components/PageTitle';
import { PagedSelector } from '../../components/PagedSelector';
import { InstallationKindSelector } from '../../components/InstallationKindSelector';
import { useDirectorySearch } from './useDirectorySearch';

interface DefinitionInfo {
  connectorId: string;
  version: string;
  endpointBindings: string[];
  secretBindings: Array<{ name: string; kind: string }>;
  operations: string[];
}

function definitionInfo(value: unknown): DefinitionInfo | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const root = value as Record<string, unknown>;
  const bindings = root.bindings as { endpoints?: unknown[]; secrets?: unknown[] } | undefined;
  if (typeof root.connectorId !== 'string' || typeof root.version !== 'string' || !bindings || !Array.isArray(bindings.endpoints) || !Array.isArray(bindings.secrets) || !Array.isArray(root.operations)) return undefined;
  const endpointBindings = bindings.endpoints.map(item => (item as { name?: unknown }).name).filter((item): item is string => typeof item === 'string');
  const secretBindings = bindings.secrets.map(item => item as { name?: unknown; kind?: unknown }).filter(item => typeof item.name === 'string' && typeof item.kind === 'string').map(item => ({ name: item.name as string, kind: item.kind as string }));
  const operations = root.operations.map(item => (item as { operationId?: unknown }).operationId).filter((item): item is string => typeof item === 'string');
  if (!endpointBindings.length || !operations.length || endpointBindings.length !== bindings.endpoints.length || secretBindings.length !== bindings.secrets.length || operations.length !== root.operations.length) return undefined;
  return { connectorId: root.connectorId, version: root.version, endpointBindings, secretBindings, operations };
}

function selectedId(explicit: Record<string, string>, logical: string, candidates: string[]): string {
  return explicit[logical] ?? (candidates.length === 1 ? candidates[0] : '');
}

export function GuidedOnboardingPage() {
  const { t } = useTranslation();
  const session = useSession();
  const cache = useQueryClient();
  const history = useHistory();
  const location = useLocation();
  const initial = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const [tenantId, setTenantId] = useState(initial.get('tenant') ?? '');
  const [applicationId, setApplicationId] = useState(initial.get('application') ?? '');
  const [environmentId, setEnvironmentId] = useState(initial.get('environment') ?? '');
  const [installationId, setInstallationId] = useState(initial.get('installation') ?? '');
  const [installationKind, setInstallationKind] = useState<Installation['installationKind']>('Direct');
  const [connectorId, setConnectorId] = useState(initial.get('connector') ?? '');
  const [version, setVersion] = useState(initial.get('version') ?? '');
  const [tenantOffset, setTenantOffset] = useState(0);
  const [applicationOffset, setApplicationOffset] = useState(0);
  const [environmentOffset, setEnvironmentOffset] = useState(0);
  const [installationOffset, setInstallationOffset] = useState(0);
  const [connectorOffset, setConnectorOffset] = useState(0);
  const [versionOffset, setVersionOffset] = useState(0);
  const tenantSearch = useDirectorySearch();
  const applicationSearch = useDirectorySearch();
  const environmentSearch = useDirectorySearch();
  const installationSearch = useDirectorySearch();
  const connectorSearch = useDirectorySearch();
  const versionSearch = useDirectorySearch();
  const [fileDefinition, setFileDefinition] = useState<object>();
  const [fileName, setFileName] = useState('');
  const [fileError, setFileError] = useState<Error>();
  const [activation, setActivation] = useState<ProvisionedActivation>();
  const [endpointSelections, setEndpointSelections] = useState<Record<string, string>>({});
  const [resourceSelections, setResourceSelections] = useState<Record<string, string>>({});

  const replaceTarget = (updates: Record<string, string>) => {
    const parameters = new URLSearchParams(location.search);
    for (const [name, value] of Object.entries(updates)) {
      if (value) parameters.set(name, value); else parameters.delete(name);
    }
    history.replace({ pathname: location.pathname, search: parameters.toString() });
  };
  const selectTenant = (value: string) => {
    setTenantId(value); setApplicationId(''); setEnvironmentId(''); setInstallationId('');
    setInstallationOffset(0); installationSearch.setText(''); setEndpointSelections({}); setResourceSelections({});
    replaceTarget({ tenant: value, application: '', environment: '', installation: '' });
  };
  const resetInstallationChoices = () => { setInstallationId(''); setInstallationOffset(0); installationSearch.setText(''); setEndpointSelections({}); setResourceSelections({}); };
  const selectEnvironment = (value: string) => { const application = selectedInstallation?.applicationId ?? applicationId; setApplicationId(application); setEnvironmentId(value); resetInstallationChoices(); replaceTarget({ application, environment: value, installation: '' }); };
  const selectInstallation = (value: string) => {
    setInstallationId(value);
    replaceTarget({ installation: value });
  };
  const selectConnector = (value: string) => { setConnectorId(value); setVersion(''); setEndpointSelections({}); setResourceSelections({}); replaceTarget({ connector: value, version: '' }); };
  const selectVersion = (value: string) => { setVersion(value); setEndpointSelections({}); setResourceSelections({}); replaceTarget({ version: value }); };

  const tenants = useQuery({ queryKey: ['tenants', 'guided', tenantOffset, tenantSearch.filter], queryFn: () => adminApi.tenants(tenantOffset, 50, tenantSearch.filter), placeholderData: previous => previous });
  const applications = useQuery({ queryKey: ['applications', 'guided', applicationOffset, applicationSearch.filter], queryFn: () => adminApi.applications(applicationOffset, 50, applicationSearch.filter), placeholderData: previous => previous });
  const environments = useQuery({ queryKey: ['environments', 'guided', environmentOffset, environmentSearch.filter], queryFn: () => adminApi.environments(environmentOffset, 50, environmentSearch.filter), placeholderData: previous => previous });
  const installations = useQuery({ queryKey: ['installations', tenantId, 'guided', installationOffset, installationSearch.filter, applicationId, environmentId], queryFn: () => adminApi.installations(tenantId, installationOffset, 50, installationSearch.filter, applicationId, environmentId), enabled: Boolean(tenantId), placeholderData: (previous, query) => query?.queryKey[1] === tenantId ? previous : undefined });
  const connectors = useQuery({ queryKey: ['connectors', 'guided', connectorOffset, connectorSearch.filter], queryFn: () => adminApi.connectors(connectorOffset, 50, connectorSearch.filter), placeholderData: previous => previous });
  const versions = useQuery({ queryKey: ['connector-versions', connectorId, 'guided', versionOffset, versionSearch.filter], queryFn: () => adminApi.connectorVersions(connectorId, versionOffset, 50, versionSearch.filter), enabled: Boolean(connectorId), placeholderData: (previous, query) => query?.queryKey[1] === connectorId ? previous : undefined });
  const uploadedInfo = definitionInfo(fileDefinition);
  const selectedVersionQuery = useQuery({ queryKey: ['connector-version', connectorId, version], queryFn: async () => {
    try { return await adminApi.connectorVersion(connectorId, version); }
    catch (error) {
      if (error instanceof ApiProblem && error.status === 404 && uploadedInfo?.connectorId === connectorId && uploadedInfo.version === version) return null;
      throw error;
    }
  }, enabled: Boolean(connectorId && version) });
  const selectedInstallationQuery = useQuery({ queryKey: ['installation', tenantId, installationId], queryFn: () => adminApi.installation(tenantId, installationId), enabled: Boolean(tenantId && installationId) });
  const currentVersion = selectedVersionQuery.data;
  const selectedInstallation = selectedInstallationQuery.data;
  const effectiveEnvironmentId = selectedInstallation?.environmentId ?? (installationId ? '' : environmentId);
  const effectiveApplicationId = selectedInstallation?.applicationId ?? (installationId ? '' : applicationId);
  const selectedTenant = useQuery({ queryKey: ['tenant', tenantId], queryFn: () => adminApi.tenant(tenantId), enabled: Boolean(tenantId) });
  const selectedApplication = useQuery({ queryKey: ['application', effectiveApplicationId], queryFn: () => adminApi.application(effectiveApplicationId), enabled: Boolean(effectiveApplicationId) });
  const selectedEnvironment = useQuery({ queryKey: ['environment', effectiveEnvironmentId], queryFn: () => adminApi.environments(0, 1, effectiveEnvironmentId), enabled: Boolean(effectiveEnvironmentId) });
  const storedDefinition = useQuery({ queryKey: ['connector-definition', connectorId, version, 'guided'], queryFn: () => adminApi.connectorDefinition(connectorId, version), enabled: Boolean(connectorId && version && currentVersion) });
  const info = definitionInfo(storedDefinition.data ?? fileDefinition);
  const bindings = useQuery({ queryKey: ['bindings', connectorId, version, effectiveEnvironmentId, 'guided'], queryFn: () => adminApi.bindings(connectorId, version, effectiveEnvironmentId), enabled: Boolean(connectorId && version && effectiveEnvironmentId && currentVersion) });
  const grants = useQuery({ queryKey: ['grants', tenantId, 'guided'], queryFn: () => adminApi.grants(tenantId, 0, 100), enabled: Boolean(tenantId) });
  const approvals = useQuery({ queryKey: ['approvals', connectorId, version, 'guided'], queryFn: () => adminApi.approvals(connectorId, version, 0, 100), enabled: Boolean(connectorId && version && currentVersion) });
  const endpointResources = useQuery({ queryKey: ['endpoint-resources', effectiveEnvironmentId, connectorId], queryFn: () => adminApi.endpointResources(effectiveEnvironmentId, connectorId), enabled: Boolean(effectiveEnvironmentId && connectorId && hasRole(session, 'SecurityAdministrator')) });
  const providerResources = useQuery({ queryKey: ['provider-resources', effectiveEnvironmentId, 'guided'], queryFn: () => adminApi.providerResources(effectiveEnvironmentId, '', 0, 100), enabled: Boolean(effectiveEnvironmentId && hasRole(session, 'SecurityAdministrator')) });
  const requestedApproval = approvals.data?.items.find(item => item.status === 'Requested');
  const approvedApproval = approvals.data?.items.find(item => item.status === 'Approved');
  const review = useQuery({ queryKey: ['approval-review', connectorId, version, 'guided'], queryFn: () => adminApi.approvalReview(connectorId, version), enabled: Boolean(connectorId && version && (requestedApproval || approvedApproval) && hasRole(session, 'ConnectorApprover')) });
  const bindingExists = Boolean(bindings.data?.items.some(item => item.environmentId === effectiveEnvironmentId));
  const missingGrants = info?.operations.filter(operation => !grants.data?.items.some(item => item.installationId === installationId && item.connectorId === connectorId && item.operationId === operation && item.enabled)) ?? [];

  const endpointCandidates = (logical: string): EndpointResourceCatalog[] => endpointResources.data?.items.filter(item => item.logicalBindingId === logical) ?? [];
  const providerCandidates = (kind: string): ProviderResourceCatalog[] => providerResources.data?.items.filter(item => item.resourceType === (kind === 'clientCertificate' ? 'ClientCertificate' : 'Secret') && (item.connectorScope === '*' || item.connectorScope === connectorId) && item.status === 'Active') ?? [];
  const selectionsComplete = Boolean(info && info.endpointBindings.every(logical => selectedId(endpointSelections, logical, endpointCandidates(logical).map(item => item.endpointId)) !== '') && info.secretBindings.every(binding => selectedId(resourceSelections, binding.name, providerCandidates(binding.kind).map(item => item.id)) !== ''));

  const refresh = (...keys: string[][]) => Promise.all(keys.map(queryKey => cache.invalidateQueries({ queryKey })));

  const createInstallation = useMutation({
    mutationFn: () => adminApi.createInstallation({ tenantId, applicationId, environmentId, installationKind }),
    onSuccess: async value => { setActivation(value); setInstallationId(value.installationId); replaceTarget({ installation: value.installationId, environment: environmentId }); await refresh(['installations', tenantId]); }
  });
  const importDefinition = useMutation({
    mutationFn: async () => {
      if (!connectorId || !version) throw new Error('guided-definition-target-missing');
      let authoritative;
      try { authoritative = await adminApi.connectorVersion(connectorId, version); }
      catch (error) {
        if (!(error instanceof ApiProblem) || error.status !== 404 || !fileDefinition) throw error;
        const validation = await adminApi.validateConnector(fileDefinition);
        if (!validation.valid || !validation.checksumSha256) throw new Error('guided-definition-invalid');
        authoritative = await adminApi.importConnector(fileDefinition, validation.checksumSha256);
      }
      if (authoritative.state === 'Draft') authoritative = await adminApi.validateStored(connectorId, authoritative);
      if (authoritative.state !== 'Validated' && authoritative.state !== 'Published') throw new Error('guided-definition-state-invalid');
      return authoritative;
    },
    onSuccess: () => refresh(['connectors'], ['connector-versions', connectorId], ['connector-version', connectorId, version], ['connector-definition', connectorId, version])
  });
  const configure = useMutation({
    mutationFn: async () => {
      if (!info || !selectedInstallation || selectedInstallation.status !== 'Active') throw new Error('guided-active-installation-required');
      const [authoritativeVersion, authoritativeInstallation] = await Promise.all([
        adminApi.connectorVersion(connectorId, version), adminApi.installation(tenantId, installationId)
      ]);
      if (authoritativeInstallation.status !== 'Active') throw new Error('guided-active-installation-required');
      if (authoritativeVersion.state !== 'Validated') throw new Error('guided-validated-version-required');
      if (authoritativeInstallation.environmentId !== selectedInstallation.environmentId) throw new Error('guided-installation-environment-changed');
      const authoritativeBindings = await adminApi.bindings(connectorId, version, authoritativeInstallation.environmentId, 0, 100);
      if (!authoritativeBindings.items.some(item => item.environmentId === authoritativeInstallation.environmentId)) {
        if (!selectionsComplete) throw new Error('guided-binding-selection-required');
        const endpointSelectionsRequest = Object.fromEntries(info.endpointBindings.map(logical => {
          const selected = endpointCandidates(logical).find(item => item.endpointId === selectedId(endpointSelections, logical, endpointCandidates(logical).map(candidate => candidate.endpointId)))!;
          return [logical, { endpointId: selected.endpointId, revision: selected.revision, checksumSha256: selected.checksumSha256 }];
        }));
        const resources = Object.fromEntries(info.secretBindings.map(binding => {
          const selected = providerCandidates(binding.kind).find(item => item.id === selectedId(resourceSelections, binding.name, providerCandidates(binding.kind).map(candidate => candidate.id)))!;
          return [binding.name, { providerId: selected.providerId, resourceId: selected.resourceId, resourceType: selected.resourceType, version: selected.version, publicMetadataRevision: selected.publicMetadataRevision, catalogRevision: selected.revision, catalogChecksumSha256: selected.checksumSha256 }];
        }));
        await adminApi.putBindings(connectorId, {
          environmentId: authoritativeInstallation.environmentId,
          connectorVersion: version,
          endpoints: {},
          endpointResources: endpointSelectionsRequest,
          secretResources: Object.fromEntries(info.secretBindings.filter(item => item.kind !== 'clientCertificate').map(item => [item.name, resources[item.name]])),
          certificateResources: Object.fromEntries(info.secretBindings.filter(item => item.kind === 'clientCertificate').map(item => [item.name, resources[item.name]]))
        });
      }
      for (const operationId of info.operations) {
        await adminApi.createGrant({ tenantId, installationId, connectorId, connectorVersion: authoritativeVersion.version, operationId });
      }
    },
    onSuccess: () => refresh(['bindings', connectorId, version], ['grants', tenantId], ['approvals', connectorId, version], ['approval-review', connectorId, version])
  });
  const requestApproval = useMutation({
    mutationFn: async () => {
      const authoritative = await adminApi.approvals(connectorId, version, 0, 100);
      if (!authoritative.items.some(item => item.status === 'Requested' || item.status === 'Approved')) await adminApi.requestApproval(connectorId, version);
    },
    onSuccess: () => refresh(['approvals', connectorId, version], ['approval-review', connectorId, version])
  });
  const approveAndPublish = useMutation({
    mutationFn: async () => {
      const decisions = await adminApi.approvals(connectorId, version, 0, 100);
      let approved = decisions.items.find(item => item.status === 'Approved');
      if (!approved) {
        const requested = decisions.items.find(item => item.status === 'Requested');
        if (!requested) throw new Error('guided-approval-request-required');
        const artifact = await adminApi.approvalReview(connectorId, version);
        approved = await adminApi.approve(connectorId, version, requested.id, artifact.digestSha256);
      }
      const authoritativeVersion = await adminApi.connectorVersion(connectorId, version);
      if (authoritativeVersion.state === 'Published') return;
      const summaries = await adminApi.connectors(0, 100, connectorId);
      const summary = summaries.items.find(item => item.connectorId === connectorId);
      if (!summary) throw new Error('guided-connector-summary-required');
      await adminApi.publish(connectorId, authoritativeVersion, summary.publicationRevision);
    },
    onSuccess: () => refresh(['connectors'], ['connector-versions', connectorId], ['connector-version', connectorId, version], ['bindings', connectorId], ['approvals', connectorId], ['approval-review', connectorId])
  });

  const mutationError = fileError ?? createInstallation.error ?? importDefinition.error ?? configure.error ?? requestApproval.error ?? approveAndPublish.error;
  const isPublished = currentVersion?.state === 'Published';
  const isReady = isPublished && selectedInstallation?.status === 'Active';
  let stateKey = 'guidedStateSelectInstallation'; let roleKey = 'roleSecurityAdministrator'; let actionKey = 'guidedActionCreateInstallation'; let prerequisiteKey = 'guidedPrerequisiteInstallation';
  if (selectedInstallation?.status === 'Pending') { stateKey = 'guidedStateEnrollmentPending'; actionKey = 'guidedActionEnrollmentHandoff'; prerequisiteKey = 'guidedPrerequisiteEnrollment'; }
  else if (selectedInstallation?.status === 'Active' && (!currentVersion || currentVersion.state === 'Draft')) { stateKey = 'guidedStateDefinition'; roleKey = 'roleConnectorEditor'; actionKey = 'guidedActionDefinition'; prerequisiteKey = 'guidedPrerequisiteDefinition'; }
  else if (selectedInstallation?.status === 'Active' && currentVersion?.state === 'Validated' && (!bindingExists || missingGrants.length > 0)) { stateKey = 'guidedStateBindingGrant'; actionKey = 'guidedActionBindingGrant'; prerequisiteKey = 'guidedPrerequisiteBindingGrant'; }
  else if (selectedInstallation?.status === 'Active' && currentVersion?.state === 'Validated' && bindingExists && missingGrants.length === 0 && !requestedApproval && !approvedApproval) { stateKey = 'guidedStateApprovalRequest'; roleKey = 'roleConnectorEditor'; actionKey = 'guidedActionRequestApproval'; prerequisiteKey = 'guidedPrerequisiteApprovalRequest'; }
  else if (selectedInstallation?.status === 'Active' && currentVersion?.state === 'Validated' && (requestedApproval || approvedApproval)) { stateKey = 'guidedStateApprovalPublish'; roleKey = 'roleConnectorApprover'; actionKey = 'guidedActionApprovePublish'; prerequisiteKey = 'guidedPrerequisiteApprovalPublish'; }
  else if (isReady) { stateKey = 'guidedStateComplete'; roleKey = 'guidedRoleNone'; actionKey = 'guidedActionComplete'; prerequisiteKey = 'guidedPrerequisiteNone'; }
  const actionRole = roleKey === 'roleSecurityAdministrator' ? 'SecurityAdministrator' : roleKey === 'roleConnectorEditor' ? 'ConnectorEditor' : 'ConnectorApprover';
  const canContinue = !isReady && actionKey !== 'guidedActionEnrollmentHandoff' && (actionKey !== 'guidedActionCreateInstallation' || !installationId) && hasRole(session, actionRole);

  if (tenants.isPending || applications.isPending || environments.isPending || connectors.isPending) return <LoadingState />;
  const loadError = tenants.error ?? applications.error ?? environments.error ?? connectors.error ?? installations.error ?? versions.error ?? selectedTenant.error ?? selectedApplication.error ?? selectedEnvironment.error ?? selectedVersionQuery.error ?? selectedInstallationQuery.error ?? storedDefinition.error ?? bindings.error ?? grants.error ?? approvals.error ?? endpointResources.error ?? providerResources.error ?? review.error;
  if (loadError && !mutationError) return <ErrorState error={loadError} />;

  return <Box sx={{ maxWidth: 960, mx: 'auto' }}>
    <PageTitle title={t('guidedOnboarding')} />
    <Card><CardContent>
      <Typography variant="overline">{t('guidedNextAction')}</Typography>
      <Typography variant="h2" sx={{ fontSize: '1.5rem', mt: 0.5 }}>{t(actionKey)}</Typography>
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} sx={{ mt: 1, flexWrap: 'wrap' }}>
        <Chip label={`${t('status')}: ${t(stateKey)}`} variant={isPublished ? 'outlined' : 'filled'} />
        {!isReady && <Chip label={`${t('guidedRequiredRole')}: ${t(roleKey)}`} color="primary" variant="outlined" />}
      </Stack>
      {!isReady && <Typography sx={{ mt: 2 }}>{t(prerequisiteKey)}</Typography>}
      {canContinue && <Button variant="contained" href="#guided-current-action" sx={{ mt: 2 }}>{t('guidedContinue')}</Button>}
      {isReady && <><Alert severity="success" sx={{ mt: 2 }} role="status">{t('guidedPublishedActive')}</Alert><Button variant="contained" href={`./documentation#invoke-${selectedInstallation?.installationKind === 'Broker' ? 'broker' : 'direct'}`} sx={{ mt: 2 }}>{t(selectedInstallation?.installationKind === 'Broker' ? 'guidedRuntimeBroker' : 'guidedRuntimeDirect')}</Button></>}
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>{t('guidedResumeSafe')}</Typography>
    </CardContent></Card>

    <Card sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2" sx={{ mb: 2 }}>{t('guidedTarget')}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{t('guidedContextHelp')}</Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: 'repeat(2, minmax(0, 1fr))' }, gap: 2 }}>
        <Typography component="h3" variant="subtitle1" sx={{ gridColumn: '1 / -1', fontWeight: 600 }}>{t('guidedInstallationContext')}</Typography>
        <PagedSelector id="guided-tenant" busy={tenants.isPlaceholderData || tenantSearch.text.trim() !== tenantSearch.filter} search={{ value: tenantSearch.text, onChange: value => { tenantSearch.setText(value); setTenantOffset(0); }, hint: t('selectorSearchNameCode') }} label={t('selectTenant')} value={tenantId} page={tenants.data!} selectedItem={selectedTenant.data} onChange={selectTenant} onOffset={setTenantOffset} itemLabel={item => `${item.displayName} · ${item.code}`} />
        <Box sx={{ display: 'contents' }}>
          <PagedSelector id="guided-application" busy={applications.isPlaceholderData || applicationSearch.text.trim() !== applicationSearch.filter} search={{ value: applicationSearch.text, onChange: value => { applicationSearch.setText(value); setApplicationOffset(0); }, hint: t('selectorSearchNameCode') }} label={t('application')} value={effectiveApplicationId} page={applications.data!} selectedItem={selectedApplication.data} onChange={value => { setApplicationId(value); setEnvironmentId(effectiveEnvironmentId); resetInstallationChoices(); replaceTarget({ application: value, environment: effectiveEnvironmentId, installation: '' }); }} onOffset={setApplicationOffset} itemLabel={item => `${item.displayName} · ${item.code}`} />
          <PagedSelector id="guided-environment" busy={environments.isPlaceholderData || environmentSearch.text.trim() !== environmentSearch.filter} search={{ value: environmentSearch.text, onChange: value => { environmentSearch.setText(value); setEnvironmentOffset(0); }, hint: t('selectorSearchNameCode') }} label={t('environment')} value={effectiveEnvironmentId} page={environments.data!} selectedItem={selectedEnvironment.data?.items.find(item => item.id === effectiveEnvironmentId)} onChange={selectEnvironment} onOffset={setEnvironmentOffset} itemLabel={item => `${item.displayName} · ${item.code}`} />
        </Box>
        {tenantId && installations.data && <PagedSelector id="guided-installation" busy={installations.isPlaceholderData || installationSearch.text.trim() !== installationSearch.filter} search={{ value: installationSearch.text, onChange: value => { installationSearch.setText(value); setInstallationOffset(0); }, hint: t('selectorSearchId') }} label={t('installation')} value={installationId} page={installations.data} selectedItem={selectedInstallation} onChange={selectInstallation} onOffset={setInstallationOffset} itemLabel={item => `${item.installationKind} · ${item.status} · ${formatDate(item.createdAt)} · ${item.id}`} />}
        <Typography component="h3" variant="subtitle1" sx={{ gridColumn: '1 / -1', fontWeight: 600, pt: 2, borderTop: 1, borderColor: 'divider' }}>{t('guidedConnectorContext')}</Typography>
        <PagedSelector id="guided-connector" busy={connectors.isPlaceholderData || connectorSearch.text.trim() !== connectorSearch.filter} search={{ value: connectorSearch.text, onChange: value => { connectorSearch.setText(value); setConnectorOffset(0); }, hint: t('selectorSearchNameCode') }} label={t('connector')} value={connectorId} page={connectors.data!} onChange={selectConnector} onOffset={setConnectorOffset} itemLabel={item => `${item.displayName} · ${item.connectorId}`} itemValue={item => item.connectorId} />
        {connectorId && versions.data && <PagedSelector id="guided-version" busy={versions.isPlaceholderData || versionSearch.text.trim() !== versionSearch.filter} search={{ value: versionSearch.text, onChange: value => { versionSearch.setText(value); setVersionOffset(0); }, hint: t('selectorSearchNameCode') }} label={t('version')} value={version} page={versions.data} selectedItem={currentVersion ?? undefined} onChange={selectVersion} onOffset={setVersionOffset} itemLabel={item => `${item.version} · ${item.state}`} itemValue={item => item.version} />}
      </Box>
    </CardContent></Card>

    {hasRole(session, 'SecurityAdministrator') && !installationId && <Card id={actionKey === 'guidedActionCreateInstallation' ? 'guided-current-action' : undefined} tabIndex={-1} sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2">1. {t('guidedActionCreateInstallation')}</Typography>
      <Typography color="text.secondary" sx={{ my: 1 }}>{t('guidedCreateInstallationHelp')}</Typography>
      {(!installationId || selectedInstallation) && <Box sx={{ maxWidth: 480, my: 2 }}>
        <InstallationKindSelector value={selectedInstallation?.installationKind ?? installationKind} onChange={setInstallationKind} disabled={Boolean(installationId) || createInstallation.isPending} />
      </Box>}
      <Button variant="contained" disabled={!tenantId || !applicationId || !environmentId || Boolean(installationId) || createInstallation.isPending} onClick={() => createInstallation.mutate()}>{t('createInstallation')}</Button>
    </CardContent></Card>}

    {hasRole(session, 'ConnectorEditor') && (!currentVersion || currentVersion.state === 'Draft') && <Card id={actionKey === 'guidedActionDefinition' ? 'guided-current-action' : undefined} tabIndex={-1} sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2">2. {t('guidedActionDefinition')}</Typography>
      <Typography color="text.secondary" sx={{ my: 1 }}>{t('guidedDefinitionHelp')}</Typography>
      <Button component="label" variant="outlined">{t('guidedSelectDefinitionFile')}<input hidden type="file" accept="application/json,.json" aria-label={t('guidedDefinitionFile')} onChange={async event => {
        const file = event.currentTarget.files?.[0]; if (!file) return;
        try {
          const parsed = JSON.parse(await file.text()) as object; const parsedInfo = definitionInfo(parsed); if (!parsedInfo) throw new Error('guided-definition-invalid');
          setFileError(undefined); setFileDefinition(parsed); setFileName(file.name); setConnectorId(parsedInfo.connectorId); setVersion(parsedInfo.version); replaceTarget({ connector: parsedInfo.connectorId, version: parsedInfo.version });
        } catch (error) { setFileError(error instanceof Error ? error : new Error('guided-definition-invalid')); }
      }} /></Button>
      {fileName && <Typography sx={{ mt: 1 }}>{t('guidedSelectedFile')}: {fileName}</Typography>}
      <Box sx={{ mt: 2 }}><Button variant="contained" disabled={!connectorId || !version || importDefinition.isPending || (!fileDefinition && !currentVersion)} onClick={() => importDefinition.mutate()}>{t('guidedValidateImport')}</Button></Box>
      <Typography color="text.secondary" sx={{ mt: 1 }}>{t('guidedAdvancedEditorHelp')}</Typography>
    </CardContent></Card>}

    {hasRole(session, 'SecurityAdministrator') && currentVersion?.state === 'Validated' && info && (!bindingExists || missingGrants.length > 0) && <Card id={actionKey === 'guidedActionBindingGrant' ? 'guided-current-action' : undefined} tabIndex={-1} sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2">3. {t('guidedActionBindingGrant')}</Typography>
      {!bindingExists && <Stack spacing={2} sx={{ my: 2 }}>
        {info.endpointBindings.map(logical => { const candidates = endpointCandidates(logical); const value = selectedId(endpointSelections, logical, candidates.map(item => item.endpointId)); return <FormControl key={logical} fullWidth><InputLabel id={`endpoint-${logical}`}>{t('endpoint')}: {logical}</InputLabel><Select labelId={`endpoint-${logical}`} label={`${t('endpoint')}: ${logical}`} value={value} onChange={event => setEndpointSelections(current => ({ ...current, [logical]: event.target.value }))}>{candidates.map(item => <MenuItem key={item.endpointId} value={item.endpointId}>{item.displayName} · {item.endpoint}</MenuItem>)}</Select></FormControl>; })}
        {info.secretBindings.map(binding => { const candidates = providerCandidates(binding.kind); const value = selectedId(resourceSelections, binding.name, candidates.map(item => item.id)); return <FormControl key={binding.name} fullWidth><InputLabel id={`resource-${binding.name}`}>{t(binding.kind === 'clientCertificate' ? 'certificate' : 'logicalCredential')}: {binding.name}</InputLabel><Select labelId={`resource-${binding.name}`} label={`${t(binding.kind === 'clientCertificate' ? 'certificate' : 'logicalCredential')}: ${binding.name}`} value={value} onChange={event => setResourceSelections(current => ({ ...current, [binding.name]: event.target.value }))}>{candidates.map(item => <MenuItem key={item.id} value={item.id}>{item.displayName} · {item.providerDisplayName}</MenuItem>)}</Select></FormControl>; })}
      </Stack>}
      {bindingExists && <Alert severity="success" sx={{ my: 2 }}>{t('guidedBindingAlreadyPresent')}</Alert>}
      <Button variant="contained" disabled={!selectedInstallation || selectedInstallation.status !== 'Active' || (!bindingExists && !selectionsComplete) || configure.isPending} onClick={() => configure.mutate()}>{t('guidedConfigureBindingGrant')}</Button>
    </CardContent></Card>}

    {hasRole(session, 'ConnectorEditor') && currentVersion?.state === 'Validated' && bindingExists && missingGrants.length === 0 && !requestedApproval && !approvedApproval && <Card id={actionKey === 'guidedActionRequestApproval' ? 'guided-current-action' : undefined} tabIndex={-1} sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2">4. {t('guidedActionRequestApproval')}</Typography>
      <Button variant="contained" disabled={Boolean(requestedApproval || approvedApproval) || requestApproval.isPending} onClick={() => requestApproval.mutate()}>{t('requestApproval')}</Button>
    </CardContent></Card>}

    {hasRole(session, 'ConnectorApprover') && currentVersion?.state === 'Validated' && (requestedApproval || approvedApproval) && <Card id={actionKey === 'guidedActionApprovePublish' ? 'guided-current-action' : undefined} tabIndex={-1} sx={{ mt: 3 }}><CardContent>
      <Typography variant="h2">5. {t('guidedActionApprovePublish')}</Typography>
      {review.data && <Box component="section" aria-label={t('guidedApprovalReview')} sx={{ my: 2 }}><Typography><strong>{t('connector')}:</strong> {review.data.artifact.connector.displayName} · {review.data.artifact.connector.version}</Typography><Typography><strong>{t('publicationDigest')}:</strong> <code>{review.data.digestSha256}</code></Typography>{review.data.artifact.operations.map(operation => <Typography key={`${operation.environment}-${operation.operationId}`}><strong>{operation.operationId}:</strong> {operation.endpoint.scheme}://{operation.endpoint.hostname}:{operation.endpoint.port}{operation.endpoint.path}</Typography>)}</Box>}
      <Button variant="contained" disabled={(!approvedApproval && !review.data) || approveAndPublish.isPending} onClick={() => approveAndPublish.mutate()}>{t('guidedVerifyApprovePublish')}</Button>
    </CardContent></Card>}

    {mutationError && <Box sx={{ mt: 2 }}><ErrorState error={mutationError} /></Box>}
    <ActivationHandoffDialog activation={activation} onClose={() => setActivation(undefined)} />
  </Box>;
}
