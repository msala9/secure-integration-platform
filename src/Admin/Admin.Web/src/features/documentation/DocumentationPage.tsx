import { useEffect } from 'react';
import { Box, Divider, Link, Paper, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Link as RouterLink } from 'react-router-dom';
import { adminGuide, type GuideSection } from '../../i18n/adminGuide.en';
import { PageTitle } from '../../components/PageTitle';

export function DocumentationPage() {
  const { t, i18n } = useTranslation();
  useEffect(() => {
    const focusFragment = () => {
      const id = window.location.hash.slice(1);
      const target = document.getElementById(id);
      if (target && target.closest('#admin-guide')) {
        target.scrollIntoView();
        target.focus({ preventScroll: true });
      }
    };
    focusFragment();
    window.addEventListener('hashchange', focusFragment);
    return () => window.removeEventListener('hashchange', focusFragment);
  }, []);

  return <Box id="admin-guide" sx={{ maxWidth: 1200, overflowWrap: 'anywhere', '& [id]': { scrollMarginTop: '7rem' } }}>
    <PageTitle title={t('documentation')} description={t('guideLanguage')} />
    {(['direct', 'broker'] as const).map(kind => <Paper key={kind} component="section" variant="outlined" sx={{ p: 3, mb: 3 }} aria-labelledby={`invoke-${kind}`}>
      <Typography variant="h2" id={`invoke-${kind}`} tabIndex={-1}>{t(kind === 'direct' ? 'guidedRuntimeDirect' : 'guidedRuntimeBroker')}</Typography>
      <Box component="ol" sx={{ pl: 3 }}>
        <li><Typography>{t(kind === 'direct' ? 'guidedDirectPrepare' : 'guidedBrokerPrepare')}</Typography></li>
        <li><Typography>{t(kind === 'direct' ? 'guidedDirectInvoke' : 'guidedBrokerInvoke')}</Typography></li>
        <li><Typography>{t('guidedInvocationVerify')}</Typography></li>
      </Box>
      <Link component={RouterLink} to="/audit">{t('audit')}</Link>
    </Paper>)}
    <Paper variant="outlined" sx={{ p: { xs: 2, md: 3 } }}>
      <Typography component="p" lang="en" sx={{ maxWidth: '78ch', mb: 3 }}>{adminGuide.introduction}</Typography>
      <Box component="nav" aria-labelledby="guide-contents">
        <Typography id="guide-contents" variant="h2" tabIndex={-1}>{t('guideContents')}</Typography>
        <Box component="ol" sx={{ pl: 3, columns: { xs: 1, md: 2 }, '& li': { breakInside: 'avoid', py: 0.5 } }}>
          {adminGuide.sections.map(section => <li key={section.id}><Link href={`#${section.id}`} lang="en">{section.title}</Link></li>)}
        </Box>
      </Box>
    </Paper>
    <Box component="article" lang="en" aria-label={adminGuide.title} sx={{ maxWidth: '80ch', mt: 4 }}>
      {(adminGuide.sections as readonly GuideSection[]).map(section => <Box component="section" aria-labelledby={section.id} key={section.id} sx={{ mb: 5 }}>
        <Typography variant="h2" id={section.id} tabIndex={-1} sx={{ fontSize: '1.5rem', mb: 2 }}><Link href={`#${section.id}`} color="inherit" underline="hover">{section.title}</Link></Typography>
        {section.route && section.navigationKey && <Link component={RouterLink} to={section.route} lang={i18n.language}>{t('guideOpenPage', { page: t(section.navigationKey) })}</Link>}
        {section.topics.map(topic => <Box key={topic.id} sx={{ mt: 3 }}>
          <Typography variant="h3" id={topic.id} tabIndex={-1} sx={{ fontSize: '1.1rem', fontWeight: 650, mb: 1.5 }}><Link href={`#${topic.id}`} color="inherit" underline="hover">{topic.title}</Link></Typography>
          {topic.paragraphs?.map(paragraph => <Typography key={paragraph} component="p" sx={{ mb: 1.5, lineHeight: 1.75 }}>{paragraph}</Typography>)}
          {topic.steps && <Box component="ol" sx={{ pl: 3, '& li': { pl: 0.5, mb: 1.5, lineHeight: 1.75 } }}>{topic.steps.map(step => <li key={step}>{step}</li>)}</Box>}
        </Box>)}
        <Link lang={i18n.language} href="#guide-contents" sx={{ display: 'inline-block', py: 1, mt: 1 }}>{t('guideBackToContents')}</Link>
        <Divider sx={{ mt: 2 }} />
      </Box>)}
    </Box>
  </Box>;
}
