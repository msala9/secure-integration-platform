import { Button, FormControl, InputLabel, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Page } from '../api/client';

export function PagedSelector<T>({ id, label, value, page, selectedItem, onChange, onOffset, itemLabel, itemValue, search, busy = false }: {
  id: string;
  label: string;
  value: string;
  page: Page<T>;
  selectedItem?: T;
  onChange: (value: string) => void;
  onOffset: (offset: number) => void;
  itemLabel: (item: T) => string;
  itemValue?: (item: T) => string;
  search?: { value: string; onChange: (value: string) => void; hint: string };
  busy?: boolean;
}) {
  const { t } = useTranslation();
  const optionValue = (item: T) => itemValue ? itemValue(item) : (item as { id: string }).id;
  const selectedOnPage = page.items.some(item => optionValue(item) === value);
  return <Stack spacing={0.5} sx={{ minWidth: 0, width: '100%', flex: '1 1 auto', maxWidth: '100%' }}>
    {search && <TextField size="small" type="search" label={t('selectorSearch', { label })} placeholder={search.hint} value={search.value} onChange={event => search.onChange(event.target.value)} slotProps={{ htmlInput: { maxLength: 100 } }} />}
    <FormControl><InputLabel id={`${id}-label`}>{label}</InputLabel><Select disabled={busy} labelId={`${id}-label`} label={label} value={value} onChange={event => onChange(event.target.value)}>
      {value && !selectedOnPage && <MenuItem value={value}>{selectedItem && optionValue(selectedItem) === value ? itemLabel(selectedItem) : value}</MenuItem>}
      {page.items.length === 0 && search && <MenuItem disabled>{t('selectorNoResults')}</MenuItem>}
      {page.items.map(item => { const itemId = optionValue(item); const current = itemId === value && selectedItem && optionValue(selectedItem) === itemId ? selectedItem : item; return <MenuItem key={itemId} value={itemId} sx={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{itemLabel(current)}</MenuItem>; })}
    </Select></FormControl>
    {(page.total > page.limit || page.offset > 0) && <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} role="group" aria-label={t('selectorPageControls')} data-testid={`${id}-pagination`}>
      <Button size="small" disabled={busy || page.offset === 0} onClick={() => onOffset(Math.max(0, page.offset - page.limit))}>{t('previousPage')}</Button>
      <Typography component="span" variant="caption" aria-live="polite">{page.total === 0 ? '0' : `${page.offset + 1}-${Math.min(page.offset + page.limit, page.total)}`} / {page.total}</Typography>
      <Button size="small" disabled={busy || page.offset + page.limit >= page.total} onClick={() => onOffset(page.offset + page.limit)}>{t('nextPage')}</Button>
    </Stack>}
  </Stack>;
}
