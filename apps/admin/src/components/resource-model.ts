/** Pure collection transforms used by tables (independent of React/rendering). */
export type TableRow = Record<string, unknown>;
export type Column = { field: string; title: string; facet?: boolean; datetime?: boolean };

export function valueAt(row: TableRow, field: string): unknown {
  return field.split('.').reduce<unknown>((value, key) => value && typeof value === 'object' && !Array.isArray(value) ? (value as TableRow)[key] : undefined, row);
}
export function textValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет';
  if (Array.isArray(value)) return value.map(textValue).join(', ');
  if (typeof value === 'object') return 'Открыть карточку';
  return String(value);
}
export function filterSortRows(rows: TableRow[], columns: Column[], query: string, facetField: string, facetValue: string, sort: string, descending: boolean): TableRow[] {
  const needle = query.trim().toLocaleLowerCase();
  const filtered = rows.filter(row => {
    const hit = !needle || columns.some(col => textValue(valueAt(row, col.field)).toLocaleLowerCase().includes(needle));
    return hit && (!facetField || !facetValue || textValue(valueAt(row, facetField)) === facetValue);
  });
  if (!sort) return filtered;
  return filtered.sort((a, b) => {
    const left = valueAt(a, sort), right = valueAt(b, sort);
    const comparison = typeof left === 'number' && typeof right === 'number' ? left - right : textValue(left).localeCompare(textValue(right), 'ru', { numeric: true, sensitivity: 'base' });
    return descending ? -comparison : comparison;
  });
}
export function paginateRows<T>(rows: T[], requestedPage: number, pageSize: number) {
  const size = Number.isFinite(pageSize) && pageSize > 0 ? Math.floor(pageSize) : 10;
  const totalPages = Math.max(1, Math.ceil(rows.length / size));
  const page = Math.max(1, Math.min(totalPages, Math.floor(requestedPage) || 1));
  return { page, totalPages, rows: rows.slice((page - 1) * size, page * size), total: rows.length };
}
