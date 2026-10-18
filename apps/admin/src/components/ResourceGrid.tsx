import { useEffect, useMemo, useState } from 'react';
import { collection, isRecord } from '../api/client';
import { valueAt, textValue, filterSortRows, paginateRows, type Column } from './resource-model';
import type { SectionId } from '../admin/routing';

type Item = Record<string, unknown>;
const definitions: Partial<Record<SectionId, Column[]>> = {
  projects: [{ field: 'name', title: 'Проект' }, { field: 'id', title: 'ID' }, { field: 'defaultChannel', title: 'Канал', facet: true }, { field: 'updatedAt', title: 'Изменён', datetime: true }],
  profiles: [{ field: 'name', title: 'Профиль' }, { field: 'id', title: 'ID' }, { field: 'loader', title: 'Загрузчик', facet: true }, { field: 'preset', title: 'Пресет', facet: true }, { field: 'isDefault', title: 'По умолчанию', facet: true }],
  channels: [{ field: 'name', title: 'Канал' }, { field: 'id', title: 'ID' }, { field: 'protected', title: 'Защищён', facet: true }, { field: 'description', title: 'Описание' }],
  packages: [{ field: 'version', title: 'Версия' }, { field: 'profileId', title: 'Профиль', facet: true }, { field: 'channel', title: 'Канал', facet: true }, { field: 'status', title: 'Состояние', facet: true }, { field: 'publishedAt', title: 'Публикация', datetime: true }],
  releases: [{ field: 'version', title: 'Версия' }, { field: 'profileId', title: 'Профиль', facet: true }, { field: 'channel', title: 'Канал', facet: true }, { field: 'status', title: 'Состояние', facet: true }, { field: 'publishedAt', title: 'Публикация', datetime: true }],
  users: [{ field: 'displayName', title: 'Пользователь' }, { field: 'email', title: 'Email' }, { field: 'roleId', title: 'Роль', facet: true }, { field: 'status', title: 'Состояние', facet: true }, { field: 'lastLoginAt', title: 'Последний вход', datetime: true }],
  roles: [{ field: 'name', title: 'Роль' }, { field: 'id', title: 'ID' }, { field: 'description', title: 'Описание' }],
  devices: [{ field: 'name', title: 'Устройство' }, { field: 'userId', title: 'Пользователь' }, { field: 'status', title: 'Состояние', facet: true }, { field: 'trustState', title: 'Доверие', facet: true }, { field: 'lastSeenAt', title: 'Активность', datetime: true }],
  audit: [{ field: 'createdAt', title: 'Дата', datetime: true }, { field: 'actor', title: 'Инициатор' }, { field: 'action', title: 'Действие', facet: true }, { field: 'target', title: 'Объект' }, { field: 'ip', title: 'IP' }],
  'extension-registry': [{ field: 'extensionId', title: 'Расширение' }, { field: 'version', title: 'Версия' }, { field: 'publisherId', title: 'Издатель', facet: true }, { field: 'publishedAt', title: 'Опубликовано', datetime: true }],
};
function displayValue(row: Item, col: Column): string {
  const value = valueAt(row, col.field);
  if (col.datetime && typeof value === 'string' && value && !Number.isNaN(Date.parse(value))) return new Date(value).toLocaleString();
  return textValue(value);
}
function details(item: Item): [string, unknown][] { return Object.entries(item).filter(([key]) => !['passwordHash', 'token', 'refreshToken'].includes(key)); }
export function StructuredDetails({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (depth > 3) return <span className="muted">Дополнительные вложенные сведения доступны через API</span>;
  if (Array.isArray(value)) return <ul className="structuredList">{value.slice(0, 50).map((item, index) => <li key={index}><StructuredDetails value={item} depth={depth + 1}/></li>)}</ul>;
  if (isRecord(value)) return <dl className="structuredFields">{Object.entries(value).slice(0, 70).map(([field, item]) => <div key={field}><dt>{field}</dt><dd><StructuredDetails value={item} depth={depth + 1}/></dd></div>)}</dl>;
  return <span>{textValue(value)}</span>;
}

export function ResourceGrid({ section, payload, onSelect, selectedId, columns }: { section: SectionId; payload: unknown; onSelect?: (item: Item) => void; selectedId?: string; columns?: Column[] }) {
  const [search, setSearch] = useState('');
  const [facetField, setFacetField] = useState('');
  const [facetValue, setFacetValue] = useState('');
  const [sort, setSort] = useState('');
  const [descending, setDescending] = useState(false);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(10);
  const [openId, setOpenId] = useState<string | null>(null);
  // Admin overview is the access-filtered source of projects. Public /projects is not.
  const source = section === 'projects' && isRecord(payload) ? payload.projects : payload;
  const rows = useMemo(() => collection<Item>(source), [source]);
  // The overview returns arrays at named keys rather than `items`.
  const projectRows = section === 'projects' && Array.isArray(source) ? source.filter(isRecord) : rows;
  const cols = columns ?? definitions[section] ?? [];
  const facets = cols.filter(c => c.facet);
  useEffect(() => { setSearch(''); setFacetField(''); setFacetValue(''); setSort(''); setPage(1); setOpenId(null); }, [section]);
  const values = useMemo(() => Array.from(new Set(projectRows.map(row => textValue(valueAt(row, facetField))))).sort(), [projectRows, facetField]);
  const sorted = useMemo(() => filterSortRows(projectRows, cols, search, facetField, facetValue, sort, descending), [projectRows, cols, search, facetField, facetValue, sort, descending]);
  const { page: current, totalPages: count, rows: visible } = paginateRows(sorted, page, size);
  const rowKey = (row: Item): string => String(row.id ?? row.commandId ?? row.targetId ?? `record:${projectRows.indexOf(row)}`);
  const focused = projectRows.find(item => rowKey(item) === (openId ?? selectedId));
  if (cols.length === 0) return <SummaryView payload={payload} />;
  return <div className="resourceGrid">
    <div className="dataToolbar">
      <label>Поиск<input aria-label="Поиск по таблице" type="search" value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} placeholder="Поиск по видимым полям" /></label>
      {facets.length > 0 && <label>Фильтр<select aria-label="Поле фильтра" value={facetField} onChange={event => { setFacetField(event.target.value); setFacetValue(''); setPage(1); }}><option value="">Все поля</option>{facets.map(col => <option key={col.field} value={col.field}>{col.title}</option>)}</select></label>}
      {facetField && <label>Значение<select aria-label="Значение фильтра" value={facetValue} onChange={event => { setFacetValue(event.target.value); setPage(1); }}><option value="">Любое</option>{values.map(value => <option key={value} value={value}>{value}</option>)}</select></label>}
      <label>Строк<select aria-label="Строк на странице" value={size} onChange={event => { setSize(Number(event.target.value)); setPage(1); }}><option value={10}>10</option><option value={25}>25</option><option value={50}>50</option></select></label>
    </div>
    {projectRows.length === 0 ? <div className="emptyState"><strong>Записей нет</strong><p>В доступном разделе пока нет объектов. Измените проект или создайте объект с помощью формы.</p></div> : sorted.length === 0 ? <div className="emptyState"><strong>Совпадений нет</strong><p>Сбросьте поиск или фильтры.</p><button onClick={() => { setSearch(''); setFacetField(''); setFacetValue(''); }}>Сбросить фильтры</button></div> : <>
      <div className="tableScroll"><table className="table resourceTable"><thead><tr>{cols.map(col => <th key={col.field} scope="col"><button className="sortButton" onClick={() => { setDescending(sort === col.field ? !descending : false); setSort(col.field); setPage(1); }} aria-label={`Сортировать по ${col.title}`}>{col.title} {sort === col.field ? (descending ? '↓' : '↑') : '↕'}</button></th>)}<th>Карточка</th></tr></thead><tbody>{visible.map(row => {
        const id = rowKey(row);
        return <tr key={id} className={id === (openId ?? selectedId) ? 'selectedRow' : ''}>{cols.map(col => <td key={col.field}>{displayValue(row, col)}</td>)}<td><button onClick={() => { setOpenId(id); onSelect?.(row); }}>Открыть</button></td></tr>;
      })}</tbody></table></div>
      <div className="pager"><span>{sorted.length} из {projectRows.length} · страница {current} / {count}</span><div><button disabled={current === 1} onClick={() => setPage(p => Math.max(1, p - 1))}>Назад</button><button disabled={current === count} onClick={() => setPage(p => Math.min(count, p + 1))}>Вперёд</button></div></div>
    </>}
    {focused && <article className="detailCard"><div className="detailHeading"><h3>Карточка: {textValue(focused.name ?? focused.displayName ?? focused.version ?? focused.id)}</h3><button onClick={() => setOpenId(null)}>Закрыть</button></div><dl>{details(focused).map(([key, value]) => <div key={key}><dt>{key}</dt><dd><StructuredDetails value={value} /></dd></div>)}</dl>{onSelect && <p className="muted">Доступные для вашей роли действия отображаются в форме соответствующего раздела.</p>}</article>}
  </div>;
}

function SummaryView({ payload }: { payload: unknown }) {
  if (!payload) return <p className="muted">Данные ещё не загружены.</p>;
  if (!isRecord(payload)) return <p className="muted">{textValue(payload)}</p>;
  const scalar = Object.entries(payload).filter(([, value]) => value == null || typeof value !== 'object');
  const arrays = Object.entries(payload).filter(([, value]) => Array.isArray(value));
  const nested = Object.entries(payload).filter(([, value]) => isRecord(value));
  return <div className="summaryGrid">{scalar.map(([key, value]) => <article className="subcard" key={key}><small>{key}</small><p>{textValue(value)}</p></article>)}{arrays.map(([key, value]) => <article className="subcard" key={key}><small>{key}</small><p>{(value as unknown[]).length} записей</p><details><summary>Открыть список</summary><ul>{(value as unknown[]).slice(0, 50).map((item, index) => <li key={index}>{isRecord(item) ? textValue(item.name ?? item.id ?? item.status ?? item.action) : textValue(item)}</li>)}</ul></details></article>)}{nested.map(([key, value]) => <article className="subcard" key={key}><small>{key}</small><dl>{Object.entries(value as Item).map(([field, item]) => <div key={field}><dt>{field}</dt><dd>{textValue(item)}</dd></div>)}</dl></article>)}</div>;
}
