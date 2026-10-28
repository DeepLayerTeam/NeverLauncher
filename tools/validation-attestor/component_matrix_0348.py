"""Independent host-side verification of the signed component selection.

This never accepts component file paths or component IDs from the worker as
truth. All optional ownership and the transitive closure derive from the
immutable, verified staged release manifest.
"""
import re

ID=re.compile(r'^[a-z0-9][a-z0-9_.-]{0,127}$')


def selected_components(manifest, choice):
    cat=manifest.get('componentCatalog')
    if not cat:
        if choice!='default': raise ValueError('selection without signed catalog')
        return set(), {f['path'] for f in manifest['files']}
    by_id={c['id']:c for c in cat['components']}
    if len(by_id)!=len(cat['components']): raise ValueError('duplicate signed component id')
    if choice.startswith('@custom:v1:'):
        text=choice[len('@custom:v1:'):]
        if ':' not in text: raise ValueError('bad custom selection syntax')
        base,operations=text.split(':',1)
    else:
        base='' if choice=='default' and not any(p['id']=='default' for p in cat.get('presets',[])) else choice
        operations=None
    if not base: base=cat.get('defaultPreset','')
    presets={p['id']:p['components'] for p in cat.get('presets',[])}
    if base:
        if base not in presets: raise ValueError('unknown signed preset '+base)
        roots=set(presets[base])
    else:
        roots={c['id'] for c in cat['components'] if c.get('default')}
    if operations is not None and operations:
        changes=operations.split(',')
        if len(changes)>len(by_id): raise ValueError('too many custom choices')
        seen=set()
        for term in changes:
            if len(term)<2 or term[0] not in '+-' or not ID.fullmatch(term[1:]) or term[1:] in seen:
                raise ValueError('invalid or duplicate custom choice')
            ident=term[1:];seen.add(ident)
            if ident not in by_id: raise ValueError('unsigned component in custom choice')
            c=by_id[ident]
            if term[0]=='-' and c.get('required'): raise ValueError('required component disabled')
            if term[0]=='+' and (c.get('limited') or c.get('visible') is False):
                raise ValueError('restricted component manually enabled')
            if term[0]=='+': roots.add(ident)
            else: roots.discard(ident)
    roots.update(c['id'] for c in cat['components'] if c.get('required'))
    selected=set()
    def include(ident, chain):
        if ident in chain: raise ValueError('dependency cycle')
        if ident in selected: return
        c=by_id.get(ident)
        if c is None: raise ValueError('unknown dependency')
        selected.add(ident)
        for dep in c.get('dependencies',[]): include(dep['id'],chain+(ident,))
    for ident in roots: include(ident,())
    groups={}
    for ident in selected:
        c=by_id[ident]
        group=c.get('exclusiveGroup','')
        if group:
            if group in groups: raise ValueError('exclusive component group conflict')
            groups[group]=ident
        for conflict in c.get('conflicts',[]):
            # The pinned native resolver enforces versionRange as well;
            # the attestor never treats a selected conflict as safe by default.
            if conflict['id'] in selected and not conflict.get('versionRange'):
                raise ValueError('conflicting selected components')
    selected_files=set()
    all_owned=set()
    for c in cat['components']:
        paths=set(c['files'])
        all_owned.update(paths)
        if c['id'] in selected:selected_files.update(paths)
    for f in manifest['files']:
        if f['path'] not in all_owned: selected_files.add(f['path'])
    return selected,selected_files
