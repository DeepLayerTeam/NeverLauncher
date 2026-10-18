import React from 'react';
export function MetricCard({ label, value }: { label: string; value: number | string }) {
  return <article className="card"><h3>{label}</h3><div className="metric">{value}</div></article>;
}

export function TextInput({ label, value, onChange, type = 'text', readOnly = false }: { label: string; value: string; onChange: (value: string) => void; type?: string; readOnly?: boolean }) {
  return <label className="field"><span>{label}</span><input value={value} type={type} readOnly={readOnly} onChange={(event) => onChange(event.target.value)} /></label>;
}

