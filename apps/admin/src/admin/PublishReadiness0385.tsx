import React from 'react';
import type { PublishBlocker0385, PublishReadiness0385 } from '../api/release';

export function PublishReadiness0385({readiness,refusal=[],refresh,disabled=false}:{readiness?:PublishReadiness0385|null;refusal?:PublishBlocker0385[];refresh:()=>void;disabled?:boolean}) {
 const blockers=refusal.length?refusal:readiness?.blockers??[];
 return <section className="subcard" aria-label="Причины отказа публикации" aria-live="polite">
  <h4>Допуск к публикации · проверка Backend</h4>
  <p role="status">{!readiness && !refusal.length?'Проверки ещё не загружены.':blockers.length?`Публикация заблокирована: ${blockers.length} причин.`:readiness?.eligible?'Предварительные проверки пройдены. При публикации Backend повторно проверит точные байты и доверенные подтверждения.':'Проверки не завершены; публикация не подтверждена.'}</p>
  {blockers.length>0 && <ol>{blockers.map((blocker,index)=><li key={`${blocker.reasonCode}:${blocker.resource}:${index}`}>
   <strong>{blocker.reasonCode}</strong> · <code>{blocker.resource}</code>
   <p>{blocker.message}</p><p><strong>Действие:</strong> {blocker.action}</p>
  </li>)}</ol>}
  <button type="button" disabled={disabled} onClick={refresh}>Повторно проверить на Backend</button>
 </section>;
}
