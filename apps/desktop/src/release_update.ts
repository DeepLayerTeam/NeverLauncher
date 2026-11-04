// Согласие пользователя относится к конкретной подписанной цели, а не к названию релиза.
export type SignedTarget0359 = {
  projectId: string; profileId: string; channel: string; version: string;
  signature?: { signature?: string };
};
export type RequirementPreview0359 = {
  installedVersion: string | null; targetVersion: string; targetSignature: string;
  changes: string[]; proposedPreset: string | null;
  blockers: string[]; requiresConfirmation: boolean;
};
export function updateIdentity0359(manifest: SignedTarget0359): string {
  const signature = manifest.signature?.signature;
  if (!signature || !/^[A-Za-z0-9+/=_-]{32,256}$/.test(signature)) {
    throw new Error('Подписанный Manifest не содержит корректной подписи');
  }
  return JSON.stringify([manifest.projectId, manifest.profileId, manifest.channel, signature]);
}
/** Согласие включает точный выбор. Подписанный релиз может содержать несколько
 * независимо устанавливаемых планов; согласие на один не разрешает остальные. */
export function approvedSelectionIdentity0393(manifest:SignedTarget0359,preset:string):string {
  return JSON.stringify([updateIdentity0359(manifest),preset]);
}
export function ensureReleaseApproval0359(
  manifest: SignedTarget0359, preview: RequirementPreview0359 | null,
  approvedIdentity: string, previewError = '', requestedPreset = '',
): void {
  updateIdentity0359(manifest); // проверять подписанный целевой объект, даже если предварительный просмотр недоступен
  if (previewError || !preview || preview.targetVersion !== manifest.version ||
      preview.targetSignature !== manifest.signature?.signature) {
    throw new Error('Невозможно подтвердить новые требования без нативной проверки установленной сборки');
  }
  if (preview.blockers.length) {
    throw new Error(preview.blockers.join('; '));
  }
  if (preview.requiresConfirmation &&
      (approvedIdentity !== approvedSelectionIdentity0393(manifest,requestedPreset) ||
       (preview.proposedPreset ?? '') !== requestedPreset)) {
    throw new Error('Изменившиеся требования или выбор компонентов требуют явного подтверждения точного preset');
  }
}
