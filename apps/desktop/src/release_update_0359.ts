// User approval is scoped to the exact signed target, not a release label.
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
export function ensureReleaseApproval0359(
  manifest: SignedTarget0359, preview: RequirementPreview0359 | null,
  approvedIdentity: string, previewError = '',
): void {
  const identity = updateIdentity0359(manifest);
  if (previewError || !preview || preview.targetVersion !== manifest.version ||
      preview.targetSignature !== manifest.signature?.signature) {
    throw new Error('Невозможно подтвердить новые требования без нативной проверки установленной сборки');
  }
  if (preview.blockers.length) {
    throw new Error(preview.blockers.join('; '));
  }
  if (preview.requiresConfirmation && approvedIdentity !== identity) {
    throw new Error('Изменившиеся требования Java, RAM и модов требуют явного подтверждения');
  }
}
