export type PasskeyBegin = { transactionToken: string; publicKey: PublicKeyCredentialRequestOptionsJSON | PublicKeyCredentialCreationOptionsJSON; expiresInSeconds?: number };
export type PasskeySessionResponse = { status?: string; accessToken?: string; session?: { id?: string }; tokens?: { accessToken?: string; refreshToken?: string }; user?: Record<string, unknown> };
export type PublicKeyCredentialRequestOptionsJSON = { challenge: string; rpId?: string; timeout?: number; userVerification?: UserVerificationRequirement; allowCredentials?: Array<{ type: PublicKeyCredentialType; id: string; transports?: AuthenticatorTransport[] }> };
export type PublicKeyCredentialCreationOptionsJSON = { challenge: string; rp: PublicKeyCredentialRpEntity; user: { id: string; name: string; displayName: string }; pubKeyCredParams: PublicKeyCredentialParameters[]; timeout?: number; excludeCredentials?: Array<{ type: PublicKeyCredentialType; id: string; transports?: AuthenticatorTransport[] }>; authenticatorSelection?: AuthenticatorSelectionCriteria; attestation?: AttestationConveyancePreference };
function b64urlToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bufferToB64url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function creationOptionsFromJSON(input: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions {
  return {
    ...input,
    challenge: b64urlToBuffer(input.challenge),
    user: { ...input.user, id: b64urlToBuffer(input.user.id) },
    excludeCredentials: input.excludeCredentials?.map((item) => ({ ...item, id: b64urlToBuffer(item.id) })),
  };
}

function requestOptionsFromJSON(input: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions {
  return {
    ...input,
    challenge: b64urlToBuffer(input.challenge),
    allowCredentials: input.allowCredentials?.map((item) => ({ ...item, id: b64urlToBuffer(item.id) })),
  };
}

export async function createPasskeyCredential(input: PublicKeyCredentialCreationOptionsJSON) {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('Этот браузер не поддерживает WebAuthn/passkeys.');
  const credential = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(input) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error('Authenticator не вернул WebAuthn registration credential.');
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      attestationObject: bufferToB64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() ?? [],
    },
  };
}

export async function getPasskeyAssertion(input: PublicKeyCredentialRequestOptionsJSON) {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('Этот браузер не поддерживает WebAuthn/passkeys.');
  const credential = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(input) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error('Authenticator не вернул WebAuthn assertion.');
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      authenticatorData: bufferToB64url(credential.response.authenticatorData),
      signature: bufferToB64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToB64url(credential.response.userHandle) : undefined,
    },
  };
}

